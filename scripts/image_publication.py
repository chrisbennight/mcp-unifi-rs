#!/usr/bin/env python3
"""Bind the tested Docker archive to verified immutable publication evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from image_tags import image_tags

REPOSITORY = "chrisbennight/mcp-unifi-rs"
IMAGE = "ghcr.io/" + REPOSITORY
WORKFLOW = ".github/workflows/build.yml"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
MAX_JSON = 4 * 1024 * 1024
INDEX_TYPES = {"application/vnd.oci.image.index.v1+json", "application/vnd.docker.distribution.manifest.list.v2+json"}
MANIFEST_TYPES = {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"}
CONFIG_TYPES = {"application/vnd.oci.image.config.v1+json", "application/vnd.docker.container.image.v1+json"}


class PublicationError(RuntimeError):
    pass


def digest(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def command(argv: list[str], environment: dict[str, str], *, capture=False, input=None) -> bytes:
    child = {key: value for key, value in environment.items() if key not in {"GITHUB_TOKEN", "GHCR_TOKEN"}}
    try:
        result = subprocess.run(argv, env=child, input=input, stdout=subprocess.PIPE if capture else subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, check=False, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        raise PublicationError("image evidence command unavailable or timed out") from None
    if result.returncode:
        raise PublicationError("image evidence command failed; inspect publication state before retrying")
    if capture and len(result.stdout) > MAX_JSON:
        raise PublicationError("image evidence response exceeds its size limit")
    return result.stdout if capture else b""


def json_object(raw: bytes) -> dict:
    if len(raw) > MAX_JSON:
        raise PublicationError("image evidence JSON exceeds its size limit")
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise PublicationError("image evidence is not valid JSON") from None
    if not isinstance(value, dict):
        raise PublicationError("image evidence must be a JSON object")
    return value


def context(environment: dict[str, str], *, publishing=False) -> dict:
    repository, sha, ref = (environment.get(key, "") for key in ("GITHUB_REPOSITORY", "GITHUB_SHA", "GITHUB_REF"))
    if (not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repository)
            or not re.fullmatch(r"[0-9a-f]{40}", sha) or not ref.startswith("refs/")
            or len(ref) > 1024 or any(ord(char) < 32 for char in ref)
            or environment.get("GITHUB_WORKFLOW_REF") != f"{repository}/{WORKFLOW}@{ref}"):
        raise PublicationError("image evidence requires its exact source workflow context")
    for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT"):
        if not re.fullmatch(r"[1-9][0-9]{0,19}", environment.get(key, "")):
            raise PublicationError("image evidence requires a complete workflow run and attempt")
    if publishing:
        if repository != REPOSITORY or environment.get("GITHUB_EVENT_NAME") != "push":
            raise PublicationError("publication requires a push to the canonical repository")
        image_tags(sha, ref)
    return {"source_repository": repository, "source_commit": sha, "source_ref": ref, "workflow": WORKFLOW,
            "run_id": int(environment["GITHUB_RUN_ID"]), "run_attempt": int(environment["GITHUB_RUN_ATTEMPT"])}


def archive_identity(directory: Path, environment: dict[str, str]) -> dict:
    archive = directory / "image.tar"
    raw = command(["skopeo", "inspect", "--raw", "--config", "docker-archive:" + str(archive)], environment, capture=True)
    config = json_object(raw)
    settings = config.get("config")
    labels = settings.get("Labels") if isinstance(settings, dict) else None
    if (config.get("os") != "linux" or config.get("architecture") != "amd64"
            or not isinstance(labels, dict) or labels.get("org.opencontainers.image.revision") != environment["GITHUB_SHA"]):
        raise PublicationError("tested archive must identify its source revision and linux/amd64")
    with archive.open("rb") as source:
        archive_digest = "sha256:" + hashlib.file_digest(source, "sha256").hexdigest()
    return {"archive_digest": archive_digest, "config_digest": digest(raw), "config_size": len(raw), "platform": "linux/amd64"}


def loaded_image(expected: dict, environment: dict[str, str]) -> str:
    reference = IMAGE + ":sha-" + expected["source_commit"]
    raw = command(["docker", "image", "inspect", "--format", "{{json .Id}}", reference], environment, capture=True)
    try:
        identity = json.loads(raw)
    except (ValueError, UnicodeDecodeError):
        raise PublicationError("loaded image has no complete immutable Docker identity") from None
    if not isinstance(identity, str) or DIGEST.fullmatch(identity) is None:
        raise PublicationError("loaded image has no complete immutable Docker identity")
    config = command(["skopeo", "inspect", "--raw", "--config", "docker-daemon:" + identity], environment, capture=True)
    if digest(config) != expected["config_digest"]:
        raise PublicationError("loaded Docker image differs from the tested archive configuration")
    return identity


def record(directory: Path, environment: dict[str, str]) -> None:
    output = directory / "tested-image.json"
    output.unlink(missing_ok=True)
    evidence = {"schema_version": 1, **context(environment), **archive_identity(directory, environment)}
    loaded_image(evidence, environment)
    output.write_text(json.dumps(evidence, sort_keys=True) + "\n")


def verify(directory: Path, environment: dict[str, str]) -> dict:
    with (directory / "tested-image.json").open("rb") as source:
        recorded = json_object(source.read(MAX_JSON + 1))
    expected = {"schema_version": 1, **context(environment), **archive_identity(directory, environment)}
    if recorded != expected:
        raise PublicationError("tested image record is stale or differs from its source archive")
    return expected


def registry_digest(tag: str, expected: dict, environment: dict[str, str], authfile: Path) -> str:
    def raw(reference: str) -> bytes:
        return command(["skopeo", "inspect", "--authfile", str(authfile), "--raw", "docker://" + reference], environment, capture=True)

    root = raw(IMAGE + ":" + tag)
    identity = digest(root)
    pinned = raw(IMAGE + "@" + identity)
    if digest(pinned) != identity:
        raise PublicationError("registry did not return the published immutable manifest")
    manifest = json_object(pinned)
    if manifest.get("schemaVersion") != 2:
        raise PublicationError("registry manifest has an unsupported schema")
    if manifest.get("mediaType") in INDEX_TYPES:
        manifests = manifest.get("manifests")
        if not isinstance(manifests, list) or len(manifests) > 64:
            raise PublicationError("registry index has an invalid platform inventory")
        candidates = [item for item in manifests if isinstance(item, dict)
                      and isinstance(item.get("platform"), dict)
                      and item["platform"].get("os") == "linux" and item["platform"].get("architecture") == "amd64"]
        if len(candidates) != 1:
            raise PublicationError("registry index lacks a unique linux/amd64 manifest")
        child = candidates[0]
        child_digest, size = child.get("digest"), child.get("size")
        if (child.get("platform") != {"os": "linux", "architecture": "amd64"}
                or not isinstance(child_digest, str) or DIGEST.fullmatch(child_digest) is None
                or child.get("mediaType") not in MANIFEST_TYPES or type(size) is not int or not 0 < size <= MAX_JSON):
            raise PublicationError("registry platform descriptor is invalid")
        pinned = raw(IMAGE + "@" + child_digest)
        if digest(pinned) != child_digest or len(pinned) != size:
            raise PublicationError("registry platform manifest differs from its descriptor")
        manifest = json_object(pinned)
        if manifest.get("mediaType") != child["mediaType"]:
            raise PublicationError("registry platform manifest type differs from its descriptor")
    config = manifest.get("config")
    if (manifest.get("schemaVersion") != 2 or manifest.get("mediaType") not in MANIFEST_TYPES
            or not isinstance(config, dict) or config.get("mediaType") not in CONFIG_TYPES
            or config.get("digest") != expected["config_digest"] or type(config.get("size")) is not int
            or config.get("size") != expected["config_size"]):
        raise PublicationError("published manifest differs from the tested image configuration")
    return identity


def publish(directory: Path, environment: dict[str, str]) -> None:
    output = directory / "unifi-publication.json"
    output.unlink(missing_ok=True)
    source = context(environment, publishing=True)
    tags = image_tags(source["source_commit"], source["source_ref"])
    actor, token = environment.get("GITHUB_ACTOR", ""), environment.get("GHCR_TOKEN", "")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_\[\]-]{0,99}", actor) or not token:
        raise PublicationError("publication requires its workflow actor and registry credential")
    expected = verify(directory, environment)
    with tempfile.TemporaryDirectory(prefix="unifi-docker-") as configuration:
        child = environment | {"DOCKER_CONFIG": configuration}
        command(["docker", "load", "--input", str(directory / "image.tar")], child)
        identity = loaded_image(expected, child)
        command(["docker", "login", "ghcr.io", "--username", actor, "--password-stdin"], child, input=token.encode())
        for tag in tags:
            reference = IMAGE + ":" + tag
            command(["docker", "tag", identity, reference], child)
            command(["docker", "push", reference], child)
        verified = {registry_digest(tag, expected, child, Path(configuration) / "config.json") for tag in tags}
        if len(verified) != 1:
            raise PublicationError("published tags identify different manifests")
        published = verified.pop()
    output.write_text(json.dumps({"schema_version": 1, **source,
        "images": [{"repository": IMAGE, "tag": tags[0], "digest": published, "platforms": ["linux/amd64"]}],
    }, sort_keys=True) + "\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["record", "publish"])
    parser.add_argument("directory", type=Path)
    arguments = parser.parse_args()
    try:
        {"record": record, "publish": publish}[arguments.action](arguments.directory, dict(os.environ))
    except PublicationError as error:
        parser.exit(1, str(error) + "\n")
    except (ValueError, KeyError, OSError):
        parser.exit(1, "image publication evidence is missing or invalid\n")


if __name__ == "__main__":
    main()
