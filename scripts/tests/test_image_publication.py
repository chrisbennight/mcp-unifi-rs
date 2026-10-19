from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import image_publication as publication


class DockerRegistryBoundary:
    def __init__(self, root: Path, *, index=False):
        self.root = root
        self.environment = dict(os.environ,
            GITHUB_REPOSITORY=publication.REPOSITORY, GITHUB_SHA="a" * 40,
            GITHUB_REF="refs/heads/main", GITHUB_EVENT_NAME="push", GITHUB_RUN_ID="123", GITHUB_RUN_ATTEMPT="1",
            GITHUB_WORKFLOW_REF=publication.REPOSITORY + "/" + publication.WORKFLOW + "@refs/heads/main",
            GITHUB_ACTOR="release-bot[bot]", GHCR_TOKEN="fixture-secret")
        self.config = json.dumps({"os": "linux", "architecture": "amd64", "config": {
            "Labels": {"org.opencontainers.image.revision": "a" * 40}, "Env": ["TOKEN=fixture-secret"]}}).encode()
        self.loaded_config = None
        self.image_id = "sha256:" + "d" * 64
        self.manifest = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                         "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                                    "digest": publication.digest(self.config), "size": len(self.config)}, "layers": []}
        self.index = index
        self.index_change = None
        self.tag_change = None
        self.calls = []
        self.configurations = []
        self.fail = None
        (root / "image.tar").write_bytes(b"synthetic tested Docker archive")

    def registry(self):
        manifest = json.dumps(self.manifest).encode()
        if not self.index:
            return manifest, {publication.digest(manifest): manifest}
        descriptor = {"mediaType": self.manifest["mediaType"], "digest": publication.digest(manifest),
                      "size": len(manifest), "platform": {"os": "linux", "architecture": "amd64"}}
        index = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.index.v1+json", "manifests": [descriptor]}
        if self.index_change:
            self.index_change(index)
        raw = json.dumps(index).encode()
        return raw, {publication.digest(raw): raw, publication.digest(manifest): manifest}

    def __call__(self, argv, **options):
        self.calls.append(argv)
        self.assert_contract(argv, options)
        if self.fail and self.fail(argv):
            return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"fixture-secret")
        output = b""
        if argv[:3] == ["docker", "image", "inspect"]:
            output = json.dumps(self.image_id).encode()
        elif argv[:2] == ["docker", "login"]:
            directory = Path(options["env"]["DOCKER_CONFIG"])
            self.configurations.append(directory)
            (directory / "config.json").write_text("fixture-secret")
        elif argv[0] == "skopeo":
            target = argv[-1]
            if target.startswith("docker-archive:"):
                output = self.config
            elif target == "docker-daemon:" + self.image_id:
                output = self.loaded_config if self.loaded_config is not None else self.config
            elif target.startswith("docker://" + publication.IMAGE):
                authfile = Path(argv[argv.index("--authfile") + 1])
                if not authfile.is_file():
                    raise AssertionError("registry inspection omitted its private auth file")
                root, documents = self.registry()
                reference = target.removeprefix("docker://" + publication.IMAGE)
                if reference.startswith("@") and reference[1:] not in documents:
                    return subprocess.CompletedProcess(argv, 1, stdout=b"", stderr=b"fixture-secret")
                output = documents[reference[1:]] if reference.startswith("@") else root
                if self.tag_change and reference == ":latest":
                    output = self.tag_change(output)
            else:
                raise AssertionError("unexpected image evidence transport")
        elif argv[:2] not in (["docker", "load"], ["docker", "tag"], ["docker", "push"]):
            raise AssertionError("unexpected publication command")
        return subprocess.CompletedProcess(argv, 0, stdout=output)

    def assert_contract(self, argv, options):
        if (options.get("shell") or options["stderr"] != subprocess.DEVNULL
                or "GHCR_TOKEN" in options["env"] or "GITHUB_TOKEN" in options["env"]
                or any("fixture-secret" in argument for argument in argv)):
            raise AssertionError("publication crossed its credential or subprocess boundary")
        if argv[:2] == ["docker", "login"]:
            if options.get("input") != b"fixture-secret":
                raise AssertionError("registry credential did not use stdin")
        elif options.get("input") is not None:
            raise AssertionError("an unrelated command received registry credentials")


class ImagePublicationTests(unittest.TestCase):
    def fixture(self, root, **options):
        boundary = DockerRegistryBoundary(root, **options)
        return boundary, patch.object(publication.subprocess, "run", side_effect=boundary)

    def test_complete_flow_binds_tested_archive_to_registry_for_both_docker_id_forms(self):
        for index in (False, True):
            with self.subTest(index=index), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                boundary, patched = self.fixture(root, index=index)
                if not index:
                    boundary.image_id = publication.digest(boundary.config)
                with patched:
                    publication.record(root, boundary.environment)
                    tested = json.loads((root / "tested-image.json").read_text())
                    self.assertEqual(boundary.image_id == tested["config_digest"], not index)
                    publication.publish(root, boundary.environment)
                record = json.loads((root / "unifi-publication.json").read_text())
                self.assertEqual(record, {"schema_version": 1, **publication.context(boundary.environment), "images": [{
                    "repository": publication.IMAGE, "tag": "sha-" + "a" * 40,
                    "digest": publication.digest(boundary.registry()[0]), "platforms": ["linux/amd64"]}]})
                self.assertNotIn("fixture-secret", json.dumps(tested) + json.dumps(record))
                pushes = [argv[-1] for argv in boundary.calls if argv[:2] == ["docker", "push"]]
                self.assertEqual(pushes, [publication.IMAGE + ":sha-" + "a" * 40, publication.IMAGE + ":latest"])
                self.assertTrue(all(not path.exists() for path in boundary.configurations))

    def test_invalid_archive_platform_revision_or_loaded_configuration_cannot_be_recorded(self):
        for defect in ("platform", "source", "loaded"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                boundary, patched = self.fixture(root)
                if defect == "loaded":
                    boundary.loaded_config = b"different configuration"
                else:
                    config = json.loads(boundary.config)
                    if defect == "platform":
                        config["architecture"] = "arm64"
                    else:
                        config["config"]["Labels"] = {}
                    boundary.config = json.dumps(config).encode()
                (root / "tested-image.json").write_text("stale record")
                with patched, self.assertRaises(publication.PublicationError):
                    publication.record(root, boundary.environment)
                self.assertFalse((root / "tested-image.json").exists())

    def test_changed_archive_attempt_or_untrusted_source_fails_before_any_push(self):
        for defect in ("archive", "attempt", "repository", "workflow", "event"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                boundary, patched = self.fixture(root)
                with patched:
                    publication.record(root, boundary.environment)
                    if defect == "archive":
                        (root / "image.tar").write_bytes(b"changed archive")
                    else:
                        key, value = {"attempt": ("GITHUB_RUN_ATTEMPT", "2"), "repository": ("GITHUB_REPOSITORY", "other/fork"),
                                      "workflow": ("GITHUB_WORKFLOW_REF", "wrong workflow"), "event": ("GITHUB_EVENT_NAME", "pull_request")}[defect]
                        boundary.environment[key] = value
                    (root / "unifi-publication.json").write_text("stale receipt")
                    with self.assertRaises(publication.PublicationError):
                        publication.publish(root, boundary.environment)
                self.assertFalse((root / "unifi-publication.json").exists())
                self.assertFalse(any(argv[:2] == ["docker", "push"] for argv in boundary.calls))

    def test_failed_push_or_registry_proof_never_emits_a_receipt_and_never_retries_pushes(self):
        for defect in ("push", "config", "child-size", "child-platform", "ambiguous", "extended-duplicate", "tag-drift"):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                boundary, patched = self.fixture(root, index=defect in {"child-size", "child-platform", "ambiguous", "extended-duplicate"})
                with patched:
                    publication.record(root, boundary.environment)
                    if defect == "push":
                        boundary.fail = lambda argv: argv[:2] == ["docker", "push"]
                    elif defect == "config":
                        boundary.manifest["config"]["digest"] = "sha256:" + "e" * 64
                    elif defect == "child-size":
                        boundary.index_change = lambda value: value["manifests"][0].update(size=1)
                    elif defect == "child-platform":
                        boundary.index_change = lambda value: value["manifests"][0]["platform"].update(architecture="arm64")
                    elif defect in {"ambiguous", "extended-duplicate"}:
                        def duplicate(value):
                            other = copy.deepcopy(value["manifests"][0])
                            if defect == "extended-duplicate":
                                other["platform"]["os.features"] = []
                            value["manifests"].append(other)
                        boundary.index_change = duplicate
                    else:
                        boundary.tag_change = lambda raw: raw + b" "
                    with self.assertRaises(publication.PublicationError) as error:
                        publication.publish(root, boundary.environment)
                self.assertNotIn("fixture-secret", str(error.exception))
                self.assertFalse((root / "unifi-publication.json").exists())
                pushes = [argv[-1] for argv in boundary.calls if argv[:2] == ["docker", "push"]]
                self.assertEqual(len(pushes), 1 if defect == "push" else 2)
                self.assertEqual(len(pushes), len(set(pushes)))
                self.assertTrue(all(not path.exists() for path in boundary.configurations))

    def test_version_channel_preserves_alias_without_advancing_latest(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boundary, patched = self.fixture(root)
            boundary.environment.update(GITHUB_REF="refs/tags/v1.2.3", GITHUB_WORKFLOW_REF=publication.REPOSITORY + "/" + publication.WORKFLOW + "@refs/tags/v1.2.3")
            with patched:
                publication.record(root, boundary.environment)
                publication.publish(root, boundary.environment)
            self.assertEqual([argv[-1] for argv in boundary.calls if argv[:2] == ["docker", "push"]],
                             [publication.IMAGE + ":sha-" + "a" * 40, publication.IMAGE + ":v1.2.3"])

    def test_pull_request_can_qualify_the_archive_without_publication_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            boundary, patched = self.fixture(root)
            boundary.environment.update(GITHUB_EVENT_NAME="pull_request", GITHUB_REF="refs/pull/1/merge",
                GITHUB_WORKFLOW_REF=publication.REPOSITORY + "/" + publication.WORKFLOW + "@refs/pull/1/merge")
            with patched:
                publication.record(root, boundary.environment)
                self.assertTrue((root / "tested-image.json").is_file())
                with self.assertRaises(publication.PublicationError):
                    publication.publish(root, boundary.environment)
            self.assertFalse(any(argv[:2] == ["docker", "push"] for argv in boundary.calls))

    def test_workflow_preserves_inventory_and_gates_attempt_specific_artifacts(self):
        root = Path(__file__).resolve().parents[2]
        workflow = (root / ".github/workflows/build.yml").read_text()
        self.assertIn("docker build --platform linux/amd64", workflow)
        self.assertLess(workflow.index("name: software-inventory"), workflow.index("- name: Record tested image identity"))
        self.assertIn("name: tested-image-${{ github.run_id }}-${{ github.run_attempt }}", workflow)
        self.assertIn("steps.tested.outcome == 'success'", workflow)
        retained = workflow.split("      - name: Retain verified publication record\n", 1)[1]
        self.assertIn("if: steps.publish.outcome == 'success'", retained)
        self.assertIn("name: unifi-publication-${{ github.run_id }}-${{ github.run_attempt }}", retained)
        self.assertIn("path: ${{ runner.temp }}/tested-image/unifi-publication.json", retained)
        self.assertIn("if-no-files-found: error", retained)


if __name__ == "__main__":
    unittest.main()
