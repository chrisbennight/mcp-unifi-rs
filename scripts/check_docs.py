#!/usr/bin/env python3
"""Validate local links, heading anchors, JSON examples and configuration coverage."""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote


ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r"!?\[[^\]]*\]\((?P<target>[^)]+)\)")
LINE_ANCHOR = re.compile(r":\d+(?:#.*)?$")
REMOTE_SCHEMES = ("http://", "https://", "mailto:")
IGNORED_DIRECTORIES = frozenset({".git", "target", ".worktrees"})


def heading_anchors(text: str) -> set[str]:
    """Collect the heading anchors used by this repository's Markdown."""
    anchors: set[str] = set()
    fenced = False
    for line in text.splitlines():
        if line.startswith(("```", "~~~")):
            fenced = not fenced
        if fenced or not re.match(r"^#{1,6}\s+", line):
            continue
        heading = re.sub(r"^#{1,6}\s+|\s+#+\s*$", "", line).lower()
        heading = re.sub(r"\[([^\]]+)\]\([^)]*\)", r"\1", heading)
        base = re.sub(r"[^\w\s-]", "", heading).replace(" ", "-")
        anchor = base
        suffix = 0
        while anchor in anchors:
            suffix += 1
            anchor = f"{base}-{suffix}"
        anchors.add(anchor)
    return anchors


def configuration_coverage(root: Path) -> list[str]:
    variables: set[str] = set()
    for filename in ("config.rs", "portable.rs"):
        source = (root / "crates/unifi-server/src" / filename).read_text(encoding="utf-8")
        production = source.split("#[cfg(test)]", maxsplit=1)[0]
        variables.update(re.findall(r'"(UNIFI_MCP_[A-Z0-9_]+)"', production))
    reference = (root / "docs/configuration.md").read_text(encoding="utf-8")
    return [f"docs/configuration.md: missing setting {name}" for name in sorted(variables) if f"`{name}`" not in reference]


def markdown_files(root: Path = ROOT) -> list[Path]:
    return sorted(
        path
        for path in root.rglob("*.md")
        if IGNORED_DIRECTORIES.isdisjoint(path.relative_to(root).parts)
    )


def validate(path: Path) -> list[str]:
    errors: list[str] = []
    text = path.read_text(encoding="utf-8")

    for block in re.finditer(r"^```json\s*\n(.*?)^```\s*$", text, re.MULTILINE | re.DOTALL):
        try:
            json.loads(block.group(1))
        except json.JSONDecodeError:
            line = text[:block.start()].count("\n") + 1
            errors.append(f"{path.relative_to(ROOT)}: invalid JSON example at line {line}")

    for match in LINK.finditer(text):
        raw_target = match.group("target").strip()
        target = (
            raw_target[1:-1]
            if raw_target.startswith("<") and raw_target.endswith(">")
            else raw_target
        )
        target = unquote(target)

        if target.startswith(REMOTE_SCHEMES):
            continue
        if LINE_ANCHOR.search(target):
            errors.append(
                f"{path.relative_to(ROOT)}: fragile line-number link: {raw_target}"
            )
            continue

        file_part, _, fragment = target.partition("#")
        resolved = (path.parent / file_part).resolve() if file_part else path.resolve()
        try:
            resolved.relative_to(ROOT)
        except ValueError:
            errors.append(
                f"{path.relative_to(ROOT)}: link escapes repository: {raw_target}"
            )
            continue
        if not resolved.exists():
            errors.append(
                f"{path.relative_to(ROOT)}: missing local link target: {raw_target}"
            )
        elif fragment and resolved.suffix.lower() == ".md":
            if fragment not in heading_anchors(resolved.read_text(encoding="utf-8")):
                errors.append(f"{path.relative_to(ROOT)}: missing heading anchor: {raw_target}")

    return errors


def main() -> int:
    files = markdown_files()
    errors = [error for path in files for error in validate(path)]
    errors.extend(configuration_coverage(ROOT))
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(f"validated {len(files)} Markdown files")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
