from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path


sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import check_docs  # noqa: E402


class MarkdownValidationTests(unittest.TestCase):
    def test_ignores_build_artifacts_and_rejects_fragile_links(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            kept = root / "docs" / "kept.md"
            ignored = root / "target" / "doc" / "generated.md"
            worktree = root / ".worktrees" / "other" / "README.md"
            target = root / "README.md"

            for path in [kept, ignored, target, worktree]:
                path.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# Readme\n", encoding="utf-8")
            kept.write_text("[ok](../README.md) [bad](../README.md:12)\n", encoding="utf-8")
            ignored.write_text("[missing](nowhere.md)\n", encoding="utf-8")
            worktree.write_text("[missing](nowhere.md)\n", encoding="utf-8")

            self.assertEqual(check_docs.markdown_files(root), [target, kept])
            previous = check_docs.ROOT
            try:
                check_docs.ROOT = root
                self.assertEqual(
                    check_docs.validate(kept),
                    ["docs/kept.md: fragile line-number link: ../README.md:12"],
                )
            finally:
                check_docs.ROOT = previous

    def test_checks_heading_links_and_json_examples(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory).resolve()
            path = root / "README.md"
            path.write_text(
                '# Setup\n## `tools.list`\n## Setup\n'
                '[valid](#toolslist) [duplicate](#setup-1) [bad](#removed)\n'
                '```json\n{"valid": true}\n```\n'
                '```json\n{"invalid": }\n```\n', encoding="utf-8")
            previous = check_docs.ROOT
            try:
                check_docs.ROOT = root
                errors = check_docs.validate(path)
                self.assertEqual(len(errors), 2)
                self.assertTrue(any("invalid JSON example" in error for error in errors))
                self.assertTrue(any("missing heading anchor: #removed" in error for error in errors))
            finally:
                check_docs.ROOT = previous

    def test_requires_documentation_for_each_production_setting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory)
            source = root / "crates/unifi-server/src"
            source.mkdir(parents=True)
            (root / "docs").mkdir()
            (source / "config.rs").write_text('"UNIFI_MCP_HOST"\n#[cfg(test)]\n"UNIFI_MCP_TEST_ONLY"')
            (source / "portable.rs").write_text('"UNIFI_MCP_ALLOW_WRITES" "UNIFI_MCP_CONTROLLER_CERT_SHA256"')
            reference = root / "docs/configuration.md"
            reference.write_text('`UNIFI_MCP_HOST`')
            self.assertEqual(check_docs.configuration_coverage(root), [
                'docs/configuration.md: missing setting UNIFI_MCP_ALLOW_WRITES',
                'docs/configuration.md: missing setting UNIFI_MCP_CONTROLLER_CERT_SHA256'])
            reference.write_text('`UNIFI_MCP_HOST` `UNIFI_MCP_ALLOW_WRITES` `UNIFI_MCP_CONTROLLER_CERT_SHA256`')
            self.assertEqual(check_docs.configuration_coverage(root), [])


if __name__ == "__main__":
    unittest.main()
