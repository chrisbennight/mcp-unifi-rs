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
            target = root / "README.md"

            for path in [kept, ignored, target]:
                path.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("# Readme\n", encoding="utf-8")
            kept.write_text("[ok](../README.md) [bad](../README.md:12)\n", encoding="utf-8")
            ignored.write_text("[missing](nowhere.md)\n", encoding="utf-8")

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


if __name__ == "__main__":
    unittest.main()
