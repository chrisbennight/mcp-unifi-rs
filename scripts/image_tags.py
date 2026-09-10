#!/usr/bin/env python3
"""Validate a source revision and print the image tags for a trusted push."""

import argparse
import re


def image_tags(sha: str, ref: str) -> list[str]:
    if not re.fullmatch(r"[0-9a-f]{40}", sha):
        raise ValueError("source revision must be a full lowercase Git SHA")
    tags = [f"sha-{sha}"]
    if ref == "refs/heads/main":
        return tags + ["latest"]
    prefix = "refs/tags/"
    if ref.startswith(prefix):
        tag = ref.removeprefix(prefix)
        if len(tag) <= 128 and re.fullmatch(
            r"v[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z][0-9A-Za-z.-]*)?", tag
        ):
            return tags + [tag]
    raise ValueError("publication requires main or a vMAJOR.MINOR.PATCH[-SUFFIX] tag")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sha", required=True)
    parser.add_argument("--ref", required=True)
    args = parser.parse_args()
    try:
        tags = image_tags(args.sha, args.ref)
    except ValueError as error:
        parser.error(str(error))
    print("\n".join(tags))


if __name__ == "__main__":
    main()
