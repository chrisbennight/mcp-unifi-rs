#!/usr/bin/env bash
set -euo pipefail

rust=false
python=false
docs=false
compose=false
image=false
publish=false
case "${GITHUB_EVENT_NAME:?event is required}" in
  workflow_dispatch|schedule) full=true ;;
  push|pull_request)
    full=false
    if [[ "$GITHUB_EVENT_NAME" == push && "${GITHUB_REF:-}" == refs/tags/* ]]; then full=true; fi
    ;;
  *) echo 'Unsupported CI event' >&2; exit 1 ;;
esac
if [[ "$full" == true ]]; then
  publish=true
  rust=true; python=true; docs=true; compose=true; image=true
else
  [[ "${BASE_SHA:-}" =~ ^[0-9a-f]{40}$ ]] || { echo 'A full base commit is required' >&2; exit 1; }
  changed_files="$(mktemp)"
  trap 'rm -f "$changed_files"' EXIT
  if [[ "$GITHUB_EVENT_NAME" == pull_request ]]; then
    git diff --name-only --no-renames -z "$BASE_SHA...HEAD" >"$changed_files"
  else
    git diff --name-only --no-renames -z "$BASE_SHA" HEAD >"$changed_files"
  fi
  while IFS= read -r -d '' path; do
    case "$path" in
      scripts/ci-scope.sh) rust=true; python=true; docs=true; compose=true; image=true ;;

      .github/workflows/test.yml) rust=true; python=true; docs=true ;;
      .github/workflows/*) rust=true; python=true; docs=true; compose=true; image=true ;;
      Cargo.toml|Cargo.lock|rust-toolchain.toml|rust-toolchain|crates/*/Cargo.toml|.cargo/*) rust=true; image=true ;;
      rustfmt.toml|.rustfmt.toml|clippy.toml|.clippy.toml) rust=true ;;
      crates/unifi-server/src/collector/tests.rs|crates/*/tests/*|crates/*/benches/*) rust=true ;;
      crates/*/*.md) docs=true ;;
      crates/*) rust=true; image=true ;;
      Dockerfile|.dockerignore|scripts/check_build_context.py|scripts/smoke_image.py|scripts/image_tags.py|scripts/qualify_*|scripts/build*|LICENSE|THIRD_PARTY_NOTICES.md)
        image=true ;;
      compose*.yml|.env*.example) compose=true ;;
    esac
    case "$path" in
      *.md) docs=true ;;
      scripts/check_docs.py) docs=true; python=true ;;
      scripts/*) python=true ;;
    esac

    case "$path" in
      crates/unifi-server/src/config.rs|crates/unifi-server/src/portable.rs) docs=true ;;
    esac
    case "$path" in
      crates/unifi-server/src/collector/tests.rs|crates/*/tests/*|crates/*/benches/*|crates/*/*.md) ;;
      Cargo.toml|Cargo.lock|rust-toolchain.toml|rust-toolchain|.cargo/*|crates/*|Dockerfile|.dockerignore|LICENSE|THIRD_PARTY_NOTICES.md) publish=true ;;
    esac
    if [[ ! -e "$path" ]]; then docs=true; fi
  done <"$changed_files"
fi
printf 'rust=%s\npython=%s\ndocs=%s\ncompose=%s\nimage=%s\npublish=%s\n' \
  "$rust" "$python" "$docs" "$compose" "$image" "$publish" >>"${GITHUB_OUTPUT:?output file is required}"
