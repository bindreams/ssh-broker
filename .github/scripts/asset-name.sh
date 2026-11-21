#!/usr/bin/env bash
# The release assets' identity, defined once. `asset-name.sh --triple` prints the target triple,
# `--exe` the executable's name and `--sums` the name of the file of its SHA-256 sum. The exe's
# name has no version in it, so that `releases/latest/download/<name>` is a stable link.
set -euo pipefail

triple=x86_64-pc-windows-msvc

case "${1:?--triple, --exe or --sums required}" in
    --triple) printf '%s\n' "$triple" ;;
    --exe) printf 'ssh-broker-%s.exe\n' "$triple" ;;
    --sums) printf 'SHA256SUMS\n' ;;
    *)
        echo "::error::unknown argument '$1'; expected --triple, --exe or --sums" >&2
        exit 1
        ;;
esac
