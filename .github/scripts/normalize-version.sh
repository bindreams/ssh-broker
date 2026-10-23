#!/usr/bin/env bash
# Echo `$1` if it is a bare MAJOR.MINOR.PATCH, otherwise exit non-zero. A leading `v` is
# rejected, not stripped: the workflows key their concurrency group on the raw input, so
# `0.1.0` and `v0.1.0` must not both name the tag `v0.1.0`. A leading zero in any component is
# rejected too: `1.02.3` and `1.2.3` are different git tags.
set -euo pipefail

input="${1-}"

if [[ ! "$input" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
    echo "::error::Invalid version: '${input}'. Pass MAJOR.MINOR.PATCH without a leading 'v'." >&2
    exit 1
fi

printf '%s\n' "$input"
