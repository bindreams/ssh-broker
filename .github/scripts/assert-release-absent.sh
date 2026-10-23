#!/usr/bin/env bash
# Succeed only when the repository (`GH_REPO`, token in `GH_TOKEN`) provably has no release
# `$1`, draft or published.
#
# `gh release view` exits non-zero both for a missing release and for transient failures.
# Treating an outage as "absent" would create a second draft, since GitHub does not enforce
# tag_name uniqueness across drafts.
set -euo pipefail

tag="${1:?tag required}"

status=0
output="$(gh release view "$tag" --json tagName 2>&1)" || status=$?

if [[ "$status" -eq 0 ]]; then
    echo "::error::Release ${tag} already exists (draft or published). Delete it or pick a new version."
    exit 1
fi
if ! grep -qi 'release not found' <<<"$output"; then
    echo "::error::Cannot confirm whether ${tag} exists: ${output}"
    exit 1
fi

echo "no existing release ${tag}"
