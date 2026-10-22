#!/usr/bin/env bash
# Succeed only when the running workflow was dispatched from `refs/heads/main` and commit `$1`
# is an ancestor of `origin/main`. Needs a checkout with full history.
#
# The attested source ref is the ref the workflow runs from, and the attestation checks require
# `refs/heads/main`; `workflow_dispatch` accepts --ref, so it is enforced here. Without the
# ancestry check a release can be pinned to unmerged code while every later check passes.
set -euo pipefail

sha="${1:?commit required}"

if [[ "$GITHUB_REF" != "refs/heads/main" ]]; then
    echo "::error::${GITHUB_WORKFLOW} must be dispatched from main, not ${GITHUB_REF}"
    exit 1
fi

git fetch --quiet origin main

status=0
git merge-base --is-ancestor "$sha" origin/main || status=$?

case "$status" in
    0)
        echo "${sha} is an ancestor of origin/main"
        ;;
    1)
        echo "::error::${sha} is not an ancestor of origin/main. Release only from merged commits."
        exit 1
        ;;
    *)
        echo "::error::git merge-base failed (exit ${status}); cannot confirm ${sha} is on main"
        exit 1
        ;;
esac
