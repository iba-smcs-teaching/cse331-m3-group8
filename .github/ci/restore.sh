#!/usr/bin/env bash
# Restore .github/ci from the starter commit, so the check that runs is the one
# you were given. Run before build.sh.
set -euo pipefail
cd "$(dirname "$0")/../.."
CI=.github/ci
[ -f "$CI/out/OVERBUDGET" ] && { echo "not run: check budget used up" >&2; exit 1; }

BASE="$(git -c safe.directory='*' rev-list --max-parents=0 HEAD 2>/dev/null | tail -1 || true)"
if [ -n "$BASE" ]; then
  git -c safe.directory='*' checkout "$BASE" -- "$CI" 2>/dev/null \
    || echo "note: could not restore $CI from $BASE; using the working copy"
else
  echo "note: not a git checkout; using the working copy of $CI"
fi
