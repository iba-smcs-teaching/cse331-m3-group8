#!/usr/bin/env bash
# Check-run budget.
#
#   budget.sh [cap]        cap defaults to 2
#
# Each check run is a `submit/*` tag, minted by `gh student submit`.
# Counting those tags counts your runs. The cap is passed in by the test
# plan rather than stored here, so the course can change it without you having to
# pull anything.
#
# Over budget writes out/OVERBUDGET, which restore.sh, build.sh and boot.sh
# all check, so the build and the QEMU boot are skipped rather than paid for.
set -uo pipefail
cd "$(dirname "$0")/../.."
CI=.github/ci
CAP="${1:-2}"
case "$CAP" in ''|*[!0-9]*) CAP=2;; esac

# Destroy any out/ the submission carried, so a committed OVERBUDGET or boot log
# cannot change this run. The runner never strips .github/, so it is done here.
rm -rf "$CI/out"
mkdir -p "$CI/out"

used="$(git -c safe.directory='*' tag --list 'submit/*' 2>/dev/null | wc -l | tr -dc '0-9')"
: "${used:=0}"

# Fail open. If the tags are not visible (running locally, or a checkout that
# did not fetch them) the count reads 0, and a cost control must never refuse an
# honest submission on missing evidence.
if [ "$used" -le "$CAP" ]; then
  shown="$used"; [ "$shown" -lt 1 ] && shown=1
  echo "Check run $shown of $CAP for this assignment."
  [ "$used" -eq "$CAP" ] && echo "This is your last check run; further submissions will not be checked."
  exit 0
fi

: > "$CI/out/OVERBUDGET"
cat >&2 <<MSG
================================================================
NOT RUN: you have used all $CAP check runs ($used tags).

This does not affect your mark. These runs carry no marks; staff mark
your report. Keep working and keep pushing: a plain git push costs
nothing and does not use up a run.

You can run the same checks yourself at any time:
  bash .github/ci/build.sh && bash .github/ci/boot.sh

Count your runs with:
  git tag --list 'submit/*'
================================================================
MSG
exit 1
