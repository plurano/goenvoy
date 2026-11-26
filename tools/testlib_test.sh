#!/usr/bin/env bash
# Exercise the test library: a fixture repository stays apart from the repository a hook exports.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Why: sourced before the first git command, so this test builds its own fixtures apart from an exported repository too.
# shellcheck source=/dev/null
. "$HERE/testlib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/caller" "$WORK/fixture"
GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 git -C "$WORK/caller" init -q
printf 'probe\n' > "$WORK/fixture/probe.txt"
# Why: the library is sourced with the caller's repository exported, the way a hook runs a test.
GIT_DIR="$WORK/caller/.git" GIT_INDEX_FILE="$WORK/caller/.git/index" GIT_WORK_TREE="$WORK/caller" \
  GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1 bash -c '
    set -euo pipefail
    . "$1/testlib.sh"
    git -C "$2" init -q
    git -C "$2" add probe.txt
  ' _ "$HERE" "$WORK/fixture"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
expect_output caller_index_untouched '' git -C "$WORK/caller" ls-files
expect_output fixture_owns_file 'probe.txt' git -C "$WORK/fixture" ls-files

# Why: a failed assertion exits its subshell, leaving the suite to check the result.
expect_assertion_failure() {
  if (expect_status "$@") > "$WORK/assertion.log" 2>&1; then
    printf 'FAIL %s: assertion accepted the planted case\n' "$1" >&2
    exit 1
  fi
  printf 'ok   %s: assertion refused the planted case\n' "$1"
}

expect_status exact_status 2 'fixture diagnostic' bash -c 'echo "fixture diagnostic" >&2; exit 2'
expect_assertion_failure wrong_status 2 'fixture diagnostic' bash -c 'echo "fixture diagnostic" >&2; exit 1'
expect_assertion_failure stdout_diagnostic 2 'fixture diagnostic' bash -c 'echo "fixture diagnostic"; exit 2'
expect_assertion_failure stdout_newline 2 'fixture diagnostic' bash -c 'echo; echo "fixture diagnostic" >&2; exit 2'
expect_assertion_failure wrong_diagnostic 2 'fixture diagnostic' bash -c 'echo "other diagnostic" >&2; exit 2'
expect_assertion_failure empty_needle 2 '' bash -c 'echo "fixture diagnostic" >&2; exit 2'
echo "testlib: all planted cases pass"
