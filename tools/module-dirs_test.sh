#!/usr/bin/env bash
# Planted cases for go.mod module discovery and path-to-module mapping.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/testlib.sh disable=SC1091
. "$HERE/testlib.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FIXTURE="$WORK/fixture"
mkdir -p "$FIXTURE/a/b/z" "$FIXTURE/c" "$FIXTURE/.workingdir2/x" "$FIXTURE/tools/go"
printf 'module example/a\n\ngo 1.22\n' >"$FIXTURE/a/go.mod"
printf 'module example/ab\n\ngo 1.22\n' >"$FIXTURE/a/b/go.mod"
printf 'module example/c\n\ngo 1.22\n' >"$FIXTURE/c/go.mod"
printf 'module example/workdir\n\ngo 1.22\n' >"$FIXTURE/.workingdir2/x/go.mod"
printf 'module example/toolsgo\n\ngo 1.22\n' >"$FIXTURE/tools/go/go.mod"
: >"$FIXTURE/a/x.go"
: >"$FIXTURE/a/b/y.go"
: >"$FIXTURE/a/b/z/w.go"
: >"$FIXTURE/c/q.go"
: >"$FIXTURE/.workingdir2/x/f.go"
: >"$FIXTURE/README.md"

# run_in_fixture ARGS...: runs tools/module-dirs.sh with ARGS inside the fixture tree.
run_in_fixture() {
  # Why: the script resolves modules from its working directory, so every case runs inside the fixture.
  (cd "$FIXTURE" && bash "$HERE/module-dirs.sh" "$@")
}

# run_stdin_in_fixture: runs tools/module-dirs.sh inside the fixture tree with stdin.txt as input.
run_stdin_in_fixture() {
  (cd "$FIXTURE" && bash "$HERE/module-dirs.sh" <"$WORK/stdin.txt")
}

want_all=$(printf '%s\n' a a/b c)
want_all="${want_all%$'\n'}"
expect_output '--all lists modules' "$want_all" run_in_fixture --all

printf '%s\n' a/x.go a/b/y.go a/b/z/w.go c/q.go c/q.go README.md >"$WORK/stdin.txt"
expect_output 'stdin path mapping' "$want_all" run_stdin_in_fixture

expect_output 'root-only path' '' run_in_fixture README.md

expect_output 'workingdir excluded' '' run_in_fixture .workingdir2/x/f.go

expect_output 'argument form' "$want_all" run_in_fixture a/x.go a/b/y.go a/b/z/w.go c/q.go c/q.go README.md

too_many=()
idx=0
while [ "$idx" -lt 4097 ]; do
  too_many+=("orphan/$idx.go")
  idx=$((idx + 1))
done
expect_refusal '4097 paths refused' 'too many paths' run_in_fixture "${too_many[@]}"

repo_count=$(find . -name go.mod -not -path './.workingdir*' -not -path './tools/go/*' | wc -l)
repo_count=${repo_count// /}
script_count=$(bash "$HERE/module-dirs.sh" --all | wc -l)
script_count=${script_count// /}
if [ "$repo_count" != "$script_count" ]; then
  printf 'FAIL real repository: find count %s, script count %s\n' "$repo_count" "$script_count" >&2
  exit 1
fi
if ! bash "$HERE/module-dirs.sh" --all | grep -qx arr; then
  printf 'FAIL real repository: expected arr module in --all output\n' >&2
  exit 1
fi
echo "ok   real repository: $script_count modules including arr"

echo "module-dirs_test: all planted cases pass"