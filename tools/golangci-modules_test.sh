#!/usr/bin/env bash
# Planted cases for per-module golangci-lint dispatch.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=tools/testlib.sh disable=SC1091
. "$HERE/testlib.sh"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

FIXTURE="$WORK/fixture"
STUB_BIN="$WORK/bin"
LOG="$WORK/golangci-stub.log"
mkdir -p "$STUB_BIN" "$FIXTURE/tools" "$FIXTURE/a/b" "$FIXTURE/c"
printf 'module example/a\n\ngo 1.22\n' >"$FIXTURE/a/go.mod"
printf 'module example/ab\n\ngo 1.22\n' >"$FIXTURE/a/b/go.mod"
printf 'module example/c\n\ngo 1.22\n' >"$FIXTURE/c/go.mod"
: >"$FIXTURE/a/x.go"
: >"$FIXTURE/a/b/y.go"
: >"$FIXTURE/c/q.go"
: >"$FIXTURE/.golangci.yml"
cp "$HERE/module-dirs.sh" "$HERE/golangci-modules.sh" "$FIXTURE/tools/"
chmod +x "$FIXTURE/tools/module-dirs.sh" "$FIXTURE/tools/golangci-modules.sh"

cat >"$STUB_BIN/golangci-lint" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
log="${GOLANGCI_STUB_LOG:?GOLANGCI_STUB_LOG unset}"
if [ ! -f go.mod ]; then
  echo "typechecking error: pattern ./...: directory prefix . does not contain main module" >&2
  exit 1
fi
if [ -f FAIL ]; then
  exit 1
fi
printf '%s %s\n' "$PWD" "$*" >>"$log"
exit 0
STUB
chmod +x "$STUB_BIN/golangci-lint"

# invoke_sut ARGS...: runs the fixture copy of tools/golangci-modules.sh with the stub golangci-lint.
invoke_sut() {
  # Why: copies under the fixture tree resolve the repository root from their own location.
  (
    cd "$FIXTURE"
    PATH="$STUB_BIN:$PATH" GOLANGCI_STUB_LOG="$LOG" bash tools/golangci-modules.sh "$@"
  )
}

: >"$LOG"
expect_pass 'two modules from go files' invoke_sut a/x.go c/q.go
line_count=$(wc -l <"$LOG")
line_count=${line_count// /}
if [ "$line_count" -ne 2 ]; then
  printf 'FAIL two modules from go files: log has %s lines, want 2\n' "$line_count" >&2
  cat "$LOG" >&2
  exit 1
fi
grep -q "$FIXTURE/a run --config=$FIXTURE/.golangci.yml ./..." "$LOG" || {
  printf 'FAIL log missing a module invocation\n' >&2
  cat "$LOG" >&2
  exit 1
}
grep -q "$FIXTURE/c run --config=$FIXTURE/.golangci.yml ./..." "$LOG" || {
  printf 'FAIL log missing c module invocation\n' >&2
  cat "$LOG" >&2
  exit 1
}
echo "ok   two modules from go files: log lines verified"

: >"$LOG"
expect_output 'README only' 'no Go module selected' invoke_sut README.md
if [ -s "$LOG" ]; then
  printf 'FAIL README only: stub was called\n' >&2
  exit 1
fi
echo "ok   README only: stub not called"

: >"$LOG"
invoke_sut --all >/dev/null
line_count=$(wc -l <"$LOG")
line_count=${line_count// /}
if [ "$line_count" -ne 3 ]; then
  printf 'FAIL --all: log has %s lines, want 3\n' "$line_count" >&2
  cat "$LOG" >&2
  exit 1
fi
echo "ok   --all: three stub calls"

touch "$FIXTURE/c/FAIL"
: >"$LOG"
expect_refusal 'FAIL in module c' 'golangci-lint failed: c' invoke_sut c/q.go
rm -f "$FIXTURE/c/FAIL"

too_many=()
idx=0
while [ "$idx" -lt 4097 ]; do
  too_many+=("a/f$idx.go")
  idx=$((idx + 1))
done
: >"$LOG"
expect_refusal 'module-dirs refusal stops the run' 'too many paths' invoke_sut "${too_many[@]}"
if [ -s "$LOG" ]; then
  printf 'FAIL module-dirs refusal: stub was called\n' >&2
  exit 1
fi
echo "ok   module-dirs refusal: stub not called"

ec=0
out=$(PATH="$STUB_BIN:$PATH" GOLANGCI_STUB_LOG="$LOG" bash -c 'cd "$1" && golangci-lint run --config=.golangci.yml ./...' _ "$FIXTURE" 2>&1) || ec=$?
if [ "$ec" -ne 1 ]; then
  printf 'FAIL old hook shape: exit %s, want 1\n' "$ec" >&2
  exit 1
fi
case "$out" in
  *'directory prefix . does not contain main module'*) echo "ok   old hook shape: reproduced root typecheck failure" ;;
  *)
    printf 'FAIL old hook shape: %s\n' "$out" >&2
    exit 1
    ;;
esac

# bash4_constructs FILE: print Bash-4-only construct lines; return 0 if none, 1 if any, 2 if FILE is too large or unreadable.
bash4_constructs() {
  local file="$1" line_count code hits rc
  line_count=$(wc -l <"$file")
  line_count=${line_count// /}
  if [ "$line_count" -gt 4000 ]; then
    echo "bash4_constructs: file has $line_count lines (max 4000): $file" >&2
    return 2
  fi
  rc=0
  code=$(grep -n -v -E '^[[:space:]]*#' "$file") || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "bash4_constructs: grep failed (exit $rc): $file" >&2
    return 2
  fi
  if [ "$rc" -eq 1 ]; then
    return 0
  fi
  rc=0
  hits=$(printf '%s\n' "$code" | grep -E \
    'mapfile|readarray|declare -[An]|local -[An]|typeset -A|coproc|\$\{[^}]*,,|\$\{[^}]*\^\^|\$\{[^}]*,\}|\$\{[^}]*\^[^}]*\}|\|&|&>>') || rc=$?
  if [ "$rc" -gt 1 ]; then
    echo "bash4_constructs: grep failed (exit $rc): $file" >&2
    return 2
  fi
  if [ "$rc" -eq 1 ]; then
    return 0
  fi
  printf '%s\n' "$hits"
  return 1
}

# check_bash32_file FILE: exits 1 naming FILE when it holds a Bash 4 construct, else prints ok.
check_bash32_file() {
  local file="$1" base out ec
  base=$(basename "$file")
  out=$(bash4_constructs "$file") && ec=0 || ec=$?
  if [ "$ec" -eq 0 ]; then
    echo "ok   bash 3.2: $base uses no Bash 4 construct"
    return 0
  fi
  if [ "$ec" -eq 2 ]; then
    exit 1
  fi
  printf 'FAIL bash 3.2: %s\n%s\n' "$base" "$out" >&2
  exit 1
}

check_bash32_file "$HERE/golangci-modules.sh"
check_bash32_file "$HERE/module-dirs.sh"

# expect_bash4_hit NAME FILE: exits 1 unless bash4_constructs finds a construct in FILE.
expect_bash4_hit() {
  local name="$1" file="$2" out ec
  out=$(bash4_constructs "$file") && ec=0 || ec=$?
  if [ "$ec" -ne 1 ]; then
    printf 'FAIL planted bash 4 construct refused: %s (want hits, ec=%s)\n' "$name" "$ec" >&2
    exit 1
  fi
  echo "ok   planted bash 4 construct refused: $name"
}

# expect_bash4_clear NAME FILE: exits 1 unless bash4_constructs finds nothing in FILE.
expect_bash4_clear() {
  local name="$1" file="$2" out ec
  out=$(bash4_constructs "$file") && ec=0 || ec=$?
  if [ "$ec" -ne 0 ]; then
    printf 'FAIL planted clean file passes: %s (want clear, ec=%s)\n%s\n' "$name" "$ec" "$out" >&2
    exit 1
  fi
  echo "ok   planted clean file passes: $name"
}

cat >"$WORK/planted-mapfile.sh" <<'EOF'
mapfile -t x <<<"$y"
EOF
printf '%s\n' 'declare -A m=()' >"$WORK/planted-declare-a.sh"
cat >"$WORK/planted-comment-only.sh" <<'EOF'
# mapfile in a comment
x=("$@")
EOF

expect_bash4_hit 'mapfile line' "$WORK/planted-mapfile.sh"
expect_bash4_hit 'declare -A' "$WORK/planted-declare-a.sh"
expect_bash4_clear 'comment and $@ only' "$WORK/planted-comment-only.sh"

MANY_FIXTURE="$WORK/many-modules"
mkdir -p "$MANY_FIXTURE/tools"
cp "$HERE/golangci-modules.sh" "$MANY_FIXTURE/tools/"
chmod +x "$MANY_FIXTURE/tools/golangci-modules.sh"
cat >"$MANY_FIXTURE/tools/module-dirs.sh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
i=1
while [ "$i" -le 513 ]; do
  echo "m$i"
  i=$((i + 1))
done
STUB
chmod +x "$MANY_FIXTURE/tools/module-dirs.sh"

: >"$LOG"
# run_many_fixture: runs the copied golangci-modules.sh --all inside the 513-module fixture with the stub linter.
run_many_fixture() {
  (cd "$MANY_FIXTURE" && PATH="$STUB_BIN:$PATH" GOLANGCI_STUB_LOG="$LOG" bash tools/golangci-modules.sh --all)
}

expect_refusal '513 modules from --all' 'too many modules (max 512)' run_many_fixture
if [ -s "$LOG" ]; then
  printf 'FAIL 513 modules: stub golangci-lint was called\n' >&2
  exit 1
fi
echo "ok   513 modules: stub not called"

echo "golangci-modules_test: all planted cases pass"
