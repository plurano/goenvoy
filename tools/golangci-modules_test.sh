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

echo "golangci-modules_test: all planted cases pass"