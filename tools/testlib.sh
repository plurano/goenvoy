#!/usr/bin/env bash
# Why: shared test assertions for tools/ test scripts.
set -euo pipefail

# Why: a git hook exports its repository and index; a fixture repository built by a test must never read or write them.
mapfile -t git_local_env < <(git rev-parse --local-env-vars)
unset "${git_local_env[@]}" git_local_env

# expect_refusal NAME NEEDLE CMD...: assert command fails and error message contains needle.
expect_refusal() {
  local name="$1" needle="$2" out
  shift 2
  if out="$("$@" 2>&1)"; then
    printf 'FAIL %s: accepted\n%s\n' "$name" "$out" >&2
    exit 1
  fi
  case "$out" in
    *"$needle"*) echo "ok   $name: refused ($needle)" ;;
    *)
      printf 'FAIL %s: refused without "%s"\n%s\n' "$name" "$needle" "$out" >&2
      exit 1
      ;;
  esac
}

# expect_status NAME STATUS NEEDLE CMD...: assert exact status, a diagnostic on stderr and empty stdout.
expect_status() (
  local name="$1" want_status="$2" needle="$3" output stderr status=0
  shift 3
  output="$(mktemp -d)" || exit 1
  trap 'rm -rf -- "$output"' EXIT
  ("$@") > "$output/stdout" 2> "$output/stderr" || status=$?
  # Why: the final dot preserves trailing newlines during command substitution.
  stderr="$(cat -- "$output/stderr" && printf '.')" || exit 1
  stderr="${stderr%.}"
  if [[ "$status" != "$want_status" ]]; then
    printf 'FAIL %s: got status %s, want %s\n%s\n' "$name" "$status" "$want_status" "$stderr" >&2
    exit 1
  fi
  if [[ -s "$output/stdout" ]]; then
    printf 'FAIL %s: stdout was not empty\n' "$name" >&2
    exit 1
  fi
  if [[ -z "$needle" || "$stderr" != *"$needle"* ]]; then
    printf 'FAIL %s: stderr did not contain the required diagnostic "%s"\n%s\n' "$name" "$needle" "$stderr" >&2
    exit 1
  fi
  printf 'ok   %s: refused (%s, status %s)\n' "$name" "$needle" "$status"
  exit 0
)

# expect_pass NAME CMD...: assert command succeeds.
expect_pass() {
  local name="$1" out
  shift 1
  if ! out="$("$@" 2>&1)"; then
    printf 'FAIL %s: command failed\n%s\n' "$name" "$out" >&2
    exit 1
  fi
  echo "ok   $name: $out"
}

# expect_output NAME WANT CMD...: assert command succeeds and stdout equals want.
expect_output() {
  local name="$1" want="$2" out
  shift 2
  if ! out="$("$@")"; then
    printf 'FAIL %s: command failed\n' "$name" >&2
    exit 1
  fi
  if [ "$out" != "$want" ]; then
    printf 'FAIL %s: got %s, want %s\n' "$name" "$out" "$want" >&2
    exit 1
  fi
  echo "ok   $name: $out"
}
