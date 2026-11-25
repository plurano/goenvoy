#!/usr/bin/env bash
# Exercise discovery, comparison, and diagnostics against tracked fixture files.
# Pass an absolute checker path to replay the missing scrubText case.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SUT=(bash "${1:-$HERE/redact-parity.sh}")
# Why: keep all caller-provided Git configuration out of the fixture repository.
for name in "${!GIT_@}"; do
  unset "$name"
done
# Why: this script resolves the checked-in helper relative to its own path at runtime.
# shellcheck source=tools/testlib.sh disable=SC1091
. "$HERE/testlib.sh"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
timeout 60 git init -q --template=''
exception=downloadclient/sabnzbd/redact.go
mkdir -p first second "${exception%/*}" unrelated

wrapper_and_span=$'type redactedError struct{}\n\nfunc (c *Client) percentSpan() {}'
shared_source="$wrapper_and_span"$'\n\nfunc (c *Client) scrubText() {}'
printf 'package alpha\n\n%s\n' "$shared_source" >first/redact.go
printf 'package alpha\n\n// Traversal tests.\n' >first/redact_as_internal_test.go
printf 'package unrelated\n' >unrelated/redact.go
timeout 60 git add first unrelated
if [[ $# -eq 0 ]]; then
  expect_refusal 'absent exception' "$exception:1: stale exception" "${SUT[@]}"
fi
printf 'package standalone\n\n%s\n' "$wrapper_and_span" >"$exception"
timeout 60 git add "$exception"
expect_refusal 'single shared copy with other redact.go files' 'found 1 redaction copies' "${SUT[@]}"

printf 'package beta\n\n%s\n' "$shared_source" >second/redact.go
timeout 60 git add second/redact.go
expect_refusal 'missing test file' 'second/redact_as_internal_test.go:1: missing file' "${SUT[@]}"

printf 'package beta\n\n// Traversal tests.\n' >second/redact_as_internal_test.go
timeout 60 git add second/redact_as_internal_test.go
expect_output 'different package names and tracked exception excluded' 'redact-parity: 2 redaction copies match' "${SUT[@]}"

# Why: two copies must still match if the checker silently drops the planted copy.
mkdir third
printf 'package gamma\n\n%s\n' "$shared_source" >third/redact.go
printf 'package gamma\n\n// Traversal tests.\n' >third/redact_as_internal_test.go
timeout 60 git add third
printf 'package beta\n\n%s\n\n' "$wrapper_and_span" >second/redact.go
expect_refusal 'missing scrubText in a copy with percentSpan' 'second/redact.go:7: differs' "${SUT[@]}"
if [[ $# -gt 0 ]]; then
  exit 0
fi

printf 'package beta\n\ntype redactedError struct{ key string }\n' >second/redact.go
expect_refusal 'implementation drift' 'second/redact.go:3: differs' "${SUT[@]}"

printf 'package beta\n\n%s\n' "$shared_source" >second/redact.go
printf 'package beta\n\n// Traversal tests.' >second/redact_as_internal_test.go
expect_refusal 'test drift at the final newline' 'second/redact_as_internal_test.go:3: differs' "${SUT[@]}"

printf 'package beta\n\n// Traversal tests.\n' >second/redact_as_internal_test.go
printf 'package standalone\n\ntype redactedError struct{}\n' >"$exception"
expect_output 'tracked exception excluded by path' 'redact-parity: 3 redaction copies match' "${SUT[@]}"

printf 'package gamma\n\ntype (\n  redactedError struct{}\n)\n' >third/redact.go
grouped_rc=0
grouped_output="$("${SUT[@]}" 2>&1)" || grouped_rc=$?
if [[ $grouped_rc -ne 1 || $grouped_output != *'third/redact.go:3: differs'* ]]; then
  printf 'FAIL grouped declaration drift: checker rc=%d\n%s\n' "$grouped_rc" "$grouped_output" >&2
  exit 1
fi
echo "ok   grouped declaration drift: refused (checker rc=$grouped_rc)"
printf 'package gamma\n\n%s\n' "$shared_source" >third/redact.go

printf 'package standalone\n' >"$exception"
expect_refusal 'exception without wrapper' "$exception:1: stale exception" "${SUT[@]}"
