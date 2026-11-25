#!/usr/bin/env bash
# Exercise discovery, comparison, and diagnostics against tracked fixture files.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Why: keep all caller-provided Git configuration out of the fixture repository.
for name in "${!GIT_@}"; do
  unset "$name"
done
# shellcheck source=tools/testlib.sh
. "$HERE/testlib.sh"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cd "$WORK"
timeout 60 git init -q --template=''
mkdir -p first second standalone unrelated

printf 'package alpha\n\ntype redactedError struct{}\n' >first/redact.go
printf 'package alpha\n\n// Traversal tests.\n' >first/redact_as_internal_test.go
printf 'package unrelated\n' >unrelated/redact.go
printf 'package standalone\n\ntype redactedError struct{}\n\nfunc (c *Client) percentSpan() {}\n' >standalone/redact.go
timeout 60 git add first standalone unrelated
expect_refusal 'single shared copy with other redact.go files' 'found 1 redaction copies' bash "$HERE/redact-parity.sh"

printf 'package beta\n\ntype redactedError struct{}\n' >second/redact.go
timeout 60 git add second/redact.go
expect_refusal 'missing test file' 'second/redact_as_internal_test.go:1: missing file' bash "$HERE/redact-parity.sh"

printf 'package beta\n\n// Traversal tests.\n' >second/redact_as_internal_test.go
timeout 60 git add second/redact_as_internal_test.go
expect_output 'different package names' 'redact-parity: 2 redaction copies match' bash "$HERE/redact-parity.sh"

printf 'package beta\n\ntype redactedError struct{ key string }\n' >second/redact.go
expect_refusal 'implementation drift' 'second/redact.go:3: differs' bash "$HERE/redact-parity.sh"

printf 'package beta\n\ntype redactedError struct{}\n' >second/redact.go
printf 'package beta\n\n// Traversal tests.' >second/redact_as_internal_test.go
expect_refusal 'test drift at the final newline' 'second/redact_as_internal_test.go:3: differs' bash "$HERE/redact-parity.sh"
