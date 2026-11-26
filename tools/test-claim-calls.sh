#!/usr/bin/env bash
# Why: a test comment should name a call made by Go code in its function.
set -euo pipefail

if (( $# > 1 )) || [[ -z "${1-.}" ]]; then
  printf 'usage: %s [repository-root]\n' "$0" >&2
  exit 2
fi

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)" || exit 2
ROOT="$(git -C "${1-.}" rev-parse --show-toplevel)" || exit 2
LIST="$(mktemp)" || exit 2
trap 'rm -f "$LIST"' EXIT
git -C "$ROOT" ls-files -z --deduplicate -- '*_test.go' > "$LIST" || exit 2
mapfile -d '' -t files < "$LIST"

# Why: check the call claims in one Go test file and send diagnostics to stderr.
scan_file() {
  CLAIM_PATH="$1" awk -f "$HERE/test-claim-calls.awk" "$ROOT/$1" >&2
}

failed=0
for file in "${files[@]}"; do
  if scan_file "$file"; then
    continue
  else
    status=$?
    if (( status != 1 )); then exit 2; fi
    failed=1
  fi
done
exit "$failed"
