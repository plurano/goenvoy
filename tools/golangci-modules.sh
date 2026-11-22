#!/usr/bin/env bash
# Run golangci-lint once per selected go.mod module.
set -euo pipefail

readonly MAX_MODULES=512

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODULE_DIRS="$SCRIPT_DIR/module-dirs.sh"

# Why: command substitution under set -e stops on a module-dirs refusal; process substitution would hide it.
if [ "${1:-}" = "--all" ]; then
  shift
  if [ "$#" -gt 0 ]; then
    echo "golangci-modules: unexpected arguments after --all" >&2
    exit 2
  fi
  listed="$(bash "$MODULE_DIRS" --all)"
elif [ "$#" -gt 0 ]; then
  listed="$(bash "$MODULE_DIRS" "$@")"
else
  listed="$(bash "$MODULE_DIRS")"
fi
modules=()
if [ -n "$listed" ]; then
  while IFS= read -r line; do
    if [ "${#modules[@]}" -ge "$MAX_MODULES" ]; then
      echo "golangci-modules: too many modules (max $MAX_MODULES)" >&2
      exit 2
    fi
    modules+=("$line")
  done <<<"$listed"
fi

if [ "${#modules[@]}" -eq 0 ]; then
  echo "no Go module selected"
  exit 0
fi

failed=()
idx=0
while [ "$idx" -lt "${#modules[@]}" ]; do
  mod="${modules[$idx]}"
  idx=$((idx + 1))
  echo "==> Linting $mod"
  if ! (cd "$ROOT/$mod" && golangci-lint run --config="$ROOT/.golangci.yml" ./...); then
    failed+=("$mod")
  fi
done

if [ "${#failed[@]}" -eq 0 ]; then
  exit 0
fi

fidx=0
while [ "$fidx" -lt "${#failed[@]}" ]; do
  echo "golangci-lint failed: ${failed[$fidx]}" >&2
  fidx=$((fidx + 1))
done
exit 1