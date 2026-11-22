#!/usr/bin/env bash
# Discover go.mod module directories and map file paths to their nearest module.
set -euo pipefail

readonly MAX_ANCESTOR_DEPTH=64
readonly MAX_INPUT_PATHS=4096

all_modules() {
  find . -name go.mod -not -path './.workingdir*' -not -path './tools/go/*' -exec dirname {} \; \
    | sed 's#^\./##' | sort -u
}

nearest_module() {
  local file="$1"
  local all_list="$2"
  local d depth

  d=$(dirname "$file")
  d="${d#./}"
  if [ -z "$d" ]; then
    d="."
  fi

  depth=0
  while [ "$depth" -lt "$MAX_ANCESTOR_DEPTH" ]; do
    depth=$((depth + 1))
    if printf '%s\n' "$all_list" | grep -qxF -- "$d"; then
      printf '%s\n' "$d"
      return 0
    fi
    if [ "$d" = "." ]; then
      return 0
    fi
    d=$(dirname "$d")
  done
  return 0
}

if [ "${1:-}" = "--all" ]; then
  all_modules
  exit 0
fi

paths=()
if [ "$#" -gt 0 ]; then
  if [ "$#" -gt "$MAX_INPUT_PATHS" ]; then
    echo "module-dirs: too many paths (max $MAX_INPUT_PATHS)" >&2
    exit 2
  fi
  while [ "$#" -gt 0 ]; do
    paths+=("$1")
    shift
  done
else
  while IFS= read -r line || [ -n "${line:-}" ]; do
    [ -z "$line" ] && continue
    if [ "${#paths[@]}" -ge "$MAX_INPUT_PATHS" ]; then
      echo "module-dirs: too many paths (max $MAX_INPUT_PATHS)" >&2
      exit 2
    fi
    paths+=("$line")
  done
fi

if [ "${#paths[@]}" -eq 0 ]; then
  exit 0
fi

all_list=$(all_modules)
found=()
idx=0
while [ "$idx" -lt "${#paths[@]}" ]; do
  file="${paths[$idx]}"
  idx=$((idx + 1))
  mapped=$(nearest_module "$file" "$all_list")
  if [ -n "$mapped" ]; then
    found+=("$mapped")
  fi
done

if [ "${#found[@]}" -eq 0 ]; then
  exit 0
fi

printf '%s\n' "${found[@]}" | sort -u