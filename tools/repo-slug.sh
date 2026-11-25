# shellcheck shell=bash

# require_repo_slug VALUE: exits 2 unless VALUE matches OWNER/REPO.
require_repo_slug() {
  local value="$1"
  if [[ ! "$value" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
    echo "error: invalid repository '$value', expected OWNER/REPO" >&2
    exit 2
  fi
}
