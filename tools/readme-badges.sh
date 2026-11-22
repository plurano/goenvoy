#!/usr/bin/env bash
# Allow plain static Shields badges with %20, %23, %25, or %2B escapes and verify workflow links.
# Reject other Shields references everywhere and badge.svg outside governance blocks.
# Scope: honest mistakes, read one line at a time with one delimiter set.
# Out of scope: delimiters read differently across contexts (a quote, space
# or ")" inside an HTML attribute) and other deliberate URL spellings.
# Compensating step: CommonMark parser nodes, golusoris/goenvoy#364.
#   usage: tools/readme-badges.sh --repo owner/name [root]
set -euo pipefail

REPO_SLUG=""
TARGET_ROOT=""

while [ $# -gt 0 ]; do
  case "$1" in
    --repo)
      if [ $# -lt 2 ]; then
        echo "usage: ${0##*/} --repo owner/name [root]" >&2
        exit 2
      fi
      REPO_SLUG="$2"
      shift 2
      ;;
    --repo=*)
      REPO_SLUG="${1#--repo=}"
      shift
      ;;
    -*)
      echo "usage: ${0##*/} --repo owner/name [root]" >&2
      exit 2
      ;;
    *)
      if [ -n "$TARGET_ROOT" ]; then
        echo "usage: ${0##*/} --repo owner/name [root]" >&2
        exit 2
      fi
      TARGET_ROOT="$1"
      shift
      ;;
  esac
done

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ROOT="${TARGET_ROOT:-$REPO_ROOT}"
ROOT="${ROOT%/}"

if [ ! -d "$ROOT" ]; then
  echo "error: directory $ROOT does not exist" >&2
  exit 1
fi

if [ -z "$REPO_SLUG" ]; then
  echo "error: --repo owner/name is required" >&2
  echo "usage: ${0##*/} --repo owner/name [root]" >&2
  exit 2
fi

# Why: owner/name slug is required to scope workflow references to this repository.
if [[ ! "$REPO_SLUG" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]]; then
  echo "error: --repo must be owner/name" >&2
  echo "usage: ${0##*/} --repo owner/name [root]" >&2
  exit 2
fi

shopt -s nullglob
files=()
for f in "$ROOT"/*.md "$ROOT"/*.markdown; do
  if [ ! -f "$f" ]; then
    continue
  fi
  files+=("$f")
done
for f in "$ROOT"/.github/* "$ROOT"/docs/*; do
  if [ ! -f "$f" ]; then
    continue
  fi
  name="${f##*/}"
  if [[ "${name,,}" == readme.md || "${name,,}" == readme.markdown ]]; then
    files+=("$f")
  fi
done

# Pattern for workflow references:
# 1) github.com/<owner>/<repo>/actions/workflows/<file>
# 2) actions/workflows/<file> (not preceded by github.com/<owner>/<repo>/)
# where <file> is [A-Za-z0-9._-]+
workflow_re="(github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/)?actions/workflows/([A-Za-z0-9._-]+)"

misses=0
ok_refs=0

for f in "${files[@]}"; do
  rel="${f#"$ROOT"/}"
  readarray -t lines <"$f"
  in_governance=0
  governance_seen=0
  for ((lnum = 1; lnum <= ${#lines[@]}; lnum++)); do
    line="${lines[lnum - 1]}"
    stripped="$line"
    static_badge_re="https://img\.shields\.io/badge/([A-Za-z0-9_.+-]|%20|%23|%25|%2[Bb])+(\?[A-Za-z0-9_.=&;:/%+-]*)?([\"')>[:space:]]|$)"
    for ((strip_i = 0; strip_i < ${#line}; strip_i++)); do
      if [[ "$stripped" =~ $static_badge_re ]]; then
        matched="${BASH_REMATCH[0]}"
        delimiter="${BASH_REMATCH[3]}"
        stripped="${stripped/"$matched"/ $delimiter}"
      else
        break
      fi
    done
    lower_line="${stripped,,}"
    decoded=""
    rest="$lower_line"
    for ((decode_i = 0; decode_i < ${#lower_line} && ${#rest} > 0; decode_i++)); do
      if [[ "$rest" =~ ^\&\#([0-9]+)\;? ]]; then
        token="${BASH_REMATCH[0]}"
        digits="${BASH_REMATCH[1]}"
        digits="${digits#"${digits%%[!0]*}"}"
        code=0
        if ((${#digits} > 0 && ${#digits} <= 7)); then
          code=$((10#$digits))
        fi
      elif [[ "$rest" =~ ^\&\#x([0-9a-f]+)\;? ]]; then
        token="${BASH_REMATCH[0]}"
        digits="${BASH_REMATCH[1]}"
        digits="${digits#"${digits%%[!0]*}"}"
        code=0
        if ((${#digits} > 0 && ${#digits} <= 6)); then
          code=$((16#$digits))
        fi
      else
        decoded+="${rest:0:1}"
        rest="${rest:1}"
        continue
      fi
      if ((code > 0 && code <= 1114111 && (code < 55296 || code > 57343))); then
        printf -v escape '\\U%08x' "$code"
        printf -v char '%b' "$escape"
        decoded+="$char"
      else
        decoded+="$token"
      fi
      rest="${rest:${#token}}"
    done
    rest="${decoded,,}"
    decoded=""
    limit=${#rest}
    for ((decode_i = 0; decode_i < limit && ${#rest} > 0; decode_i++)); do
      if [[ "$rest" =~ ^%([0-9a-f]{2}) ]]; then
        token="${BASH_REMATCH[0]}"
        code=$((16#${BASH_REMATCH[1]}))
        if ((code > 0)); then
          printf -v escape '\\U%08x' "$code"
          printf -v char '%b' "$escape"
          decoded+="$char"
        else
          decoded+="$token"
        fi
        rest="${rest:${#token}}"
      else
        decoded+="${rest:0:1}"
        rest="${rest:1}"
      fi
    done
    lower_line="${decoded,,}"
    marker="${line#"${line%%[![:space:]]*}"}"
    marker="${marker%"${marker##*[![:space:]]}"}"
    if [[ "$marker" == '<!-- praetor:readme-governance:start -->' ]]; then
      if [ "$in_governance" -ne 0 ]; then
        printf 'readme-badges: %s:%s: governance start inside block\n' "$rel" "$lnum" >&2
        misses=$((misses + 1))
      elif [[ "$rel" != README.md ]] || [ "$governance_seen" -eq 1 ]; then
        printf 'readme-badges: %s:%s: governance start not allowed here\n' "$rel" "$lnum" >&2
        misses=$((misses + 1))
        in_governance=2
        governance_start="$lnum"
      else
        in_governance=1
        governance_seen=1
        governance_start="$lnum"
      fi
    fi
    if [[ "$marker" == '<!-- praetor:readme-governance:end -->' ]]; then
      if [ "$in_governance" -eq 0 ]; then
        printf 'readme-badges: %s:%s: governance end without start\n' "$rel" "$lnum" >&2
        misses=$((misses + 1))
      else
        in_governance=0
      fi
    fi
    if [[ "$lower_line" == *shields* ]]; then
      printf 'readme-badges: %s:%s: shields reference is not a plain static badge\n' "$rel" "$lnum" >&2
      misses=$((misses + 1))
    fi
    if [ "$in_governance" -ne 1 ] && [[ "$lower_line" == *badge.svg* ]]; then
      printf 'readme-badges: %s:%s: badge.svg outside the governance block\n' "$rel" "$lnum" >&2
      misses=$((misses + 1))
    fi
    if [[ "$line" != *actions/workflows* ]]; then
      continue
    fi

    cur="$line"
    limit=$((${#line} + 1))
    for ((i = 0; i < limit; i++)); do
      if [[ "$cur" =~ $workflow_re ]]; then
        matched="${BASH_REMATCH[0]}"
        owner_repo="${BASH_REMATCH[2]}"
        wf="${BASH_REMATCH[3]}"
        cur="${cur#*"$matched"}"

        # Why: trailing dots are sentence punctuation; strip them without a loop.
        wf="${wf%"${wf##*[!.]}"}"

        # Why: ignore references to workflows hosted in other repositories.
        if [ -n "$owner_repo" ] && [ "${owner_repo,,}" != "${REPO_SLUG,,}" ]; then
          continue
        fi

        if [ -n "$wf" ] && [ -f "$ROOT/.github/workflows/$wf" ]; then
          ok_refs=$((ok_refs + 1))
        else
          printf 'readme-badges: %s:%s: workflow %s not in .github/workflows\n' "$rel" "$lnum" "$wf" >&2
          misses=$((misses + 1))
        fi
      else
        break
      fi
    done
  done
  if [ "$in_governance" -ne 0 ]; then
    printf 'readme-badges: %s:%s: unclosed governance block\n' "$rel" "$governance_start" >&2
    misses=$((misses + 1))
  fi
done

if [ "$misses" -gt 0 ]; then
  exit 1
fi

echo "readme-badges: $ok_refs workflow references ok"
