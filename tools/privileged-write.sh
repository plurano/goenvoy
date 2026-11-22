#!/usr/bin/env bash
# Detect privileged in-place writes; privileged install must stage to .new
# or create directories. Only allow listed commands without redirects.
# Path-qualified sudo/doas, a redirect before the launcher, and separators
# inside $( ) or backticks still count as one simple command.
# Single-line quoted YAML run values and &> / &>> redirects are read.
# A quoted or backslash-escaped ; | & does not end a command.
# Bash splits words on space and tab only.
# Make files (Makefile, makefile, GNUmakefile, *.mk) read recipe prefixes
# @ - +, $$, and a leading punctuation .RECIPEPREFIX as make reads them.
# Scope: honest mistakes, read one physical line at a time. Out of scope:
# line continuation, quotes spanning lines, quoted or escaped launcher
# names, a .RECIPEPREFIX of \# (every recipe then reads as a comment).
# Compensating step: shfmt syntax tree, golusoris/goenvoy#363.
# PRIVWRITE_TIMEOUT (default 60) bounds git ls-files and each awk run, in seconds.
set -euo pipefail

if (( $# > 1 )); then
  printf "usage: tools/privileged-write.sh [root]\n" >&2
  exit 2
fi
deadline="${PRIVWRITE_TIMEOUT:-60}"
if [[ ! "$deadline" =~ ^[1-9][0-9]{0,2}$ ]]; then
  printf "privileged-write: invalid PRIVWRITE_TIMEOUT: '%s'\n" "$deadline" >&2
  exit 2
fi
command -v timeout >/dev/null 2>&1 || {
  printf "privileged-write: timeout is required\n" >&2
  exit 2
}
root="$(cd "${1:-$(dirname "${BASH_SOURCE[0]}")/..}" && pwd)"
list="$(mktemp)"
trap 'rm -f "$list" "$list.hits"' EXIT
if ! timeout "$deadline" git -C "$root" ls-files -z > "$list"; then
  printf "privileged-write: git ls-files failed or passed the %ss deadline\n" "$deadline" >&2
  exit 2
fi
cd "$root"
count=0
failed=0
while IFS= read -r -d '' file; do
  is_make=0
  is_yaml=0
  case "${file##*/}" in
    Makefile|makefile|GNUmakefile|*.mk) is_make=1 ;;
  esac
  case "$file" in
    .github/workflows/*.yml|.github/workflows/*.yaml|.github/actions/*.yml|.github/actions/*.yaml) is_yaml=1 ;;
    *.sh|*.bash) ;;
    *) (( is_make )) || continue ;;
  esac
  [[ -f "$file" ]] || continue
  count=$((count + 1))
  if PRIVWRITE_FILE="$file" timeout "$deadline" awk -v is_make="$is_make" -v is_yaml="$is_yaml" '
    BEGIN {
      name = "[a-z_][a-z0-9_]*" "(su" "do|privi" "lege)[a-z0-9_]*|" "(su" "do|privi" "lege)[a-z0-9_]*"
      variable = "\\$(" name ")|\\$\\{(" name ")\\}|\\$\\((" name ")\\)"
      path = "([^[:space:];|&\140\"\047()]*/)?"
      prefix = "(^|[;&|\140([:space:]])" path "(" "su" "do|do" "as|" variable "|\"(" variable ")\")"
      make_prefix = "(^[[:punct:]]?|[;&|\140([:space:]])[@+-]*" path "(" "su" "do|do" "as|" variable "|\"(" variable ")\")"
      command = prefix "[[:space:]]+[^[:space:];|&]+"
      make_command = make_prefix "[[:space:]]+[^[:space:];|&]+"
    }
    FNR > 100000 { print ENVIRON["PRIVWRITE_FILE"] ":" FNR; failed = 1; nextfile }
    /^[ \t]*#/ { next }
    {
      line = $0
      if (is_yaml && match(line, "^[ \t]*(-[ \t]+)?run:[ \t]*[" sprintf("%c", 39) "\"]")) {
        yaml_quote = substr(line, RLENGTH, 1)
        line = substr(line, 1, RLENGTH - 1) " " substr(line, RLENGTH + 1)
        if (substr(line, length(line), 1) == yaml_quote) line = substr(line, 1, length(line) - 1)
      }
      active_prefix = prefix
      active_command = command
      if (is_make) {
        gsub(/\$\$/, "$", line)
        active_prefix = make_prefix
        active_command = make_command
      }
      while (match(tolower(line), active_command)) {
        start = RSTART
        call = substr(line, RSTART, RLENGTH)
        rest = substr(line, RSTART + RLENGTH)
        match(tolower(call), active_prefix "[[:space:]]+")
        candidate = tolower(substr(call, 1, RLENGTH))
        gsub(/[^a-z0-9_]/, "", candidate)
        if (candidate ~ "^su" "do_(askpass|command|editor|gid|home|prompt|ps1|tty|uid|user)$") {
          line = substr(line, start + RLENGTH - 1)
          continue
        }
        lead = substr(line, 1, start)
        lead_redirect = 0
        lead_backtick = 0
        ldepth = 0
        lprev = ""
        in_squote = 0
        in_dquote = 0
        for (lp = 1; lp <= length(lead); lp++) {
          lchar = substr(lead, lp, 1)
          if (in_squote) {
            if (lchar == "\047") in_squote = 0
          } else if (in_dquote) {
            if (lchar == "\\" && lp < length(lead)) lp++
            else if (lchar == "\"") in_dquote = 0
          } else if (lchar == "\\" && lp < length(lead)) {
            lp++
          } else if (lchar == "\047") {
            in_squote = 1
          } else if (lchar == "\"") {
            in_dquote = 1
          } else if (lchar == "`") {
            if (lead_backtick == 0) {
              lsaved_bt = lead_redirect
              lead_redirect = 0
              lead_backtick = 1
            } else {
              lead_redirect = lsaved_bt
              lead_backtick = 0
            }
            lprev = lchar
          } else if (lchar == "(") {
            lsaved[ldepth++] = lead_redirect
            lead_redirect = 0
            lprev = lchar
          } else if (lchar == ")") {
            if (ldepth > 0) lead_redirect = lsaved[--ldepth]
            lprev = lchar
          } else if (lchar == ">") {
            lead_redirect = 1
            lprev = lchar
          } else if (lchar == ";" || lchar == "|" || lchar == "&") {
            if (lchar == ";" || ((lchar == "&" || lchar == "|") && lprev != ">" && lprev != "<")) {
              lead_redirect = 0
            }
            lprev = lchar
          } else {
            lprev = lchar
          }
        }
        call = substr(call, RLENGTH + 1)
        gsub(/&>/, ">", rest)
        segment_first = rest
        in_squote = 0
        in_dquote = 0
        depth = 0
        in_backtick = 0
        for (p = 1; p <= length(rest); p++) {
          char = substr(rest, p, 1)
          if (in_squote) {
            if (char == "\047") in_squote = 0
          } else if (in_dquote) {
            if (char == "\\" && p < length(rest)) p++
            else if (char == "\"") in_dquote = 0
          } else if (char == "\\" && p < length(rest)) {
            p++
          } else if (char == "\047") {
            in_squote = 1
          } else if (char == "\"") {
            in_dquote = 1
          } else if (char == "$" && p < length(rest) && substr(rest, p + 1, 1) == "(") {
            depth++
            p++
          } else if (char == "(" && depth > 0) {
            depth++
          } else if (char == ")" && depth > 0) {
            depth--
          } else if (char == "`") {
            if (lead_backtick == 1) {
              segment_first = substr(rest, 1, p - 1)
              break
            }
            in_backtick = 1 - in_backtick
          } else if ((char == ";" || char == "|" || char == "&") && depth == 0 && in_backtick == 0) {
            segment_first = substr(rest, 1, p - 1)
            break
          }
        }
        segments[1] = segment_first
        install_ok = 0
        if (call == "install") {
          delete args
          count_args = 0
          word = ""
          started = 0
          quote = ""
          refused = 0
          segment = segments[1]
          for (pos = 1; pos <= length(segment); pos++) {
            char = substr(segment, pos, 1)
            if (quote == "\047") {
              if (char == "\047") quote = ""
              else word = word char
            } else if (quote == "\"") {
              if (char == "\\" && pos < length(segment)) {
                next_char = substr(segment, ++pos, 1)
                if (index("$`\"\\", next_char)) word = word next_char
                else word = word char next_char
              } else if (char == "\"") quote = ""
              else word = word char
            } else if (char == "\\") {
              if (pos < length(segment)) word = word substr(segment, ++pos, 1)
              else word = word char
              started = 1
            } else if (char == "\047" || char == "\"") {
              quote = char
              started = 1
            } else if (char == " " || char == "\t") {
              if (started) args[++count_args] = word
              word = ""
              started = 0
            } else if (char == "#" && !started) {
              break
            } else {
              if (char !~ /^[[:alnum:]_./:=,@%+-]$/) refused = 1
              word = word char
              started = 1
            }
          }
          if (started) args[++count_args] = word
          last = ""
          if (quote != "") refused = 1
          directory = 0
          for (i = 1; i <= count_args; i++) {
            if (args[i] == "") continue
            if (args[i] !~ /^-/) {
              last = args[i]
            } else if (args[i] == "--directory") {
              directory = 1
            } else if (args[i] ~ /^--(compare|preserve-timestamps|verbose|strip|no-target-directory)$/) {
              continue
            } else if (args[i] ~ /^--(mode|owner|group)=./) {
              continue
            } else if (args[i] ~ /^--(mode|owner|group)$/) {
              i++
            } else if (args[i] ~ /^-[CDTdpsv]+$/) {
              if (args[i] ~ /d/) directory = 1
            } else if (args[i] ~ /^-[CDTdpsv]*[gmo]$/) {
              if (args[i] ~ /d/) directory = 1
              i++
            } else if (args[i] ~ /^-[CDTdpsv]*[gmo].+$/) {
              flags = args[i]
              sub(/[gmo].*$/, "", flags)
              if (flags ~ /d/) directory = 1
            } else {
              refused = 1
              break
            }
          }
          if (!refused && (directory || last ~ /\.new$/)) install_ok = 1
        }
        if (call !~ /^(install|mv|rm|chown|chmod|test|cat|systemctl)$/ || segments[1] ~ />/ || lead_redirect || (call == "install" && !install_ok)) {
          print ENVIRON["PRIVWRITE_FILE"] ":" FNR
          failed = 1
        }
        line = rest
      }
    }
    END { exit failed }
  ' "./$file" < /dev/null > "$list.hits"; then :; else
    status=$?
    if (( status == 124 )); then
      printf "privileged-write: %s: scan passed the %ss deadline\n" "$file" "$deadline" >&2
      rm -f "$list.hits"
      exit 124
    fi
    if (( status != 1 )); then
      printf "privileged-write: %s: awk failed with status %d\n" "$file" "$status" >&2
      rm -f "$list.hits"
      exit "$status"
    fi
    failed=1
  fi
  while IFS= read -r hit; do
    printf "privileged-write: %s: privileged command not on the allow-list or writing through a redirect; stage the file and rename it into place\n" "$hit" >&2
  done < "$list.hits"
  rm -f "$list.hits"
done < "$list"
if (( failed )); then exit 1; fi
printf "privileged-write: %s files clean\n" "$count"
