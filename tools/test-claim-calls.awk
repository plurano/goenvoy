# Why: only Go code can supply calls for claims in full-line test comments.

BEGIN {
  identifier = "[[:alpha:]_][[:alnum:]_]*"
  boundary = "(^|[^[:alnum:]_])"
  verb = "(checks?|asserts?|verif(y|ies)|proves?|ensures?|tests?)"
  claim_pattern = boundary verb "[[:blank:]]+(that[[:blank:]]+)?" identifier "([.]" identifier ")*[(]"
  call_pattern = boundary identifier "[(]"
}

function masked_width(pair,    ch) {
  if (mask_end == "*/") {
    if (pair != mask_end) return 1
    mask_end = ""
    return 2
  }

  ch = substr(pair, 1, 1)
  if (ch == mask_end) {
    mask_end = ""
  } else if (ch == "\\" && mask_end != "`") {
    return 2
  }
  return 1
}

function code_only(line,    code, limit, i, pair, ch) {
  limit = length(line)
  for (i = 1; i <= limit; i++) {
    pair = substr(line, i, 2)
    ch = substr(pair, 1, 1)
    if (mask_end != "") {
      i += masked_width(pair) - 1
    } else if (pair == "//") {
      break
    } else if (pair == "/*") {
      mask_end = "*/"
      code = code " "
      i++
    } else if (ch == "\"" || ch == "'" || ch == "`") {
      mask_end = ch
      code = code " "
    } else {
      code = code ch
    }
  }
  # Why: only raw strings and block comments can continue on the next line.
  if (mask_end == "\"" || mask_end == "'") mask_end = ""
  return code
}

function record_matches(line, pattern, is_claim,    limit, i, name) {
  limit = length(line)
  for (i = 0; i < limit && match(is_claim ? tolower(line) : line, pattern); i++) {
    name = substr(line, RSTART, RLENGTH - 1)
    sub(/^.*[^[:alnum:]_]/, "", name)
    if (is_claim) {
      claim_names[++claim_count] = name
      claim_lines[claim_count] = NR
    } else {
      calls[name] = 1
    }
    # Why: the opening parenthesis can be the boundary for a nested call.
    line = substr(line, RSTART + RLENGTH - 1)
  }
}

function finish_function(    i, name) {
  for (i = 1; i <= claim_count; i++) {
    name = claim_names[i]
    if (!(name in calls)) {
      printf "%s:%d: comment claims %s( but the function never calls %s(\n", ENVIRON["CLAIM_PATH"], claim_lines[i], name, name
      found = 1
    }
  }
  delete calls
  claim_count = 0
  in_function = 0
}

mask_end == "" && /^[[:blank:]]*\/\// {
  record_matches($0, claim_pattern, 1)
  next
}

{ code = code_only($0) }

code ~ /^func[[:blank:]]/ {
  if (in_function) finish_function()
  in_function = 1
  record_matches(code, call_pattern, 0)
  if (code ~ /[{].*[}][[:blank:]]*$/) finish_function()
  next
}

in_function {
  record_matches(code, call_pattern, 0)
  if (code ~ /^}[[:blank:]]*$/) finish_function()
  next
}

{ claim_count = 0 }

END {
  if (in_function) finish_function()
  if (found) exit 1
}
