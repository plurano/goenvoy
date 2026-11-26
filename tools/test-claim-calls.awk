# Why: only Go code can supply calls for claims in full-line test comments.

BEGIN {
  identifier = "[[:alpha:]_][[:alnum:]_]*"
  boundary = "(^|[^[:alnum:]_\200-\377])"
  verb = "(checks?|asserts?|verif(y|ies)|proves?|ensures?|tests?)"
  claim_pattern = boundary verb "[[:blank:]]+(that[[:blank:]]+)?" identifier "([.]" identifier ")*[(]"
  selector = identifier "([[:blank:]]*[.][[:blank:]]*" identifier ")*"
  type_args = "[[]([^][]|[[][^][]*[]])*[]]"
  call_tail = "[[:blank:]]*(" type_args "[[:blank:]]*)?[(]"
  call_pattern = boundary selector call_tail
  declaration_pattern = "^[[:blank:]]*func([[:blank:]]+|[[:blank:]]*[(][^)]*[)][[:blank:]]*)" identifier
  type_literal_keyword = boundary "(struct|interface)[[:space:]]*$"
  signature_continuation_keyword = boundary "(chan|func|interface|map|struct)[[:space:]]*$"
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

function record_claims(line,    limit, i, name) {
  limit = length(line)
  for (i = 0; i < limit && match(tolower(line), claim_pattern); i++) {
    name = substr(line, RSTART, RLENGTH - 1)
    sub(/^.*[[:blank:]]/, "", name)
    claim_names[++claim_count] = name
    claim_lines[claim_count] = NR
    line = substr(line, RSTART + RLENGTH - 1)
  }
}

function record_calls(line,    limit, i, j, name) {
  limit = length(line)
  for (i = 0; i < limit && match(line, call_pattern); i++) {
    name = substr(line, RSTART, RLENGTH)
    # Why: the opening parenthesis can be the boundary for a nested call.
    line = substr(line, RSTART + RLENGTH - 1)
    sub(/^[^[:alnum:]_]/, "", name)
    sub(call_tail "$", "", name)
    gsub(/[[:blank:]]/, "", name)
    # Why: each dot starts a suffix that a shorter claim can name.
    calls[name] = 1
    for (j = 1; j <= length(name); j++) {
      if (substr(name, j, 1) == ".") calls[substr(name, j + 1)] = 1
    }
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
  in_signature = 0
}

mask_end == "" && /^[[:blank:]]*\/\// {
  record_claims($0)
  next
}

function within_type_literal(prefix) {
  return signature_type_depth || prefix ~ type_literal_keyword ||
    (after_type_literal_keyword && prefix !~ /[^[:space:]]/)
}

function signature_boundary(line,    limit, i, ch) {
  limit = length(line)
  for (i = 1; i <= limit; i++) {
    ch = substr(line, i, 1)
    if (ch == "{") {
      if (!within_type_literal(substr(line, 1, i - 1))) return i
      signature_type_depth++
    } else if (ch == "}") {
      signature_type_depth--
    } else if (ch ~ /[([]/) {
      signature_group_depth++
    } else if (ch ~ /[])]/) {
      signature_group_depth--
    } else if (ch == ";" && !signature_type_depth) {
      return i
    }
  }
  if (line ~ /[^[:space:]]/) after_type_literal_keyword = line ~ type_literal_keyword
  return 0
}

function closing_brace(line, start,    limit, i, ch, end) {
  limit = length(line)
  for (i = start; i <= limit; i++) {
    ch = substr(line, i, 1)
    if (ch == "{") {
      brace_depth++
    } else if (ch == "}" && --brace_depth == 0 && !end) {
      end = i
    }
  }
  return end
}

function scope_end(line,    position) {
  if (!in_signature) return closing_brace(line, 1)
  position = signature_boundary(line)
  if (position) {
    if (substr(line, position, 1) == "{") {
      in_signature = 0
      return closing_brace(line, position)
    }
    # Why: later top-level code on the same line still contributes to brace depth.
    closing_brace(line, position + 1)
    return position
  }
  # Why: Go inserts a semicolon at the end of a complete signature without a body.
  if (!signature_type_depth && !signature_group_depth &&
      line ~ /([[:alnum:]_\200-\377]|[])}])[[:space:]]*$/ && line !~ signature_continuation_keyword) {
    return length(line)
  }
  return 0
}

{
  code = code_only($0)
  # Why: function literals share the enclosing top-level declaration's claims and calls.
  if (brace_depth == 0 && !in_signature && code ~ declaration_pattern) {
    if (in_function) finish_function()
    in_function = 1
    in_signature = 1
    signature_type_depth = signature_group_depth = after_type_literal_keyword = 0
    sub(declaration_pattern, "", code)
  }

  end = scope_end(code)
  if (in_function) {
    record_calls(end ? substr(code, 1, end) : code)
    if (end) finish_function()
  } else {
    claim_count = 0
  }
}

END {
  if (in_function) finish_function()
  if (found) exit 3
}
