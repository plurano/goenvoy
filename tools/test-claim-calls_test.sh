#!/usr/bin/env bash
# Why: planted fixtures check that Go calls satisfy claims and literal or comment text cannot.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CHECKER="${1-$HERE/test-claim-calls.sh}"
if (( $# > 1 )) || [[ "$CHECKER" != /* ]]; then
  printf 'usage: %s [absolute-checker-path]\n' "$0" >&2
  exit 2
fi

# Why: the fixture repositories and their checker must ignore Git state inherited from the caller.
unset "${!GIT_@}"
export GIT_CONFIG_GLOBAL=/dev/null GIT_CONFIG_NOSYSTEM=1
# shellcheck source=tools/testlib.sh
. "$HERE/testlib.sh"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Why: create a fixture repository and stage the test source read from stdin.
track_fixture() {
  local name="$1" file="$2"
  git -C "$WORK" init -q "$name"
  cat > "$WORK/$name/$file"
  git -C "$WORK/$name" add -- "$file"
}

SUT=(bash "$CHECKER")

track_fixture planted planted_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	carriesKey(nil)
}
GO
expect_status planted 1 'planted_test.go:3: comment claims redactError( but the function never calls redactError(' "${SUT[@]}" "$WORK/planted"

track_fixture fixed fixed_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	c.redactError(nil)
}
GO
expect_pass fixed "${SUT[@]}" "$WORK/fixed"

track_fixture body body_test.go <<'GO'
package example

func TestRedact(t *testing.T) {
	// Check that redactError(nil) returns nil.
	t.Run("nil", func(t *testing.T) {
		carriesKey(nil)
	})
}
GO
expect_status body 1 'body_test.go:4: comment claims redactError(' "${SUT[@]}" "$WORK/body"

track_fixture qualified_mismatch qualified_mismatch_test.go <<'GO'
package example

// TestMatch verifies that errors.Is(err, target) finds the wrapped error.
func TestMatch(t *testing.T) {
	Is(err, target)
}
GO
expect_status qualified_mismatch 1 'qualified_mismatch_test.go:3: comment claims errors.Is( but the function never calls errors.Is(' "${SUT[@]}" "$WORK/qualified_mismatch"

track_fixture qualified_match qualified_match_test.go <<'GO'
package example

// TestMatch verifies that errors.Is(err, target) finds the wrapped error.
func TestMatch(t *testing.T) {
	errors.Is(err, target)
	// Check that outer.errors.Is(err, target) finds the wrapped error.
	root.outer.errors.Is(err, target)
}
GO
expect_pass qualified_match "${SUT[@]}" "$WORK/qualified_match"

track_fixture qualified_chain_mismatch qualified_chain_mismatch_test.go <<'GO'
package example

// TestMatch verifies outer.errors.Is(err, target).
func TestMatch(t *testing.T) { other.errors.Is(err, target) }
GO
expect_status qualified_chain_mismatch 1 'qualified_chain_mismatch_test.go:3: comment claims outer.errors.Is(' "${SUT[@]}" "$WORK/qualified_chain_mismatch"

track_fixture type_args type_args_test.go <<'GO'
package example

// TestPick checks pick(0).
func TestPick(t *testing.T) { pick[int](0) }

// TestNested checks pick(nil).
func TestNested(t *testing.T) { pick[map[string]int](nil) }
GO
expect_pass type_args "${SUT[@]}" "$WORK/type_args"

track_fixture spaced_call spaced_call_test.go <<'GO'
package example

// TestHelper checks helper().
func TestHelper(t *testing.T) { helper /* note */ () }
GO
expect_pass spaced_call "${SUT[@]}" "$WORK/spaced_call"

track_fixture declared_name declared_name_test.go <<'GO'
package example

// helper checks helper().
func helper() {}
GO
expect_status declared_name 1 'declared_name_test.go:3: comment claims helper(' "${SUT[@]}" "$WORK/declared_name"

track_fixture declared_name_method declared_name_method_test.go <<'GO'
package example

// helper checks helper().
func (r T) helper() {}
GO
expect_status declared_name_method 1 'declared_name_method_test.go:3: comment claims helper(' "${SUT[@]}" "$WORK/declared_name_method"

track_fixture declared_name_generic declared_name_generic_test.go <<'GO'
package example

// helper checks helper().
func helper[T any]() {}
GO
expect_status declared_name_generic 1 'declared_name_generic_test.go:3: comment claims helper(' "${SUT[@]}" "$WORK/declared_name_generic"

track_fixture nested_block_one_line nested_block_one_line_test.go <<'GO'
package example

func f() { if true {}
	// checks missing()
}
GO
expect_status nested_block_one_line 1 'nested_block_one_line_test.go:4: comment claims missing(' "${SUT[@]}" "$WORK/nested_block_one_line"

track_fixture closing_with_paren closing_with_paren_test.go <<'GO'
package example

func TestFirst(t *testing.T) {
	t.Run("claim", func(t *testing.T) {
		// checks helper()
	})
	t.Run("call", func(t *testing.T) {
		helper()
	}) }

// TestNext checks other().
func TestNext(t *testing.T) { other() }
GO
expect_pass closing_with_paren "${SUT[@]}" "$WORK/closing_with_paren"

track_fixture bodyless bodyless_test.go <<'GO'
package example

// f checks helper().
func f()
func other() { helper() }
GO
expect_status bodyless 1 'bodyless_test.go:3: comment claims helper(' "${SUT[@]}" "$WORK/bodyless"

track_fixture sig_chan_struct_inner sig_chan_struct_inner_test.go <<'GO'
package example

func waitDone(done chan struct{}) {
	// checks missing()
}
GO
expect_status sig_chan_struct_inner 1 'sig_chan_struct_inner_test.go:4: comment claims missing(' "${SUT[@]}" "$WORK/sig_chan_struct_inner"

track_fixture sig_chan_struct sig_chan_struct_test.go <<'GO'
package example

// waitDone checks helper().
func waitDone(done chan struct{}) {
	helper()
}
GO
expect_pass sig_chan_struct "${SUT[@]}" "$WORK/sig_chan_struct"

track_fixture sig_interface_result sig_interface_result_test.go <<'GO'
package example

// mk checks helper().
func mk() interface{ M() } {
	helper()
	return nil
}
GO
expect_pass sig_interface_result "${SUT[@]}" "$WORK/sig_interface_result"

track_fixture sig_type_param sig_type_param_test.go <<'GO'
package example

// pick checks helper().
func pick[T interface{ ~int }](v T) {
	helper()
}

// pickNested checks helper().
func pickNested[T interface
{
	M(struct { V interface{ N() } })
}](v T) {
	helper()
}
GO
expect_pass sig_type_param "${SUT[@]}" "$WORK/sig_type_param"

track_fixture sig_struct_result_one_line sig_struct_result_one_line_test.go <<'GO'
package example

func external() struct{}

// mk checks helper().
func mk() struct{} { helper() }

func externalInline() struct{}; var unrelated = func() {
	// checks missing()
}
GO
expect_pass sig_struct_result_one_line "${SUT[@]}" "$WORK/sig_struct_result_one_line"

track_fixture sig_struct_result_missing sig_struct_result_missing_test.go <<'GO'
package example

// mk checks helper().
func mk() struct{} { other() }
GO
expect_status sig_struct_result_missing 1 'sig_struct_result_missing_test.go:3: comment claims helper(' "${SUT[@]}" "$WORK/sig_struct_result_missing"

track_fixture multi_line_params multi_line_params_test.go <<'GO'
package example

// multi checks helper().
func multi(
	a int,
) {
	helper()
}
GO
expect_pass multi_line_params "${SUT[@]}" "$WORK/multi_line_params"

track_fixture non_ascii non_ascii_test.go <<'GO'
package example

// f checks café().
func f() {}
GO
expect_pass non_ascii "${SUT[@]}" "$WORK/non_ascii"

track_fixture prose prose_test.go <<'GO'
package example

// TestNil checks that a nil error never reports a key.
func TestNil(t *testing.T) {
	carriesKey(nil)
}
GO
expect_pass prose "${SUT[@]}" "$WORK/prose"

track_fixture non_test client.go <<'GO'
package example

// inspect checks that redactError(nil) returns nil.
func inspect() {
	carriesKey(nil)
}
GO
expect_pass non_test "${SUT[@]}" "$WORK/non_test"

track_fixture other_function other_function_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	wrapRedactError(nil)
}

func TestOther(t *testing.T) {
	c.redactError(nil)
}
GO
expect_status other_function 1 'other_function_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/other_function"

track_fixture comment_only comment_only_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	// Call redactError(nil) with a nil error.
	carriesKey(nil)
}
GO
expect_status comment_only 1 'comment_only_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/comment_only"

track_fixture string_message string_message_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	if carriesKey(nil) {
		t.Errorf("redactError(nil) left a key in the error")
	}
}
GO
expect_status string_message 1 'string_message_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/string_message"

track_fixture trailing_comment trailing_comment_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	carriesKey(nil) // Call redactError(nil) with a nil error.
}
GO
expect_status trailing_comment 1 'trailing_comment_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/trailing_comment"

track_fixture raw_string raw_string_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	t.Log(`first line
redactError(nil)
last line`)
}
GO
expect_status raw_string 1 'raw_string_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/raw_string"

track_fixture escaped_string_refusal escaped_string_refusal_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	t.Log("escaped quote: \" redactError(nil)")
}
GO
expect_status escaped_string_refusal 1 'escaped_string_refusal_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/escaped_string_refusal"

track_fixture escaped_rune_refusal escaped_rune_refusal_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	t.Log('\'', "a'", "redactError(nil)")
}
GO
expect_status escaped_rune_refusal 1 'escaped_rune_refusal_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/escaped_rune_refusal"

track_fixture escaped_literals escaped_literals_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	t.Log("// escaped quote: \" still a string", c.redactError(nil))
	t.Log('"', '\'', carriesKey(nil))
	// Check that carriesKey(nil) returns false.
}
GO
expect_pass escaped_literals "${SUT[@]}" "$WORK/escaped_literals"

track_fixture block_comment block_comment_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	carriesKey(nil) /* redactError(nil) */
}
GO
expect_status block_comment 1 'block_comment_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/block_comment"

track_fixture multiline_block_comment multiline_block_comment_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	/*
	redactError(nil)
	*/
	carriesKey(nil)
}
GO
expect_status multiline_block_comment 1 'multiline_block_comment_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/multiline_block_comment"

mkdir "$WORK/awk-bin"
cat > "$WORK/awk-bin/awk" <<'BASH'
#!/usr/bin/env bash
printf 'planted awk failure\n' >&2
exit 1
BASH
chmod +x "$WORK/awk-bin/awk"
PATH="$WORK/awk-bin:$PATH" expect_status awk_failure 2 'planted awk failure' "${SUT[@]}" "$WORK/fixed"

track_fixture missing_file missing_file_test.go <<'GO'
package example
GO
rm "$WORK/missing_file/missing_file_test.go"
expect_status missing_file 2 'missing_file_test.go' "${SUT[@]}" "$WORK/missing_file"

expect_status usage 2 'usage:' "${SUT[@]}" "$WORK/fixed" extra

echo 'test-claim-calls: all planted cases pass'
