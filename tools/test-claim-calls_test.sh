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
expect_refusal planted 'planted_test.go:3: comment claims redactError( but the function never calls redactError(' "${SUT[@]}" "$WORK/planted"

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
expect_refusal body 'body_test.go:4: comment claims redactError(' "${SUT[@]}" "$WORK/body"

track_fixture dotted dotted_test.go <<'GO'
package example

// TestMatch verifies that errors.Is(err, target) finds the wrapped error.
func TestMatch(t *testing.T) {
	errors.Is(err, target)
}
GO
expect_pass dotted "${SUT[@]}" "$WORK/dotted"

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
expect_refusal other_function 'other_function_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/other_function"

track_fixture comment_only comment_only_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	// Call redactError(nil) with a nil error.
	carriesKey(nil)
}
GO
expect_refusal comment_only 'comment_only_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/comment_only"

track_fixture string_message string_message_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	if carriesKey(nil) {
		t.Errorf("redactError(nil) left a key in the error")
	}
}
GO
expect_refusal string_message 'string_message_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/string_message"

track_fixture trailing_comment trailing_comment_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	carriesKey(nil) // Call redactError(nil) with a nil error.
}
GO
expect_refusal trailing_comment 'trailing_comment_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/trailing_comment"

track_fixture raw_string raw_string_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	t.Log(`first line
redactError(nil)
last line`)
}
GO
expect_refusal raw_string 'raw_string_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/raw_string"

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

track_fixture escaped_rune_refusal escaped_rune_refusal_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	t.Log("escaped quote: \" redactError(nil)")
}
GO
expect_refusal escaped_rune_refusal 'escaped_rune_refusal_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/escaped_rune_refusal"

track_fixture block_comment block_comment_test.go <<'GO'
package example

// TestRedact checks that redactError(nil) returns nil.
func TestRedact(t *testing.T) {
	carriesKey(nil) /* redactError(nil) */
}
GO
expect_refusal block_comment 'block_comment_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/block_comment"

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
expect_refusal multiline_block_comment 'multiline_block_comment_test.go:3: comment claims redactError(' "${SUT[@]}" "$WORK/multiline_block_comment"

echo 'test-claim-calls: all planted cases pass'
