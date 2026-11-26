package tautulli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// TestScrubOverlappingKeySpellings checks offset-anchored matching in text and bodies.
func TestScrubOverlappingKeySpellings(t *testing.T) {
	t.Parallel()
	const (
		percentKey   = "ab-~"
		backslashKey = "b-~"
		otherDigit   = '3'
	)
	first, last := percentKey[2], percentKey[3]
	upper := fmt.Sprintf("%%%02X%%%02X", first, last)
	lower := fmt.Sprintf("%%%02x%%%02x", first, last)
	unicodePair := fmt.Sprintf("\\u%04X\\u%04X", first, last)
	mixed := fmt.Sprintf("%%%02X\\u%04X", first, last)
	otherPercent := fmt.Sprintf("%%%02X%%%02X", first, otherDigit)
	otherUnicode := fmt.Sprintf("\\u%04X\\u%04X", first, otherDigit)
	percentPrefix := "prefix %" + percentKey[:2]
	backslashPrefix := "prefix \\" + backslashKey[:1]
	const suffix = " suffix"
	cases := []struct {
		name, key, text string
		redact          bool
	}{
		{"percent upper hex", percentKey, percentPrefix + upper + suffix, true},
		{"percent lower hex", percentKey, percentPrefix + lower + suffix, true},
		{"percent before Unicode", percentKey, percentPrefix + unicodePair + suffix, true},
		{"backslash before Unicode", backslashKey, backslashPrefix + unicodePair + suffix, true},
		{"ends at text boundary", percentKey, percentPrefix + mixed, true},
		{"percent different digit", percentKey, percentPrefix + otherPercent + suffix, false},
		{"percent before different Unicode digit", percentKey, percentPrefix + otherUnicode + suffix, false},
		{"backslash before different Unicode digit", backslashKey, backslashPrefix + otherUnicode + suffix, false},
		{"truncated final escape", percentKey, percentPrefix + mixed[:len(mixed)-1], false},
		{"key in fixed placeholder", "ACT", "ACT", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{apiKey: tc.key}
			want := tc.text
			if tc.redact {
				want = "REDACTED"
			}
			if got := c.scrubText(tc.text); got != want {
				t.Errorf("scrubText = %q; want %q", got, want)
			}
			if got := c.scrubBody(tc.text); got != want {
				t.Errorf("scrubBody = %q; want %q", got, want)
			}
		})
	}
}

type redactFixtureURLAs struct{ link *url.Error }

// Error returns a fixed message without the fixture URL.
func (*redactFixtureURLAs) Error() string { return "fixture transport failure" }

// As supplies the fixture URL error separately from the error tree.
func (e *redactFixtureURLAs) As(target any) bool {
	dst, ok := target.(**url.Error)
	if !ok {
		return false
	}
	*dst = e.link
	return true
}

// TestScrubErrorHidesCustomURLAs checks that root and nested custom As methods stay opaque.
func TestScrubErrorHidesCustomURLAs(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	node := &redactFixtureURLAs{link: &url.Error{Op: "Get", URL: "http://h/" + key}}
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"root", node},
		{"nested", errors.Join(errors.New("fixture sibling"), node)},
		{"key-bearing parent", fmt.Errorf("fixture %s: %w", key, node)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertCustomURLAsHidden(t, c, "scrubError", c.scrubError(tc.err))
			assertCustomURLAsHidden(t, c, "redactError", c.redactError(tc.err))
		})
	}
}

// assertCustomURLAsHidden checks that the custom As hook cannot supply a URL.
func assertCustomURLAsHidden(t *testing.T, c *Client, name string, got error) {
	t.Helper()
	assertOpaqueError(t, c, name, got)
	var link *url.Error
	if errors.As(got, &link) {
		t.Errorf("%s recovered a URL from a custom As hook", name)
	}
}

// assertOpaqueError checks that the wrapper only prints sanitized text.
func assertOpaqueError(t *testing.T, c *Client, name string, got error) {
	t.Helper()
	if hiddenRedaction(got) == nil {
		t.Errorf("%s returned %T; want opaque wrapper", name, got)
	}
	for _, format := range [...]string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X"} {
		formatted := fmt.Sprintf(format, got)
		if c.containsKey(formatted) {
			t.Errorf("%s exposed the key with format %q", name, format)
		}
		if (format == "%x" || format == "%X") && formatted != fmt.Sprintf(format, got.Error()) {
			t.Errorf("%s did not hex-format the sanitized message with %q", name, format)
		}
	}
}

type redactFirstChild struct {
	child *url.Error
	calls int
}

// Error returns a message independent of the wrapped error.
func (*redactFirstChild) Error() string { return "fixture transport failure" }

// next returns the fixture child on the first call only.
func (e *redactFirstChild) next() error {
	e.calls++
	if e.calls == 1 {
		return e.child
	}
	return nil
}

type redactFirstSingle struct{ *redactFirstChild }

// Unwrap returns the first child as a single wrapped error.
func (e redactFirstSingle) Unwrap() error { return e.next() }

type redactFirstJoin struct{ *redactFirstChild }

// Unwrap returns the first child as a joined error.
func (e redactFirstJoin) Unwrap() []error {
	if first := e.next(); first != nil {
		return []error{first}
	}
	return nil
}

// TestRedactErrorReadsUnwrapOnce checks that each walk inspects the first result from Unwrap.
func TestRedactErrorReadsUnwrapOnce(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name string
		wrap func(*redactFirstChild) error
	}{
		{"single", func(first *redactFirstChild) error { return redactFirstSingle{first} }},
		{"join", func(first *redactFirstChild) error { return redactFirstJoin{first} }},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			const key = "plum"
			c := &Client{apiKey: key}
			link := &url.Error{Op: "Get", URL: "http://h/" + key, Err: errors.New("dial")}
			for name, apply := range map[string]func(error) error{"scrubError": c.scrubError, "redactError": c.redactError} {
				first := &redactFirstChild{child: link}
				assertFirstChildHidden(subtest, c, name, apply(tc.wrap(first)), first)
			}
			first := &redactFirstChild{child: link}
			got := &redactedError{err: tc.wrap(first), key: key}
			var copied *url.Error
			if !errors.As(got, &copied) || copied == nil || copied == link || c.containsKey(copied.URL) {
				subtest.Error("errors.As did not sanitize the first child")
			}
			if first.calls != 1 {
				subtest.Errorf("errors.As called Unwrap %d times; want 1", first.calls)
			}
		})
	}
}

// assertFirstChildHidden checks opacity and the call count after each walk.
func assertFirstChildHidden(t *testing.T, c *Client, name string, got error, first *redactFirstChild) {
	t.Helper()
	assertOpaqueError(t, c, name, got)
	if first.calls != 1 {
		t.Errorf("%s called Unwrap %d times; want 1", name, first.calls)
	}
	var copied *url.Error
	if errors.As(got, &copied) {
		t.Errorf("%s recovered a URL after Unwrap stopped returning children", name)
	}
	if first.calls != 2 {
		t.Errorf("%s and errors.As called Unwrap %d times; want 2", name, first.calls)
	}
}

type redactFixtureFormatter struct {
	cause error
	text  string
}

// Error returns key-free text.
func (e *redactFixtureFormatter) Error() string { return e.cause.Error() }

// Unwrap returns the fixture cause.
func (e *redactFixtureFormatter) Unwrap() error { return e.cause }

// Format prints the fixture's separate formatting text for %v and %+v.
func (e *redactFixtureFormatter) Format(f fmt.State, verb rune) {
	text := e.Error()
	if verb == 'v' {
		text = e.text
	}
	if _, err := io.WriteString(f, text); err != nil {
		return
	}
}

type redactFormatterBody struct{ cause error }

// Read returns the fixture formatting error.
func (b redactFormatterBody) Read([]byte) (int, error) { return 0, b.cause }

// Close closes the fixture body.
func (redactFormatterBody) Close() error { return nil }

// RoundTrip returns a response with a failing body without sending a request.
func (b redactFormatterBody) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: http.StatusOK, Body: b, Request: req}, nil
}

// newFormatterResponseClient creates a client whose response body returns a custom formatter error.
func newFormatterResponseClient(t *testing.T, key string, cause error) *Client {
	t.Helper()
	transport := redactFormatterBody{cause: &redactFixtureFormatter{cause: cause, text: key}}
	c, err := New("http://127.0.0.1", key, WithHTTPClient(&http.Client{Transport: transport}))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// assertFormatterRedacted checks formatting, sentinel identity, and formatter opacity.
func assertFormatterRedacted(t *testing.T, got, sentinel error, key string) {
	t.Helper()
	if got == nil {
		t.Fatal("expected a sanitized error")
	}
	assertNoKeyForms(t, fmt.Sprintf("%v", got), key)
	assertNoKeyForms(t, fmt.Sprintf("%+v", got), key)
	if !errors.Is(got, sentinel) {
		t.Error("errors.Is did not reach the sentinel")
	}
	var exposed *redactFixtureFormatter
	if errors.As(got, &exposed) {
		t.Error("errors.As exposed the original formatter")
	}
}

// TestScrubErrorHidesCustomFormatter checks root and nested formatters even when Error omits the key.
func TestScrubErrorHidesCustomFormatter(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	sentinel := errors.New("fixture read failure")
	escapedKey := strings.Replace(key, "-", fmt.Sprintf("%%%02X", '-'), 1)
	unsafeFormatter := &redactFixtureFormatter{cause: sentinel, text: escapedKey}
	cases := []struct {
		name string
		err  error
	}{
		{"root formatter", unsafeFormatter},
		{"nested formatter", errors.Join(errors.New("fixture sibling"), unsafeFormatter)},
		{"key-free formatter", &redactFixtureFormatter{cause: sentinel, text: "fixture plain formatting"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertFormatterRedacted(t, c.scrubError(tc.err), sentinel, key)
		})
	}
}

type redactFixtureCause struct{ error }

type redactFixtureGoStringer struct {
	text   string
	called *bool
}

// Error returns a message without the fixture text.
func (redactFixtureGoStringer) Error() string { return "fixture formatting failure" }

// GoString records the call and returns the fixture text.
func (e redactFixtureGoStringer) GoString() string {
	*e.called = true
	return e.text
}

type redactFixtureReflectedError struct{ text string }

// Error returns a message without the fixture text.
func (redactFixtureReflectedError) Error() string { return "fixture reflection failure" }

type redactStringPointerError string

// Error returns a message independent of the pointed-to string.
func (*redactStringPointerError) Error() string { return "fixture reflection failure" }

// TestRedactErrorHidesStringPointer checks a root string pointee and key-free identity.
func TestRedactErrorHidesStringPointer(t *testing.T) {
	t.Parallel()
	const key = "plum"
	c := &Client{apiKey: key}
	hidden, plain := redactStringPointerError(key), redactStringPointerError("pear")
	for name, apply := range map[string]func(error) error{"scrubError": c.scrubError, "redactError": c.redactError} {
		got := apply(&hidden)
		assertOpaqueError(t, c, name, got)
		var exposed *redactStringPointerError
		if errors.As(got, &exposed) {
			t.Errorf("%s exposed the original string pointer", name)
		}
		if apply(&plain) != &plain { //nolint:errorlint // require the exact pointer to pass through
			t.Errorf("%s changed the identity of a key-free string pointer", name)
		}
	}
}

// TestScrubErrorHidesGoSyntax checks both ways that Go-syntax output can expose the key.
func TestScrubErrorHidesGoSyntax(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c, err := New("http://127.0.0.1", key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	var called bool
	custom := redactFixtureGoStringer{text: key, called: &called}
	for _, original := range []error{custom, errors.Join(custom), redactFixtureReflectedError{text: key}} {
		got := c.scrubError(original)
		if _, wrapped := got.(*redactedError); !wrapped { //nolint:errorlint // check the wrapper itself
			t.Errorf("scrubError(%T) = %T; want redacted wrapper", original, got)
		}
		if strings.Contains(fmt.Sprintf("%#v", got), key) {
			t.Errorf("Go-syntax output exposes the key from %T", original)
		}
	}
	if called {
		t.Error("Go-syntax formatting invoked the original GoString method")
	}
	for _, tc := range [...]struct{ name, key string }{
		{"key-free error", key},
		{"key in type name", "errors.errorString"},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			assertScrubErrorIdentity(subtest, tc.key)
		})
	}
}

// assertScrubErrorIdentity checks the original pointer and its errors.Is match.
func assertScrubErrorIdentity(t *testing.T, key string) {
	t.Helper()
	original := errors.New("fixture failure")
	got := (&Client{apiKey: key}).scrubError(original)
	if any(got) != any(original) {
		t.Errorf("scrubError changed the identity of %T", original)
	}
	if !errors.Is(got, original) {
		t.Error("errors.Is lost the original error")
	}
}

type redactCycleFieldError struct{ fields map[string]any }

// Error returns a message independent of the map.
func (redactCycleFieldError) Error() string { return "fixture transport failure" }

// TestScrubErrorReflectCycle isolates a self-referential map from the test runner.
func TestScrubErrorReflectCycle(t *testing.T) {
	t.Parallel()
	const child = "redact-cycle-child"
	if slices.Contains(os.Args[1:], child) {
		assertReflectCycleHidden(t)
		return
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("locate test executable: %v", err)
	}
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestScrubErrorReflectCycle$", "--", child)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "fatal error: stack overflow") {
			t.Fatal("scrubError overflowed the child stack")
		}
		t.Fatalf("cycle child: %v\n%s", err, output)
	}
}

// assertReflectCycleHidden checks the child without risking the parent's stack.
func assertReflectCycleHidden(t *testing.T) {
	t.Helper()
	debug.SetMaxStack(1 << 20)
	fields := map[string]any{}
	fields["cycle"] = fields
	assertReflectedError(t, "fixture-key42", redactCycleFieldError{fields: fields}, true)
}

type redactReflectFieldError struct {
	text      string
	bytes     []byte
	number    int
	pointer   *struct{ text string }
	Formatter any
}

// Error returns a message independent of the fields.
func (*redactReflectFieldError) Error() string { return "fixture transport failure" }

type redactNestedGoStringer struct{ called bool }

// GoString records a call without exposing fixture data.
func (e *redactNestedGoStringer) GoString() string {
	e.called = true
	return "fixture nested formatting"
}

// TestScrubErrorReflectFields checks leaf detection, pointer depth, and nested formatting.
func TestScrubErrorReflectFields(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	const number = 42082
	escaped := fmt.Sprintf("%%%02X%s", key[0], key[1:])
	formatter := &redactNestedGoStringer{}
	for _, tc := range []struct {
		name, key string
		err       *redactReflectFieldError
		hide      bool
	}{
		{"escaped string", key, &redactReflectFieldError{text: escaped}, true},
		{"byte slice", key, &redactReflectFieldError{bytes: []byte(key)}, true},
		{"integer", strconv.Itoa(number), &redactReflectFieldError{number: number}, true},
		{"nested formatter", key, &redactReflectFieldError{Formatter: formatter}, true},
		{"key-free fields", key, &redactReflectFieldError{text: "fixture safe text", number: 1}, false},
		{"nested pointer", key, &redactReflectFieldError{pointer: &struct{ text string }{text: key}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertReflectedError(t, tc.key, tc.err, tc.hide)
			if tc.err.Formatter == formatter && formatter.called {
				t.Error("scrubError invoked the nested GoString method")
			}
		})
	}
}

type redactSliceFieldError struct{ fields []string }

// Error returns a message independent of the slice.
func (*redactSliceFieldError) Error() string { return "fixture transport failure" }

// TestScrubErrorReflectValueBound checks the last allowed value and the first overflow.
func TestScrubErrorReflectValueBound(t *testing.T) {
	t.Parallel()
	// Why: the root pointer, struct, and slice occupy three slots before the elements.
	const bound = 1024 - 3
	for _, tc := range []struct {
		name  string
		count int
		hide  bool
	}{
		{"exactly 1024 values", bound, false},
		{"one value over", bound + 1, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			node := &redactSliceFieldError{fields: make([]string, tc.count)}
			assertReflectedError(t, "fixture-key42", node, tc.hide)
		})
	}
}

// assertReflectedError checks opaque wrapping or exact identity.
func assertReflectedError(t *testing.T, key string, original error, hide bool) {
	t.Helper()
	got := (&Client{apiKey: key}).scrubError(original)
	if hide {
		if hiddenRedaction(got) == nil {
			t.Errorf("scrubError returned %T; want opaque wrapper", got)
		}
		return
	}
	if got != original { //nolint:errorlint // require the exact input to pass through
		t.Error("scrubError changed the identity of a safe error")
	}
}

// TestCanonicalKeyProjection checks escaped input across decoding projections and bounds.
func TestCanonicalKeyProjection(t *testing.T) {
	t.Parallel()
	key := "ab" + "12"
	c, err := New("http://127.0.0.1", key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for _, tc := range []struct{ name, input, want string }{
		{"mixed pass consumes key prefix", `%ab\u0031\u0032`, "REDACTED"},
		{"two backslash layers", `%ab\\u0031\\u0032`, "REDACTED"},
		{"decode projection limit", `\u0025255c %255c%5cu0030 \\u00255c %25255c`, "REDACTED"},
		{"unrelated escapes", `%ab\u0031\u0033`, `%ab\u0031\u0033`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := c.scrubText(tc.input); got != tc.want {
				t.Error("unexpected text redaction")
			}
			if got := c.scrubBody(tc.input); got != tc.want {
				t.Error("unexpected body redaction")
			}
		})
	}
}

// TestDecodeProjectionByteBudget checks the accumulated lengths of distinct decoded texts.
func TestDecodeProjectionByteBudget(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	// Why: nine projections retain 171 parent bytes, plus nine bytes per suffix byte.
	const input = `%61 \\u002561 %5cu0061`
	const ordinary = `%61\u0062`
	under := input + strings.Repeat("x", 4)
	exact := under + "x"
	c := &Client{apiKey: key}
	for _, tc := range []struct {
		name, text, want string
		contains         bool
	}{
		{"under budget", under, under, false},
		{"exact budget", exact, exact, false},
		{"over budget", exact + "x", "REDACTED", true},
		{"ordinary mixed escapes", key + " " + ordinary, "REDACTED " + ordinary, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := c.scrubText(tc.text); got != tc.want {
				t.Error("unexpected text redaction")
			}
			if got := c.containsKey(tc.text); got != tc.contains {
				t.Errorf("containsKey = %t; want %t", got, tc.contains)
			}
		})
	}
}

// TestDecodeLayerProjectionLimit isolates the projection cap so the depth limit cannot mask its removal.
func TestDecodeLayerProjectionLimit(t *testing.T) {
	t.Parallel()
	const key = "ab" + "12"
	c, err := New("http://127.0.0.1", key)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Why: each mixed input yields three distinct projections by decoding either escape or both.
	mixed := []string{`%61\u0062`, `%63\u0064`, `%65\u0066`, `%67\u0068`, `%69\u006a`, `%6b\u006c`}
	cases := []struct {
		name       string
		frontier   []string
		wantCount  int
		wantRedact bool
	}{
		{"exactly 16 projections", append(slices.Clone(mixed[:5]), "%6d"), 16, false},
		{"redact on projection 17", mixed, 0, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			seen := make(map[string]struct{}, len(tc.frontier))
			for _, input := range tc.frontier {
				seen[input] = struct{}{}
			}
			remainingBytes := uint64(1024)
			next, redact := c.decodeLayer(tc.frontier, seen, &remainingBytes)
			if redact != tc.wantRedact || len(next) != tc.wantCount {
				subtest.Errorf("decodeLayer returned %d projections and redact=%t, want %d and %t", len(next), redact, tc.wantCount, tc.wantRedact)
			}
			if added := len(seen) - len(tc.frontier); added != 16 {
				subtest.Errorf("decodeLayer recorded %d new projections, want 16", added)
			}
		})
	}
}

// TestSanitizedURLCopyClassifiesCycle checks that classification is bounded and captured at copy time.
func TestSanitizedURLCopyClassifiesCycle(t *testing.T) {
	t.Parallel()
	loop := &url.Error{}
	loop.Err = loop
	original := &url.Error{Err: loop}
	copyErr := answerWithinTwoSeconds(t, "copy URL error with cyclic cause", func() *url.Error {
		var copied *url.Error
		(&redactedError{err: original}).As(&copied)
		return copied
	})
	if copyErr == nil {
		t.Fatal("expected a sanitized URL error copy")
	}
	// Why: break the original cycle after copying so a live classifier fails without exhausting the stack.
	loop.Err = &net.DNSError{IsTimeout: true, IsTemporary: true}
	if answerWithinTwoSeconds(t, "copied Timeout", copyErr.Timeout) {
		t.Error("copied Timeout classified the changed cause")
	}
	if answerWithinTwoSeconds(t, "copied Temporary", copyErr.Temporary) {
		t.Error("copied Temporary classified the changed cause")
	}
}

// Unwrap returns the fixture sentinel.
func (e redactFixtureCause) Unwrap() error { return e.error }

type redactTimeoutCause struct{ redactFixtureCause }

// Timeout reports whether this fixture is non-nil.
func (e *redactTimeoutCause) Timeout() bool { return e != nil }

type redactTemporaryCause struct{ redactFixtureCause }

// Temporary reports that the fixture is temporary.
func (redactTemporaryCause) Temporary() bool { return true }

type redactNilTimeoutCause struct{ redactFixtureCause }

// Timeout reports a timeout for the typed-nil fixture.
func (e *redactNilTimeoutCause) Timeout() bool { return e == nil }

// TestURLCopyUnsafeCause compares the root and errors.As copies with the wrapper's classification.
func TestURLCopyUnsafeCause(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	var dns *net.DNSError
	for _, tc := range []struct {
		name    string
		cause   error
		timeout bool
	}{
		{"wrapped-typed-nil-DNS", &net.OpError{Op: "dial", Err: dns}, false},
		{"nil-safe-classifier", (*redactNilTimeoutCause)(nil), false},
		{"typed-nil-DNS", dns, false},
		{"non-nil-DNS", &net.DNSError{IsTimeout: true}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			original := &url.Error{Op: "Get", URL: "http://h/" + key, Err: tc.cause}
			assertURLCauseViews(t, c.redactError(original), original, tc.timeout)
			assertURLCauseViews(t, c.scrubError(errors.Join(original)), original, tc.timeout)
		})
	}
}

// TestURLCopyPreviouslyRedactedUnsafeCause checks classifiers on a reused unsafe wrapper and both URL copy paths.
func TestURLCopyPreviouslyRedactedUnsafeCause(t *testing.T) {
	t.Parallel()
	const key = "plum"
	c := &Client{apiKey: key}
	var dns *net.DNSError
	prior := hiddenRedaction(c.redactError(&net.OpError{Op: "dial", Err: dns}))
	if prior == nil {
		t.Fatal("expected a previously redacted cause")
	}
	original := &url.Error{Op: "Get", URL: "http://h/" + key, Err: prior}
	assertURLCauseViews(t, c.redactError(original), original, false)
	assertURLCauseViews(t, c.scrubError(errors.Join(original)), original, false)
	if prior.Timeout() || prior.Temporary() {
		t.Error("previously redacted cause reported a classification")
	}
}

// assertURLCauseViews checks the copied cause and both views of its classifiers.
func assertURLCauseViews(t *testing.T, got error, original *url.Error, timeout bool) {
	t.Helper()
	var copied *url.Error
	if !errors.As(got, &copied) || copied == nil || copied == original {
		t.Fatal("expected a sanitized URL error copy")
	}
	if isNilError(copied.Err) {
		t.Fatal("expected a non-nil copied cause")
	}
	if !timeout && copied.Err.Error() != redactedTreeMsg {
		t.Error("unsafe copied cause did not use the fixed message")
	}
	assertURLClassifications(t, got, copied, timeout)
}

// assertURLClassifications compares the classifications of the copy and the returned error.
func assertURLClassifications(t *testing.T, got error, copied *url.Error, timeout bool) {
	t.Helper()
	// Why: a DNSError timeout also classifies as temporary.
	if copied.Timeout() != timeout || copied.Temporary() != timeout {
		t.Error("unexpected copy classification")
	}
	var outerTimeout interface{ Timeout() bool }
	if !errors.As(got, &outerTimeout) || outerTimeout.Timeout() != timeout {
		t.Error("unexpected outer Timeout classification")
	}
	var outerTemporary interface{ Temporary() bool }
	if !errors.As(got, &outerTemporary) || outerTemporary.Temporary() != timeout {
		t.Error("unexpected outer Temporary classification")
	}
}

// TestSanitizedURLCopyClassifiesImmediateCause checks both URL-copy paths and the original URL error.
func TestSanitizedURLCopyClassifiesImmediateCause(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	sentinel := errors.New("fixture DNS failure")
	timeout := &net.DNSError{UnwrapErr: sentinel, IsTimeout: true, IsTemporary: true}
	timeoutOnly := &redactTimeoutCause{redactFixtureCause{sentinel}}
	temporaryOnly := redactTemporaryCause{redactFixtureCause{sentinel}}
	c := &Client{apiKey: key}
	cases := []struct {
		name                       string
		cause                      error
		wantTimeout, wantTemporary bool
	}{
		{"ordinary wrapper", fmt.Errorf("fixture wrapper: %w", timeout), false, false},
		{"DNS error", timeout, true, true},
		{"timeout only", timeoutOnly, true, false},
		{"temporary only", temporaryOnly, false, true},
		{"nil", nil, false, false},
		{"redacted cause", &redactedError{err: timeout, msg: "fixture hidden cause", key: key}, true, true},
		{"different classifier nodes", &redactedError{err: errors.Join(timeoutOnly, temporaryOnly), key: key}, true, true},
		{"nested URL commits to its cause", &redactedError{err: errors.Join(&url.Error{Err: timeoutOnly}, temporaryOnly), key: key}, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			fixture := url.Error{Op: "Get", URL: "http://fixture.invalid/" + key, Err: tc.cause}
			subtest.Run("As", func(view *testing.T) {
				view.Parallel()
				original := fixture
				want := original.Err
				got := c.scrubError(errors.Join(&original))
				assertURLCopyClassifies(view, got, &original, want, sentinel, key, tc.wantTimeout, tc.wantTemporary)
			})
			subtest.Run("redactError", func(view *testing.T) {
				view.Parallel()
				original := fixture
				want := original.Err
				got := c.redactError(&original)
				assertURLCopyClassifies(view, got, &original, want, sentinel, key, tc.wantTimeout, tc.wantTemporary)
			})
		})
	}
}

// assertURLCopyClassifies checks classification and sentinel identity through a sanitized copy.
func assertURLCopyClassifies(t *testing.T, got error, original *url.Error, want, sentinel error, key string, wantTimeout, wantTemporary bool) {
	t.Helper()
	var copyErr *url.Error
	if !errors.As(got, &copyErr) || copyErr == nil || copyErr == original {
		t.Fatalf("expected a sanitized URL error copy, got %T", got)
	}
	if want == nil {
		if original.Err != nil || copyErr.Err != nil {
			t.Error("copy changed a nil cause")
		}
	} else {
		assertRedactedRootCause(t, copyErr, original, want)
		if !errors.Is(copyErr, sentinel) {
			t.Error("errors.Is through the copy did not reach the sentinel")
		}
	}
	fallback := &net.DNSError{IsTimeout: true, IsTemporary: true}
	nested := &redactedError{err: errors.Join(copyErr, fallback), key: key}
	assertClassifierValues(t, "copy", copyErr, wantTimeout, wantTemporary)
	assertClassifierValues(t, "nested", nested, wantTimeout, wantTemporary)
	assertClassifierValues(t, "original", original, wantTimeout, wantTemporary)
}

// assertClassifierValues checks both classifications on one view of the error.
func assertClassifierValues(t *testing.T, name string, got interface {
	Timeout() bool
	Temporary() bool
}, wantTimeout, wantTemporary bool,
) {
	t.Helper()
	if timeout := got.Timeout(); timeout != wantTimeout {
		t.Errorf("%s Timeout=%v, want %v", name, timeout, wantTimeout)
	}
	if temporary := got.Temporary(); temporary != wantTemporary {
		t.Errorf("%s Temporary=%v, want %v", name, temporary, wantTemporary)
	}
}

// TestAcceptedKeyScrubAllocations bounds the cost of scrubbing key-free text.
func TestAcceptedKeyScrubAllocations(t *testing.T) { //nolint:paralleltest // AllocsPerRun requires serial execution.
	const text = "fixture text without a match"
	short := &Client{apiKey: strings.Repeat("Z", 8)}
	long := &Client{apiKey: strings.Repeat("Z", 256)}
	shortAllocs := testing.AllocsPerRun(100, func() { _ = short.scrub(text) })
	longAllocs := testing.AllocsPerRun(100, func() { _ = long.scrub(text) })
	if shortAllocs > 1 || longAllocs > shortAllocs {
		t.Errorf("scrub allocations: 8-byte key=%g, 256-byte key=%g; want at most 1 with no growth", shortAllocs, longAllocs)
	}
}

// redactAsProbe is a second error type in the tree, used to prove As answers only a URL error target.
type redactAsProbe struct{ text string }

// Error returns the fixture text.
func (e *redactAsProbe) Error() string { return e.text }

// assertNoKeyForms reports every raw, query-escaped, or Go-quoted form of key found in text.
func assertNoKeyForms(t *testing.T, text, key string) {
	t.Helper()
	quoted := strconv.Quote(key)
	for _, form := range []string{key, url.QueryEscape(key), quoted[1 : len(quoted)-1]} {
		if strings.Contains(text, form) {
			t.Errorf("key form %q leaked: %s", form, text)
		}
	}
}

// TestRedactedErrorAsURLError checks that errors.As reaches a sanitized copy of a nested URL error and nothing else.
func TestRedactedErrorAsURLError(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, key string }{
		{name: "plain", key: "plain-key"},
		{name: "unreserved punctuation", key: "Fixture-0._~"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkRedactedErrorAs(t, tc.key)
		})
	}
}

// checkRedactedErrorAs redacts a tree that nests a key-bearing URL error and checks what errors.As reaches.
func checkRedactedErrorAs(t *testing.T, key string) {
	t.Helper()
	const op = "Get"
	c := &Client{apiKey: key}
	inner := &url.Error{
		Op:  op,
		URL: "http://h/?apikey=" + url.QueryEscape(key),
		Err: fmt.Errorf("dial %s %q", key, key),
	}
	probe := &redactAsProbe{text: "probe " + key}
	tree := fmt.Errorf("outer: %w", errors.Join(probe, fmt.Errorf("mid: %w", inner)))
	var present *redactAsProbe
	if !errors.As(tree, &present) {
		t.Fatal("fixture broken: probe missing from the original tree")
	}

	got := c.redactError(tree)
	assertNoKeyForms(t, got.Error(), key)
	var uerr *url.Error
	if !errors.As(got, &uerr) {
		t.Fatal("errors.As into *url.Error = false; want true")
	}
	if uerr == inner {
		t.Error("errors.As returned the original URL error, not a copy")
	}
	if uerr.Op != op {
		t.Errorf("Op = %q; want %q", uerr.Op, op)
	}
	assertNoKeyForms(t, uerr.Error(), key)
	assertNoKeyForms(t, uerr.URL, key)
	var hidden *redactAsProbe
	if errors.As(got, &hidden) {
		t.Error("errors.As into another tree type = true; want false")
	}
}

// TestURLErrorRedactsQueryBeforeScrubbing checks URL redaction on root and nested errors.
func TestURLErrorRedactsQueryBeforeScrubbing(t *testing.T) {
	t.Parallel()
	c, err := New("http://127.0.0.1", "api")
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, tc := range []struct{ name, rawURL, wantURL string }{
		{
			name:    "foreign apikey",
			rawURL:  "http://h/x?apikey=foreign&q=api",
			wantURL: "http://h/x?REDACTEDkey=REDACTED&q=REDACTED",
		},
		{
			name:    "path only",
			rawURL:  "http://h/api?q=keep",
			wantURL: "http://h/REDACTED?q=keep",
		},
		{
			name:    "malformed query",
			rawURL:  "http://h/api?q=%zz",
			wantURL: "http://h/REDACTED",
		},
		{
			name:    "unchanged",
			rawURL:  "http://h/x?q=keep",
			wantURL: "http://h/x?q=keep",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			original := &url.Error{Op: http.MethodGet, URL: tc.rawURL, Err: errors.New("fixture transport failure")}
			unchanged := tc.rawURL == tc.wantURL
			t.Run("root", func(t *testing.T) {
				t.Parallel()
				result := c.redactError(original)
				assertRedactedURLRoot(t, result, original, tc.wantURL, unchanged)
			})
			t.Run("nested", func(t *testing.T) {
				t.Parallel()
				result := c.redactError(errors.Join(original))
				assertRedactedURLError(t, result, original, tc.wantURL, unchanged)
			})
		})
	}
}

// assertRedactedURLRoot checks that redaction exposes the URL error directly at the root.
func assertRedactedURLRoot(t *testing.T, result error, original *url.Error, wantURL string, unchanged bool) {
	t.Helper()
	if unchanged && any(result) != any(original) {
		t.Error("redactError did not preserve the clean root error")
	}
	if copied, ok := result.(*url.Error); !unchanged && (!ok || copied == nil) { //nolint:errorlint // require the root type directly
		t.Fatalf("redacted root = %T; want a non-nil *url.Error copy", result)
	}
	assertRedactedURLError(t, result, original, wantURL, unchanged)
}

// assertRedactedURLError checks the URL, operation, and identity of the exposed error.
func assertRedactedURLError(t *testing.T, result error, original *url.Error, wantURL string, wantOriginal bool) {
	t.Helper()
	var exposed *url.Error
	if !errors.As(result, &exposed) || exposed == nil {
		t.Fatal("expected errors.As to expose a non-nil URL error")
	}
	if (exposed == original) != wantOriginal {
		t.Error("expected URL error identity to be preserved only for the unchanged URL")
	}
	if exposed.Op != http.MethodGet {
		t.Errorf("Op = %q, want %q", exposed.Op, http.MethodGet)
	}
	if exposed.URL == wantURL {
		return
	}
	t.Errorf("URL = %q, want %q", exposed.URL, wantURL)
}

// TestRedactedErrorAsOpRedaction checks that errors.As yields a copy whose Op and text lack the key held by a nested URL error's Op.
func TestRedactedErrorAsOpRedaction(t *testing.T) {
	t.Parallel()
	const key = "plain-key"
	c := &Client{apiKey: key}
	inner := &url.Error{Op: "Get " + key, URL: "http://h/", Err: errors.New("fixture transport failure")}
	tree := fmt.Errorf("outer: %w", errors.Join(&redactAsProbe{text: "probe"}, fmt.Errorf("mid: %w", inner)))

	got := c.redactError(tree)
	assertNoKeyForms(t, got.Error(), key)
	var uerr *url.Error
	if !errors.As(got, &uerr) {
		t.Fatal("errors.As into *url.Error = false; want true")
	}
	if uerr == inner {
		t.Error("errors.As returned the original URL error, not a copy")
	}
	assertNoKeyForms(t, uerr.Op, key)
	assertNoKeyForms(t, uerr.Error(), key)
	if inner.Op != "Get "+key {
		t.Errorf("original Op = %q; the copy must not mutate it", inner.Op)
	}
}

// TestRedactedErrorAsEscapedURL checks that a joined URL error exposes a sanitized URL.
func TestRedactedErrorAsEscapedURL(t *testing.T) {
	t.Parallel()
	const key = "fixture"
	c := &Client{apiKey: key}
	inner := &url.Error{Op: "Get", URL: "http://h/" + testUnicodeEscape(key[0]) + key[1:], Err: errors.New("transport failure")}
	got := c.redactError(errors.Join(errors.New("other failure"), inner))

	var uerr *url.Error
	if !errors.As(got, &uerr) {
		t.Fatal("errors.As into *url.Error = false; want true")
	}
	if uerr == inner || uerr.URL != "REDACTED" {
		t.Error("errors.As did not return a copy with a redacted URL")
	}
}

// TestRedactedErrorAsKeepsOriginalKey checks delayed URL extraction after the client is replaced.
func TestRedactedErrorAsKeepsOriginalKey(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	inner := &url.Error{
		Op:  "fixture op " + key,
		URL: "https://example.invalid/" + url.PathEscape(key),
		Err: errors.New("fixture cause " + key),
	}
	hidden := c.scrubError(fmt.Errorf("outer: %w", inner))
	*c = Client{apiKey: key + "-replacement"}

	var got *url.Error
	if !errors.As(hidden, &got) || got == nil || got == inner {
		t.Fatal("errors.As did not return a sanitized URL error copy")
	}
	if got.Op != "fixture op REDACTED" || got.URL != "https://example.invalid/REDACTED" {
		t.Error("recovered URL error did not redact the original key")
	}
	if got.Err == nil || got.Err.Error() != "fixture cause REDACTED" {
		t.Error("recovered URL error cause did not redact the original key")
	}
}

// TestRedactedErrorAsFanoutBounded checks that errors.As on a hidden exponential tree with a key-bearing leaf returns promptly.
func TestRedactedErrorAsFanoutBounded(t *testing.T) {
	t.Parallel()
	const key = "plain-key"
	tree := errors.New("fixture fanout leaf " + key)
	for range 40 {
		tree = redactionFanout{prev: tree}
	}
	hidden := &redactedError{msg: "fixture fanout", err: tree, key: key}
	if answerWithinTwoSeconds(t, "errors.As", func() bool {
		var uerr *url.Error
		return errors.As(hidden, &uerr)
	}) {
		t.Error("errors.As found a *url.Error in a tree that holds none")
	}
}

// redactSliceErr is an uncomparable error type; comparing two values of it with == panics.
type redactSliceErr []string

// Error returns constant fixture text.
func (redactSliceErr) Error() string { return "fixture slice error" }

// hiddenRedacted returns the redactedError that scrubError builds for err and fails the test when err is not hidden.
func hiddenRedacted(t *testing.T, key string, err error) error {
	t.Helper()
	got := answerWithinTwoSeconds(t, "scrubError", func() error {
		return (&Client{apiKey: key}).scrubError(err)
	})
	if hidden, ok := got.(*redactedError); !ok || hidden == nil { //nolint:errorlint // require the wrapper itself without traversing the tree
		t.Fatalf("scrubError(%T) = %T; want *redactedError", err, got)
	}
	return got
}

// answerWithinTwoSeconds runs ask and fails the test if it does not answer within 2s.
func answerWithinTwoSeconds[T any](t *testing.T, name string, ask func() T) T {
	t.Helper()
	done := make(chan T, 1)
	go func() { done <- ask() }()
	select {
	case got := <-done:
		return got
	case <-time.After(2 * time.Second):
		t.Fatalf("%s did not return within 2s", name)
		var zero T
		return zero
	}
}

// TestRedactedErrorSearchesFanoutBounded checks that Timeout, Temporary and errors.Is on a hidden exponential tree return promptly.
func TestRedactedErrorSearchesFanoutBounded(t *testing.T) {
	t.Parallel()
	var err error
	err = errors.New("fixture fanout leaf")
	for range 30 {
		err = redactionFanout{prev: err}
	}
	hidden := hiddenRedacted(t, "plain-key", err)
	absent := errors.New("not in the tree")
	checks := map[string]func() bool{
		"Timeout":   func() bool { return hidden.(interface{ Timeout() bool }).Timeout() },     //nolint:forcetypeassert // the wrapper's own method set under test
		"Temporary": func() bool { return hidden.(interface{ Temporary() bool }).Temporary() }, //nolint:forcetypeassert // the wrapper's own method set under test
		"Is":        func() bool { return errors.Is(hidden, absent) },
	}
	for name, ask := range checks {
		if answerWithinTwoSeconds(t, name, ask) {
			t.Errorf("%s = true on a tree with no matching node", name)
		}
	}
}

// redactCycleErr is a single-unwrap error whose Unwrap returns a cycle.
type redactCycleErr struct {
	text string
	next error
}

// Error returns the fixture text.
func (e *redactCycleErr) Error() string { return e.text }

// Unwrap returns the next error in the cycle.
func (e *redactCycleErr) Unwrap() error { return e.next }

// TestRedactedErrorWalkCycle checks that errors.Is, Timeout, and Temporary terminate on cyclic single-unwrap chains.
func TestRedactedErrorWalkCycle(t *testing.T) {
	t.Parallel()
	const key = "plain-key"
	unrelated := errors.New("unrelated sentinel")
	self := &redactCycleErr{text: "self " + key}
	self.next = self
	first := &redactCycleErr{text: "first " + key}
	second := &redactCycleErr{text: "second", next: first}
	first.next = second
	cases := []struct {
		name string
		err  error
	}{
		{name: "self cycle", err: self},
		{name: "two-node cycle", err: first},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := hiddenRedacted(t, key, tc.err)
			if answerWithinTwoSeconds(t, "Is", func() bool { return errors.Is(got, unrelated) }) {
				t.Error("errors.Is(got, unrelated) = true; want false")
			}
			if answerWithinTwoSeconds(t, "Timeout", func() bool {
				return got.(interface{ Timeout() bool }).Timeout() //nolint:forcetypeassert // wrapper method set under test
			}) {
				t.Error("Timeout() = true; want false")
			}
			if answerWithinTwoSeconds(t, "Temporary", func() bool {
				return got.(interface{ Temporary() bool }).Temporary() //nolint:forcetypeassert // wrapper method set under test
			}) {
				t.Error("Temporary() = true; want false")
			}
		})
	}
}

// TestRedactedErrorIsFindsSentinel checks that errors.Is reaches a sentinel three wraps deep, inside an errors.Join branch, and across a 200-wrap quiet chain.
func TestRedactedErrorIsFindsSentinel(t *testing.T) {
	t.Parallel()
	const key = "plain-key"
	sentinel := errors.New("fixture sentinel")
	unrelatedSentinel := errors.New("unrelated sentinel")
	deep := fmt.Errorf("a %s: %w", key, fmt.Errorf("b: %w", fmt.Errorf("c: %w", sentinel)))
	joined := errors.Join(errors.New("other branch"), fmt.Errorf("k %s: %w", key, sentinel))
	longChain := sentinel
	for range 200 {
		longChain = &redactCycleErr{text: "quiet wrap", next: longChain}
	}
	cases := []struct {
		name string
		tree error
	}{
		{name: "three wraps deep", tree: deep},
		{name: "join branch", tree: joined},
		{name: "long quiet chain", tree: longChain},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			hidden := hiddenRedacted(t, key, tc.tree)
			if !errors.Is(hidden, sentinel) {
				t.Error("errors.Is(hidden, sentinel) = false; want true")
			}
			if errors.Is(hidden, unrelatedSentinel) {
				t.Error("errors.Is(hidden, unrelatedSentinel) = true; want false")
			}
		})
	}
}

// TestRedactedErrorAsTypedNilURLError checks that errors.As skips a typed-nil *url.Error without panicking and still finds a valid *url.Error sibling.
func TestRedactedErrorAsTypedNilURLError(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	var typedNil *url.Error
	valid := &url.Error{
		Op:  "Get " + key,
		URL: "http://h/?apikey=" + url.QueryEscape(key),
		Err: fmt.Errorf("dial %s", key),
	}
	cases := []struct {
		name      string
		tree      error
		wantMatch bool
	}{
		{
			name:      "typed nil before valid URL error",
			tree:      &redactCycleErr{text: "outer " + key, next: errors.Join(typedNil, valid)},
			wantMatch: true,
		},
		{
			name:      "only typed nil URL error",
			tree:      &redactCycleErr{text: "outer " + key, next: errors.Join(typedNil)},
			wantMatch: false,
		},
		{
			name:      "root typed nil URL error",
			tree:      typedNil,
			wantMatch: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertTypedNilURLErrorAs(t, c, tc.tree, valid, key, tc.wantMatch)
		})
	}
}

// assertTypedNilURLErrorAs checks errors.As against a hidden tree containing a typed-nil *url.Error.
func assertTypedNilURLErrorAs(t *testing.T, c *Client, tree error, valid *url.Error, key string, wantMatch bool) {
	t.Helper()
	got := c.redactError(tree)
	assertNoKeyForms(t, got.Error(), key)
	var uerr *url.Error
	if matched := errors.As(got, &uerr); matched != wantMatch {
		t.Fatalf("errors.As = %v; want %v", matched, wantMatch)
	}
	if !wantMatch {
		if uerr != nil {
			t.Errorf("uerr = %v; want nil", uerr)
		}
		return
	}
	if uerr == nil || uerr == valid {
		t.Fatalf("uerr = %v; want a non-nil sanitized copy", uerr)
	}
	assertNoKeyForms(t, uerr.Error(), key)
	assertNoKeyForms(t, uerr.URL, key)
}

// TestRedactErrorJoinFanoutBounded checks that a 40-level errors.Join fan-out over a key-bearing leaf returns promptly with the fixed over-budget message.
func TestRedactErrorJoinFanoutBounded(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	tree := fmt.Errorf("leaf %s", key)
	for range 40 {
		tree = errors.Join(tree, tree)
	}
	cases := []struct {
		name string
		call func(error) error
	}{
		{name: "scrubError", call: c.scrubError},
		{name: "redactError", call: c.redactError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var got error
			if !answerWithinTwoSeconds(t, tc.name, func() bool {
				got = tc.call(tree)
				return got != nil
			}) {
				t.Fatalf("%s returned nil", tc.name)
			}
			hidden, ok := got.(*redactedError) //nolint:errorlint // require the wrapper itself without traversing the tree
			if !ok || hidden == nil {
				t.Fatalf("%s(%T) = %T; want *redactedError", tc.name, tree, got)
			}
			if hidden.Error() != redactedTreeMsg {
				t.Errorf("Error() = %q; want %q", hidden.Error(), redactedTreeMsg)
			}
			assertNoKeyForms(t, hidden.Error(), key)
		})
	}
}

// TestRedactedErrorWalkJoinBudget checks the last allowed join, its leaf, and the first disallowed join.
func TestRedactedErrorWalkJoinBudget(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name       string
		joins      int
		wantVisits int
		wantLeaf   bool
	}{
		{name: "64 joins", joins: 64, wantVisits: 65, wantLeaf: true},
		{name: "65 joins", joins: 65, wantVisits: 64, wantLeaf: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			leaf := errors.New("fixture leaf")
			tree := leaf
			for range tc.joins {
				tree = errors.Join(tree)
			}
			var visits int
			var last error
			(&redactedError{err: tree}).walk(nil, func(node error, _ int) (bool, int) {
				visits++
				last = node
				return false, 0
			})
			if visits != tc.wantVisits {
				t.Errorf("visited %d nodes; want %d", visits, tc.wantVisits)
			}
			if sawLeaf := last == leaf; sawLeaf != tc.wantLeaf { //nolint:errorlint // require a visit to the leaf itself
				t.Errorf("visited leaf = %v; want %v", sawLeaf, tc.wantLeaf)
			}
		})
	}
}

// TestRedactedErrorIsUncomparableTarget checks that errors.Is with an uncomparable target reports false and never panics.
func TestRedactedErrorIsUncomparableTarget(t *testing.T) {
	t.Parallel()
	const key = "plain-key"
	leaf := redactSliceErr{"leaf"}
	hidden := hiddenRedacted(t, key, fmt.Errorf("a %s: %w", key, leaf))
	if errors.Is(hidden, redactSliceErr{"x"}) {
		t.Error("errors.Is with an uncomparable target = true; want false")
	}
}

// redactDynamicErr can carry a dynamically uncomparable value in a comparable struct type.
type redactDynamicErr struct {
	value   any
	matches bool
}

// Error returns the fixture error text.
func (redactDynamicErr) Error() string { return "fixture dynamic error" }

// Is reports whether this fixture matches another dynamic error.
func (e redactDynamicErr) Is(target error) bool {
	_, ok := target.(redactDynamicErr)
	return ok && e.matches
}

// TestRedactedErrorIsDynamicTarget checks dynamically uncomparable targets and the fallback to a custom Is.
func TestRedactedErrorIsDynamicTarget(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	target := redactDynamicErr{value: []string{"fixture"}}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{name: "no match", want: false},
		{name: "custom match", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			node := redactDynamicErr{value: target.value, matches: tc.want}
			sentinel := errors.New("fixture sentinel")
			hidden := hiddenRedacted(t, key, fmt.Errorf("fixture %s: %w", key, errors.Join(sentinel, node)))
			if got := errors.Is(hidden, target); got != tc.want {
				t.Errorf("errors.Is with dynamically uncomparable target = %v; want %v", got, tc.want)
			}
			if !errors.Is(hidden, sentinel) {
				t.Error("errors.Is did not match a pointer sentinel")
			}
		})
	}
}

// redactIsNode is a tree node that answers errors.Is through its own Is method, for one sentinel it does not equal.
type redactIsNode struct {
	text    string
	matches error
}

// Error returns the fixture text.
func (n redactIsNode) Error() string { return n.text }

// Is reports whether target is the one sentinel this node stands for.
func (n redactIsNode) Is(target error) bool { return target == n.matches }

// TestRedactedErrorIsNodeMethod checks that errors.Is reaches a node that matches only through its own Is method, two wraps deep.
func TestRedactedErrorIsNodeMethod(t *testing.T) {
	t.Parallel()
	const key = "node-key"
	matched := errors.New("fixture matched sentinel")
	other := errors.New("fixture other sentinel")
	node := redactIsNode{text: "node " + key, matches: matched}
	tree := fmt.Errorf("a %s: %w", key, fmt.Errorf("b: %w", node))
	hidden := hiddenRedacted(t, key, tree)
	if !errors.Is(hidden, matched) {
		t.Error("errors.Is through the node's Is method = false; want true")
	}
	if errors.Is(hidden, other) {
		t.Error("errors.Is with a sentinel the node does not report = true; want false")
	}
}

type redactForwardingIs struct {
	cause, matches error
	calls          atomic.Int32
}

// Error returns fixed fixture text.
func (*redactForwardingIs) Error() string { return "fixture forwarding Is" }

// Unwrap returns the fixture's cause.
func (e *redactForwardingIs) Unwrap() error { return e.cause }

// Is compares directly when configured and otherwise forwards at most three times.
func (e *redactForwardingIs) Is(target error) bool {
	calls := e.calls.Add(1)
	if e.matches != nil {
		return target == e.matches
	}
	return calls <= 3 && !isNilError(e.cause) && errors.Is(e.Unwrap(), target)
}

// TestRedactedErrorIsChecksCustomSubtree checks the boundary, unsafe tree, and direct match cases.
func TestRedactedErrorIsChecksCustomSubtree(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name      string
		cause     func(*redactedError, *redactCountingBoundary) error
		wantMatch bool
		wantCalls int32
	}{
		{"cycle", func(root *redactedError, _ *redactCountingBoundary) error { return root }, false, 0},
		{"sibling", func(_ *redactedError, foreign *redactCountingBoundary) error { return foreign }, false, 0},
		{"unsafe", func(*redactedError, *redactCountingBoundary) error { return (*net.DNSError)(nil) }, false, 0},
		{"safe direct match", func(*redactedError, *redactCountingBoundary) error {
			return errors.New("fixture child")
		}, true, 1},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			target := errors.New("fixture target")
			node := &redactForwardingIs{}
			root := &redactedError{key: "maple", err: node}
			foreign := &redactCountingBoundary{sentinel: target}
			node.cause = tc.cause(root, foreign)
			if tc.wantMatch {
				node.matches = target
			}
			assertCustomIs(subtest, root, target, node, tc.wantMatch, tc.wantCalls)
			if foreign.calls.match != 0 {
				subtest.Errorf("foreign Is called %d times; want 0", foreign.calls.match)
			}
		})
	}
}

// assertCustomIs checks the match and the custom method's call count.
func assertCustomIs(t *testing.T, root, target error, node *redactForwardingIs, wantMatch bool, wantCalls int32) {
	t.Helper()
	if got := errors.Is(root, target); got != wantMatch {
		t.Errorf("errors.Is = %t; want %t", got, wantMatch)
	}
	if calls := node.calls.Load(); calls != wantCalls {
		t.Errorf("custom Is called %d times; want %d", calls, wantCalls)
	}
}

// TestRedactedErrorIsStdlibDeadline checks identity through a URL error.
func TestRedactedErrorIsStdlibDeadline(t *testing.T) {
	t.Parallel()
	cause := &url.Error{Op: "Get", URL: "http://h", Err: context.DeadlineExceeded}
	root := &redactedError{key: "maple", err: cause}
	if !errors.Is(root, context.DeadlineExceeded) {
		t.Error("errors.Is missed the deadline cause")
	}
}

type redactIsLink struct{ cause error }

// Error returns fixed fixture text.
func (redactIsLink) Error() string { return "fixture link" }

// Unwrap returns the next link.
func (e redactIsLink) Unwrap() error { return e.cause }

// wrapIsFixture adds the specified number of single links above the target.
func wrapIsFixture(target error, links int) error {
	for range links {
		target = redactIsLink{cause: target}
	}
	return target
}

// TestRedactedErrorIsCustomPrecheckFloor checks the last allowed custom call and the first disallowed call.
func TestRedactedErrorIsCustomPrecheckFloor(t *testing.T) {
	t.Parallel()
	// Why: the links and the custom node each cost one step before reserving maxInspectionReads.
	const links = maxWalkSteps - maxInspectionReads - 1
	for _, tc := range [...]struct {
		name      string
		links     int
		wantMatch bool
		wantCalls int32
	}{
		{"at floor", links, true, 1},
		{"below floor", links + 1, false, 0},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			target := errors.New("fixture target")
			node := &redactForwardingIs{matches: target}
			root := &redactedError{key: "maple", err: wrapIsFixture(node, tc.links)}
			assertCustomIs(subtest, root, target, node, tc.wantMatch, tc.wantCalls)
		})
	}
}

// TestRedactedErrorIsChargesObservedValues checks dropped values and synthetic slots at the next pre-check floor.
func TestRedactedErrorIsChargesObservedValues(t *testing.T) {
	t.Parallel()
	// Why: the first custom node and the join occupy two slots before the join clips its children.
	typedNil := make(redactWideJoin, maxErrNodes-1)
	typedNil[0] = (*net.DNSError)(nil)
	typedNil[maxErrNodes-3] = (*net.DNSError)(nil)
	for _, tc := range [...]struct {
		name          string
		cause         error
		reads, visits int
	}{
		{"overflowing chain", wrapIsFixture(errors.New("fixture tail"), maxErrNodes-1), maxInspectionReads, maxErrNodes},
		{"clipped join with typed nils", typedNil, 4, 1},
		{"clipped join with plain nils", make(redactWideJoin, maxErrNodes-1), 2, 1},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			// Why: the outer join and both custom nodes each cost one visit, separately from the first pre-check.
			links := maxWalkSteps - maxInspectionReads - 3 - tc.reads - tc.visits
			assertNextCustomIsFloor(subtest, tc.cause, links, true, 1)
			assertNextCustomIsFloor(subtest, tc.cause, links+1, false, 0)
		})
	}
}

// assertNextCustomIsFloor checks whether the second custom method can run after an unsafe pre-check.
func assertNextCustomIsFloor(t *testing.T, cause error, links int, wantMatch bool, wantCalls int32) {
	t.Helper()
	target := errors.New("fixture target")
	first := &redactForwardingIs{cause: cause, matches: target}
	next := &redactForwardingIs{matches: target}
	root := &redactedError{key: "maple", err: errors.Join(wrapIsFixture(first, links), next)}
	assertCustomIs(t, root, target, next, wantMatch, wantCalls)
	if calls := first.calls.Load(); calls != 0 {
		t.Errorf("unsafe custom Is called %d times; want 0", calls)
	}
}

// TestRedactedErrorIsChargesCustomPrecheck checks that prechecking a custom Is spends walk steps.
func TestRedactedErrorIsChargesCustomPrecheck(t *testing.T) {
	t.Parallel()
	// Why: 65 minus 33 reads leaves 32 visits, and one fewer lead link offsets the extra read in the longer row.
	const descendants = (maxInspectionReads - 1) / 2
	const links = maxWalkSteps - maxInspectionReads - 1
	for _, tc := range [...]struct {
		name               string
		descendants, links int
		want               bool
	}{
		{"target at last visit", descendants, links, true},
		{"target one visit too far", descendants + 1, links - 1, false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			target := errors.New("fixture target")
			node := &redactForwardingIs{
				cause:   wrapIsFixture(target, tc.descendants-1),
				matches: errors.New("fixture other target"),
			}
			root := &redactedError{key: "maple", err: wrapIsFixture(node, tc.links)}
			assertCustomIs(subtest, root, target, node, tc.want, 1)
		})
	}
}

// TestRedactErrorRootPathRedaction checks literal and percent-encoded keys in a URL error's path.
func TestRedactErrorRootPathRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	escapedKey := strings.Replace(key, "-", fmt.Sprintf("%%%02X", '-'), 1)
	for _, tc := range []struct{ name, path, wantURL, wantError string }{
		{"literal", key, "http://h/REDACTED", `Get "http://h/REDACTED": fixture transport failure`},
		{"percent encoded", escapedKey, "REDACTED", `Get "REDACTED": fixture transport failure`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{apiKey: key}
			original := &url.Error{
				Op:  "Get",
				URL: "http://h/" + tc.path,
				Err: errors.New("fixture transport failure"),
			}
			got := c.redactError(original)
			var copied *url.Error
			if !errors.As(got, &copied) || copied == nil || copied == original {
				t.Fatal("expected a sanitized URL error copy")
			}
			if copied.URL != tc.wantURL {
				t.Errorf("copied URL = %q; want %q", copied.URL, tc.wantURL)
			}
			if got.Error() != tc.wantError {
				t.Errorf("Error() = %q; want %q", got.Error(), tc.wantError)
			}
		})
	}
}

// TestRedactErrorTypedNilTree checks that trees holding a typed-nil error return the fixed message without panicking.
func TestRedactErrorTypedNilTree(t *testing.T) {
	t.Parallel()
	c := &Client{apiKey: "plain-key"}
	tree := errors.Join((*url.Error)(nil), errors.New("boom"))
	cases := []struct {
		name string
		call func(error) error
	}{
		{name: "redactError", call: c.redactError},
		{name: "scrubError", call: c.scrubError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			for _, input := range []error{tree, (*url.Error)(nil)} {
				got := tc.call(input)
				if got == nil {
					t.Fatalf("%s(%v) = nil; want non-nil", tc.name, input)
				}
				if got.Error() != redactedTreeMsg {
					t.Errorf("%s(%v).Error() = %q; want %q", tc.name, input, got.Error(), redactedTreeMsg)
				}
			}
		})
	}
}

// TestRedactedErrorTypedNilWalk checks that Is, As, Timeout, and Temporary skip a typed-nil node without panicking.
func TestRedactedErrorTypedNilWalk(t *testing.T) {
	t.Parallel()
	c := &Client{apiKey: "plain-key"}
	tree := &redactCycleErr{text: "outer", next: errors.Join((*url.Error)(nil))}
	got := c.redactError(tree)
	if errors.Is(got, errors.New("unrelated")) {
		t.Error("errors.Is = true; want false")
	}
	var uerr *url.Error
	if errors.As(got, &uerr) || uerr != nil {
		t.Errorf("errors.As = true or non-nil (%v); want false and nil", uerr)
	}
	if got.(interface{ Timeout() bool }).Timeout() { //nolint:forcetypeassert // wrapper method set under test
		t.Error("Timeout() = true; want false")
	}
	if got.(interface{ Temporary() bool }).Temporary() { //nolint:forcetypeassert // wrapper method set under test
		t.Error("Temporary() = true; want false")
	}
}

// TestIsNilError checks nil detection across untyped nil, typed-nil values, non-nil pointers, and value errors.
func TestIsNilError(t *testing.T) {
	t.Parallel()
	c := &Client{apiKey: "fixture-nil-key"}
	var typedNil *url.Error
	var sliceNil redactSliceErr
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{name: "nil", err: nil, want: true},
		{name: "typed-nil pointer", err: typedNil, want: true},
		{name: "typed-nil slice", err: sliceNil, want: true},
		{name: "non-nil pointer", err: &url.Error{Op: "Get", URL: "http://h/", Err: errors.New("x")}, want: false},
		{name: "value type", err: redactIsNode{text: "v"}, want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := isNilError(tc.err); got != tc.want {
				t.Errorf("isNilError(%T) = %v; want %v", tc.err, got, tc.want)
			}
			assertNilScrubResult(t, c.scrubError(tc.err), tc.err, tc.want)
		})
	}
}

// assertNilScrubResult checks whether scrubError preserved the input or hid a typed-nil error.
func assertNilScrubResult(t *testing.T, got, input error, wantNil bool) {
	t.Helper()
	if input == nil || !wantNil {
		if got != input { //nolint:errorlint // require the exact input to pass through
			t.Errorf("scrubError(%T) did not preserve the input", input)
		}
		return
	}
	hidden, ok := got.(*redactedError) //nolint:errorlint // typed nil must return the concrete safe wrapper
	if !ok || hidden == nil || hidden.Error() != redactedTreeMsg {
		t.Errorf("scrubError(%T) did not return the fixed redaction message", input)
	}
}

// redactClassifier answers both classification methods.
type redactClassifier struct{}

// Timeout reports a timeout.
func (redactClassifier) Timeout() bool { return true }

// Temporary reports a temporary error.
func (redactClassifier) Temporary() bool { return true }

// redactAsClassifier records calls that request a classifier through As.
type redactAsClassifier struct {
	classifier interface {
		Timeout() bool
		Temporary() bool
	}
	cause error
	calls int
}

// Error returns the fixture error text.
func (*redactAsClassifier) Error() string { return "fixture classifier" }

// Unwrap returns the fixture's visible cause.
func (e *redactAsClassifier) Unwrap() error { return e.cause }

// As supplies the fixed classifier for either classification method.
func (e *redactAsClassifier) As(target any) bool {
	e.calls++
	switch dst := target.(type) {
	case *interface{ Timeout() bool }:
		*dst = e.classifier
		return true
	case *interface{ Temporary() bool }:
		*dst = e.classifier
		return true
	default:
		return false
	}
}

// redactNonErrorClassifier delegates to a wrapper without implementing error.
type redactNonErrorClassifier struct{ cause *redactedError }

// Unwrap returns the package wrapper.
func (c redactNonErrorClassifier) Unwrap() error { return c.cause }

// Timeout reports the package wrapper's timeout classification.
func (c redactNonErrorClassifier) Timeout() bool { return c.cause.Timeout() }

// Temporary reports the package wrapper's temporary classification.
func (c redactNonErrorClassifier) Temporary() bool { return c.cause.Temporary() }

// TestRedactedErrorClassifiers checks custom As and URL errors with nil and non-nil causes.
func TestRedactedErrorClassifiers(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	cases := []struct {
		name  string
		cause error
		want  bool
	}{
		{"custom As skipped", &redactAsClassifier{classifier: redactClassifier{}}, false},
		{"typed nil URL cause", &url.Error{Op: "Get", URL: "http://h/", Err: (*net.DNSError)(nil)}, false},
		{"URL cause", &url.Error{Op: "Get", URL: "http://h/", Err: &net.DNSError{IsTimeout: true, IsTemporary: true}}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := hiddenRedacted(t, key, errors.Join(errors.New(key), tc.cause))
			if value := got.(interface{ Timeout() bool }).Timeout(); value != tc.want { //nolint:forcetypeassert // wrapper method under test
				t.Errorf("Timeout() = %v; want %v", value, tc.want)
			}
			if value := got.(interface{ Temporary() bool }).Temporary(); value != tc.want { //nolint:forcetypeassert // wrapper method under test
				t.Errorf("Temporary() = %v; want %v", value, tc.want)
			}
		})
	}
}

// TestRedactedErrorTimeoutTemporaryURLOrder checks that the first classifier decides both answers.
func TestRedactedErrorTimeoutTemporaryURLOrder(t *testing.T) {
	t.Parallel()
	nonTimeout := &url.Error{Err: errors.New("fixture failure")}
	timeout := &net.DNSError{IsTimeout: true, IsTemporary: true}
	cases := []struct {
		name string
		tree error
		want bool
	}{
		{"URL error first", errors.Join(nonTimeout, timeout), false},
		{"timeout first", errors.Join(timeout, nonTimeout), true},
		{"URL error with nil cause", errors.Join(&url.Error{}, timeout), false},
		{"URL error with typed-nil cause", errors.Join(&url.Error{Err: (*net.DNSError)(nil)}, timeout), false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := &redactedError{err: tc.tree}
			if value := got.Timeout(); value != tc.want {
				t.Errorf("Timeout() = %v; want %v", value, tc.want)
			}
			if value := got.Temporary(); value != tc.want {
				t.Errorf("Temporary() = %v; want %v", value, tc.want)
			}
		})
	}
}

// TestRedactedErrorURLImmediateCause checks classification of the direct cause of a nested URL error.
func TestRedactedErrorURLImmediateCause(t *testing.T) {
	t.Parallel()
	timeout := &net.DNSError{IsTimeout: true, IsTemporary: true}
	cases := []struct {
		name  string
		cause error
		want  bool
	}{
		{"ordinary wrapper", fmt.Errorf("fixture: %w", timeout), false},
		{"custom As skipped", &redactAsClassifier{classifier: redactClassifier{}}, false},
		{"direct DNS error", timeout, true},
		{"redacted cause", &redactedError{err: timeout}, true},
		{"URL cause", &url.Error{Err: timeout}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			tree := errors.Join(errors.New("other failure"), &url.Error{Err: tc.cause}, timeout)
			got := &redactedError{err: tree}
			if value := got.Timeout(); value != tc.want {
				t.Errorf("Timeout() = %v; want %v", value, tc.want)
			}
			if value := got.Temporary(); value != tc.want {
				t.Errorf("Temporary() = %v; want %v", value, tc.want)
			}
		})
	}
}

// redactCountingError counts Is calls made while walking a fixture tree.
type redactCountingError struct{ calls int }

// Error returns the fixture error text.
func (*redactCountingError) Error() string { return "fixture counting error" }

// Is counts the visit and leaves the search running.
func (e *redactCountingError) Is(error) bool {
	e.calls++
	return false
}

// TestRedactedErrorWalkNestedBudget verifies that nested wrappers share the outer walk budget.
func TestRedactedErrorWalkNestedBudget(t *testing.T) {
	t.Parallel()
	counted := &redactCountingError{}
	children := make([]error, maxWalkSteps+1)
	for i := range children {
		children[i] = counted
	}
	var tree error = counted
	for range 4 {
		children[0] = tree
		tree = &redactedError{err: errors.Join(children...)}
	}
	if errors.Is(tree, errors.New("fixture absent target")) {
		t.Error("errors.Is matched an absent target")
	}
	if counted.calls == 0 || counted.calls > maxWalkSteps {
		t.Errorf("counted %d Is calls; want 1 through %d", counted.calls, maxWalkSteps)
	}
}

// redactWideJoin exposes a fixed child slice without formatting its children.
type redactWideJoin []error

// Error returns the fixture error text.
func (redactWideJoin) Error() string { return "fixture wide join" }

// Unwrap returns the fixture children, which may include nil slots.
func (e redactWideJoin) Unwrap() []error { return e }

// appendWrapped exposes the bounded queue to existing traversal tests.
func appendWrapped(queue []error, err error) []error {
	queue, _, _ = appendWrappedChildren(queue, err)
	return queue
}

// TestRedactedErrorWalkWideJoin checks dense and sparse joins with a target beyond the budget.
func TestRedactedErrorWalkWideJoin(t *testing.T) {
	t.Parallel()
	target := errors.New("fixture target beyond budget")
	dense := make(redactWideJoin, 1<<16)
	child := errors.New("fixture child")
	for i := range dense {
		dense[i] = child
	}
	dense[len(dense)-1] = target
	sparse := make(redactWideJoin, len(dense))
	sparse[len(sparse)-1] = target
	assertWideJoinBudget(t, dense, target)
	assertWideJoinBudget(t, sparse, target)
}

// assertWideJoinBudget checks that structural and forwarding walks leave the tail unread.
func assertWideJoinBudget(t *testing.T, tree redactWideJoin, target error) {
	t.Helper()
	children, clipped := walkChildren(tree, tree, maxWalkSteps)
	if len(children) > maxWalkSteps || !clipped {
		t.Errorf("walkChildren returned %d children, clipped %v; budget %d", len(children), clipped, maxWalkSteps)
	}
	queue := appendWrapped([]error{tree}, tree)
	if len(queue) > maxErrNodes+1 {
		t.Errorf("appendWrapped returned %d nodes; budget %d plus overflow", len(queue), maxErrNodes)
	}
	if slices.Contains(queue[1:], target) {
		t.Error("appendWrapped read the child beyond the budget")
	}
	got := (&Client{}).scrubError(tree)
	if got.Error() != redactedTreeMsg {
		t.Errorf("scrubError = %q; want %q", got.Error(), redactedTreeMsg)
	}
	if errors.Is(&redactedError{err: tree}, target) {
		t.Error("errors.Is matched the target beyond the budget")
	}
}

// TestRedactedErrorWalkQueueOverflow checks a full structural queue followed by a single unwrap.
func TestRedactedErrorWalkQueueOverflow(t *testing.T) {
	t.Parallel()
	leaf := errors.New("fixture leaf")
	children := make([]error, maxErrNodes-1)
	for i := range children {
		children[i] = leaf
	}
	children[0] = fmt.Errorf("fixture single wrapper: %w", leaf)
	children[1] = errors.Join(leaf)
	got := (&Client{}).scrubError(errors.Join(children...))
	if got.Error() != redactedTreeMsg {
		t.Errorf("scrubError = %q; want %q", got.Error(), redactedTreeMsg)
	}
}

// rootURLFieldError keeps fixture data in a field separate from its message.
type rootURLFieldError struct{ Key string }

// Error returns a message independent of the fixture data.
func (*rootURLFieldError) Error() string { return "fixture transport failure" }

// TestRedactErrorRootURLHidesCause checks that a copied URL error exposes only an opaque cause.
func TestRedactErrorRootURLHidesCause(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	cause := &rootURLFieldError{Key: key}
	root := &url.Error{Op: "Get", URL: "http://h/?apikey=" + key, Err: cause}
	c := &Client{apiKey: key}

	err := c.redactError(root)
	var copied *url.Error
	if !errors.As(err, &copied) || any(err) != any(copied) || copied == root {
		t.Fatal("redactError did not return a sanitized root URL error copy")
	}
	var leaked *rootURLFieldError
	if errors.As(err, &leaked) {
		t.Error("errors.As exposed the original cause type")
	}
	if !errors.Is(err, cause) {
		t.Error("errors.Is did not match the hidden cause")
	}
}

// TestRedactErrorRootURLNilCause checks that a nil interface cause is preserved in a URL error copy.
func TestRedactErrorRootURLNilCause(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	root := &url.Error{Op: "Get", URL: "http://h/?apikey=" + key}
	var copied *url.Error
	if !errors.As((&Client{apiKey: key}).redactError(root), &copied) || copied == root {
		t.Fatal("redactError did not return a sanitized URL error copy")
	}
	if copied.Err != nil {
		t.Errorf("copied cause = %T; want nil", copied.Err)
	}
}

type redactObservedSingle struct {
	first, later error
	calls        atomic.Int32
}

// Error returns fixed fixture text.
func (*redactObservedSingle) Error() string { return "fixture observed cause" }

// Unwrap returns the first cause once and the later cause thereafter.
func (e *redactObservedSingle) Unwrap() error {
	if e.calls.Add(1) == 1 {
		return e.first
	}
	return e.later
}

type redactObservedRootCause struct {
	redactObservedSingle
	redactClassifier
}

// TestRedactErrorRootURLUsesFirstCauseRead checks copy classification and identity from one inspection.
func TestRedactErrorRootURLUsesFirstCauseRead(t *testing.T) {
	t.Parallel()
	const cleanURL = "http://h/feed"
	client := &Client{apiKey: "maple"}
	safeChild := errors.New("fixture safe child")
	for _, tc := range [...]struct {
		name, url string
		first     error
		unsafe    bool
		unchanged bool
	}{
		{"unsafe first read", cleanURL, (*net.DNSError)(nil), true, false},
		{"safe with changed URL", cleanURL + "?apikey=maple", safeChild, false, false},
		{"safe with clean URL", cleanURL, safeChild, false, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			cause := &redactObservedRootCause{
				redactObservedSingle: redactObservedSingle{first: tc.first, later: safeChild},
			}
			input := &url.Error{Op: "Get", URL: tc.url, Err: cause}
			got := client.redactError(input)
			if calls := cause.calls.Load(); calls != 1 {
				subtest.Errorf("root copy read Unwrap %d times; want 1", calls)
			}
			if input.Op != "Get" || input.URL != tc.url || input.Err != cause { //nolint:errorlint // the original must retain its exact cause
				subtest.Error("redactError changed the input")
			}
			assertObservedRootURL(subtest, got, input, tc.unchanged, tc.unsafe)
		})
	}
}

type redactRootCauseLink struct {
	text  string
	next  error
	calls *int
}

// Error counts calls and returns the link's fixture text.
func (e *redactRootCauseLink) Error() string {
	*e.calls++
	return e.text
}

// Unwrap returns the next link.
func (e *redactRootCauseLink) Unwrap() error { return e.next }

type redactReplacingRootCause struct {
	parent      *url.Error
	replacement error
	onRootText  bool
	textReads   int
}

// Error returns the inspected cause's text.
func (e *redactReplacingRootCause) Error() string {
	e.textReads++
	if e.onRootText && e.textReads == 2 {
		e.replace()
	}
	return "fixture inspected cause"
}

// Unwrap replaces the parent's cause on its first call when configured for structural inspection.
func (e *redactReplacingRootCause) Unwrap() error {
	if !e.onRootText {
		e.replace()
	}
	return nil
}

// replace swaps the parent's cause once.
func (e *redactReplacingRootCause) replace() {
	if e.parent != nil {
		e.parent.Err = e.replacement
		e.parent = nil
	}
}

// TestRedactErrorRootURLReplacedCause checks that replacement text is never read.
func TestRedactErrorRootURLReplacedCause(t *testing.T) {
	t.Parallel()
	const cleanURL = "http://h/feed"
	client := &Client{apiKey: "maple"}
	for _, tc := range [...]struct {
		name, url  string
		onRootText bool
	}{
		{"changed URL", cleanURL + "?apikey=maple", false},
		{"clean URL", cleanURL, false},
		{"clean URL replaced in root text", cleanURL, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			calls := 0
			replacement := &redactRootCauseLink{text: "fixture maple replacement", calls: &calls}
			input := &url.Error{Op: "Get", URL: tc.url}
			input.Err = &redactReplacingRootCause{parent: input, replacement: replacement, onRootText: tc.onRootText}
			got := client.redactError(input)
			if any(input.Err) != any(replacement) {
				subtest.Error("fixture did not replace the root URL cause")
			}
			if tc.url == cleanURL {
				assertFixedRootURL(subtest, got)
			} else {
				assertReplacedRootURLCopy(subtest, got, input, cleanURL+"?apikey=REDACTED")
			}
			if calls != 0 {
				subtest.Errorf("replacement Error called %d times; want 0", calls)
			}
		})
	}
}

type redactChangingRootFields struct {
	parent     *url.Error
	change     func(*url.Error)
	onRootText bool
	textReads  int
}

// Error changes the parent fields during the root text check when configured.
func (e *redactChangingRootFields) Error() string {
	e.textReads++
	if e.onRootText && e.textReads == 2 {
		e.applyChange()
	}
	return "fixture inspected cause"
}

// Unwrap changes the parent fields during structural inspection when configured.
func (e *redactChangingRootFields) Unwrap() error {
	if !e.onRootText {
		e.applyChange()
	}
	return nil
}

// applyChange updates the parent fields once.
func (e *redactChangingRootFields) applyChange() {
	if e.parent != nil {
		e.change(e.parent)
		e.parent = nil
	}
}

// TestRedactErrorRootURLChangedFields checks both callback stages and an unchanged control.
func TestRedactErrorRootURLChangedFields(t *testing.T) {
	t.Parallel()
	const cleanOp, cleanURL = "Get", "http://h/feed"
	changeURL := func(parent *url.Error) { parent.URL = cleanURL + "?apikey=maple" }
	changeOp := func(parent *url.Error) { parent.Op = cleanOp + " maple" }
	keepFields := func(parent *url.Error) { parent.Op, parent.URL = cleanOp, cleanURL }
	client := &Client{apiKey: "maple"}
	for _, tc := range [...]struct {
		name       string
		change     func(*url.Error)
		onRootText bool
		keep       bool
	}{
		{"URL during inspection", changeURL, false, false},
		{"URL during root text", changeURL, true, false},
		{"Op during inspection", changeOp, false, false},
		{"Op during root text", changeOp, true, false},
		{"unchanged fields", keepFields, true, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			input := &url.Error{Op: cleanOp, URL: cleanURL}
			cause := &redactChangingRootFields{parent: input, change: tc.change, onRootText: tc.onRootText}
			input.Err = cause
			got := client.redactError(input)
			if cause.parent != nil || cause.textReads != 2 {
				subtest.Errorf("change applied = %t, cause text reads = %d; want true, 2", cause.parent == nil, cause.textReads)
			}
			assertChangedRootURL(subtest, got, input, tc.keep)
		})
	}
}

type redactNestedFieldWriter struct {
	parent  *url.Error
	detail  *redactNestedDetailError
	at      int
	reads   int
	writeOp bool
	wrote   bool
}

// Error writes the fixture key once at the requested call and returns clean text.
func (e *redactNestedFieldWriter) Error() string {
	e.reads++
	if e.reads == e.at {
		switch {
		case e.detail != nil:
			e.detail.Detail = "maple"
		case e.writeOp:
			e.parent.Op = "Get maple"
		default:
			e.parent.URL += "?apikey=maple"
		}
		e.wrote = true
		e.parent, e.detail = nil, nil
	}
	return "clean cause"
}

type redactNestedDetailError struct {
	Detail string
	cause  error
}

// Error delegates to the cause without reading Detail.
func (e *redactNestedDetailError) Error() string { return e.cause.Error() }

// Unwrap returns the cause that can update Detail.
func (e *redactNestedDetailError) Unwrap() error { return e.cause }

type redactCountedCheckNode struct {
	next                   error
	textReads, unwrapReads int
}

// Error counts the text reads and returns fixed text.
func (e *redactCountedCheckNode) Error() string {
	e.textReads++
	return "read failed"
}

// Unwrap counts the structural reads and returns the next node.
func (e *redactCountedCheckNode) Unwrap() error {
	e.unwrapReads++
	return e.next
}

const nestedFieldFixtureURL = "http://h/feed"

type nestedFieldChangeCase struct {
	field                    string
	setupCalls, checkCalls   int
	wantUnchanged, wantWrite nestedFieldURLFields
}

type nestedFieldURLFields struct{ op, url string }

type nestedFieldWritePhase string

const (
	nestedFieldWriteSetup nestedFieldWritePhase = "setup"
	nestedFieldWriteCheck nestedFieldWritePhase = "check"
	nestedFieldNoWrite    nestedFieldWritePhase = "none"
)

// expectedAt uses the call counts measured with the writer unfired.
func (tc nestedFieldChangeCase) expectedAt(at int) (nestedFieldWritePhase, nestedFieldURLFields) {
	switch {
	case at <= tc.setupCalls:
		return nestedFieldWriteSetup, tc.wantWrite
	case at <= tc.setupCalls+tc.checkCalls:
		return nestedFieldWriteCheck, tc.wantWrite
	default:
		return nestedFieldNoWrite, tc.wantUnchanged
	}
}

// TestRedactErrorNestedFieldChangedDuringCheck checks setup writes, inspection writes, and unfired controls.
func TestRedactErrorNestedFieldChangedDuringCheck(t *testing.T) {
	t.Parallel()
	cleanNested := nestedFieldURLFields{"Get", nestedFieldFixtureURL}
	redactedURL := nestedFieldURLFields{"Get", "http://h/feed?apikey=REDACTED"}
	redactedOp := nestedFieldURLFields{"Get REDACTED", nestedFieldFixtureURL}
	outer := nestedFieldURLFields{"Get", "http://h/outer"}
	noURL := nestedFieldURLFields{}
	for _, wrapper := range [...]struct {
		name   string
		wrap   func(error) error
		fields [3]nestedFieldChangeCase
	}{
		{
			"quiet",
			func(nested error) error { return &redactCountedCheckNode{next: nested} },
			[3]nestedFieldChangeCase{
				{"URL", 0, 2, cleanNested, redactedURL},
				{"Op", 0, 2, cleanNested, redactedOp},
				{"Detail", 0, 2, noURL, noURL},
			},
		},
		{
			"errorf",
			func(nested error) error { return fmt.Errorf("read response: %w", nested) },
			[3]nestedFieldChangeCase{
				{"URL", 1, 2, cleanNested, redactedURL},
				{"Op", 1, 2, cleanNested, redactedOp},
				{"Detail", 1, 2, noURL, noURL},
			},
		},
		{
			"root",
			func(nested error) error {
				return &url.Error{Op: "Get", URL: "http://h/outer", Err: fmt.Errorf("x: %w", nested)}
			},
			[3]nestedFieldChangeCase{
				{"URL", 1, 2, outer, outer},
				{"Op", 1, 2, outer, outer},
				{"Detail", 1, 2, outer, outer},
			},
		},
		{
			"root live cause",
			func(nested error) error { return &url.Error{Op: "Get", URL: "http://h/outer", Err: nested} },
			[3]nestedFieldChangeCase{
				{"URL", 0, 3, outer, outer},
				{"Op", 0, 3, outer, outer},
				{"Detail", 0, 3, outer, outer},
			},
		},
	} {
		for _, tc := range wrapper.fields {
			t.Run(wrapper.name+"/"+tc.field, func(subtest *testing.T) {
				subtest.Parallel()
				testNestedFieldChangeCalls(subtest, tc, wrapper.wrap)
			})
		}
	}
}

// testNestedFieldChangeCalls tries each call at which the writer might fire.
func testNestedFieldChangeCalls(t *testing.T, tc nestedFieldChangeCase, wrap func(error) error) {
	t.Helper()
	for at := 1; at <= 5; at++ {
		t.Run("at="+strconv.Itoa(at), func(subtest *testing.T) {
			subtest.Parallel()
			phase, wantFields := tc.expectedAt(at)
			writer := &redactNestedFieldWriter{at: at, writeOp: tc.field == "Op"}
			var nested error
			if tc.field == "Detail" {
				writer.detail = &redactNestedDetailError{Detail: "clean detail", cause: writer}
				nested = writer.detail
			} else {
				writer.parent = &url.Error{Op: "Get", URL: nestedFieldFixtureURL, Err: writer}
				nested = writer.parent
			}
			input := wrap(nested)
			setupReads, setupWrote := writer.reads, writer.wrote
			if setupReads != tc.setupCalls || setupWrote != (phase == nestedFieldWriteSetup) {
				subtest.Fatalf("after setup: reads = %d, wrote = %t; want %d, %t (phase %s)",
					setupReads, setupWrote, tc.setupCalls, phase == nestedFieldWriteSetup, phase)
			}
			got := answerWithinTwoSeconds(subtest, "redactError", func() error {
				return (&Client{apiKey: "maple"}).redactError(input)
			})
			redactReads, redactWrote := writer.reads, writer.wrote
			if redactWrote != (phase != nestedFieldNoWrite) {
				subtest.Fatalf("after redactError: wrote = %t after %d total reads; want %t (phase %s)",
					redactWrote, redactReads, phase != nestedFieldNoWrite, phase)
			}
			assertNestedFieldChange(subtest, input, got, phase, wantFields)
		})
	}
}

// assertNestedFieldChange checks identity, URL recovery, and all three formatting forms.
func assertNestedFieldChange(t *testing.T, input, got error, phase nestedFieldWritePhase, wantFields nestedFieldURLFields) {
	t.Helper()
	wrote := phase != nestedFieldNoWrite
	if wrote && got == nil {
		t.Fatalf("redactError returned nil after a write in phase %s", phase)
	}
	kept := got == input //nolint:errorlint // compare fixture pointer identities
	if kept == wrote {
		t.Errorf("redactError kept input = %t in phase %s; want %t", kept, phase, !wrote)
	}
	assertNestedFieldURL(t, got, wantFields)
	if !wrote {
		return
	}
	for index, text := range [...]string{fmt.Sprint(got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got)} {
		if strings.Contains(text, "maple") {
			t.Errorf("format %d exposed the fixture key", index)
		}
	}
}

// assertNestedFieldURL checks the expected URL match and its exact fields.
func assertNestedFieldURL(t *testing.T, got error, wantFields nestedFieldURLFields) {
	t.Helper()
	var recovered *url.Error
	wantURL := wantFields.url != ""
	if matched := errors.As(got, &recovered); matched != wantURL {
		t.Fatalf("errors.As URL match = %t; want %t", matched, wantURL)
	}
	if !wantURL {
		return
	}
	if recovered == nil {
		t.Fatal("errors.As matched a nil URL error")
	}
	if recovered.Op != wantFields.op || recovered.URL != wantFields.url {
		t.Errorf("errors.As recovered Op %q and URL %q; want Op %q and URL %q",
			recovered.Op, recovered.URL, wantFields.op, wantFields.url)
	}
}

// assertChangedRootURL checks the fixed message and formatting, or exact identity for the control.
func assertChangedRootURL(t *testing.T, got error, input *url.Error, keep bool) {
	t.Helper()
	if keep {
		if any(got) != input {
			t.Error("redactError changed identity after assigning identical fields")
		}
		return
	}
	assertFixedRootURL(t, got)
	for index, text := range [...]string{fmt.Sprint(got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got)} {
		if strings.Contains(text, "maple") {
			t.Errorf("format %d exposed the fixture key", index)
		}
	}
}

// TestURLErrorFieldSet pins the fields inspected before retaining a URL error.
func TestURLErrorFieldSet(t *testing.T) {
	t.Parallel()
	typ := reflect.TypeFor[url.Error]()
	fields := [...]string{"Op", "URL", "Err"}
	if typ.NumField() != len(fields) {
		t.Fatalf("url.Error has %d fields; want %d", typ.NumField(), len(fields))
	}
	for index, name := range fields {
		if field := typ.Field(index); field.Name != name {
			t.Errorf("url.Error field %d = %s; want %s", index, field.Name, name)
		}
	}
}

// assertReplacedRootURLCopy checks the copied URL and the text of its inspected cause.
func assertReplacedRootURLCopy(t *testing.T, got error, input *url.Error, wantURL string) {
	t.Helper()
	copied, ok := got.(*url.Error) //nolint:errorlint // require the direct URL copy
	if !ok || copied == input || copied.URL != wantURL {
		t.Fatalf("redactError returned %T; want a sanitized URL copy", got)
	}
	if copied.Err == nil || copied.Err.Error() != "fixture inspected cause" {
		t.Errorf("copied cause = %v; want the inspected cause's text", copied.Err)
	}
}

// TestRedactErrorRootURLUncomparableCause checks clean roots whose cause cannot be compared safely.
func TestRedactErrorRootURLUncomparableCause(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name  string
		cause error
	}{
		{"non-comparable type", redactSliceErr{"fixture"}},
		{"non-comparable field", redactDynamicErr{value: []string{"fixture"}}},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			client := &Client{apiKey: "maple"}
			assertFixedRootURL(subtest, client.redactError(&url.Error{Op: "Get", URL: "http://h/feed", Err: tc.cause}))
		})
	}
}

// TestRedactErrorCleanRootURLNodeLimit checks the root's slot in the structural budget.
func TestRedactErrorCleanRootURLNodeLimit(t *testing.T) {
	t.Parallel()
	client := &Client{apiKey: "maple"}
	for _, tc := range [...]struct {
		name, leaf string
		nodes      int
	}{
		{"63 nodes with key", "fixture maple leaf", maxErrNodes - 1},
		{"64 nodes with key", "fixture maple leaf", maxErrNodes},
		{"63 keyless nodes", "fixture leaf", maxErrNodes - 1},
		{"64 keyless nodes", "fixture leaf", maxErrNodes},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			calls := 0
			var cause error = &redactRootCauseLink{text: tc.leaf, calls: &calls}
			for range tc.nodes - 1 {
				cause = &redactRootCauseLink{text: "fixture link", next: cause, calls: &calls}
			}
			input := &url.Error{Op: "Get", URL: "http://h/feed", Err: cause}
			got := client.redactError(input)
			assertCleanRootURLNodeLimit(subtest, input, got, tc.nodes, calls, strings.Contains(tc.leaf, "maple"))
		})
	}
}

// TestRedactErrorNodeLimitContract pins the documented error inspection limit.
func TestRedactErrorNodeLimitContract(t *testing.T) {
	t.Parallel()
	if maxErrNodes != 64 {
		t.Errorf("maxErrNodes = %d; want 64", maxErrNodes)
	}
}

// TestRedactErrorCleanRootURLReadLimit checks that typed nils spend the cause budget.
func TestRedactErrorCleanRootURLReadLimit(t *testing.T) {
	t.Parallel()
	client := &Client{apiKey: "maple"}
	for _, tc := range [...]struct {
		name  string
		count int
		cause func(int, *int) error
		fixed bool
	}{
		{"64 reads in join", 62, typedNilRootJoin, true},
		{"63 reads in join", 61, typedNilRootJoin, false},
		{"64 reads in chain", 62, typedNilRootChain, true},
		{"63 reads in chain", 61, typedNilRootChain, false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			calls := 0
			input := &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: tc.cause(tc.count, &calls)}
			got := client.redactError(input)
			if tc.fixed {
				assertFixedRootURL(subtest, got)
			} else {
				assertObservedRootURL(subtest, got, input, false, true)
			}
			if calls != 0 {
				subtest.Errorf("cause leaf or link Error called %d times; want 0", calls)
			}
		})
	}
}

// typedNilRootJoin builds a join of counted leaves and a final typed nil.
func typedNilRootJoin(leaves int, calls *int) error {
	var children [maxErrNodes - 1]error
	for index := range leaves {
		children[index] = &redactRootCauseLink{text: "fixture leaf", calls: calls}
	}
	children[leaves] = (*redactRootCauseLink)(nil)
	return errors.Join(children[:leaves+1]...)
}

// typedNilRootChain builds counted links over a terminal cause that unwraps to a typed nil.
func typedNilRootChain(links int, calls *int) error {
	var cause error = &redactRootCauseLink{text: "fixture leaf", next: (*redactRootCauseLink)(nil), calls: calls}
	for range links {
		cause = &redactRootCauseLink{text: "fixture link", next: cause, calls: calls}
	}
	return cause
}

// TestRedactErrorCheckMethodCounts pins the call counts on clean trees.
func TestRedactErrorCheckMethodCounts(t *testing.T) {
	t.Parallel()
	// Why: 7e87a4b checks each node's text and children once; the URL root reads its direct cause's text again.
	const nodeTextReads, rootCauseTextReads, unwrapReads = 1, 2, 1
	for _, tc := range [...]struct {
		name     string
		wrap     func(error) error
		wantHead int
	}{
		{"scrub", func(head error) error { return head }, nodeTextReads},
		{"root URL", func(head error) error {
			return &url.Error{Op: "Get", URL: "http://h/feed", Err: head}
		}, rootCauseTextReads},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			leaf := &redactCountedCheckNode{}
			head := &redactCountedCheckNode{next: leaf}
			input := tc.wrap(head)
			got := answerWithinTwoSeconds(subtest, "redactError", func() error {
				return (&Client{apiKey: "maple"}).redactError(input)
			})
			if got != input { //nolint:errorlint // compare fixture pointer identities
				subtest.Error("redactError changed the identity of a clean chain")
			}
			assertCheckNodeReads(subtest, "head", head, tc.wantHead, unwrapReads)
			assertCheckNodeReads(subtest, "leaf", leaf, nodeTextReads, unwrapReads)
		})
	}
}

// assertCheckNodeReads checks both method counts for one node.
func assertCheckNodeReads(t *testing.T, name string, node *redactCountedCheckNode, wantText, wantUnwrap int) {
	t.Helper()
	if node.textReads != wantText || node.unwrapReads != wantUnwrap {
		t.Errorf("%s Error and Unwrap reads = %d, %d; want %d, %d", name, node.textReads, node.unwrapReads, wantText, wantUnwrap)
	}
}

// assertCleanRootURLNodeLimit checks overflow, copy, and keep outcomes.
func assertCleanRootURLNodeLimit(t *testing.T, input *url.Error, got error, nodes, calls int, carries bool) {
	t.Helper()
	switch {
	case nodes >= maxErrNodes:
		assertFixedRootURL(t, got)
		if calls != 0 {
			t.Errorf("overflowing cause Error called %d times; want 0", calls)
		}
	case carries:
		copied, ok := got.(*url.Error) //nolint:errorlint // require the direct URL copy
		if !ok || copied == input || hiddenRedaction(copied.Err) == nil {
			t.Fatalf("redactError returned %T; want a URL copy with a hidden cause", got)
		}
		assertNoKeyForms(t, copied.Error(), "maple")
	default:
		if any(got) != input {
			t.Error("redactError changed the identity of a within-budget clean root")
		}
	}
}

// assertFixedRootURL checks that redaction replaced the whole URL error with the fixed message.
func assertFixedRootURL(t *testing.T, got error) {
	t.Helper()
	hidden, ok := got.(*redactedError) //nolint:errorlint // require the fixed wrapper itself
	if !ok || hidden.Error() != redactedTreeMsg || !hidden.unsafe {
		t.Errorf("redactError returned %T; want a fixed redaction wrapper", got)
	}
}

// assertObservedRootURL checks that a root is preserved or copied with the observed cause.
func assertObservedRootURL(t *testing.T, got error, input *url.Error, unchanged, unsafe bool) {
	t.Helper()
	if unchanged {
		if any(got) != input {
			t.Error("redactError changed the identity of a clean URL error")
		}
		return
	}
	copied, ok := got.(*url.Error) //nolint:errorlint // require the URL copy as the direct result
	if !ok || copied == nil || copied == input {
		t.Fatalf("redactError returned %T; want a direct URL copy", got)
	}
	assertObservedRootCause(t, copied.Err, unsafe)
}

// assertObservedRootCause checks the opaque or classified cause selected for the observed tree.
func assertObservedRootCause(t *testing.T, cause error, unsafe bool) {
	t.Helper()
	if !unsafe {
		classified, ok := cause.(*classifiedURLCause) //nolint:errorlint // require the direct classified cause
		if !ok {
			t.Fatalf("copied cause = %T; want *classifiedURLCause", cause)
		}
		assertClassifierValues(t, "safe cause", classified, true, true)
		return
	}
	if _, ok := cause.(*opaqueURLCause); !ok { //nolint:errorlint // require the direct opaque cause
		t.Errorf("copied cause = %T; want *opaqueURLCause", cause)
	}
	if classification, ok := cause.(interface{ Timeout() bool }); ok {
		t.Errorf("unsafe cause has Timeout() = %t; want no Timeout method", classification.Timeout())
	}
	if classification, ok := cause.(interface{ Temporary() bool }); ok {
		t.Errorf("unsafe cause has Temporary() = %t; want no Temporary method", classification.Temporary())
	}
	if cause == nil || cause.Error() != redactedTreeMsg {
		t.Errorf("copied cause = %v; want %q", cause, redactedTreeMsg)
	}
}

// TestRedactedErrorIsNestedWrapper checks identity at the walk boundary.
func TestRedactedErrorIsNestedWrapper(t *testing.T) {
	t.Parallel()
	target := &redactedError{msg: "fixture nested wrapper", err: errors.New("fixture cause")}
	other := &redactedError{msg: target.msg, err: target.err}
	for _, tc := range []struct {
		name  string
		depth int
		want  bool
	}{
		{name: "last visited node", depth: maxWalkSteps - 1, want: true},
		{name: "first node past budget", depth: maxWalkSteps},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var node error = target
			for range tc.depth {
				node = &redactCycleErr{next: node}
			}
			tree := &redactedError{err: node}
			if got := errors.Is(tree, target); got != tc.want {
				t.Errorf("errors.Is with nested wrapper = %v, want %v", got, tc.want)
			}
			if errors.Is(tree, other) {
				t.Error("errors.Is matched a different wrapper with the same contents")
			}
		})
	}
}

// TestUnsafeTreeClassifications covers a classifier above a typed-nil descendant.
func TestUnsafeTreeClassifications(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	var dns *net.DNSError
	original := &url.Error{Op: "Get", URL: "http://h/?apikey=" + key, Err: &net.OpError{Op: "dial", Err: dns}}
	tree := &net.OpError{Op: "read", Err: original}
	c := &Client{apiKey: key}
	for name, apply := range map[string]func(error) error{"redactError": c.redactError, "scrubError": c.scrubError} {
		t.Run(name, func(subtest *testing.T) {
			subtest.Parallel()
			got, ok := apply(tree).(*redactedError) //nolint:errorlint // require the wrapper itself
			if !ok {
				subtest.Fatal("expected an opaque wrapper")
			}
			assertURLCauseViews(subtest, got, original, false)
			var classifier interface{ Timeout() bool }
			if got.As(&classifier) {
				subtest.Error("As exposed a hidden timeout classifier")
			}
		})
	}
}

// TestSameKeyWrapperRechecksCurrentTree checks direct, nested, and copied classifications after mutation.
func TestSameKeyWrapperRechecksCurrentTree(t *testing.T) {
	t.Parallel()
	const key = "maple"
	client := &Client{apiKey: key}
	leaf := &net.DNSError{Err: key, IsTimeout: true, IsTemporary: true}
	inner := hiddenRedaction(hiddenRedacted(t, key, leaf))
	children := make([]error, maxErrNodes-1)
	children[0] = inner
	padding := errors.New(key)
	for index := 1; index < len(children); index++ {
		children[index] = padding
	}
	outer := hiddenRedaction(hiddenRedacted(t, key, errors.Join(children...)))
	inner.err = errors.Join((*net.DNSError)(nil), leaf)
	cycle := &redactedError{key: key}
	cycle.err = cycle
	for _, tc := range [...]struct {
		name   string
		cause  *redactedError
		viaURL bool
	}{
		{"direct wrapper", inner, false},
		{"enclosing wrapper at inspection limit", outer, false},
		{"sanitized URL copy", inner, true},
		{"self-referencing wrapper", cycle, false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			if tc.viaURL {
				assertErrorClassifications(subtest, copyClassificationURL(subtest, client, tc.cause), false, false)
				return
			}
			assertBoundedClassifications(subtest, tc.cause, false, false)
		})
	}
}

// TestURLCopyUsesIndependentClassifierWalks checks that a timeout delegate cannot discard the temporary sibling.
func TestURLCopyUsesIndependentClassifierWalks(t *testing.T) {
	t.Parallel()
	const key = "maple"
	client := &Client{apiKey: key}
	sentinel := errors.New("fixture failure")
	timeout := &fs.PathError{Err: &redactTimeoutCause{redactFixtureCause{sentinel}}}
	temporary := redactTemporaryCause{redactFixtureCause{sentinel}}
	for _, tc := range [...]struct {
		name string
		tree error
	}{
		{"timeout delegate before temporary sibling", errors.Join(timeout, temporary)},
		{"temporary sibling before timeout delegate", errors.Join(temporary, timeout)},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			cause := &redactedError{key: key, err: tc.tree}
			assertErrorClassifications(subtest, cause, true, true)
			assertErrorClassifications(subtest, copyClassificationURL(subtest, client, cause), true, true)
		})
	}
}

// copyClassificationURL recovers a sanitized URL error for comparison with its original cause.
func copyClassificationURL(t *testing.T, client *Client, cause error) *url.Error {
	t.Helper()
	original := &url.Error{Op: "Get", URL: "http://h/" + client.apiKey, Err: cause}
	var copied *url.Error
	if !errors.As(client.scrubError(original), &copied) || copied == nil || copied == original {
		t.Fatal("expected a sanitized URL error copy")
	}
	return copied
}

type redactURLClassifier struct {
	redactClassifier
	error
}

type redactChangingJoin struct {
	changed atomic.Bool
	link    *url.Error
	after   []error
}

type redactObservedJoin struct {
	first, later []error
	firstReads   int32
	calls        atomic.Int32
}

// Error returns a fixed fixture message.
func (*redactObservedJoin) Error() string { return "fixture observed join" }

// Unwrap returns the first children for the configured number of reads.
func (e *redactObservedJoin) Unwrap() []error {
	if e.calls.Add(1) <= e.firstReads {
		return e.first
	}
	return e.later
}

// TestRedactedErrorClassifiesObservedTree checks both classifications and the number of unwraps.
func TestRedactedErrorClassifiesObservedTree(t *testing.T) {
	t.Parallel()
	leaf := &net.DNSError{IsTimeout: true, IsTemporary: true}
	for _, tc := range [...]struct {
		name         string
		first, later []error
		nested, want bool
	}{
		{"stable", []error{leaf}, []error{leaf}, false, true},
		{"later typed nil", []error{leaf}, []error{leaf, (*net.DNSError)(nil)}, false, true},
		{"later false leaf", []error{leaf}, []error{&net.DNSError{}}, false, true},
		{"first typed nil", []error{(*net.DNSError)(nil), leaf}, []error{leaf}, false, false},
		{"nested same-key wrapper", []error{leaf}, []error{&net.DNSError{}}, true, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			assertSingleTreeRead(subtest, tc.want, func() (*atomic.Int32, error) {
				join := &redactObservedJoin{first: tc.first, later: tc.later, firstReads: 1}
				var tree error = join
				if tc.nested {
					tree = &redactedError{key: "maple", err: tree}
				}
				return &join.calls, tree
			})
		})
	}
}

// TestRedactedErrorSnapshotsStartingWrapper checks that a cycle reuses the initial wrapper snapshot.
func TestRedactedErrorSnapshotsStartingWrapper(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name     string
		classify func(*redactedError) bool
	}{
		{"Timeout", (*redactedError).Timeout},
		{"Temporary", (*redactedError).Temporary},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			cause := &redactObservedSingle{later: trueClassifierLeaf()}
			root := &redactedError{key: "maple", err: cause}
			cause.first = root
			if got := answerWithinTwoSeconds(subtest, tc.name, func() bool { return tc.classify(root) }); got {
				subtest.Errorf("%s() = %t; want false", tc.name, got)
			}
			if calls := cause.calls.Load(); calls != 1 {
				subtest.Errorf("classification read Unwrap %d times; want 1", calls)
			}
		})
	}
}

// assertSingleTreeRead asks each classifier on a fresh tree and checks its unwrap count.
func assertSingleTreeRead(t *testing.T, want bool, fixture func() (*atomic.Int32, error)) {
	t.Helper()
	for _, check := range [...]struct {
		name     string
		classify func(*redactedError) bool
	}{
		{"Timeout", (*redactedError).Timeout},
		{"Temporary", (*redactedError).Temporary},
	} {
		calls, tree := fixture()
		if got := check.classify(&redactedError{key: "maple", err: tree}); got != want {
			t.Errorf("%s() = %t; want %t", check.name, got, want)
		}
		if count := calls.Load(); count != 1 {
			t.Errorf("%s read Unwrap %d times; want 1", check.name, count)
		}
	}
}

type redactObservedURLJoin struct{ *redactObservedJoin }

// Timeout reports the classification associated with the observed children.
func (e *redactObservedURLJoin) Timeout() bool { return e.calls.Load() <= e.firstReads }

// Temporary reports the classification associated with the observed children.
func (e *redactObservedURLJoin) Temporary() bool { return e.calls.Load() <= e.firstReads }

// TestURLCopyClassifiesObservedCause checks that both captured classifications use the cause inspection.
func TestURLCopyClassifiesObservedCause(t *testing.T) {
	t.Parallel()
	first := &net.DNSError{IsTimeout: true, IsTemporary: true}
	later := &net.DNSError{}
	join := &redactObservedURLJoin{&redactObservedJoin{first: []error{first}, later: []error{later}, firstReads: 2}}
	hidden := &redactedError{key: "maple", err: &url.Error{Err: join}}
	var copied *url.Error
	if !errors.As(hidden, &copied) || copied == nil {
		t.Fatal("expected a sanitized URL error copy")
	}
	reads := join.calls.Load()
	if reads != 2 {
		t.Errorf("errors.As read Unwrap %d times; want 2", reads)
	}
	_ = join.Unwrap()
	reads++
	assertClassifierValues(t, "original after Unwrap", join, false, false)
	assertClassifierValues(t, "copy", copied, true, true)
	if count := join.calls.Load(); count != reads {
		t.Errorf("copied classifiers read Unwrap %d times; want 0", count-reads)
	}
}

type redactFlippingURLCause struct{ calls atomic.Int32 }

// Error returns the fixture's message.
func (*redactFlippingURLCause) Error() string { return "changing URL cause" }

// Unwrap returns a positive cause on the first read and a negative cause thereafter.
func (e *redactFlippingURLCause) Unwrap() error {
	if e.calls.Add(1) == 1 {
		return trueClassifierLeaf()
	}
	return &net.DNSError{}
}

// TestURLCopySharesWrapperSnapshot checks that both classifiers observe the same wrapper tree.
func TestURLCopySharesWrapperSnapshot(t *testing.T) {
	t.Parallel()
	flip := &redactFlippingURLCause{}
	wrapper := &redactedError{key: "maple", err: flip}
	cause := &net.OpError{Op: "read", Err: wrapper}
	hidden := &redactedError{key: "maple", err: &url.Error{Err: cause}}
	var copied *url.Error
	if !errors.As(hidden, &copied) || copied == nil {
		t.Fatal("expected a sanitized URL error copy")
	}
	if count := flip.calls.Load(); count != 1 {
		t.Fatalf("errors.As read wrapper Unwrap %d times; want 1", count)
	}
	flipped := flip.Unwrap()
	if timeout, temporary := stdlibErrorClassifications(flipped); timeout || temporary {
		t.Errorf("advanced cause classifications = (%t, %t); want (false, false)", timeout, temporary)
	}
	assertClassifierValues(t, "copy", copied, true, true)
	if count := flip.calls.Load(); count != 2 {
		t.Errorf("wrapper Unwrap read %d times after advance and copied classifiers; want 2", count)
	}
}

type redactObservedExternalClassifier struct {
	calls atomic.Int32
	cause error
}

// Error returns a fixed fixture message.
func (*redactObservedExternalClassifier) Error() string { return "fixture external classifier" }

// Unwrap returns the package wrapper on the first read.
func (e *redactObservedExternalClassifier) Unwrap() error {
	if e.calls.Add(1) == 1 {
		return e.cause
	}
	return nil
}

// Timeout reports a timeout.
func (*redactObservedExternalClassifier) Timeout() bool { return true }

// Temporary reports a temporary error.
func (*redactObservedExternalClassifier) Temporary() bool { return true }

// TestExternalClassifierUsesObservedSubtree checks that a recorded wrapper blocks both classifiers.
func TestExternalClassifierUsesObservedSubtree(t *testing.T) {
	t.Parallel()
	assertSingleTreeRead(t, false, func() (*atomic.Int32, error) {
		wrapper := &redactedError{key: "maple", err: &net.DNSError{IsTimeout: true, IsTemporary: true}}
		node := &redactObservedExternalClassifier{cause: wrapper}
		return &node.calls, node
	})
}

// Error returns the fixture join message.
func (*redactChangingJoin) Error() string { return "fixture changing join" }

// Unwrap returns the URL alone until the test switches the fixture's children.
func (e *redactChangingJoin) Unwrap() []error {
	if e.changed.Load() {
		return e.after
	}
	return []error{e.link}
}

// TestURLCopyUsesObservedUnsafeTree checks unsafe children seen during URL recovery.
func TestURLCopyUsesObservedUnsafeTree(t *testing.T) {
	t.Parallel()
	const key = "maple"
	client := &Client{apiKey: key}
	original := &url.Error{
		Op: "Get", URL: "https://example.invalid/" + key,
		Err: &net.DNSError{IsTimeout: true, IsTemporary: true},
	}
	wide := make([]error, maxErrNodes+1)
	child := errors.New("fixture sibling")
	for i := range wide {
		wide[i] = child
	}
	wide[0] = original
	for _, tc := range [...]struct {
		name  string
		after []error
		want  bool
	}{
		{"unchanged", nil, true},
		{"typed nil", []error{(*redactNilTimeoutCause)(nil), original}, false},
		{"sibling typed nil", []error{original, &redactCycleErr{text: "fixture sibling", next: (*redactNilTimeoutCause)(nil)}}, false},
		{"overflow", wide, false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			tree := &redactChangingJoin{link: original, after: tc.after}
			got, ok := client.scrubError(tree).(*redactedError) //nolint:errorlint // require the wrapper itself
			if !ok {
				subtest.Fatal("expected an opaque wrapper")
			}
			tree.changed.Store(tc.after != nil)
			var copied *url.Error
			if !errors.As(got, &copied) || copied == nil || copied == original {
				subtest.Fatal("expected a sanitized URL error copy")
			}
			assertNoKeyForms(subtest, copied.Error(), key)
			assertClassifierValues(subtest, "copy", copied, tc.want, tc.want)
			assertClassifierValues(subtest, "wrapper", got, tc.want, tc.want)
		})
	}
}

// TestUnsafeParentURLCopyIsUnclassified checks that a typed-nil sibling suppresses URL copy classification.
func TestUnsafeParentURLCopyIsUnclassified(t *testing.T) {
	t.Parallel()
	const key = "plum"
	original := &url.Error{
		Op:  "Get " + key,
		URL: "http://h/?apikey=" + key,
		Err: redactURLClassifier{error: errors.New("dial " + key)},
	}
	tree := errors.Join((*redactNilTimeoutCause)(nil), original)
	c := &Client{apiKey: key}
	for _, tc := range [...]struct {
		name  string
		apply func(error) error
	}{
		{"redactError", c.redactError},
		{"scrubError", c.scrubError},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			assertUnsafeParentURLCopy(subtest, c, tc.apply(tree), original)
		})
	}
}

// assertUnsafeParentURLCopy checks that the wrapper and its sanitized URL copy suppress classification.
func assertUnsafeParentURLCopy(t *testing.T, c *Client, result error, original *url.Error) {
	t.Helper()
	got, ok := result.(*redactedError) //nolint:errorlint // require the wrapper itself
	if !ok {
		t.Fatal("expected an opaque wrapper")
	}
	var copied *url.Error
	if !errors.As(got, &copied) || copied == nil || copied == original {
		t.Fatal("expected a sanitized URL error copy")
	}
	if isNilError(copied.Err) {
		t.Fatal("expected a non-nil copied cause")
	}
	if c.containsKey(copied.Op) || c.containsKey(copied.URL) || c.containsKey(copied.Err.Error()) {
		t.Error("copied URL error exposed the key")
	}
	assertURLClassifications(t, got, copied, false)
	var classifier interface{ Timeout() bool }
	if got.As(&classifier) {
		t.Error("As exposed a hidden timeout classifier")
	}
}

type redactCountingTimeout struct{ calls int }

// Error returns a fixed fixture message.
func (*redactCountingTimeout) Error() string { return "fixture timeout" }

// Timeout counts classification calls and reports a timeout.
func (e *redactCountingTimeout) Timeout() bool {
	e.calls++
	return true
}

// TestOwnedURLCauseClassification checks that classification stops at package-owned URL causes.
func TestOwnedURLCauseClassification(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	for name, want := range map[string]bool{"opaque": false, "classified": true} {
		t.Run(name, func(subtest *testing.T) {
			subtest.Parallel()
			counted := &redactCountingTimeout{}
			opaque := opaqueURLCause{hidden: &redactedError{msg: "fixture timeout", key: key, err: counted}}
			var root error = &opaque
			if want {
				root = &classifiedURLCause{opaqueURLCause: opaque, timeout: true}
			}
			parent := fmt.Errorf("fixture %s: %w", key, root)
			assertOwnedURLCauseClassification(subtest, c.scrubError(parent), counted, want)
		})
	}
}

// assertOwnedURLCauseClassification checks captured classification and hidden identity.
func assertOwnedURLCauseClassification(t *testing.T, result error, counted *redactCountingTimeout, want bool) {
	t.Helper()
	got, ok := result.(*redactedError) //nolint:errorlint // require the wrapper itself
	if !ok {
		t.Fatal("scrubError did not wrap the key-bearing cause")
	}
	if got.Timeout() != want || got.Temporary() {
		t.Error("unexpected classification of package-owned cause")
	}
	if counted.calls != 0 {
		t.Error("classification called the hidden cause")
	}
	if !errors.Is(got, counted) {
		t.Error("errors.Is did not reach the hidden cause")
	}
}

// TestURLNilCauseIsSafe checks the root and wrapper views of a URL error with no cause.
func TestURLNilCauseIsSafe(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	root := &url.Error{Op: "Get", URL: "http://h/?apikey=" + key}
	c := &Client{apiKey: key}
	for name, apply := range map[string]func(error) error{"redactError": c.redactError, "scrubError": c.scrubError} {
		t.Run(name, func(subtest *testing.T) {
			subtest.Parallel()
			got := apply(root)
			assertNoKeyForms(subtest, got.Error(), key)
			var copied *url.Error
			if !errors.As(got, &copied) || copied == nil || copied == root || copied.Err != nil {
				subtest.Fatal("expected a sanitized URL error copy with a nil cause")
			}
			assertNoKeyForms(subtest, copied.Error(), key)
			assertURLClassifications(subtest, got, copied, false)
		})
	}
}

// TestForeignRedactionRemainsOpaque checks that a wrapper cannot recover a URL using a different key.
func TestForeignRedactionRemainsOpaque(t *testing.T) {
	t.Parallel()
	const first, second = "cedar", "maple"
	inner := &url.Error{
		Op: first + second, URL: "https://example.invalid/" + second + "?apikey=" + first,
		Err: &net.DNSError{Err: first + second, IsTimeout: true},
	}
	foreign := (&Client{apiKey: first}).scrubError(&redactCycleErr{text: "fixture outer", next: inner})
	assertRecoverableForeignURL(t, foreign, inner, first)
	c := &Client{apiKey: second}
	for name, apply := range map[string]func(error) error{"redactError": c.redactError, "scrubError": c.scrubError} {
		t.Run(name, func(subtest *testing.T) {
			subtest.Parallel()
			assertForeignRedactionOpaque(subtest, apply(foreign), inner.Err, first, second)
		})
	}
}

// TestForeignRedactionBehindStdlibDelegates checks the key boundary before stdlib classifier calls.
func TestForeignRedactionBehindStdlibDelegates(t *testing.T) {
	t.Parallel()
	const first, second = "cedar", "maple"
	dns := &net.DNSError{Err: first, IsTimeout: true}
	inner := &url.Error{Op: "Get", URL: "https://example.invalid/?apikey=" + first, Err: dns}
	foreign := (&Client{apiKey: first}).scrubError(inner)
	assertRecoverableForeignURL(t, foreign, inner, first)
	client := &Client{apiKey: second}
	for _, tc := range [...]struct {
		name    string
		wrapper error
		target  error
		want    bool
	}{
		{"op error", &net.OpError{Err: foreign}, dns, false},
		{"op error with syscall", &net.OpError{Err: &os.SyscallError{Err: foreign}}, dns, false},
		{"syscall error", &os.SyscallError{Err: foreign}, dns, false},
		{"path error", &fs.PathError{Err: foreign}, dns, false},
		{"safe op error", &net.OpError{Op: "dial " + second, Err: &net.DNSError{IsTimeout: true}}, nil, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			assertStdlibDelegate(subtest, client.redactError(tc.wrapper), tc.target, first, second, tc.want)
			assertStdlibDelegate(subtest, client.scrubError(tc.wrapper), tc.target, first, second, tc.want)
		})
	}
}

var (
	_ interface{ RedactionBoundary() } = (*redactedError)(nil)
	_ interface{ RedactionBoundary() } = (*opaqueURLCause)(nil)
	_ interface{ RedactionBoundary() } = (*classifiedURLCause)(nil)
)

type redactBoundaryCalls struct{ message, match, recover, timeout, temporary, marker int }

type redactCountingBoundary struct {
	cause    *redactedError
	sentinel error
	calls    redactBoundaryCalls
}

// Error counts message calls and returns the foreign fixture's text.
func (e *redactCountingBoundary) Error() string {
	e.calls.message++
	return "cedar boundary"
}

// Is counts identity hooks and recognizes the fixture sentinel.
func (e *redactCountingBoundary) Is(target error) bool {
	e.calls.match++
	return e.calls.match == 1 && (target == e.sentinel || errors.Is(e.cause, target))
}

// As counts recovery hooks and forwards the first one to the hidden cause.
func (e *redactCountingBoundary) As(target any) bool {
	e.calls.recover++
	return e.calls.recover == 1 && e.cause.As(target)
}

// Timeout counts classifier calls and forwards the first one to the hidden cause.
func (e *redactCountingBoundary) Timeout() bool {
	e.calls.timeout++
	return e.calls.timeout == 1 && e.cause.Timeout()
}

// Temporary counts classifier calls and forwards the first one to the hidden cause.
func (e *redactCountingBoundary) Temporary() bool {
	e.calls.temporary++
	return e.calls.temporary == 1 && e.cause.Temporary()
}

// RedactionBoundary marks the fixture and counts any invocation of the marker.
func (e *redactCountingBoundary) RedactionBoundary() { e.calls.marker++ }

// TestSiblingModuleRedactionBoundary checks that marked wrappers remain opaque across a cycle.
func TestSiblingModuleRedactionBoundary(t *testing.T) {
	t.Parallel()
	const key = "maple"
	for _, tc := range [...]struct {
		name     string
		delegate bool
		url      *url.Error
	}{
		{name: "cycle"},
		{name: "cycle with visible URL sibling", url: &url.Error{Op: "Get", URL: "http://h/" + key}},
		{name: "cycle behind external classifier", delegate: true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			link := &redactCycleErr{}
			root := &redactedError{key: key, err: link}
			foreign := &redactCountingBoundary{cause: root, sentinel: errors.New("foreign sentinel")}
			forward := &redactForwardingDelegate{err: foreign}
			link.next = foreign
			if tc.delegate {
				link.next = forward
			}
			if tc.url != nil {
				link.next = errors.Join(foreign, tc.url)
			}
			assertBoundedClassifications(subtest, root, false, false)
			assertSiblingModuleSearch(subtest, root, foreign, tc.url)
			if foreign.calls != (redactBoundaryCalls{}) || forward.timeoutCalls != 0 || forward.temporaryCalls != 0 {
				subtest.Errorf("boundary calls = %+v; forwarding calls = (%d, %d); want zero", foreign.calls, forward.timeoutCalls, forward.temporaryCalls)
			}
		})
	}
}

// assertSiblingModuleSearch checks identity and URL recovery without invoking the marked wrapper.
func assertSiblingModuleSearch(t *testing.T, root *redactedError, foreign *redactCountingBoundary, visible *url.Error) {
	t.Helper()
	if answerWithinTwoSeconds(t, "foreign sentinel", func() bool { return errors.Is(root, foreign.sentinel) }) {
		t.Error("errors.Is called the foreign wrapper's identity hook")
	}
	if !answerWithinTwoSeconds(t, "foreign identity", func() bool { return errors.Is(root, foreign) }) {
		t.Error("errors.Is did not recognize the foreign wrapper itself")
	}
	type urlRecovery struct {
		found  bool
		copied *url.Error
	}
	recovery := answerWithinTwoSeconds(t, "URL recovery", func() urlRecovery {
		var recovered *url.Error
		found := errors.As(root, &recovered)
		return urlRecovery{found: found, copied: recovered}
	})
	if visible == nil {
		if recovery != (urlRecovery{}) {
			t.Errorf("errors.As through the foreign wrapper = (%t, %p); want (false, nil)", recovery.found, recovery.copied)
		}
		return
	}
	copied := recovery.copied
	if !recovery.found || copied == nil || copied == visible || copied.URL != "http://h/REDACTED" || copied.Err != nil {
		t.Error("errors.As did not recover a sanitized copy of the visible URL sibling")
	}
}

// assertRecoverableForeignURL verifies that the first-key wrapper can recover a sanitized URL copy.
func assertRecoverableForeignURL(t *testing.T, foreign error, original *url.Error, key string) {
	t.Helper()
	var recovered *url.Error
	if !errors.As(foreign, &recovered) || recovered == nil || recovered == original {
		t.Fatal("expected the first-key wrapper to recover a sanitized URL copy")
	}
	assertNoKeyForms(t, recovered.Error(), key)
}

// redactTLSPermanentError mirrors the GOROOT crypto/tls/conn.go permanentError at lines 187–194.
type redactTLSPermanentError struct{ err net.Error }

// Error returns the delegated message.
func (e *redactTLSPermanentError) Error() string { return e.err.Error() }

// Unwrap returns the delegated error.
func (e *redactTLSPermanentError) Unwrap() error { return e.err }

// Timeout returns the delegated classification.
func (e *redactTLSPermanentError) Timeout() bool { return e.err.Timeout() }

// Temporary reports false for a permanent error.
func (*redactTLSPermanentError) Temporary() bool { return false }

type redactForwardingDelegate struct {
	err interface {
		error
		Timeout() bool
		Temporary() bool
	}
	timeoutCalls, temporaryCalls int
}

// Error returns the delegated message.
func (e *redactForwardingDelegate) Error() string { return e.err.Error() }

// Unwrap returns the delegated error.
func (e *redactForwardingDelegate) Unwrap() error { return e.err }

// Timeout counts the call and returns the delegated classification.
func (e *redactForwardingDelegate) Timeout() bool {
	e.timeoutCalls++
	return e.err.Timeout()
}

// Temporary counts the call and returns the delegated classification.
func (e *redactForwardingDelegate) Temporary() bool {
	e.temporaryCalls++
	return e.err.Temporary()
}

type redactTLSWriteFailure struct {
	net.Conn
	err error
}

// Write forwards handshake writes and injects the fixture error afterward.
func (c *redactTLSWriteFailure) Write(data []byte) (int, error) {
	if c.err != nil {
		return 0, c.err
	}
	return c.Conn.Write(data)
}

// tlsPermanentError runs an in-memory handshake and gets the TLS wrapper for a failed write.
func tlsPermanentError(t *testing.T, cause error) error {
	t.Helper()
	const host = "example.invalid"
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate TLS fixture key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{DNSNames: []string{host}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatalf("create TLS fixture certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse TLS fixture certificate: %v", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	pipe, peer := net.Pipe()
	t.Cleanup(func() {
		if closeErr := errors.Join(pipe.Close(), peer.Close()); closeErr != nil {
			t.Errorf("close TLS fixture pipe: %v", closeErr)
		}
	})
	conn := &redactTLSWriteFailure{Conn: pipe}
	client := tls.Client(conn, &tls.Config{ServerName: host, RootCAs: roots, MinVersion: tls.VersionTLS13})
	server := tls.Server(peer, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, SessionTicketsDisabled: true})
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- server.HandshakeContext(ctx) }()
	clientErr, serverErr := client.HandshakeContext(ctx), <-done
	if err = errors.Join(clientErr, serverErr); err != nil {
		t.Fatalf("handshake over TLS fixture pipe: %v", err)
	}
	conn.err = cause
	_, err = client.Write([]byte("fixture"))
	if fmt.Sprintf("%T", err) != "*tls.permanentError" || !errors.Is(err, cause) {
		t.Fatalf("TLS fixture write returned %T; want *tls.permanentError wrapping the fixture cause", err)
	}
	return err
}

// TestForeignRedactionBehindDelegatingClassifier checks external delegates over both key boundaries.
func TestForeignRedactionBehindDelegatingClassifier(t *testing.T) {
	t.Parallel()
	const first, second = "cedar", "maple"
	firstClient, client := &Client{apiKey: first}, &Client{apiKey: second}
	dns := &net.DNSError{Err: first, IsTimeout: true}
	sameKeyDNS := &net.DNSError{Err: second, IsTimeout: true}
	foreign := hiddenRedaction(firstClient.scrubError(dns))
	sameKey := hiddenRedaction(client.scrubError(sameKeyDNS))
	if foreign == nil || sameKey == nil {
		t.Fatal("expected opaque DNS fixtures")
	}
	delegate := &redactTLSPermanentError{err: foreign}
	for _, tc := range [...]struct {
		name  string
		input error
		cause error
	}{
		{"op error with foreign delegate", &net.OpError{Err: delegate}, dns},
		{"foreign delegate", delegate, dns},
		{"real TLS delegate", &net.OpError{Err: tlsPermanentError(t, foreign)}, dns},
		{"same-key delegate", errors.Join(&redactTLSPermanentError{err: sameKey}, errors.New(second)), sameKeyDNS},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			for _, apply := range [...]func(error) error{client.redactError, client.scrubError} {
				got := apply(tc.input)
				assertOpaqueError(subtest, firstClient, tc.name, got)
				assertOpaqueError(subtest, client, tc.name, got)
				assertErrorClassifications(subtest, got, false, false)
				if !errors.Is(got, tc.cause) {
					subtest.Error("errors.Is did not preserve hidden identity")
				}
			}
		})
	}
	assertForwardingDelegateBoundaries(t)
}

// assertForwardingDelegateBoundaries checks both external classifiers at each package wrapper boundary.
func assertForwardingDelegateBoundaries(t *testing.T) {
	t.Helper()
	for _, tc := range [...]struct{ name, key string }{
		{"foreign forwarding delegate", "cedar"},
		{"same-key forwarding delegate", "maple"},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			leaf := &net.DNSError{IsTimeout: true, IsTemporary: true}
			delegate := &redactForwardingDelegate{err: &redactedError{key: tc.key, err: leaf}}
			hidden := &redactedError{key: "maple", err: delegate}
			assertErrorClassifications(subtest, hidden, false, false)
			if delegate.timeoutCalls != 0 {
				subtest.Errorf("called delegated Timeout %d times; want 0", delegate.timeoutCalls)
			}
			if delegate.temporaryCalls != 0 {
				subtest.Errorf("called delegated Temporary %d times; want 0", delegate.temporaryCalls)
			}
		})
	}
}

// assertStdlibDelegate checks normal classification or opacity at the foreign-key boundary.
func assertStdlibDelegate(t *testing.T, got, target error, first, second string, want bool) {
	t.Helper()
	if !want {
		assertForeignRedactionOpaque(t, got, target, first, second)
		return
	}
	assertOpaqueError(t, &Client{apiKey: second}, "same-key stdlib wrapper", got)
	assertErrorClassifications(t, got, true, true)
}

// assertForeignRedactionOpaque checks that a foreign wrapper exposes only sanitized output and identity.
func assertForeignRedactionOpaque(t *testing.T, got, target error, first, second string) {
	t.Helper()
	for _, output := range []string{got.Error(), fmt.Sprintf("%v", got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got)} {
		if strings.Contains(output, first) || strings.Contains(output, second) {
			t.Error("formatted error revealed a key")
		}
	}
	var copied *url.Error
	if errors.As(got, &copied) || copied != nil {
		t.Error("errors.As recovered a URL across the foreign-key boundary")
	}
	assertErrorClassifications(t, got, false, false)
	if !errors.Is(got, target) {
		t.Error("errors.Is did not preserve hidden identity")
	}
}

// assertErrorClassifications checks the classifiers errors.As finds for an error.
func assertErrorClassifications(t *testing.T, got error, wantTimeout, wantTemporary bool) {
	t.Helper()
	var timeout interface{ Timeout() bool }
	if !errors.As(got, &timeout) || timeout.Timeout() != wantTimeout {
		t.Errorf("errors.As Timeout classifier missing or differs from %t", wantTimeout)
	}
	var temporary interface{ Temporary() bool }
	if !errors.As(got, &temporary) || temporary.Temporary() != wantTemporary {
		t.Errorf("errors.As Temporary classifier missing or differs from %t", wantTemporary)
	}
}

// TestRedactedErrorStdlibDelegateCycles checks that both classifications stop within the walk budget.
func TestRedactedErrorStdlibDelegateCycles(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name        string
		withSyscall bool
	}{
		{"op error", false},
		{"op error with syscall", true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			hidden := &redactedError{key: "maple"}
			var cause error = hidden
			if tc.withSyscall {
				cause = &os.SyscallError{Syscall: "read", Err: cause}
			}
			hidden.err = &net.OpError{Op: "read", Err: cause}
			assertBoundedClassifications(subtest, hidden, false, false)
		})
	}
}

// assertBoundedClassifications checks that each classifier answers promptly and matches its expected result.
func assertBoundedClassifications(t *testing.T, hidden *redactedError, wantTimeout, wantTemporary bool) {
	t.Helper()
	if got := answerWithinTwoSeconds(t, "Timeout", hidden.Timeout); got != wantTimeout {
		t.Errorf("Timeout() = %t; want %t", got, wantTimeout)
	}
	if got := answerWithinTwoSeconds(t, "Temporary", hidden.Temporary); got != wantTemporary {
		t.Errorf("Temporary() = %t; want %t", got, wantTemporary)
	}
}

// TestRedactedErrorAsSuppliedClassifiers checks that classification skips custom As methods.
func TestRedactedErrorAsSuppliedClassifiers(t *testing.T) {
	t.Parallel()
	client := &Client{apiKey: "maple"}
	foreign := hiddenRedacted(t, "cedar", &net.DNSError{Err: "cedar", IsTimeout: true})
	leaf := &net.DNSError{IsTimeout: true, IsTemporary: true}
	sameKey := &redactedError{key: "maple", err: leaf}
	delegate := &redactTLSPermanentError{err: hiddenRedaction(foreign)}
	for _, tc := range [...]struct {
		name string
		hook *redactAsClassifier
		want bool
	}{
		{"op error with foreign wrapper", &redactAsClassifier{classifier: &net.OpError{Err: foreign}}, false},
		{"foreign delegate", &redactAsClassifier{classifier: delegate}, false},
		{"op error with foreign delegate", &redactAsClassifier{classifier: &net.OpError{Err: delegate}}, false},
		{"op error with typed nil", &redactAsClassifier{classifier: &net.OpError{Err: (*redactedError)(nil)}}, false},
		{"same-key wrapper", &redactAsClassifier{classifier: sameKey}, false},
		{"non-error delegate", &redactAsClassifier{classifier: redactNonErrorClassifier{cause: sameKey}}, false},
		{"custom classifier skipped", &redactAsClassifier{classifier: redactClassifier{}}, false},
		{"walk continues into Unwrap", &redactAsClassifier{classifier: redactClassifier{}, cause: leaf}, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			got := client.scrubError(tc.hook)
			assertOpaqueError(subtest, client, tc.name, got)
			assertErrorClassifications(subtest, got, tc.want, tc.want)
			if tc.hook.calls != 0 {
				subtest.Errorf("custom As called %d times during classification", tc.hook.calls)
			}
		})
	}
}

// TestRedactedErrorStdlibClassifierParity compares classified redactions with their raw stdlib errors.
func TestRedactedErrorStdlibClassifierParity(t *testing.T) {
	t.Parallel()
	const key = "maple"
	client := &Client{apiKey: key}
	for _, tc := range [...]struct {
		name string
		raw  error
	}{
		{"accept reset", &net.OpError{Op: "accept", Err: syscall.ECONNRESET}},
		{"read syscall timeout", &net.OpError{Op: "read", Err: &os.SyscallError{Syscall: "read", Err: syscall.ETIMEDOUT}}},
		{"read indirect timeout", &net.OpError{Op: "read", Err: fmt.Errorf("w: %w", &net.DNSError{IsTimeout: true})}},
		{"open path timeout", &fs.PathError{Op: "open", Path: "p", Err: &net.DNSError{IsTimeout: true}}},
		{"read syscall again", &os.SyscallError{Syscall: "read", Err: syscall.EAGAIN}},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			wantTimeout, wantTemporary := stdlibErrorClassifications(tc.raw)
			if tc.name == "accept reset" && (runtime.GOOS == "linux" || runtime.GOOS == "darwin") && !wantTemporary {
				subtest.Error("stdlib accept reset should be temporary")
			}
			input := errors.Join(errors.New(key), tc.raw)
			for _, apply := range [...]func(error) error{client.redactError, client.scrubError} {
				got := apply(input)
				assertOpaqueError(subtest, client, tc.name, got)
				assertErrorClassifications(subtest, got, wantTimeout, wantTemporary)
			}
		})
	}
}

// stdlibErrorClassifications returns the answers found by errors.As on an unredacted error.
func stdlibErrorClassifications(err error) (bool, bool) {
	var timeout interface{ Timeout() bool }
	var temporary interface{ Temporary() bool }
	return errors.As(err, &timeout) && timeout.Timeout(), errors.As(err, &temporary) && temporary.Temporary()
}

// TestRedactedErrorStdlibDelegateBudget checks classifier chains at and beyond both limits.
func TestRedactedErrorStdlibDelegateBudget(t *testing.T) {
	t.Parallel()
	// Why: each wrapper costs one read, and entering the terminal tree requires maxInspectionReads left.
	const walkDepth = maxWalkSteps - maxInspectionReads
	for _, tc := range [...]struct {
		name  string
		cause error
		depth int
		wrap  func(error) error
		want  bool
	}{
		{"at structural limit", trueClassifierLeaf(), maxErrNodes - 1, wrapWithOpError, true},
		{"over structural limit", trueClassifierLeaf(), maxErrNodes, wrapWithOpError, false},
		{"at walk budget", walkBudgetTail(), walkDepth, wrapWithSameKey, true},
		{"over walk budget", walkBudgetTail(), walkDepth + 1, wrapWithSameKey, false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			cause := tc.cause
			for range tc.depth {
				cause = tc.wrap(cause)
			}
			assertBoundedClassifications(subtest, &redactedError{key: "maple", err: cause}, tc.want, tc.want)
		})
	}
}

// wrapWithOpError adds a stdlib delegate to the fixture tree.
func wrapWithOpError(err error) error { return &net.OpError{Op: "read", Err: err} }

// wrapWithSameKey adds a same-key wrapper to the fixture tree.
func wrapWithSameKey(err error) error { return &redactedError{key: "maple", err: err} }

// trueClassifierLeaf returns a leaf answering true to both classifiers.
func trueClassifierLeaf() error { return &net.DNSError{IsTimeout: true, IsTemporary: true} }

// walkBudgetTail builds a maxErrNodes-wide terminal tree with the positive classifier last.
func walkBudgetTail() error {
	leaves := make([]error, 0, maxErrNodes-1)
	for range maxErrNodes - 2 {
		leaves = append(leaves, errors.New("fixture leaf"))
	}
	leaves = append(leaves, trueClassifierLeaf())
	return errors.Join(leaves...)
}

// TestClassificationWrapperEntryFloor checks that the final wrapper reserves a full inspection.
func TestClassificationWrapperEntryFloor(t *testing.T) {
	t.Parallel()
	// Why: the join and each link cost one read, and the final single-leaf tree requires maxInspectionReads left.
	const depth = maxWalkSteps - maxInspectionReads - 1
	for _, tc := range [...]struct {
		name  string
		extra error
		want  bool
	}{
		{"at entry floor", nil, true},
		{"below entry floor", errors.New("unvisited sibling"), false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			cause := trueClassifierLeaf()
			for range depth {
				cause = wrapWithSameKey(cause)
			}
			joined := errors.Join(cause, tc.extra)
			assertClassifierValues(subtest, tc.name, &redactedError{key: "maple", err: joined}, tc.want, tc.want)
		})
	}
}

// TestURLCopyClassificationEntryFloor checks that only inspected nodes count in either classification.
func TestURLCopyClassificationEntryFloor(t *testing.T) {
	t.Parallel()
	// Why: the cause costs two reads, the join and its first child cost two, and depth - 1 links cost one each.
	const depth = maxWalkSteps - maxInspectionReads - 3
	for _, tc := range [...]struct {
		name  string
		extra error
		want  bool
	}{
		{name: "at entry floor", want: true},
		{name: "below entry floor", extra: errors.New("unvisited sibling")},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			chain := sameKeyClassifierChain(depth)
			cause := wrapWithOpError(wrapWithSameKey(errors.Join(chain, tc.extra)))
			original := &url.Error{URL: "http://h/maple", Err: cause}
			hidden := &redactedError{key: "maple", err: original}
			var copied *url.Error
			if !errors.As(hidden, &copied) || copied == nil || copied == original {
				subtest.Fatal("expected a sanitized URL error copy")
			}
			assertClassifierValues(subtest, "copy", copied, tc.want, tc.want)
		})
	}
}

// TestClassificationChargesSharedWrapperOnce checks that wrapper identity determines the snapshot charge.
func TestClassificationChargesSharedWrapperOnce(t *testing.T) {
	t.Parallel()
	// Why: the root join costs four reads, the shared snapshot costs one, and depth - 1 links cost one each.
	const depth = maxWalkSteps - maxInspectionReads - 4
	for _, tc := range [...]struct {
		name string
		same bool
	}{
		{name: "shared wrapper", same: true},
		{name: "distinct wrappers"},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			leaf := errors.New("fixture leaf")
			first := wrapWithSameKey(leaf)
			second := first
			if !tc.same {
				second = wrapWithSameKey(leaf)
			}
			joined := errors.Join(first, second, sameKeyClassifierChain(depth))
			root := &redactedError{key: "maple", err: joined}
			assertClassifierValues(subtest, tc.name, root, tc.same, tc.same)
		})
	}
}

// TestClassificationChargesStartingWrapperOnce checks the starting charge on a join with a self-reference.
func TestClassificationChargesStartingWrapperOnce(t *testing.T) {
	t.Parallel()
	// Why: the starting join costs three reads and depth - 1 links cost one each before the final reservation.
	const depth = maxWalkSteps - maxInspectionReads - 2
	for _, tc := range [...]struct {
		name  string
		extra error
		want  bool
	}{
		{name: "starting wrapper re-entry", want: true},
		{name: "below entry floor", extra: errors.New("unvisited sibling")},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			root := &redactedError{key: "maple"}
			root.err = errors.Join(root, sameKeyClassifierChain(depth), tc.extra)
			charge, snapshot := startHiddenClassification(root)
			span, unsafe := charge.children(errorSlot{tree: &snapshot.tree, index: 1})
			if unsafe || span.tree != &snapshot.tree {
				subtest.Fatal("re-entry did not return the original snapshot")
			}
			// Why: dispatching the cycle repeats indefinitely, so continue from the pending sibling after one re-entry.
			pending := errorTree{nodes: snapshot.tree.nodes[2:3], ends: []int{1}}
			if got := classifyTree(pending, root.key, charge, hiddenTimeoutClassifier.Timeout); got != tc.want {
				subtest.Errorf("pending sibling Timeout = %t; want %t", got, tc.want)
			}
		})
	}
}

// sameKeyClassifierChain wraps a positive classifier in distinct same-key wrappers.
func sameKeyClassifierChain(depth int) error {
	leaf := trueClassifierLeaf()
	for range depth {
		leaf = wrapWithSameKey(leaf)
	}
	return leaf
}

type redactCountingUnwrap struct{ calls int }

// Error returns a fixed counting fixture message.
func (*redactCountingUnwrap) Error() string { return "counting leaf" }

// Unwrap counts a read and ends the branch.
func (e *redactCountingUnwrap) Unwrap() error {
	e.calls++
	return nil
}

// wideRedactionChain puts the next wrapper before the counting leaves in depth-first order.
func wideRedactionChain(depth, extra int, leaf *redactCountingUnwrap) *redactedError {
	root := &redactedError{key: "maple", err: walkBudgetTail()}
	for i := range depth {
		width := maxErrNodes - 2
		if i == depth-1 {
			width += extra
		}
		children := make([]error, width)
		children[0] = root
		for i := 1; i < len(children); i++ {
			children[i] = leaf
		}
		root = &redactedError{key: "maple", err: errors.Join(children...)}
	}
	return root
}

// TestClassificationChargesInspections checks that each classifier budgets wide wrapper reads.
func TestClassificationChargesInspections(t *testing.T) {
	t.Parallel()
	// Why: each wide tree costs maxErrNodes - 1 reads, with the last width adjusted to leave maxInspectionReads.
	const depth = (maxWalkSteps - maxInspectionReads + maxErrNodes - 2) / (maxErrNodes - 1)
	const extra = maxWalkSteps - maxInspectionReads - depth*(maxErrNodes-1)
	for _, tc := range [...]struct {
		name     string
		depth    int
		extra    int
		classify func(*redactedError) bool
		want     bool
	}{
		{"wide Timeout at budget", depth, extra, (*redactedError).Timeout, true},
		{"wide Timeout over budget", depth, extra + 1, (*redactedError).Timeout, false},
		{"wide Temporary at budget", depth, extra, (*redactedError).Temporary, true},
		{"wide Temporary over budget", depth, extra + 1, (*redactedError).Temporary, false},
		{"small timeout tree", 2, 0, (*redactedError).Timeout, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			leaf := &redactCountingUnwrap{}
			root := wideRedactionChain(tc.depth, tc.extra, leaf)
			if got := tc.classify(root); got != tc.want {
				subtest.Errorf("classification = %t; want %t", got, tc.want)
			}
			if want := tc.depth*(maxErrNodes-3) + tc.extra; leaf.calls != want {
				subtest.Errorf("classification read %d counting leaves; want %d", leaf.calls, want)
			}
		})
	}
}

// TestClassifyStdlibNilDelegates checks that absent delegates stop and typed-nil delegates are unsafe.
func TestClassifyStdlibNilDelegates(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name  string
		cause error
	}{
		{"nil", nil},
		{"typed nil syscall", (*os.SyscallError)(nil)},
		{"typed nil classifier", (*net.DNSError)(nil)},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			if tc.cause == nil {
				assertNilStdlibDelegateStops(subtest)
				return
			}
			joined := errors.Join(&net.OpError{Op: "read", Err: tc.cause}, trueClassifierLeaf())
			if _, unsafe := inspectErrorTree(joined); !unsafe {
				subtest.Error("inspection accepted a typed-nil delegate")
			}
			assertClassifierValues(subtest, tc.name, &redactedError{key: "maple", err: joined}, false, false)
		})
	}
}

// assertNilStdlibDelegateStops checks a missing delegate with a positive sibling still pending.
func assertNilStdlibDelegateStops(t *testing.T) {
	t.Helper()
	node := &net.OpError{Op: "read"}
	leaf := trueClassifierLeaf()
	// Why: the absent delegate has no child; a positive sibling remains pending when classification stops.
	tree := errorTree{nodes: []error{errors.Join(node, leaf), node, leaf}, ends: []int{3, 3, 3}}
	slot := errorSlot{tree: &tree, index: 1}
	if action, got := classifyNode(slot, "maple", hiddenTimeoutClassifier.Timeout); action != walkStop || got {
		t.Errorf("Timeout classification = (%v, %t); want (%v, false)", action, got, walkStop)
	}
	if action, got := classifyNode(slot, "maple", hiddenTemporaryClassifier.Temporary); action != walkStop || got {
		t.Errorf("Temporary classification = (%v, %t); want (%v, false)", action, got, walkStop)
	}
	var snapshots classificationSnapshots
	charge := classificationCharge{snapshots: &snapshots, reads: len(tree.nodes)}
	if classifyTree(tree, "maple", charge, hiddenTimeoutClassifier.Timeout) || classifyTree(tree, "maple", charge, hiddenTemporaryClassifier.Temporary) {
		t.Error("classification reached the positive sibling after an absent delegate")
	}
}

type redactForeignOpaqueCause struct{}

// Error returns the foreign fixture's message.
func (redactForeignOpaqueCause) Error() string { return "foreign opaque cause" }

// RedactionBoundary marks the fixture as belonging to another client module.
func (redactForeignOpaqueCause) RedactionBoundary() {}

// TestClassificationStopsAtForeignOpaqueCause checks the boundary before a positive sibling.
func TestClassificationStopsAtForeignOpaqueCause(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name  string
		first error
		want  bool
	}{
		{"foreign boundary", redactForeignOpaqueCause{}, false},
		{"ordinary error", errors.New("ordinary cause"), true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			joined := errors.Join(tc.first, trueClassifierLeaf())
			assertClassifierValues(subtest, tc.name, &redactedError{key: "maple", err: joined}, tc.want, tc.want)
		})
	}
}

// TestSpellingUsesASCIIHex checks control bytes, digit case, and the entire first-digit alphabet.
func TestSpellingUsesASCIIHex(t *testing.T) {
	t.Parallel()
	const key, letterKey = "AB", "JB"
	c, letters := &Client{apiKey: key}, &Client{apiKey: letterKey}
	suffix := key[1:]
	controls := string([]byte{0x14, 0x11})
	for _, tc := range []struct {
		text string
		want bool
	}{
		{"%" + controls + suffix, false},
		{fmt.Sprintf("%%%02x%s", key[0], suffix), true},
		{fmt.Sprintf("%%%02x%s", strings.ToLower(key)[0], suffix), false},
	} {
		if c.matchesKeySpelling(tc.text) != tc.want {
			t.Error("unexpected ASCII digit or control-byte match")
		}
	}
	for _, format := range []string{"%%%02x%s", "%%%02X%s"} {
		if !letters.matchesKeySpelling(fmt.Sprintf(format, letterKey[0], letterKey[1:])) {
			t.Error("hex letter case did not match")
		}
	}
	for _, keyByte := range []byte{key[0], 0xaf} {
		assertASCIIHexAlphabet(t, keyByte)
	}
}

// TestMalformedEscapeAllocations checks unchanged text and a constant allocation count for invalid escapes.
func TestMalformedEscapeAllocations(t *testing.T) { //nolint:paralleltest // AllocsPerRun requires serial execution.
	client := &Client{apiKey: "maple"}
	for _, tc := range [...]struct{ name, candidate string }{ //nolint:paralleltest // AllocsPerRun requires serial subtests.
		{"percent", "%zz "},
		{"backslash Unicode", `\u00zz `},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			many := strings.Repeat(tc.candidate, 64)
			assertConstantEscapeAllocs(subtest, "scrubBody", client.scrubBody, tc.candidate, many)
			assertConstantEscapeAllocs(subtest, "scrubText", client.scrubText, tc.candidate, many)
		})
	}
}

// assertConstantEscapeAllocs compares allocation counts and verifies that both inputs survive scrubbing.
func assertConstantEscapeAllocs(t *testing.T, name string, scrub func(string) string, one, many string) {
	t.Helper()
	if scrub(one) != one || scrub(many) != many {
		t.Errorf("%s changed key-free malformed escapes", name)
	}
	oneAllocs := testing.AllocsPerRun(100, func() { _ = scrub(one) })
	manyAllocs := testing.AllocsPerRun(100, func() { _ = scrub(many) })
	if oneAllocs != manyAllocs {
		t.Errorf("%s allocated %.0f times for one candidate and %.0f times for 64", name, oneAllocs, manyAllocs)
	}
}

// assertASCIIHexAlphabet checks every possible first byte of a hex spelling.
func assertASCIIHexAlphabet(t *testing.T, keyByte byte) {
	t.Helper()
	digits := fmt.Sprintf("%02x", keyByte)
	upper := strings.ToUpper(digits)
	for first := range 256 {
		text := string([]byte{byte(first & 0xff), digits[1]})
		want := first == int(digits[0]) || first == int(upper[0])
		if matchesHexByte(text, keyByte) != want {
			t.Errorf("unexpected hex match for first byte %#02x", first)
		}
	}
}

// TestDecodeLayerChargesRetainedStorage checks the first layer of the exact-budget fixture.
func TestDecodeLayerChargesRetainedStorage(t *testing.T) {
	t.Parallel()
	const input = `%61 %255cu0061 \\u002561` + "x"
	c := &Client{apiKey: "fixture-key42"}
	const exact = 3 * uint64(len(input))
	for _, tc := range []struct {
		name   string
		budget uint64
		redact bool
	}{
		{"exact storage", exact, false},
		{"one byte short", exact - 1, true},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			remaining := tc.budget
			next, redact := c.decodeLayer([]string{input}, map[string]struct{}{input: {}}, &remaining)
			if redact != tc.redact {
				subtest.Errorf("redact = %t, want %t", redact, tc.redact)
			}
			switch {
			case tc.redact && next != nil:
				subtest.Error("over-budget decode retained a partial frontier")
			case !tc.redact && (len(next) != 3 || remaining != 0):
				subtest.Errorf("retained %d projections with %d bytes uncharged", len(next), remaining)
			}
		})
	}
}

// TestSpellingScanWorkBound checks an adversarial shared prefix and ordinary body spellings.
func TestSpellingScanWorkBound(t *testing.T) {
	t.Parallel()
	// Why: the leading percent costs one comparison, then each of the N-K remaining starts costs K.
	cases := []struct {
		name      string
		textLen   int
		keyLen    int
		want      bool
		guardHang bool
	}{
		{name: "below budget", textLen: 88, keyLen: 9, want: false},                  // Why: 712 comparisons leave one of 713.
		{name: "at budget", textLen: 89, keyLen: 9, want: true},                      // Why: 721 comparisons exhaust all 721.
		{name: "long key", textLen: 9000, keyLen: 4096, want: true, guardHang: true}, // Why: 20086785 comparisons would exceed 76096.
	}
	for _, tc := range cases {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			client := &Client{apiKey: strings.Repeat("a", tc.keyLen-1) + "b"}
			text := "%" + strings.Repeat("a", tc.textLen-1)
			assertSpellingScanAndScrub(subtest, client, text, tc.want, tc.guardHang)
		})
	}
	const word = "fixture"
	key := strings.Repeat(word, 4) + "body"
	c := &Client{apiKey: key}
	const body = `{"status":"fixture body","url":"/api?query=%20"}`
	escaped := fmt.Sprintf("%%%02x%s", key[0], key[1:])
	if c.matchesKeySpelling(body) || !c.matchesKeySpelling(body+escaped) {
		t.Error("unexpected spelling scan result for an ordinary body")
	}
}

// assertSpellingScanAndScrub checks the spelling limit and its effect on the scrubbed text.
func assertSpellingScanAndScrub(t *testing.T, client *Client, text string, want, guardHang bool) {
	t.Helper()
	scan := func() bool { return client.matchesKeySpelling(text) }
	scrub := func() string { return client.scrubText(text) }
	var scanned bool
	var scrubbed string
	if guardHang {
		scanned = answerWithinTwoSeconds(t, "matchesKeySpelling", scan)
		scrubbed = answerWithinTwoSeconds(t, "scrubText", scrub)
	} else {
		scanned, scrubbed = scan(), scrub()
	}
	if scanned != want {
		t.Errorf("matchesKeySpelling with text length %d and key length %d = %t, want %t", len(text), len(client.apiKey), scanned, want)
	}
	wantText := text
	if want {
		wantText = "REDACTED"
	}
	if scrubbed != wantText {
		t.Errorf("scrubText with text length %d and key length %d: redacted = %t, unchanged = %t, want redacted = %t", len(text), len(client.apiKey), scrubbed == "REDACTED", scrubbed == text, want)
	}
}
