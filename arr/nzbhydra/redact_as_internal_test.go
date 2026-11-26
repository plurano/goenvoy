package nzbhydra

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
			original := &url.Error{Op: "Get", URL: "http://fixture.invalid/" + key, Err: tc.cause}
			subtest.Run("As", func(view *testing.T) {
				view.Parallel()
				assertURLCopyClassifies(view, c.scrubError(errors.Join(original)), original, sentinel, key, tc.wantTimeout, tc.wantTemporary)
			})
			subtest.Run("redactError", func(view *testing.T) {
				view.Parallel()
				assertURLCopyClassifies(view, c.redactError(original), original, sentinel, key, tc.wantTimeout, tc.wantTemporary)
			})
		})
	}
}

// assertURLCopyClassifies checks classification and sentinel identity through a sanitized copy.
func assertURLCopyClassifies(t *testing.T, got error, original *url.Error, sentinel error, key string, wantTimeout, wantTemporary bool) {
	t.Helper()
	var copyErr *url.Error
	if !errors.As(got, &copyErr) || copyErr == nil || copyErr == original {
		t.Fatalf("expected a sanitized URL error copy, got %T", got)
	}
	if original.Err == nil {
		if copyErr.Err != nil {
			t.Error("copy changed a nil cause")
		}
	} else if !errors.Is(copyErr, sentinel) {
		t.Error("errors.Is through the copy did not reach the sentinel")
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
	c := &Client{apiKey: key}
	inner := &url.Error{
		Op:  "Get",
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
	if uerr.Op != inner.Op {
		t.Errorf("Op = %q; want %q", uerr.Op, inner.Op)
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
				if unchanged && any(result) != any(original) {
					t.Error("redactError did not preserve the clean root error")
				}
				assertRedactedURLError(t, result, original, tc.wantURL, unchanged)
			})
			t.Run("nested", func(t *testing.T) {
				t.Parallel()
				result := c.redactError(errors.Join(original))
				assertRedactedURLError(t, result, original, tc.wantURL, unchanged)
			})
		})
	}
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
	c := &Client{apiKey: "fixture"}
	inner := &url.Error{Op: "Get", URL: `http://h/\u0066ixture`, Err: errors.New("transport failure")}
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
			(&redactedError{err: tree}).walk(nil, func(node error) walkAction {
				visits++
				last = node
				return walkDescend
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
	queue, _ = appendWrappedChildren(queue, err)
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
			defer func() {
				if recover() != nil {
					subtest.Error("classification panicked on an unsafe tree")
				}
			}()
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
			opaque := opaqueURLCause{hidden: &redactedError{msg: key, key: key, err: counted}}
			var root error = &opaque
			if want {
				root = &classifiedURLCause{opaqueURLCause: opaque, timeout: true}
			}
			assertOwnedURLCauseClassification(subtest, c.scrubError(root), counted, want)
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
			defer func() {
				if recover() != nil {
					subtest.Error("classification panicked")
				}
			}()
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

// TestRedactedErrorStdlibDelegateBudget checks classifier chains at and beyond the structural limit.
func TestRedactedErrorStdlibDelegateBudget(t *testing.T) {
	t.Parallel()
	for _, tc := range [...]struct {
		name  string
		depth int
		want  bool
	}{
		{"at structural limit", maxErrNodes - 1, true},
		{"over structural limit", maxErrNodes, false},
		{"over walk budget", maxWalkSteps + 1, false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			var cause error = &net.DNSError{IsTimeout: true}
			for range tc.depth {
				cause = &net.OpError{Op: "read", Err: cause}
			}
			assertBoundedClassifications(subtest, &redactedError{key: "maple", err: cause}, tc.want, tc.want)
		})
	}
}

// TestClassifyStdlibNilDelegates checks that absent delegates stop before scheduling children.
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
			node := &net.OpError{Op: "read", Err: tc.cause}
			if action, got := classifyNode(node, "maple", hiddenTimeoutClassifier.Timeout); action != walkStop || got {
				subtest.Errorf("Timeout classification = (%v, %t); want (%v, false)", action, got, walkStop)
			}
			if action, got := classifyNode(node, "maple", hiddenTemporaryClassifier.Temporary); action != walkStop || got {
				subtest.Errorf("Temporary classification = (%v, %t); want (%v, false)", action, got, walkStop)
			}
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
