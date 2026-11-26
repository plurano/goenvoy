package mylar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// TestRedactErrorRootIdentity checks that a root URL error is copied only when sanitizing changes it.
func TestRedactErrorRootIdentity(t *testing.T) {
	t.Parallel()
	const key = "plain-key"
	sentinel := errors.New("fixture transport failure")
	cases := []struct {
		name string
		uerr *url.Error
		keep bool
	}{
		{name: "keyless", uerr: &url.Error{Op: "Get", URL: "http://example.invalid/path?q=1", Err: sentinel}, keep: true},
		{name: "key in URL", uerr: &url.Error{Op: "Get", URL: "http://example.invalid/?apikey=" + key, Err: sentinel}},
		{name: "key in Op", uerr: &url.Error{Op: "Get " + key, URL: "http://example.invalid/", Err: sentinel}},
		{name: "key in cause", uerr: &url.Error{Op: "Get", URL: "http://example.invalid/", Err: fmt.Errorf("fixture %s: %w", key, sentinel)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertRootIdentity(t, &Client{apiKey: key}, tc.uerr, sentinel, tc.keep)
		})
	}
}

// assertRootIdentity checks the identity, cause, and text of a redacted root URL error.
func assertRootIdentity(t *testing.T, c *Client, uerr *url.Error, sentinel error, keep bool) {
	t.Helper()
	got := c.redactError(uerr)
	if same := any(got) == any(uerr); same != keep {
		t.Errorf("same error value = %v; want %v", same, keep)
	}
	// Why: a sanitized root stays a *url.Error copy, not a hidden wrapper, so callers keep Op, URL and Err.
	if clean, ok := got.(*url.Error); !keep && (!ok || clean.Op != c.scrub(uerr.Op)) { //nolint:errorlint // root type wanted, not a tree search
		t.Errorf("redacted root = %T; want a *url.Error copy with a scrubbed Op", got)
	}
	if keep && !errors.Is(got, uerr) {
		t.Error("errors.Is lost the original root URL error")
	}
	if !errors.Is(got, sentinel) {
		t.Error("errors.Is lost the sentinel cause")
	}
	if c.containsKey(got.Error()) {
		t.Errorf("key form leaked: %s", got.Error())
	}
}

// TestAPIErrorJSONFormRedaction checks that a status body holding the JSON-escaped key is scrubbed.
func TestAPIErrorJSONFormRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	const escaped = `fixture\u002dkey`
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := io.Copy(w, strings.NewReader(`{"error":"`+escaped+`"}`)); err != nil {
			t.Errorf("mylar test: write JSON form response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, key, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var out any
	err = c.get(ctx, "fixture", nil, &out)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %v", err)
	}
	if want := "REDACTED"; apiErr.Body != want {
		t.Errorf("body = %q; want %q", apiErr.Body, want)
	}
	if text := apiErr.Error(); strings.Contains(text, key) || strings.Contains(text, escaped) {
		t.Error("key leaked in error text")
	}
}

// TestAPIErrorStatusCanonicalRedaction checks that only status text containing a key is scrubbed.
func TestAPIErrorStatusCanonicalRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	cases := []struct{ name, status, want string }{
		{name: "escaped key", status: "500 fixture%2dkey", want: "REDACTED"},
		{name: "plain status", status: "500 Internal Server Error", want: "500 Internal Server Error"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := responseTextClient(t, key, "fixture failure")
			c.httpClient.Transport = responseStatusTransport{RoundTripper: c.httpClient.Transport, status: tc.status}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err := c.GetIndex(ctx)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected APIError, got %v", err)
			}
			if apiErr.Status != tc.want {
				t.Errorf("status = %q; want %q", apiErr.Status, tc.want)
			}
		})
	}
}

// TestAPIErrorPercentVariantRedaction checks that a status body holding a lower-, upper-, or mixed-case percent-hex key is scrubbed.
func TestAPIErrorPercentVariantRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key~1"
	cases := []struct{ name, spelling string }{
		{name: "lower-case hex", spelling: "fixture%2dkey%7e1"},
		{name: "upper-case hex", spelling: "fixture%2Dkey%7E1"},
		{name: "mixed-case hex", spelling: "fixture%2Dkey%7e1"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			apiErr := percentFormAPIError(t, key, tc.spelling)
			if want := "REDACTED"; apiErr.Body != want {
				t.Errorf("body = %q; want %q", apiErr.Body, want)
			}
			if text := apiErr.Error(); strings.Contains(text, key) || strings.Contains(text, tc.spelling) {
				t.Error("key leaked in error text")
			}
		})
	}
}

// percentFormAPIError returns the APIError for a 500 response whose body echoes spelling.
func percentFormAPIError(t *testing.T, key, spelling string) *APIError {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := io.Copy(w, strings.NewReader("apikey="+spelling)); err != nil {
			t.Errorf("mylar test: write percent form response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, key, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	var out any
	err = c.get(ctx, "fixture", nil, &out)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %v", err)
	}
	return apiErr
}

// temporaryCause is a fixture error whose Temporary method returns a fixed value.
type temporaryCause struct {
	text      string
	temporary bool
}

// Error returns the fixture error text.
func (e temporaryCause) Error() string { return e.text }

// Temporary reports the configured temporary state.
func (e temporaryCause) Temporary() bool { return e.temporary }

// TestRedactedErrorTemporary checks that the wrapper forwards Temporary from the hidden error.
func TestRedactedErrorTemporary(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	c := &Client{apiKey: key}
	cases := []struct {
		name  string
		cause error
		root  bool
		want  bool
	}{
		{name: "temporary cause", cause: temporaryCause{text: "fixture " + key, temporary: true}, want: true},
		{name: "permanent cause", cause: temporaryCause{text: "fixture " + key, temporary: false}, want: false},
		{name: "wrapped temporary cause", cause: fmt.Errorf("fixture %s: %w", key, temporaryCause{text: "fixture cause", temporary: true}), want: true},
		{name: "cause without method", cause: errors.New("fixture " + key), want: false},
		{name: "root url error temporary cause", cause: &url.Error{Op: "Get", URL: "http://example.invalid/", Err: temporaryCause{text: "fixture " + key, temporary: true}}, root: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertTemporaryRedacted(t, c, tc.cause, tc.root, tc.want)
		})
	}
}

// assertTemporaryRedacted checks the wrapper type and Temporary result from scrubError or redactError.
func assertTemporaryRedacted(t *testing.T, c *Client, cause error, root, want bool) {
	t.Helper()
	if root {
		got := c.redactError(cause)
		uerr, ok := got.(*url.Error) //nolint:errorlint // root type assertion wanted, not a tree search
		if !ok {
			t.Fatalf("redactError(%T) = %T; want *url.Error", cause, got)
		}
		if gotTemp := uerr.Temporary(); gotTemp != want {
			t.Errorf("Temporary() = %v; want %v", gotTemp, want)
		}
		return
	}
	got := c.scrubError(cause)
	hidden, ok := got.(*redactedError) //nolint:errorlint // wrapper type assertion wanted
	if !ok {
		t.Fatalf("scrubError(%T) = %T; want *redactedError", cause, got)
	}
	if gotTemp := hidden.Temporary(); gotTemp != want {
		t.Errorf("Temporary() = %v; want %v", gotTemp, want)
	}
}

// TestAPIErrorBodyEscapedForms checks JSON token and plain text redaction through the public client.
func TestAPIErrorBodyEscapedForms(t *testing.T) {
	t.Parallel()
	const key = "fixture-part~token"
	cases := []struct{ name, body, want string }{
		{"raw JSON value", `{"error":"fixture-part~token"}`, `{"error":"REDACTED"}`},
		{"mixed percent and unicode", `{"error":"apikey=fixture%2Dpart\u007etoken"}`, "REDACTED"},
		{"unicode value", `{"error":"fixture\u002dpart~token"}`, "REDACTED"},
		{"unicode object key", `{"fixture\u002dpart~token":"error"}`, "REDACTED"},
		{"unrelated JSON", `{"error":"other"}`, `{"error":"other"}`},
		{"plain text", "before fixture-part~token after", "before REDACTED after"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertAPIErrorEscapedBody(t, key, tc.body, tc.want)
		})
	}
}

// TestAPIErrorBodyEscapeLayers checks mixed escapes, fixpoint convergence, and the decode limit.
func TestAPIErrorBodyEscapeLayers(t *testing.T) {
	t.Parallel()
	const key = "fixture"
	cases := []struct{ name, body, want string }{
		{"percent after Unicode", `{"error":"\u002566ixture"}`, "REDACTED"},
		{"key-free mixed escapes", `{"error":"\u002566able"}`, `{"error":"\u002566able"}`},
		{"key beyond limit", `{"error":"%2525252566ixture"}`, "REDACTED"},
		{"still changing at limit", `{"error":"%25252561ble"}`, "REDACTED"},
		{"stable at limit", `{"error":"%252561ble"}`, `{"error":"%252561ble"}`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertAPIErrorEscapedBody(t, key, tc.body, tc.want)
		})
	}
}

// TestAPIErrorBodyMalformedEscapes checks escaped keys and malformed response bodies.
func TestAPIErrorBodyMalformedEscapes(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, key, body, want string }{
		{"large number", "fixture-part~token", `{"n":1e1000,"error":"fixture\u002dpart~token"}`, "REDACTED"},
		{"scrub breaks escape", "b123456", `{"noise":"\b123456","error":"\u0062123456"}`, "REDACTED"},
		{"large number control", "fixture-part~token", `{"n":1e1000,"error":"none"}`, `{"n":1e1000,"error":"none"}`},
		{"non JSON escaped key", "b123456", `oops \u0062123456`, "REDACTED"},
		{"surrogate pair", "fixture-key", `{"error":"\ud83d\ude00"}`, `{"error":"\ud83d\ude00"}`},
		{"lone surrogate", "fixture-key", `{"error":"\ud800"}`, `{"error":"\ud800"}`},
		{"truncated unicode", "fixture-key", `abc\u00`, `abc\u00`},
		{"truncated slash", "fixture-key", `abc\`, `abc\`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertAPIErrorEscapedBody(t, tc.key, tc.body, tc.want)
		})
	}
}

// TestDecodeBackslashEscapes checks tolerant escape decoding and byte preservation.
func TestDecodeBackslashEscapes(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, input, want string }{
		{"simple escapes", `\"\\\/\b\f\n\r\t`, "\"\\/\b\f\n\r\t"},
		{"unicode hex cases", `\u0062\u00e9\u00E9`, "béé"},
		{"surrogate pair", `\ud83d\ude00`, "😀"},
		{"lowest pair", `\ud800\udc00`, "\U00010000"},
		{"lone high", `\ud800x`, "�x"},
		{"lone low", `\udc00`, "�"},
		{"invalid and incomplete", `\u00xz\u00\q\`, `\u00xz\u00\q\`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if got := decodeEscapes(tc.input, backslashEscapes); got != tc.want {
				t.Errorf("decodeEscapes(%q) = %q; want %q", tc.input, got, tc.want)
			}
			if got := decodeEscapes(tc.input, percentEscapes|backslashEscapes); got != tc.want {
				t.Errorf("mixed decodeEscapes(%q) = %q; want %q", tc.input, got, tc.want)
			}
		})
	}
}

// assertAPIErrorEscapedBody checks the response body and error text from the public client.
func assertAPIErrorEscapedBody(t *testing.T, key, body, want string) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		if _, err := io.Copy(w, strings.NewReader(body)); err != nil {
			t.Errorf("write response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, key, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = c.GetIndex(ctx)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %v", err)
	}
	if apiErr.Body != want {
		t.Errorf("body = %q; want %q", apiErr.Body, want)
	}
	if (&Client{apiKey: key}).containsKey(err.Error()) || (key != "" && strings.Contains(apiErr.Body, key)) {
		t.Error("key leaked")
	}
}

// TestTransportURLPathKeyRedaction checks URL path redaction after a transport failure.
func TestTransportURLPathKeyRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	const escaped = "fixture%2dkey"
	cases := []struct{ name, path string }{
		{"raw path", key},
		{"escaped path", escaped},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertTransportURLPathKeyRedaction(t, key, escaped, tc.path)
		})
	}
}

// assertTransportURLPathKeyRedaction checks the error text and URL after a transport failure.
func assertTransportURLPathKeyRedaction(t *testing.T, key, escaped, path string) {
	t.Helper()
	hc := &http.Client{Transport: redactTransport{err: errors.New("fixture transport failure")}}
	c, err := New("http://example.invalid/"+path, key, WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = c.GetIndex(ctx)
	var uerr *url.Error
	if !errors.As(err, &uerr) {
		t.Fatalf("expected URL error, got %v", err)
	}
	for _, text := range []string{err.Error(), uerr.URL} {
		if strings.Contains(text, key) || strings.Contains(text, escaped) {
			t.Errorf("key leaked: %s", text)
		}
	}
}

// tokenCause is a fixture error with clean message text and an exported key-bearing field.
type tokenCause struct {
	Token   string
	msg     string
	err     error
	timeout bool
}

// Error returns key-free text and dereferences e so a typed-nil call would panic.
func (e *tokenCause) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return "fixture transport cause"
}

// Unwrap returns the wrapped sentinel error.
func (e *tokenCause) Unwrap() error { return e.err }

// Timeout reports whether the fixture cause timed out.
func (e *tokenCause) Timeout() bool { return e.timeout }

// hiddenCauseCase defines one test case for URL error causes recovered via errors.As.
type hiddenCauseCase struct {
	name        string
	cause       error
	sentinel    error
	wantTimeout bool
	wantFixed   bool
}

// TestRedactedErrorAsHidesCause checks that a recovered URL error copy wraps its cause in an opaque error.
func TestRedactedErrorAsHidesCause(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	c := &Client{apiKey: key}
	sentinel := errors.New("fixture transport failure")
	cases := []hiddenCauseCase{
		{name: "wrapped sentinel cause", cause: &tokenCause{Token: key, err: sentinel}, sentinel: sentinel},
		{name: "direct sentinel cause", cause: sentinel, sentinel: sentinel},
		{name: "timeout cause", cause: &tokenCause{Token: key, timeout: true}, wantTimeout: true},
		{name: "nil cause", cause: nil},
		{name: "typed-nil cause", cause: (*tokenCause)(nil), wantFixed: true},
		{name: "wrapped typed-nil cause", cause: fmt.Errorf("wrap: %w", (*tokenCause)(nil)), wantFixed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertHiddenURLCause(t, c, key, tc)
		})
	}
}

// assertHiddenURLCause checks that errors.As on a hidden URL error hides the underlying cause tree.
func assertHiddenURLCause(t *testing.T, c *Client, key string, tc hiddenCauseCase) {
	t.Helper()
	hidden := c.redactError(fmt.Errorf("outer: %w", &url.Error{Op: "Get", URL: "http://example.invalid/?apikey=" + key, Err: tc.cause}))
	var uerr *url.Error
	if !errors.As(hidden, &uerr) || uerr == nil {
		t.Fatal("errors.As into *url.Error = false or nil; want non-nil")
	}
	if c.containsKey(uerr.Error()) || strings.Contains(uerr.Error(), key) {
		t.Errorf("uerr.Error() leaked key: %s", uerr.Error())
	}
	if tc.cause == nil {
		if uerr.Err != nil {
			t.Errorf("copied cause = %T; want nil", uerr.Err)
		}
		return
	}
	if uerr.Err == nil {
		t.Fatal("sanitized URL error lost its cause")
	}
	assertOpaqueURLCause(t, uerr, tc)
}

// assertOpaqueURLCause checks that a non-nil URL error cause is opaque while preserving Is and Timeout.
func assertOpaqueURLCause(t *testing.T, uerr *url.Error, tc hiddenCauseCase) {
	t.Helper()
	if tc.wantFixed && uerr.Err.Error() != redactedTreeMsg {
		t.Error("unsafe copied cause did not use the fixed message")
	}
	if _, ok := uerr.Err.(*tokenCause); ok { //nolint:errorlint // verify direct type assertion on uerr.Err fails
		t.Error("uerr.Err exposed *tokenCause")
	}
	if _, ok := errors.Unwrap(uerr).(*tokenCause); ok { //nolint:errorlint // verify type assertion on errors.Unwrap(uerr) fails
		t.Error("errors.Unwrap(uerr) exposed *tokenCause")
	}
	var typedCause *tokenCause
	if errors.As(uerr.Err, &typedCause) {
		t.Errorf("errors.As(uerr.Err, &typedCause) = true (%v); want false", typedCause)
	}
	if tc.sentinel != nil && !errors.Is(uerr, tc.sentinel) {
		t.Error("errors.Is(uerr, sentinel) = false; want true")
	}
	if uerr.Timeout() != tc.wantTimeout {
		t.Errorf("uerr.Timeout() = %v; want %v", uerr.Timeout(), tc.wantTimeout)
	}
}

// TestCanonicalKeyRedaction checks escaped keys in error text and API response bodies.
func TestCanonicalKeyRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key"
	cases := []struct{ name, key, text, want string }{
		{"lowercase percent", key, "before fixture%2dkey after", "REDACTED"},
		{"uppercase percent", key, "before fixture%2Dkey after", "REDACTED"},
		{"unicode escape", key, `before fixture\u002dkey after`, "REDACTED"},
		{"mixed escapes", key, `before fixture%2d\u006bey after`, "REDACTED"},
		{"prefix only", key, "before fixture%2dke after", "before fixture%2dke after"},
		{"empty key", "", `before fixture%2d\u006bey after`, `before fixture%2d\u006bey after`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{apiKey: tc.key}
			raw := errors.New(tc.text)
			if got := c.containsKey(tc.text); got != (tc.text != tc.want) {
				t.Errorf("containsKey = %v; want %v", got, tc.text != tc.want)
			}
			if got := c.scrubError(raw).Error(); got != tc.want {
				t.Errorf("scrubError = %q; want %q", got, tc.want)
			}
			if got := c.hideCause(raw).Error(); got != tc.want {
				t.Errorf("hideCause = %q; want %q", got, tc.want)
			}
			assertAPIErrorEscapedBody(t, tc.key, tc.text, tc.want)
		})
	}
}
