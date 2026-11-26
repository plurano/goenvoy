package jackett

import (
	"context"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
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

// TestRedactErrorSameKeyWrapperIdentity checks repeated redaction and URL recovery.
func TestRedactErrorSameKeyWrapperIdentity(t *testing.T) {
	t.Parallel()
	client := &Client{apiKey: "maple"}
	for _, tc := range [...]struct {
		name, key string
		wrap      bool
		keep      bool
	}{
		{"same-key wrapper", "maple", false, true},
		{"same-key wrapper in chain", "maple", true, true},
		{"foreign-key wrapper in chain", "cedar", true, false},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			owner := &Client{apiKey: tc.key}
			input := owner.redactError(fmt.Errorf("fixture op: %w", &url.Error{
				Op: "Get", URL: "http://h/feed?apikey=" + tc.key, Err: io.EOF,
			}))
			if tc.wrap {
				input = fmt.Errorf("fixture again: %w", input)
			}
			got := client.redactError(input)
			if same := any(got) == any(input); same != tc.keep {
				subtest.Errorf("same error value = %t; want %t", same, tc.keep)
			}
			wantURL := ""
			if tc.keep {
				wantURL = wrapperFixtureRedactedURL
			}
			assertSameKeyWrapperURL(subtest, got, wantURL)
		})
	}
}

// TestRedactErrorSameKeyWrapperOuterText checks that a same-key wrapper does not exempt outer text.
func TestRedactErrorSameKeyWrapperOuterText(t *testing.T) {
	t.Parallel()
	const key = "maple"
	client := &Client{apiKey: key}
	inner := client.redactError(fmt.Errorf("fixture %s: %w", key, io.EOF))
	input := fmt.Errorf("fixture %s: %w", key, inner)
	got := client.redactError(input)
	if got == nil {
		t.Fatal("redactError returned nil for the key-bearing outer error")
	}
	if any(got) == any(input) {
		t.Error("redactError kept the key-bearing outer error")
	}
	if text := got.Error(); text != "fixture REDACTED: fixture REDACTED: EOF" {
		t.Errorf("redactError text = %q; want fixture REDACTED: fixture REDACTED: EOF", text)
	}
	for _, text := range [...]string{fmt.Sprint(got), fmt.Sprintf("%+v", got), fmt.Sprintf("%#v", got)} {
		assertNoKeyForms(t, text, key)
	}
}

const (
	wrapperFixtureURL         = "http://h/feed"
	wrapperFixtureRedactedURL = wrapperFixtureURL + "?apikey=REDACTED"
)

type redactWrapperField struct{ Cause error }

// Error returns fixture text independent of the wrapped error.
func (*redactWrapperField) Error() string { return "fixture exported cause" }

// Unwrap returns the cause also visible through reflection.
func (e *redactWrapperField) Unwrap() error { return e.Cause }

type redactWrapperTimeout struct {
	redactFixtureCause
	redactClassifier
}

// TestRedactErrorOwnedWrapperPositions checks each wrapper type, key, and position.
func TestRedactErrorOwnedWrapperPositions(t *testing.T) {
	t.Parallel()
	client := &Client{apiKey: "maple"}
	for _, key := range [...]string{"maple", "cedar"} {
		t.Run(key, func(keyTest *testing.T) {
			keyTest.Parallel()
			owner := &Client{apiKey: key}
			rawURL := wrapperFixtureURL + "?apikey=" + key
			wrapped := owner.redactError(fmt.Errorf("fixture op: %w", &url.Error{Op: "Get", URL: rawURL, Err: io.EOF}))
			timeout := redactWrapperTimeout{redactFixtureCause: redactFixtureCause{error: io.EOF}}
			for _, wrapper := range [...]struct {
				name, recoveredURL string
				err                error
			}{
				{"redacted", wrapperFixtureRedactedURL, wrapped},
				{"opaque URL cause", "", redactWrapperFixtureCause[*opaqueURLCause](keyTest, owner, rawURL, io.EOF)},
				{"classified URL cause", "", redactWrapperFixtureCause[*classifiedURLCause](keyTest, owner, rawURL, timeout)},
			} {
				keyTest.Run(wrapper.name, func(wrapperTest *testing.T) {
					wrapperTest.Parallel()
					assertOwnedWrapperPositions(wrapperTest, client, wrapper.err, key == client.apiKey, wrapper.recoveredURL)
				})
			}
		})
	}
	t.Run("external formatter", testExternalFormatterPositions)
}

// redactWrapperFixtureCause returns the sanitized cause of a URL error containing the owner's key.
func redactWrapperFixtureCause[T error](t *testing.T, owner *Client, rawURL string, cause error) T {
	t.Helper()
	input := &url.Error{Op: "Get", URL: rawURL, Err: cause}
	copied, ok := owner.redactError(input).(*url.Error) //nolint:errorlint // require the direct URL copy
	if !ok || copied == input || copied.URL != wrapperFixtureRedactedURL {
		t.Fatal("redactError did not return a sanitized URL copy")
	}
	sanitized, ok := copied.Err.(T) //nolint:errorlint // check the direct URL cause kind
	if !ok {
		t.Fatalf("copied cause = %T; want %T", copied.Err, sanitized)
	}
	return sanitized
}

// assertOwnedWrapperPositions checks identity and URL recovery at each wrapper position.
func assertOwnedWrapperPositions(t *testing.T, client *Client, wrapped error, keep bool, recoveredURL string) {
	t.Helper()
	if !keep {
		recoveredURL = ""
	}
	for _, position := range [...]struct {
		name, wantURL string
		input         error
	}{
		{"root", recoveredURL, wrapped},
		{"wrapped chain", recoveredURL, fmt.Errorf("fixture again: %w", wrapped)},
		{"URL cause", wrapperFixtureURL, &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: wrapped}},
		{"exported field", recoveredURL, &redactWrapperField{Cause: wrapped}},
	} {
		t.Run(position.name, func(subtest *testing.T) {
			subtest.Parallel()
			got := client.redactError(position.input)
			if got == nil {
				subtest.Fatal("redactError returned nil for the wrapper position")
			}
			if same := any(got) == any(position.input); same != keep {
				subtest.Errorf("same error value = %t; want %t", same, keep)
			}
			exposed := assertSameKeyWrapperURL(subtest, got, position.wantURL)
			if !keep && exposed != nil {
				assertSameKeyWrapperURL(subtest, exposed.Err, "")
			}
		})
	}
}

// testExternalFormatterPositions checks that an external formatter remains opaque.
func testExternalFormatterPositions(t *testing.T) {
	t.Parallel()
	client := &Client{apiKey: "maple"}
	formatter := &redactFixtureFormatter{cause: io.EOF, text: "fixture maple formatting"}
	reflected := &redactReflectFieldError{Formatter: formatter}
	for _, tc := range [...]struct {
		name  string
		input error
	}{
		{"URL cause", &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: formatter}},
		{"exported field", &redactWrapperField{Cause: formatter}},
		{"URL cause with reflected formatter", &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: reflected}},
		{"exported field with reflected formatter", &redactWrapperField{Cause: reflected}},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			got := client.redactError(tc.input)
			if any(got) == any(tc.input) {
				subtest.Error("redactError kept an error containing an external formatter")
			}
			assertNoKeyForms(subtest, fmt.Sprintf("%#v", got), "maple")
		})
	}
}

type redactIdempotentCase struct {
	name, wantText             string
	input                      error
	wantURL                    *url.Error
	keep, fixedCause           bool
	wantTimeout, wantTemporary bool
}

// TestRedactErrorIdempotent checks the first result and that a second pass keeps it.
func TestRedactErrorIdempotent(t *testing.T) {
	t.Parallel()
	client := &Client{apiKey: "maple"}
	foreign := (&Client{apiKey: "cedar"}).redactError(fmt.Errorf("fixture cedar: %w", io.EOF))
	timeout := redactWrapperTimeout{redactFixtureCause: redactFixtureCause{error: io.EOF}}
	var leaves [maxErrNodes]error
	for index := range leaves {
		leaves[index] = io.EOF
	}
	for _, tc := range [...]redactIdempotentCase{
		{
			name:    "key in URL",
			input:   &url.Error{Op: "Get", URL: wrapperFixtureURL + "?apikey=maple", Err: io.EOF},
			wantURL: &url.Error{Op: "Get", URL: wrapperFixtureRedactedURL, Err: io.EOF},
		},
		{
			name:    "key in Op",
			input:   &url.Error{Op: "Get maple", URL: wrapperFixtureURL, Err: io.EOF},
			wantURL: &url.Error{Op: "Get REDACTED", URL: wrapperFixtureURL, Err: io.EOF},
		},
		{name: "key in error text", input: errors.New("fixture maple cause"), wantText: "fixture REDACTED cause"},
		{name: "key in joined error", input: errors.Join(io.EOF, errors.New("fixture maple cause")), wantText: "EOF\nfixture REDACTED cause"},
		{name: "clean error", input: io.EOF, keep: true, wantText: "EOF"},
		{
			name: "clean URL", input: &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: io.EOF}, keep: true,
			wantURL: &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: io.EOF},
		},
		{
			name:          "URL copy with timeout",
			input:         &url.Error{Op: "Get", URL: wrapperFixtureURL + "?apikey=maple", Err: timeout},
			wantURL:       &url.Error{Op: "Get", URL: wrapperFixtureRedactedURL, Err: io.EOF},
			wantTimeout:   true,
			wantTemporary: true,
		},
		{
			name:       "URL with typed-nil cause",
			input:      &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: (*redactNilTimeoutCause)(nil)},
			wantURL:    &url.Error{Op: "Get", URL: wrapperFixtureURL, Err: errors.New(redactedTreeMsg)},
			fixedCause: true,
		},
		{name: "over-limit tree", input: errors.Join(leaves[:]...), wantText: redactedTreeMsg},
		{name: "foreign-key wrapper", input: foreign, wantText: "fixture REDACTED: EOF"},
	} {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			first := client.redactError(tc.input)
			assertFirstRedaction(subtest, first, tc)
			if second := client.redactError(first); any(second) != any(first) {
				subtest.Errorf("second redaction returned %T; want the first %T value", second, first)
			}
		})
	}
}

// assertFirstRedaction checks first-pass identity, URL recovery, and exact text.
func assertFirstRedaction(t *testing.T, got error, tc redactIdempotentCase) {
	t.Helper()
	if same := any(got) == any(tc.input); same != tc.keep {
		t.Errorf("first redaction kept the input = %t; want %t", same, tc.keep)
	}
	wantText := tc.wantText
	if tc.wantURL != nil {
		assertFirstRedactionURL(t, got, tc)
		wantText = tc.wantURL.Error()
	}
	if got == nil || got.Error() != wantText {
		t.Errorf("first redaction text = %v; want %q", got, wantText)
	}
}

// assertFirstRedactionURL checks the first URL result's fields and classification.
func assertFirstRedactionURL(t *testing.T, got error, tc redactIdempotentCase) {
	t.Helper()
	copied, ok := got.(*url.Error) //nolint:errorlint // check the direct URL result
	if !ok || copied == nil || copied.Op != tc.wantURL.Op || copied.URL != tc.wantURL.URL {
		t.Fatalf("first redaction returned %T (%v); want Op %q and URL %q", got, got, tc.wantURL.Op, tc.wantURL.URL)
	}
	if tc.fixedCause {
		assertObservedRootCause(t, copied.Err, true)
	}
	if timedOut, temporary := copied.Timeout(), copied.Temporary(); timedOut != tc.wantTimeout || temporary != tc.wantTemporary {
		t.Errorf("URL copy Timeout() = %t, Temporary() = %t; want %t, %t", timedOut, temporary, tc.wantTimeout, tc.wantTemporary)
	}
}

// assertSameKeyWrapperURL checks sanitized URL recovery across the wrapper.
func assertSameKeyWrapperURL(t *testing.T, got error, wantURL string) *url.Error {
	t.Helper()
	var exposed *url.Error
	want := wantURL != ""
	if found := errors.As(got, &exposed); found != want {
		t.Errorf("errors.As found a URL error = %t; want %t", found, want)
	} else if found && (exposed == nil || exposed.URL != wantURL) {
		t.Errorf("exposed URL error = %v; want URL %q", exposed, wantURL)
	}
	return exposed
}

// assertRootIdentity checks the identity, cause, and text of a redacted root URL error.
func assertRootIdentity(t *testing.T, c *Client, uerr *url.Error, sentinel error, keep bool) {
	t.Helper()
	op, want := uerr.Op, uerr.Err
	fields := [2]string{op, uerr.URL}
	got := c.redactError(uerr)
	if [2]string{uerr.Op, uerr.URL} != fields || uerr.Err != want { //nolint:errorlint // require the exact original cause
		t.Error("redactError modified the input URL error")
	}
	if same := any(got) == any(uerr); same != keep {
		t.Errorf("same error value = %v; want %v", same, keep)
	}
	if keep {
		if !errors.Is(got, uerr) {
			t.Error("errors.Is lost the original root URL error")
		}
	} else {
		clean, ok := got.(*url.Error) //nolint:errorlint // require the root type directly
		if !ok || clean.Op != c.scrub(op) {
			t.Fatalf("redacted root = %T; want a *url.Error copy with a scrubbed Op", got)
		}
		assertRedactedRootCause(t, clean, uerr, want)
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
			t.Errorf("jackett test: write JSON form response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, key, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = c.doRequest(ctx, srv.URL+"/fixture")
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
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			}))
			t.Cleanup(srv.Close)
			client := srv.Client()
			client.Transport = statusRewriteTransport{RoundTripper: client.Transport, status: tc.status}
			c, err := New(srv.URL, key, WithHTTPClient(client))
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			_, err = c.GetIndexers(ctx)
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
			t.Errorf("jackett test: write percent form response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, key, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = c.doRequest(ctx, srv.URL+"/fixture")
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
		{name: "root url error temporary cause", cause: &url.Error{Op: "Get", URL: "http://example.invalid/", Err: &temporaryCause{text: "fixture " + key, temporary: true}}, root: true, want: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertTemporaryRedacted(t, c, tc.cause, tc.root, tc.want)
		})
	}
}

// assertTemporaryRedacted checks the wrapper type and Temporary result from scrubError or redactError.
func assertTemporaryRedacted(t *testing.T, c *Client, cause error, root, wantTemporary bool) {
	t.Helper()
	if root {
		original, isURL := cause.(*url.Error) //nolint:errorlint // inspect the fixture root, not its error tree
		if !isURL {
			t.Fatalf("root fixture has type %T; want *url.Error", cause)
		}
		want := original.Err
		got := c.redactError(cause)
		uerr, ok := got.(*url.Error) //nolint:errorlint // root type assertion wanted, not a tree search
		if !ok {
			t.Fatalf("redactError(%T) = %T; want *url.Error", cause, got)
		}
		assertRedactedRootCause(t, uerr, original, want)
		if gotTemp := uerr.Temporary(); gotTemp != wantTemporary {
			t.Errorf("Temporary() = %v; want %v", gotTemp, wantTemporary)
		}
		return
	}
	got := c.scrubError(cause)
	hidden, ok := got.(*redactedError) //nolint:errorlint // wrapper type assertion wanted
	if !ok {
		t.Fatalf("scrubError(%T) = %T; want *redactedError", cause, got)
	}
	if gotTemp := hidden.Temporary(); gotTemp != wantTemporary {
		t.Errorf("Temporary() = %v; want %v", gotTemp, wantTemporary)
	}
}

// assertRedactedRootCause checks that the copied root wraps its original cause.
func assertRedactedRootCause(t *testing.T, got, original *url.Error, want error) {
	t.Helper()
	if got == original {
		t.Fatal("redactError returned the original *url.Error")
	}
	if original.Err != want { //nolint:errorlint // require the original cause instance
		t.Error("redactError changed the original URL error's cause")
	}
	hidden := hiddenRedaction(got.Err)
	if hidden == nil {
		t.Fatalf("redacted root cause has type %T; want a package redaction wrapper", got.Err)
	}
	if hidden.err != want { //nolint:errorlint // require the original cause instance
		t.Error("redacted root wrapper does not retain the original cause")
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
	percentAfterUnicode := testUnicodeEscape('%') + testPercentEscape(key[0])[1:] + key[1:]
	beyondLimit := testLayeredPercentEscape(key[0], maxDecodePasses+1) + key[1:]
	cases := []struct{ name, body, want string }{
		{"percent after Unicode", `{"error":"` + percentAfterUnicode + `"}`, "REDACTED"},
		{"key-free mixed escapes", `{"error":"\u002566able"}`, `{"error":"\u002566able"}`},
		{"percent layers beyond limit", `{"error":"` + beyondLimit + `"}`, "REDACTED"},
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

// TestAPIErrorBodyScrubKeepsEscapedKey checks redaction when inline replacement leaves an escaped key.
func TestAPIErrorBodyScrubKeepsEscapedKey(t *testing.T) {
	t.Parallel()
	const splitKey, slashKey = `ab`, `a\`
	splitUnicode := `{"x":"\u00` + splitKey + `","y":"` + testUnicodeEscape(splitKey[0]) + testUnicodeEscape(splitKey[1]) + `"}`
	slashUnicode := `{"v":"` + slashKey[:1] + `\\` + testUnicodeEscape(slashKey[0]) + testUnicodeEscape(slashKey[1]) + `"}`
	cases := []struct{ name, key, body, want string }{
		{"split unicode escape", splitKey, splitUnicode, "REDACTED"},
		{"escaped backslash before encoded key", slashKey, slashUnicode, "REDACTED"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertAPIErrorEscapedBody(t, tc.key, tc.body, tc.want)
		})
	}
}

// testUnicodeEscape spells a fixture byte as an ASCII Unicode escape.
func testUnicodeEscape(b byte) string { return fmt.Sprintf(`\u%04x`, b) }

// testPercentEscape spells a fixture byte as a percent escape.
func testPercentEscape(b byte) string { return fmt.Sprintf("%%%02x", b) }

// testLayeredPercentEscape re-encodes the leading percent sign for each additional layer.
func testLayeredPercentEscape(b byte, layers int) string {
	spelling := testPercentEscape(b)
	for range layers - 1 {
		spelling = testPercentEscape(spelling[0]) + spelling[1:]
	}
	return spelling
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
	c, err := New(srv.URL, "", WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	// Why: fixture key injection tests body redaction independently of constructor validation.
	c.apiKey = key
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = c.Search(ctx, "", nil)
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

// redactionTransport adapts a fixture function to http.RoundTripper.
type redactionTransport func(*http.Request) (*http.Response, error)

// RoundTrip returns the configured fixture response or error.
func (f redactionTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

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
	hc := &http.Client{Transport: redactionTransport(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("fixture transport failure")
	})}
	c, err := New("http://example.invalid/"+path, key, WithHTTPClient(hc))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = c.Search(ctx, "", nil)
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
			if got := c.hideURLCause(raw, false).Error(); got != tc.want {
				t.Errorf("hideURLCause = %q; want %q", got, tc.want)
			}
			assertAPIErrorEscapedBody(t, tc.key, tc.text, tc.want)
		})
	}
}

// TestAPIErrorStatusCodeEcho checks rendered redaction and raw status on errors returned by the client.
func TestAPIErrorStatusCodeEcho(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, key, body, want string }{
		{"echo_empty", "418", "", "HTTP REDACTED"},
		{"echo_body", "418", "nope", "HTTP REDACTED: nope"},
		{"different_key", "abc", "", "HTTP 418"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			c := statusCodeEchoClient(subtest, tc.key, tc.body, http.StatusTeapot)
			ctx, cancel := context.WithTimeout(subtest.Context(), 5*time.Second)
			defer cancel()
			_, err := c.GetIndexers(ctx)
			assertStatusCodeEcho(subtest, err, http.StatusTeapot, tc.want)
		})
	}
}

// TestAPIErrorStatusCodeEchoCallerBuilt checks the raw status fallback for caller-built errors.
func TestAPIErrorStatusCodeEchoCallerBuilt(t *testing.T) {
	t.Parallel()
	cases := []struct{ name, body, want string }{
		{"empty", "", "HTTP 500"},
		{"body", "nope", "HTTP 500: nope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(subtest *testing.T) {
			subtest.Parallel()
			err := &APIError{StatusCode: http.StatusInternalServerError, Body: tc.body}
			assertStatusCodeEcho(subtest, err, http.StatusInternalServerError, tc.want)
		})
	}
}

// statusCodeEchoClient starts a fixture server with the given status and body.
func statusCodeEchoClient(t *testing.T, key, body string, code int) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		if _, err := io.WriteString(w, body); err != nil {
			t.Errorf("write fixture response: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, key, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatalf("create fixture client: %v", err)
	}
	return c
}

// assertStatusCodeEcho checks the error type, raw status, and complete rendered message.
func assertStatusCodeEcho(t *testing.T, err error, code int, want string) {
	t.Helper()
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("expected APIError, got %v", err)
	}
	if apiErr.StatusCode != code {
		t.Errorf("StatusCode = %d, want %d", apiErr.StatusCode, code)
	}
	if got, fullWant := err.Error(), "jackett: "+want; got != fullWant {
		t.Errorf("Error() = %q, want %q", got, fullWant)
	}
}

// TestAPIErrorLiteralsSetStatusText checks that package literals initialize the rendered status code.
func TestAPIErrorLiteralsSetStatusText(t *testing.T) {
	t.Parallel()
	const maxEntries = 128
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read module directory: %v", err)
	}
	if len(entries) > maxEntries {
		t.Fatalf("module directory exceeds %d entries", maxEntries)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		files := token.NewFileSet()
		for _, pos := range apiErrorLiteralsMissingStatusText(t, files, name, nil) {
			t.Errorf("%s: APIError literal is missing statusText", files.Position(pos))
		}
	}
}

// TestAPIErrorLiteralsSetStatusTextFixture checks the scanner on both literal forms.
func TestAPIErrorLiteralsSetStatusTextFixture(t *testing.T) {
	t.Parallel()
	const source = `package fixture
var missing = &APIError{StatusCode: 418}
var set = APIError{StatusCode: 418, statusText: "REDACTED"}
`
	files := token.NewFileSet()
	positions := apiErrorLiteralsMissingStatusText(t, files, "fixture.go", source)
	if len(positions) != 1 {
		t.Fatalf("reported %d literals, want 1", len(positions))
	}
	if line := files.Position(positions[0]).Line; line != 2 {
		t.Errorf("reported literal at line %d, want line 2", line)
	}
}

// apiErrorLiteralsMissingStatusText finds APIError literals missing the rendered status code.
func apiErrorLiteralsMissingStatusText(t *testing.T, files *token.FileSet, name string, source any) []token.Pos {
	t.Helper()
	const maxNodes = 100_000
	parsed, err := parser.ParseFile(files, name, source, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", name, err)
	}
	var missing []token.Pos
	nodes := 0
	for node := range ast.Preorder(parsed) {
		nodes++
		if nodes > maxNodes {
			t.Fatalf("%s exceeds %d AST nodes", name, maxNodes)
		}
		literal, ok := node.(*ast.CompositeLit)
		if ok && isAPIErrorWithoutStatusText(literal) {
			missing = append(missing, literal.Pos())
		}
	}
	return missing
}

// isAPIErrorWithoutStatusText reports whether a literal names APIError and omits statusText.
func isAPIErrorWithoutStatusText(literal *ast.CompositeLit) bool {
	name, ok := literal.Type.(*ast.Ident)
	if !ok || name.Name != "APIError" {
		return false
	}
	return !slices.ContainsFunc(literal.Elts, func(element ast.Expr) bool {
		field, keyed := element.(*ast.KeyValueExpr)
		if !keyed {
			return false
		}
		fieldName, named := field.Key.(*ast.Ident)
		return named && fieldName.Name == "statusText"
	})
}
