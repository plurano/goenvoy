package mylar

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"syscall"
	"testing"
	"time"
)

type redactTransport struct{ err error }

// RoundTrip returns the fixture error without sending a request.
func (r redactTransport) RoundTrip(*http.Request) (*http.Response, error) { return nil, r.err }

type redactTimeout struct{ error }

// Unwrap returns the fixture cause.
func (e redactTimeout) Unwrap() error { return e.error }

// Timeout reports the fixture timeout.
func (redactTimeout) Timeout() bool { return true }

// TestRequestRedaction checks transport, timeout, and status error sanitization.
func TestRequestRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	sentinel := errors.New("fixture transport failure")
	sensitive := fmt.Errorf("raw %s escaped %s: %w", key, url.QueryEscape(key), sentinel)
	cases := []struct {
		name      string
		closed    bool
		transport http.RoundTripper
		timeout   bool
	}{
		{name: "closed server", closed: true},
		{name: "custom transport", transport: redactTransport{err: sensitive}},
		{name: "timeout", transport: redactTransport{err: redactTimeout{error: sensitive}}, timeout: true},
		{name: "status body"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkRequestRedaction(t, key, sentinel, tc.closed, tc.transport, tc.timeout)
		})
	}
}

// checkRequestRedaction checks redaction and error kinds using the configured fixture.
func checkRequestRedaction(t *testing.T, key string, sentinel error, closed bool, transport http.RoundTripper, timedOut bool) {
	t.Helper()
	baseURL, client := redactionEndpoint(t, key, closed)
	if transport != nil {
		client.Transport = transport
	}
	c, err := New(baseURL, key, WithHTTPClient(client))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	_, err = c.GetIndex(ctx)
	assertRedactedTree(t, err, key)
	assertRedactionKind(t, err, sentinel, closed, transport, timedOut)
}

// redactionEndpoint supplies a response server or a deterministic dial failure.
func redactionEndpoint(t *testing.T, key string, dialFailure bool) (string, *http.Client) {
	t.Helper()
	if dialFailure {
		transport := redactTransport{err: &net.OpError{Op: "dial", Net: "tcp", Err: syscall.ECONNREFUSED}}
		return "http://example.invalid", &http.Client{Transport: transport}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		body := fmt.Sprintf("raw %s escaped %s", key, url.QueryEscape(key))
		if _, err := io.Copy(w, strings.NewReader(body)); err != nil {
			t.Errorf("mylar test: write redaction response: %v", err)
		}
	}))
	t.Cleanup(server.Close)
	return server.URL, server.Client()
}

// Why: sentinel, timeout, and status contracts survive text sanitization.
func assertRedactionKind(t *testing.T, err, sentinel error, closed bool, transport http.RoundTripper, timedOut bool) {
	t.Helper()
	if transport != nil && !errors.Is(err, sentinel) {
		t.Error("sentinel match lost")
	}
	if timedOut {
		var timeout interface{ Timeout() bool }
		if !errors.As(err, &timeout) || !timeout.Timeout() {
			t.Error("timeout lost")
		}
	}
	if !closed && transport == nil {
		var apiErr *APIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode != http.StatusInternalServerError {
			t.Errorf("expected HTTP 500 APIError, got %v", err)
		}
	}
}

// Why: inspect every reachable error and diagnostic format for fixture key text.
func assertRedactedTree(t *testing.T, err error, key string) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Error("redaction marker missing")
	}
	queue := []error{err}
	for i := 0; i < len(queue) && i < 256; i++ {
		current := queue[i]
		text := fmt.Sprintf("%v %+v %#v", current, current, current)
		if strings.Contains(text, key) || strings.Contains(text, url.QueryEscape(key)) {
			t.Errorf("key leaked: %s", text)
		}
		if child := errors.Unwrap(current); child != nil {
			queue = append(queue, child)
		}
		if joined, ok := current.(interface{ Unwrap() []error }); ok {
			queue = append(queue, joined.Unwrap()...)
		}
	}
	if len(queue) > 256 {
		t.Fatal("error tree exceeded test bound")
	}
}

// TestScrub checks repeated literal, empty, and absent key text.
func TestScrub(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	cases := []struct {
		name, key, input, want string
		contains               bool
	}{
		{"empty key", "", "unchanged", "unchanged", false},
		{"absent key", key, "unchanged", "unchanged", false},
		{"repeated literal", key, key + ":" + key, "REDACTED:REDACTED", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{apiKey: tc.key}
			if got := c.scrub(tc.input); got != tc.want {
				t.Errorf("scrub = %q, want %q", got, tc.want)
			}
			if got := c.containsKey(tc.input); got != tc.contains {
				t.Errorf("containsKey = %t, want %t", got, tc.contains)
			}
		})
	}
}

// TestWideErrorTree checks fail-closed handling beyond the traversal bound.
func TestWideErrorTree(t *testing.T) {
	t.Parallel()
	for _, count := range []int{maxErrNodes - 1, 64, 65, 256} {
		children := make([]error, count)
		for i := range children {
			children[i] = errors.New("fixture plain error")
		}
		joined := errors.Join(children...)
		c := &Client{apiKey: "fixture-key42"}
		got := c.scrubError(joined)
		if count == maxErrNodes-1 {
			assertVisibleErrorTree(t, got, children[0])
			continue
		}
		hidden, ok := got.(*redactedError) //nolint:errorlint // require the wrapper itself without traversing the tree
		if !ok || hidden == nil || errors.Unwrap(hidden) != nil {
			t.Fatal("wide tree exposed")
		}
		if hidden.Error() != redactedTreeMsg {
			t.Errorf("Error() = %q; want %q", hidden.Error(), redactedTreeMsg)
		}
		if !errors.Is(hidden, children[0]) {
			t.Error("sentinel match lost")
		}
	}
}

// assertVisibleErrorTree checks visibility and sentinel matching below the node bound.
func assertVisibleErrorTree(t *testing.T, got, sentinel error) {
	t.Helper()
	var hidden *redactedError
	if errors.As(got, &hidden) {
		t.Fatal("below-bound tree hidden")
	}
	if !errors.Is(got, sentinel) {
		t.Error("below-bound sentinel match lost")
	}
}

// TestRedactError checks root URL sanitization without discarding outer error trees.
func TestRedactError(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	c := &Client{apiKey: key}
	inner := errors.New("fixture inner sentinel")
	uerr := &url.Error{Op: "Get", URL: "http://example.invalid/?apikey=" + url.QueryEscape(key), Err: inner}
	keyless := errors.Join(io.ErrUnexpectedEOF, errors.New("fixture plain error"))
	cases := []struct {
		name      string
		err       error
		sentinel  error
		hasURL    bool
		unchanged bool
	}{
		{name: "root URL", err: uerr, sentinel: inner, hasURL: true},
		{name: "joined URL", err: errors.Join(io.ErrUnexpectedEOF, uerr), sentinel: io.ErrUnexpectedEOF, hasURL: true},
		{name: "wrapped URL", err: fmt.Errorf("read: %w", uerr), sentinel: inner, hasURL: true},
		{name: "keyless join", err: keyless, sentinel: io.ErrUnexpectedEOF, unchanged: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := c.redactError(tc.err)
			assertNoKey(t, got.Error(), key)
			assertSentinel(t, got, tc.sentinel)
			assertMatchedURLError(t, got, key, tc.hasURL)
			if same := any(got) == any(tc.err); same != tc.unchanged {
				t.Errorf("same error value = %v; want %v", same, tc.unchanged)
			}
		})
	}
}

// assertMatchedURLError checks whether errors.As reaches a sanitized *url.Error.
func assertMatchedURLError(t *testing.T, got error, key string, wantURL bool) {
	t.Helper()
	var matched *url.Error
	if isURL := errors.As(got, &matched); isURL != wantURL {
		t.Errorf("URL error reachable = %v; want %v", isURL, wantURL)
	}
	if wantURL {
		if matched == nil {
			t.Fatal("matched URL error = nil; want non-nil")
		}
		assertNoKey(t, matched.URL, key)
	}
}

// assertSentinel checks that error redaction preserves the expected cause.
func assertSentinel(t *testing.T, got, sentinel error) {
	t.Helper()
	if !errors.Is(got, sentinel) {
		t.Error("lost sentinel")
	}
}

// TestNewRedaction checks constructor errors with keys embedded in invalid URLs.
func TestNewRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	const escaped = "fixture%2Dkey42"
	for _, base := range []string{"http://%zz/", "ftp://example.invalid/", "https:///"} {
		t.Run(base, func(t *testing.T) {
			t.Parallel()
			c, err := New(base+"?raw="+key+"&escaped="+escaped, key)
			if c != nil || err == nil {
				t.Fatalf("New = %v, %v; want nil client and error", c, err)
			}
			assertNoKey(t, err.Error(), key)
			if strings.Contains(err.Error(), escaped) {
				t.Error("constructor error leaked the percent-escaped key")
			}
		})
	}
}

// TestNewRedactsForeignQueryKey checks that constructor errors strip a query apikey different from the client key.
func TestNewRedactsForeignQueryKey(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, baseURL, key string
	}{
		{name: "unsupported scheme", baseURL: "ftp://example.invalid/?apikey=other", key: "k"},
		{name: "parse failure", baseURL: "http://%zz/?apikey=other", key: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(tc.baseURL, tc.key)
			if c != nil || err == nil {
				t.Fatalf("New(%q) = %v, %v; want nil client and error", tc.baseURL, c, err)
			}
			if strings.Contains(err.Error(), "other") {
				t.Errorf("error leaked query key: %s", err.Error())
			}
		})
	}
}

// TestNewDropsUserinfo checks that constructor errors return a fixed message and omit userinfo and keys.
func TestNewDropsUserinfo(t *testing.T) {
	t.Parallel()
	const key = "fixture-userinfo-key"
	cases := []struct {
		name, baseURL, secret string
	}{
		{name: "password equal to key with query", baseURL: "ftp://user:fixture-userinfo-key@example.invalid/?apikey=fixture-userinfo-key", secret: key},
		{name: "foreign password with query", baseURL: "ftp://user:foreign-pass@example.invalid/?apikey=fixture-userinfo-key", secret: "foreign-pass"},
		{name: "parse failure with foreign password", baseURL: "http://user:foreign-pass@%zz/?apikey=fixture-userinfo-key", secret: "foreign-pass"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertNewDropsUserinfo(t, tc.baseURL, key, tc.secret)
		})
	}
}

// assertNewDropsUserinfo checks that New fails on baseURL with the fixed message without leaking user, key, or secret.
func assertNewDropsUserinfo(t *testing.T, baseURL, key, secret string) {
	t.Helper()
	c, err := New(baseURL, key)
	if c != nil || err == nil {
		t.Fatalf("New(%q) = %v, %v; want nil client and error", baseURL, c, err)
	}
	const want = "mylar: invalid base URL: must be http(s) with a host"
	if err.Error() != want {
		t.Errorf("err.Error() = %q; want %q", err.Error(), want)
	}
	for _, sub := range []string{"user", key, secret} {
		if strings.Contains(err.Error(), sub) {
			t.Errorf("error leaked %q: %s", sub, err.Error())
		}
	}
}

// TestNewOversizedKey checks that an oversized API key does not panic during constructor error scrubbing.
func TestNewOversizedKey(t *testing.T) {
	t.Parallel()
	key := strings.Repeat("k~", 150000)
	cases := []struct {
		name, baseURL string
	}{
		{name: "unsupported scheme", baseURL: "ftp://example.invalid/?raw=" + key},
		{name: "parse failure", baseURL: "http://%zz/?raw=" + key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New(tc.baseURL, key)
			if c != nil {
				t.Errorf("New() client = %v; want nil", c)
			}
			if err == nil {
				t.Fatal("New() error = nil; want non-nil")
			}
			assertNoKey(t, err.Error(), key)
		})
	}
}

// TestCheckErrorTreeNil checks that a nil error never reports a key or panics.
func TestCheckErrorTreeNil(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, key string
	}{
		{name: "keyed client", key: "k"},
		{name: "empty key", key: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{apiKey: tc.key}
			if carry, _ := c.checkErrorTree(nil); carry {
				t.Error("checkErrorTree(nil) = true; want false")
			}
			if got := c.redactError(nil); got != nil {
				t.Errorf("redactError(nil) = %v; want nil", got)
			}
			if got := c.scrubError(nil); got != nil {
				t.Errorf("scrubError(nil) = %v; want nil", got)
			}
		})
	}
}

// assertNoKey checks text for raw and query-escaped keys.
func assertNoKey(t *testing.T, text, key string) {
	t.Helper()
	if strings.Contains(text, key) || strings.Contains(text, url.QueryEscape(key)) {
		t.Errorf("key leaked: %s", text)
	}
}

// assertSafeText checks both key forms and the redaction marker.
func assertSafeText(t *testing.T, text, key string) {
	t.Helper()
	assertNoKey(t, text, key)
	if !strings.Contains(text, "REDACTED") {
		t.Errorf("missing REDACTED: %s", text)
	}
}

// responseTextClient creates a client serving the supplied response text.
func responseTextClient(t *testing.T, key, body string) *Client {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if _, err := io.Copy(w, strings.NewReader(body)); err != nil {
			t.Errorf("write response text: %v", err)
		}
	}))
	t.Cleanup(srv.Close)
	c, err := New(srv.URL, key, WithHTTPClient(srv.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestDecodeErrorRedaction checks server text embedded in decoder errors.
func TestDecodeErrorRedaction(t *testing.T) {
	t.Parallel()
	// Why: integer overflow errors echo this oversized numeric fixture key.
	const numericKey = "1234567890123456789012345678901234567890"
	cases := []struct {
		name string
		key  string
		body string
		call func(context.Context, *Client) error
	}{
		{name: "json number", key: numericKey, body: numericKey, call: func(ctx context.Context, c *Client) error {
			var out int
			return c.get(ctx, "getComic", nil, &out)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := responseTextClient(t, tc.key, tc.body)
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := tc.call(ctx, c)
			if err == nil {
				t.Fatal("expected decoder error")
			}
			assertSafeText(t, err.Error(), tc.key)
		})
	}
}

type responseStatusTransport struct {
	http.RoundTripper
	status string
}

// RoundTrip replaces the fixture response status text.
func (tr responseStatusTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := tr.RoundTripper.RoundTrip(req)
	if err == nil {
		resp.StatusCode = http.StatusInternalServerError
		resp.Status = tr.status
	}
	return resp, err
}

// TestStatusTextRedaction checks server status text exposed through APIError fields.
func TestStatusTextRedaction(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	cases := []struct {
		name string
		call func(context.Context, *Client) error
	}{
		{name: "get", call: func(ctx context.Context, c *Client) error {
			_, err := c.GetComic(ctx, "fixture")
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := responseTextClient(t, key, "fixture failure")
			c.httpClient.Transport = responseStatusTransport{
				RoundTripper: c.httpClient.Transport,
				status:       "500 raw=" + key + " echo=" + key,
			}
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			err := tc.call(ctx, c)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("expected APIError, got %v", err)
			}
			assertSafeText(t, apiErr.Status, key)
			if apiErr.Status != "500 raw=REDACTED echo=REDACTED" {
				t.Error("Status did not preserve the status code and both redaction markers")
			}
			if apiErr.StatusCode != http.StatusInternalServerError {
				t.Errorf("status code = %d", apiErr.StatusCode)
			}
		})
	}
}

// TestRedactQuotedKey checks nested URL errors with escaped keys and preserves joined causes.
func TestRedactQuotedKey(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	for _, tc := range []struct{ name, spelling string }{
		{"literal", key},
		{"percent encoded", "fixture%2Dkey42"},
		{"Unicode escaped", `fixture\u002dkey42`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{apiKey: key}
			original := errors.Join(io.ErrUnexpectedEOF,
				&url.Error{Op: "Get", URL: "http://h/?apikey=" + tc.spelling, Err: errors.New("x")})
			got := c.redactError(original)
			text := got.Error()
			if c.containsKey(text) || !strings.Contains(text, "REDACTED") {
				t.Error("expected redaction marker in key-free error text")
			}
			if !errors.Is(got, io.ErrUnexpectedEOF) {
				t.Error("lost sentinel")
			}
		})
	}
}

// TestScrubQuotedKey checks literal and escaped keys, along with absent and empty keys.
func TestScrubQuotedKey(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	cases := []struct {
		name, key, input, want string
		contains               bool
	}{
		{"empty", "", "plain", "plain", false},
		{"absent", key, "plain", "plain", false},
		{"literal", key, "key=" + key, "key=REDACTED", true},
		{"percent encoded", key, "key=" + strings.Replace(key, "-", "%2D", 1), "REDACTED", true},
		{"Unicode escaped", key, "key=" + strings.Replace(key, "-", `\u002d`, 1), "REDACTED", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c := &Client{apiKey: tc.key}
			if c.scrubText(tc.input) != tc.want {
				t.Error("unexpected text redaction")
			}
			if c.containsKey(tc.input) != tc.contains {
				t.Error("unexpected key detection")
			}
		})
	}
}

// redactionFanout is a keyless error whose Unwrap returns the previous level twice.
type redactionFanout struct{ prev error }

// Error returns constant text so only the tree shape costs time.
func (redactionFanout) Error() string { return "fixture fanout level" }

// Unwrap returns the previous level twice, doubling the tree per level.
func (e redactionFanout) Unwrap() []error { return []error{e.prev, e.prev} }

// TestRedactErrorFanoutBounded checks that a keyless exponential error tree returns promptly.
func TestRedactErrorFanoutBounded(t *testing.T) {
	t.Parallel()
	c := &Client{apiKey: "fixture-key42"}
	var err error
	err = errors.New("fixture fanout leaf")
	for range 40 {
		err = redactionFanout{prev: err}
	}
	done := make(chan error, 1)
	go func() { done <- c.redactError(err) }()
	select {
	case got := <-done:
		hidden, ok := got.(*redactedError) //nolint:errorlint // require the wrapper itself without traversing the tree
		if !ok || hidden == nil {
			t.Fatalf("redactError(%T) = %T; want *redactedError", err, got)
		}
		if hidden.Error() != redactedTreeMsg {
			t.Errorf("Error() = %q; want %q", hidden.Error(), redactedTreeMsg)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("redactError did not return within 2s")
	}
}

// TestNewAPIKeyAlphabet covers accepted and rejected API key bytes.
func TestNewAPIKeyAlphabet(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name, key string
		wantError bool
	}{
		{name: "alphanumeric", key: "Fixture9key"},
		{name: "punctuation boundary", key: "-._~"},
		{name: "empty"},
		{name: "space", key: "fixture key", wantError: true},
		{name: "plus", key: "fixture+key", wantError: true},
		{name: "percent", key: "fixture%key", wantError: true},
		{name: "slash", key: "fixture/key", wantError: true},
		{name: "non-ASCII", key: "fixtureäkey", wantError: true},
		{name: "invalid UTF-8", key: "fixture\xffkey", wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			c, err := New("http://localhost", tc.key)
			if tc.wantError {
				assertInvalidAPIKey(t, c, err)
				return
			}
			if err != nil || c == nil || c.apiKey != tc.key {
				t.Error("New did not retain an allowed key")
			}
		})
	}
}

// assertInvalidAPIKey checks the fixed diagnostic without printing the rejected input.
func assertInvalidAPIKey(t *testing.T, c *Client, err error) {
	t.Helper()
	const invalid = "mylar: invalid API key: only letters, digits and - . _ ~ allowed"
	if c != nil || err == nil || err.Error() != invalid {
		t.Error("New did not reject the key with the fixed diagnostic")
	}
}

// TestResponseReadHidesCustomFormatter checks the error returned to callers when reading the body fails.
func TestResponseReadHidesCustomFormatter(t *testing.T) {
	t.Parallel()
	const key = "fixture-key42"
	sentinel := errors.New("fixture read failure")
	c := newFormatterResponseClient(t, key, sentinel)
	_, err := c.GetIndex(t.Context())
	assertFormatterRedacted(t, err, sentinel, key)
}
