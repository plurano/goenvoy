package tvdb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/golusoris/goenvoy/metadata"
)

// authRecorder stores the last Authorization header seen by the test server.
type authRecorder struct {
	mu     sync.Mutex
	header string
}

// record saves the Authorization header from an incoming request.
func (r *authRecorder) record(req *http.Request) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.header = req.Header.Get("Authorization")
}

// get returns the last recorded Authorization header.
func (r *authRecorder) get() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.header
}

// seriesSuccessBody is the JSON body returned by the token-binding test server.
const seriesSuccessBody = `{"status":"success","data":{"id":1,"name":"Test Series"}}`

// newTokenBindingServer returns an httptest server that records GET Authorization headers.
func newTokenBindingServer(t *testing.T, rec *authRecorder) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/series/1" {
			rec.record(r)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(seriesSuccessBody))
			return
		}
		t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "not found", http.StatusNotFound)
	}))
}

// setClientToken assigns the cached bearer token under the client mutex.
func setClientToken(c *Client, token string) {
	c.mu.Lock()
	c.token = token
	c.mu.Unlock()
}

// doGetAuthCase is one table row for Authorization header binding checks.
type doGetAuthCase struct {
	name       string
	useDoGetAs bool
	asToken    string
	wantAuth   string
}

// runDoGetAuthCase executes a doGetAuthCase against the token-binding test server.
func runDoGetAuthCase(t *testing.T, tc doGetAuthCase) {
	t.Helper()

	var rec authRecorder
	srv := newTokenBindingServer(t, &rec)
	defer srv.Close()

	c := New("test-key", metadata.WithBaseURL(srv.URL))
	setClientToken(c, "rotated")

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	var out response[SeriesBase]
	var err error
	if tc.useDoGetAs {
		err = c.doGetAs(ctx, tc.asToken, "/series/1", &out)
	} else {
		err = c.doGet(ctx, "/series/1", &out)
	}
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	if got := rec.get(); got != tc.wantAuth {
		t.Fatalf("Authorization = %q, want %q", got, tc.wantAuth)
	}
	if out.Data.Name != "Test Series" {
		t.Fatalf("name = %q, want %q", out.Data.Name, "Test Series")
	}
}

func TestDoGetAsSendsCapturedToken(t *testing.T) {
	t.Parallel()

	cases := []doGetAuthCase{
		{
			name:       "doGetAs_captured",
			useDoGetAs: true,
			asToken:    "captured",
			wantAuth:   "Bearer captured",
		},
		{
			name:       "doGet_fallback",
			useDoGetAs: false,
			wantAuth:   "Bearer rotated",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runDoGetAuthCase(t, tc)
		})
	}
}
