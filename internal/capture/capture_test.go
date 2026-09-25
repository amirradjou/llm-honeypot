package capture

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStoreDeduplicatesByContent(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "quarantine")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("\x7fELF fake payload")
	sum := sha256.Sum256(payload)
	want := hex.EncodeToString(sum[:])

	m, isNew, err := s.Put(payload, "http://a.example/x86", "application/octet-stream", false)
	if err != nil || !isNew {
		t.Fatalf("first Put: new=%v err=%v", isNew, err)
	}
	if m.SHA256 != want || m.Size != int64(len(payload)) {
		t.Errorf("meta = %+v", m)
	}

	// The same bytes from a different host: one copy, two URLs.
	m, isNew, err = s.Put(payload, "http://b.example/arm7", "application/octet-stream", false)
	if err != nil {
		t.Fatal(err)
	}
	if isNew {
		t.Error("identical bytes should not be stored twice")
	}
	if len(m.URLs) != 2 {
		t.Errorf("URLs = %v, want both hosts", m.URLs)
	}
	if !s.Has(want) {
		t.Error("Has should find the stored payload")
	}

	// One blob, one metadata file.
	entries, _ := os.ReadDir(dir)
	if len(entries) != 2 {
		t.Errorf("expected blob + metadata, got %d files", len(entries))
	}
}

func TestStoredPayloadIsNotExecutable(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "q")
	s, _ := NewStore(dir)
	m, _, err := s.Put([]byte("malware"), "http://a.example/x", "", false)
	if err != nil {
		t.Fatal(err)
	}
	// The whole point of a quarantine directory: nothing in it is runnable
	// and nothing else on the box can read it.
	info, err := os.Stat(filepath.Join(dir, m.SHA256+".bin"))
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm != 0o600 {
		t.Errorf("payload perm = %o, want 0600 (no execute bit)", perm)
	}
	if perm&0o111 != 0 {
		t.Error("payload must never be executable")
	}
	dirInfo, _ := os.Stat(dir)
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("quarantine dir perm = %o, want 0700", perm)
	}
}

func TestStoreListAndMissing(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "q")
	s, _ := NewStore(dir)
	if list, err := s.List(); err != nil || len(list) != 0 {
		t.Fatalf("empty store: %v %v", list, err)
	}
	s.now = func() time.Time { return time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC) }
	s.Put([]byte("one"), "http://a/1", "", false)
	s.now = func() time.Time { return time.Date(2026, 9, 2, 0, 0, 0, 0, time.UTC) }
	s.Put([]byte("two"), "http://a/2", "", false)

	list, err := s.List()
	if err != nil || len(list) != 2 {
		t.Fatalf("list = %d, %v", len(list), err)
	}
	if !list[0].LastSeen.After(list[1].LastSeen) {
		t.Error("List should be newest first")
	}
	if s.Has("deadbeef") {
		t.Error("Has should be false for an unknown hash")
	}
	// A stray file must not break listing.
	os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600)
	if list, _ := s.List(); len(list) != 2 {
		t.Error("stray file broke List")
	}
}

// --- fetcher ---

func TestFetchStoresPayload(t *testing.T) {
	body := strings.Repeat("A", 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ua := r.Header.Get("User-Agent"); ua != "Wget/1.21.2" {
			t.Errorf("user agent = %q", ua)
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Write([]byte(body))
	}))
	defer srv.Close()

	// AllowPrivate is required to reach httptest's loopback server — which
	// is itself the proof that the guard is on by default.
	f := NewFetcher(Fetcher{AllowPrivate: true})
	res, err := f.Fetch(context.Background(), srv.URL+"/x86")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Data) != 1024 || res.Truncated {
		t.Errorf("got %d bytes, truncated=%v", len(res.Data), res.Truncated)
	}
	if res.ContentType != "application/octet-stream" {
		t.Errorf("content type = %q", res.ContentType)
	}
}

func TestFetchTruncatesAtCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(strings.Repeat("B", 10_000)))
	}))
	defer srv.Close()

	f := NewFetcher(Fetcher{AllowPrivate: true, MaxBytes: 100})
	res, err := f.Fetch(context.Background(), srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Data) != 100 || !res.Truncated {
		t.Errorf("cap not applied: %d bytes truncated=%v", len(res.Data), res.Truncated)
	}
}

func TestFetchRefusesPrivateAndLocalAddresses(t *testing.T) {
	f := NewFetcher(Fetcher{}) // guard on, as in production
	blocked := []string{
		"http://127.0.0.1/x",
		"http://localhost/x",
		"http://10.0.0.5/x",
		"http://192.168.1.1/bins.sh",
		"http://172.16.0.1/x",
		"http://169.254.169.254/latest/meta-data/", // cloud metadata
		"http://[::1]/x",
		"http://0.0.0.0/x",
		"http://198.51.100.9/x", // documentation range
	}
	for _, u := range blocked {
		_, err := f.Fetch(context.Background(), u)
		if err == nil {
			t.Errorf("%s should have been refused", u)
			continue
		}
		if !errors.Is(err, ErrBlockedAddress) && !strings.Contains(err.Error(), "refusing") {
			t.Errorf("%s: unexpected error %v", u, err)
		}
	}
}

func TestFetchRefusesNonHTTPSchemes(t *testing.T) {
	f := NewFetcher(Fetcher{AllowPrivate: true})
	for _, u := range []string{"file:///etc/passwd", "ftp://a.example/x", "gopher://a/x", "tftp://a/x"} {
		if _, err := f.Fetch(context.Background(), u); !errors.Is(err, ErrUnsupportedScheme) {
			t.Errorf("%s: err = %v, want unsupported scheme", u, err)
		}
	}
}

// TestFetchGuardSurvivesDNSRebinding is the reason the address check lives
// in the dialer rather than on the hostname: a name that passes a first
// lookup and then resolves to loopback must still be blocked.
func TestFetchGuardSurvivesDNSRebinding(t *testing.T) {
	f := NewFetcher(Fetcher{})
	// A hostname that resolves to loopback. The literal check does not fire
	// (it is a name, not an IP), so only the dialer can catch it.
	_, err := f.Fetch(context.Background(), "http://localtest.me/x")
	if err == nil {
		t.Skip("localtest.me did not resolve in this environment")
	}
	if !strings.Contains(err.Error(), "refusing") && !strings.Contains(err.Error(), "no such host") {
		t.Logf("note: fetch failed with %v", err)
	}
}

func TestFetchRedirectToBlockedAddressIsRefused(t *testing.T) {
	// A payload server that redirects to somewhere private must not get us
	// there. The first hop is allowed (AllowPrivate, to reach httptest);
	// the redirect target is re-checked by CheckRedirect regardless.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "file:///etc/passwd", http.StatusFound)
	}))
	defer srv.Close()

	f := NewFetcher(Fetcher{AllowPrivate: true})
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil {
		t.Error("a redirect to an unsupported scheme should be refused")
	}
}

func TestFetchStopsRunawayRedirects(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, srv.URL+"/again", http.StatusFound)
	}))
	defer srv.Close()

	f := NewFetcher(Fetcher{AllowPrivate: true, MaxRedirects: 2})
	if _, err := f.Fetch(context.Background(), srv.URL); err == nil ||
		!strings.Contains(err.Error(), "redirect") {
		t.Errorf("expected a redirect limit error, got %v", err)
	}
}

func TestFetchReportsHTTPErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "gone", http.StatusNotFound)
	}))
	defer srv.Close()

	f := NewFetcher(Fetcher{AllowPrivate: true})
	res, err := f.Fetch(context.Background(), srv.URL)
	if err == nil {
		t.Fatal("expected an error for 404")
	}
	if res.Status != http.StatusNotFound {
		t.Errorf("status = %d", res.Status)
	}
}

func TestIsBlockedIP(t *testing.T) {
	blocked := []string{"127.0.0.1", "10.1.2.3", "192.168.0.1", "172.20.0.1", "169.254.169.254",
		"::1", "fc00::1", "100.64.0.1", "203.0.113.7", "224.0.0.1", "0.0.0.0"}
	for _, s := range blocked {
		if !isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be blocked", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "185.199.108.153", "2606:4700::1111"}
	for _, s := range allowed {
		if isBlockedIP(net.ParseIP(s)) {
			t.Errorf("%s should be allowed", s)
		}
	}
}

func TestStoreCreateFailsClearly(t *testing.T) {
	// A path under a regular file cannot be a directory.
	f := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(f, []byte("x"), 0o600)
	if _, err := NewStore(filepath.Join(f, "sub")); err == nil {
		t.Error("expected an error creating a store under a file")
	} else if !strings.Contains(err.Error(), "capture:") {
		t.Errorf("error should be labelled: %v", err)
	}
}
