package analysis

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"sync"
	"time"
)

// Dashboard serves the live view of what the bots are doing. It only ever
// reads the recordings, so it is safe to run alongside a live honeypot.
//
// It renders attacker-controlled text, so every template is html/template
// (contextually auto-escaping) and nothing is assembled with string
// concatenation. The dashboard is also why the default bind address is
// loopback: this page is a summary of hostile input and has no business
// being exposed on a box that is deliberately inviting attackers.
type Dashboard struct {
	dataDir string
	// ttl caps how often the recordings are re-read, so a page refresh
	// loop cannot turn into a disk-read loop.
	ttl time.Duration
	now func() time.Time

	mu       sync.Mutex
	cached   []*Session
	cachedAt time.Time
}

// NewDashboard returns a handler reading recordings from dataDir. A ttl of
// 0 defaults to five seconds.
func NewDashboard(dataDir string, ttl time.Duration) *Dashboard {
	if ttl <= 0 {
		ttl = 5 * time.Second
	}
	return &Dashboard{dataDir: dataDir, ttl: ttl, now: time.Now}
}

// refreshSeconds is how often the page asks the browser to reload. It is
// never shorter than the read TTL, so a refresh always has fresh data to
// show rather than re-rendering the cache.
func (d *Dashboard) refreshSeconds() int {
	secs := int(d.ttl.Seconds())
	if secs < 5 {
		secs = 5
	}
	if secs > 300 {
		secs = 300
	}
	return secs
}

// sessions returns the recordings, re-reading at most once per ttl.
func (d *Dashboard) sessions() ([]*Session, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.cached != nil && d.now().Sub(d.cachedAt) < d.ttl {
		return d.cached, nil
	}
	s, err := Load(d.dataDir)
	if err != nil {
		return nil, err
	}
	d.cached, d.cachedAt = s, d.now()
	return s, nil
}

// ServeHTTP routes the three endpoints the dashboard exposes.
func (d *Dashboard) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// The page embeds no external resources, so it can afford a strict
	// policy — worth having when the content is attacker-derived.
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")

	switch r.URL.Path {
	case "/":
		d.serveHTML(w, r)
	case "/report.md":
		d.serveMarkdown(w, r)
	case "/healthz":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintln(w, "ok")
	default:
		http.NotFound(w, r)
	}
}

func (d *Dashboard) serveMarkdown(w http.ResponseWriter, _ *http.Request) {
	sessions, err := d.sessions()
	if err != nil {
		http.Error(w, "cannot read recordings", http.StatusInternalServerError)
		return
	}
	var buf bytes.Buffer
	if err := WriteReport(&buf, sessions, ReportOptions{Transcript: true}); err != nil {
		http.Error(w, "cannot render report", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	_, _ = w.Write(buf.Bytes())
}

// view is what the HTML template renders.
type view struct {
	Generated string
	// RefreshSeconds drives the meta refresh. The page carries no
	// JavaScript - the CSP forbids it - so this is how it stays live.
	RefreshSeconds int
	Stats          Stats
	Clusters       []*Cluster
	Recent         []*Session
	Days           []dayBar
	Tables         []table
}

type dayBar struct {
	Day     string
	Count   int
	Percent int
}

type table struct {
	Title  string
	Column string
	Rows   []Entry
	Total  int
}

func (d *Dashboard) serveHTML(w http.ResponseWriter, _ *http.Request) {
	sessions, err := d.sessions()
	if err != nil {
		http.Error(w, "cannot read recordings", http.StatusInternalServerError)
		return
	}
	v := d.buildView(sessions)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := dashboardTmpl.Execute(w, v); err != nil {
		// Headers are already out; the page will simply be truncated.
		return
	}
}

// buildView assembles everything the page shows.
func (d *Dashboard) buildView(sessions []*Session) view {
	st := Summarise(sessions)
	v := view{
		Generated:      d.now().UTC().Format("2006-01-02 15:04:05 UTC"),
		RefreshSeconds: d.refreshSeconds(),
		Stats:          st,
		Clusters:       ClusterSessions(sessions),
	}
	v.Tables = []table{
		{"Credentials tried", "user:password", st.CredPairs.Top(10), st.CredPairs.Distinct()},
		{"Usernames", "username", st.Usernames.Top(10), st.Usernames.Distinct()},
		{"Passwords", "password", st.Passwords.Top(10), st.Passwords.Distinct()},
		{"First command", "command", st.FirstCommands.Top(10), st.FirstCommands.Distinct()},
		{"Commands", "command", st.CommandNames.Top(10), st.CommandNames.Distinct()},
		{"Source IPs", "ip", st.SourceIPs.Top(10), st.SourceIPs.Distinct()},
		{"Payload hosts", "host", st.DownloadHosts.Top(10), st.DownloadHosts.Distinct()},
		{"Payload families", "file", st.PayloadNames.Top(10), st.PayloadNames.Distinct()},
	}
	// Most recent sessions first.
	for i := len(sessions) - 1; i >= 0 && len(v.Recent) < 25; i-- {
		v.Recent = append(v.Recent, sessions[i])
	}
	max := 0
	for _, n := range st.SessionsByDay {
		if n > max {
			max = n
		}
	}
	for _, day := range sortedDays(st.SessionsByDay) {
		n := st.SessionsByDay[day]
		pct := 0
		if max > 0 {
			pct = n * 100 / max
			if pct < 2 {
				pct = 2 // a quiet day should still be visible
			}
		}
		v.Days = append(v.Days, dayBar{Day: day, Count: n, Percent: pct})
	}
	if len(v.Clusters) > 10 {
		v.Clusters = v.Clusters[:10]
	}
	return v
}

// dashboardTmpl is parsed once at startup. html/template escapes every
// interpolation for its context, which is what keeps attacker-supplied
// commands and passwords from becoming markup on this page.
var dashboardTmpl = template.Must(template.ParseFS(templateFS, "templates/dashboard.html"))
