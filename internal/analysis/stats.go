package analysis

import (
	"sort"
	"strings"
	"time"
)

// Counter tallies strings and returns them ranked.
type Counter struct {
	counts map[string]int
	total  int
}

// NewCounter returns an empty counter.
func NewCounter() *Counter { return &Counter{counts: map[string]int{}} }

// Add records one occurrence of v. Empty strings are ignored so callers
// can feed optional fields without filtering first.
func (c *Counter) Add(v string) {
	if v == "" {
		return
	}
	c.counts[v]++
	c.total++
}

// Total is the number of recorded occurrences.
func (c *Counter) Total() int { return c.total }

// Distinct is the number of different values seen.
func (c *Counter) Distinct() int { return len(c.counts) }

// Entry is one ranked value.
type Entry struct {
	Value string
	Count int
}

// Top returns the n most common values, ties broken alphabetically so the
// output is stable between runs.
func (c *Counter) Top(n int) []Entry {
	out := make([]Entry, 0, len(c.counts))
	for v, n := range c.counts {
		out = append(out, Entry{v, n})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if n > 0 && len(out) > n {
		out = out[:n]
	}
	return out
}

// Cluster is a group of sessions that ran the same sequence of commands.
type Cluster struct {
	Fingerprint string
	Sessions    []*Session
	// SourceIPs and Credentials are the distinct values across the cluster.
	SourceIPs   []string
	Credentials []string
}

// Size is the number of sessions in the cluster.
func (c *Cluster) Size() int { return len(c.Sessions) }

// Example returns a representative session (the first, by time).
func (c *Cluster) Example() *Session { return c.Sessions[0] }

// Cluster groups sessions by identical command sequences, largest first.
// This is what turns thousands of connections into a handful of distinct
// attacker behaviours.
func ClusterSessions(sessions []*Session) []*Cluster {
	byPrint := map[string]*Cluster{}
	for _, s := range sessions {
		fp := s.Fingerprint()
		c, ok := byPrint[fp]
		if !ok {
			c = &Cluster{Fingerprint: fp}
			byPrint[fp] = c
		}
		c.Sessions = append(c.Sessions, s)
	}
	out := make([]*Cluster, 0, len(byPrint))
	for _, c := range byPrint {
		ips, creds := NewCounter(), NewCounter()
		for _, s := range c.Sessions {
			ips.Add(s.RemoteIP)
			creds.Add(s.Credentials())
		}
		for _, e := range ips.Top(0) {
			c.SourceIPs = append(c.SourceIPs, e.Value)
		}
		for _, e := range creds.Top(0) {
			c.Credentials = append(c.Credentials, e.Value)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Size() != out[j].Size() {
			return out[i].Size() > out[j].Size()
		}
		return out[i].Fingerprint < out[j].Fingerprint
	})
	return out
}

// Stats is the numeric summary behind the report.
type Stats struct {
	Sessions       int
	Authenticated  int
	WithCommands   int
	TotalCommands  int
	TotalDownloads int
	ModelCalls     int

	First, Last   time.Time
	SessionsByDay map[string]int

	DwellMedian time.Duration
	DwellP90    time.Duration
	DwellMax    time.Duration

	CommandsMedian int
	CommandsMax    int

	// Probes are sessions that logged in and left almost immediately,
	// having run nothing or a single look-around command. Bots that
	// suspect a honeypot behave this way.
	Probes int
	// Silent are sessions that authenticated but never ran a command.
	Silent int

	Usernames     *Counter
	Passwords     *Counter
	CredPairs     *Counter
	FirstCommands *Counter
	AllCommands   *Counter
	CommandNames  *Counter
	SourceIPs     *Counter
	DownloadHosts *Counter
	DownloadURLs  *Counter
	PayloadNames  *Counter
}

// probeMaxCommands and probeMaxDwell define "looked around and left".
const (
	probeMaxCommands = 1
	probeMaxDwell    = 10 * time.Second
)

// Summarise computes the statistics for a set of sessions.
func Summarise(sessions []*Session) Stats {
	st := Stats{
		SessionsByDay: map[string]int{},
		Usernames:     NewCounter(),
		Passwords:     NewCounter(),
		CredPairs:     NewCounter(),
		FirstCommands: NewCounter(),
		AllCommands:   NewCounter(),
		CommandNames:  NewCounter(),
		SourceIPs:     NewCounter(),
		DownloadHosts: NewCounter(),
		DownloadURLs:  NewCounter(),
		PayloadNames:  NewCounter(),
	}
	st.Sessions = len(sessions)
	if len(sessions) == 0 {
		return st
	}

	dwells := make([]time.Duration, 0, len(sessions))
	cmdCounts := make([]int, 0, len(sessions))

	for _, s := range sessions {
		if st.First.IsZero() || s.Start.Before(st.First) {
			st.First = s.Start
		}
		if s.Start.After(st.Last) {
			st.Last = s.Start
		}
		st.SessionsByDay[s.Start.UTC().Format("2006-01-02")]++
		st.SourceIPs.Add(s.RemoteIP)

		for _, a := range s.Auths {
			// Key attempts have no password; count them by user only.
			st.Usernames.Add(a.User)
			st.Passwords.Add(a.Password)
			if a.Password != "" {
				st.CredPairs.Add(a.User + ":" + a.Password)
			}
		}
		if s.Accepted != nil {
			st.Authenticated++
		}

		dwells = append(dwells, s.Duration)
		cmdCounts = append(cmdCounts, len(s.Commands))
		st.TotalCommands += len(s.Commands)
		st.ModelCalls += s.ModelCalls

		if len(s.Commands) > 0 {
			st.WithCommands++
			st.FirstCommands.Add(s.Commands[0].Line)
		}
		for _, c := range s.Commands {
			st.AllCommands.Add(c.Line)
			st.CommandNames.Add(c.Name())
		}
		for _, d := range s.Downloads {
			st.TotalDownloads++
			st.DownloadHosts.Add(d.Host())
			st.DownloadURLs.Add(d.URL)
			st.PayloadNames.Add(payloadName(d.URL))
		}

		switch {
		case s.Accepted != nil && len(s.Commands) == 0:
			st.Silent++
		case len(s.Commands) <= probeMaxCommands && s.Duration <= probeMaxDwell:
			st.Probes++
		}
	}

	st.DwellMedian = percentileDuration(dwells, 0.50)
	st.DwellP90 = percentileDuration(dwells, 0.90)
	st.DwellMax = percentileDuration(dwells, 1.0)
	st.CommandsMedian = percentileInt(cmdCounts, 0.50)
	st.CommandsMax = percentileInt(cmdCounts, 1.0)
	return st
}

// Days is the number of distinct days covered, at least 1.
func (s Stats) Days() int {
	if len(s.SessionsByDay) == 0 {
		return 1
	}
	return len(s.SessionsByDay)
}

// SessionsPerDay is the mean over the days covered.
func (s Stats) SessionsPerDay() float64 {
	return float64(s.Sessions) / float64(s.Days())
}

// payloadName is the file a URL would land in, used to spot payload
// families (x86, arm7, bins.sh...) across different hosts.
func payloadName(url string) string {
	u := url
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	u = strings.TrimRight(u, "/")
	if i := strings.LastIndexByte(u, '/'); i >= 0 {
		u = u[i+1:]
	}
	return u
}

func percentileDuration(v []time.Duration, p float64) time.Duration {
	if len(v) == 0 {
		return 0
	}
	s := append([]time.Duration(nil), v...)
	sort.Slice(s, func(i, j int) bool { return s[i] < s[j] })
	return s[pctIndex(len(s), p)]
}

func percentileInt(v []int, p float64) int {
	if len(v) == 0 {
		return 0
	}
	s := append([]int(nil), v...)
	sort.Ints(s)
	return s[pctIndex(len(s), p)]
}

// pctIndex maps a percentile to an index using nearest-rank, which is the
// right choice for small samples: every reported value is a real
// observation rather than an interpolation between two sessions.
func pctIndex(n int, p float64) int {
	if n == 0 {
		return 0
	}
	i := int(float64(n)*p+0.5) - 1
	if i < 0 {
		i = 0
	}
	if i >= n {
		i = n - 1
	}
	return i
}
