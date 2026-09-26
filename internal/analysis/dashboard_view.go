package analysis

import (
	"fmt"
	"sort"
	"strings"
)

// sortedDays returns the day keys in chronological order.
func sortedDays(byDay map[string]int) []string {
	out := make([]string, 0, len(byDay))
	for d := range byDay {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// --- display helpers, as methods so the HTML template can call them ---

// Short renders the session's dwell time for display.
func (s *Session) Short() string { return short(s.Duration) }

// Started is the session start in a compact form.
func (s *Session) Started() string { return s.Start.UTC().Format("01-02 15:04:05") }

// NumCommands counts chained commands separately.
func (s *Session) NumCommands() int { return s.CommandCount() }

// User is the credential the session logged in with, or "-".
func (s *Session) User() string {
	if s.Accepted == nil {
		return "-"
	}
	return s.Accepted.User
}

// Summary is a one-line description of what the session did.
func (s *Session) Summary() string {
	if len(s.Commands) == 0 {
		return "(no commands)"
	}
	return s.Fingerprint()
}

// Pre-formatted durations for the template.
func (s Stats) DwellMedianShort() string { return short(s.DwellMedian) }
func (s Stats) DwellP90Short() string    { return short(s.DwellP90) }
func (s Stats) DwellMaxShort() string    { return short(s.DwellMax) }

// PerDay is the mean sessions per day, with a trailing ".0" trimmed.
func (s Stats) PerDay() string {
	return strings.TrimSuffix(fmt.Sprintf("%.1f", s.SessionsPerDay()), ".0")
}

// ProbeShare is the percentage of sessions that looked like a bot losing
// interest, for the detection panel.
func (s Stats) ProbeShare() int {
	if s.Sessions == 0 {
		return 0
	}
	return (s.Probes + s.Silent) * 100 / s.Sessions
}

// SourceIPList is the distinct source IPs of a cluster, capped.
func (c *Cluster) SourceIPList() string { return joinCapped(c.SourceIPs, 4) }

// CredentialList is the distinct credentials of a cluster, capped.
func (c *Cluster) CredentialList() string { return joinCapped(c.Credentials, 4) }
