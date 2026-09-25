package analysis

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// ReportOptions tune what the report shows.
type ReportOptions struct {
	// Title heads the report; empty uses a generated one.
	Title string
	// TopN is how many rows each ranked table shows (0 → 10).
	TopN int
	// Clusters is how many behaviour clusters to describe (0 → 5).
	Clusters int
	// Transcript includes the command lines of each cluster's example.
	Transcript bool
}

func (o ReportOptions) withDefaults() ReportOptions {
	if o.TopN <= 0 {
		o.TopN = 10
	}
	if o.Clusters <= 0 {
		o.Clusters = 5
	}
	return o
}

// WriteReport renders a Markdown report of what the bots did. It is
// written to be readable as plain text in a terminal as well as rendered.
func WriteReport(w io.Writer, sessions []*Session, opts ReportOptions) error {
	opts = opts.withDefaults()
	st := Summarise(sessions)

	title := opts.Title
	if title == "" {
		title = "What the bots did"
		if !st.First.IsZero() {
			title += fmt.Sprintf(" — %s to %s",
				st.First.UTC().Format("2006-01-02"), st.Last.UTC().Format("2006-01-02"))
		}
	}
	p := &printer{w: w}
	p.line("# %s", title)
	p.blank()

	if st.Sessions == 0 {
		p.line("No sessions recorded yet. Point a bot at the honeypot and come back.")
		return p.err
	}

	p.line("## Overview")
	p.blank()
	p.kv("Sessions", "%d over %d day(s) (%.1f/day)", st.Sessions, st.Days(), st.SessionsPerDay())
	p.kv("Distinct source IPs", "%d", st.SourceIPs.Distinct())
	p.kv("Authenticated", "%d", st.Authenticated)
	p.kv("Ran at least one command", "%d", st.WithCommands)
	p.kv("Commands run", "%d (median %d per session, max %d)", st.TotalCommands, st.CommandsMedian, st.CommandsMax)
	p.kv("Dwell time", "median %s, p90 %s, longest %s",
		short(st.DwellMedian), short(st.DwellP90), short(st.DwellMax))
	p.kv("Download attempts", "%d from %d host(s)", st.TotalDownloads, st.DownloadHosts.Distinct())
	p.kv("Model calls", "%d", st.ModelCalls)
	p.blank()

	p.line("## Did they suspect anything?")
	p.blank()
	p.line("%d session(s) authenticated and never ran a command; %d ran a single", st.Silent, st.Probes)
	p.line("look-around command and left within %s. Both are the shape a bot makes when", short(probeMaxDwell))
	p.line("it decides a box is not worth its time — a rising share is the signal that the")
	p.line("disguise is slipping.")
	p.blank()

	p.table("Credentials tried", "user:password", st.CredPairs, opts.TopN)
	p.table("Usernames", "username", st.Usernames, opts.TopN)
	p.table("Passwords", "password", st.Passwords, opts.TopN)
	p.table("First command of a session", "command", st.FirstCommands, opts.TopN)
	p.table("Commands (by name)", "command", st.CommandNames, opts.TopN)
	p.table("Busiest source IPs", "ip", st.SourceIPs, opts.TopN)

	if st.TotalDownloads > 0 {
		p.table("Payload hosts", "host", st.DownloadHosts, opts.TopN)
		p.table("Payload families", "file", st.PayloadNames, opts.TopN)
		p.table("Payload URLs", "url", st.DownloadURLs, opts.TopN)
	}

	p.writeClusters(sessions, opts)
	p.writeDaily(st)
	return p.err
}

func (p *printer) writeClusters(sessions []*Session, opts ReportOptions) {
	clusters := ClusterSessions(sessions)
	p.line("## Attacker behaviours")
	p.blank()
	p.line("Sessions grouped by the exact sequence of commands they ran. Payload names")
	p.line("are normalised, so two bots that differ only in the binary they fetched")
	p.line("appear as one behaviour.")
	p.blank()
	p.line("%d distinct behaviour(s) across %d session(s).", len(clusters), len(sessions))
	p.blank()

	shown := clusters
	if len(shown) > opts.Clusters {
		shown = shown[:opts.Clusters]
	}
	for i, c := range shown {
		p.line("### %d. %s", i+1, c.Fingerprint)
		p.blank()
		p.kv("Sessions", "%d", c.Size())
		p.kv("Source IPs", "%s", escapePipes(joinCapped(c.SourceIPs, 5)))
		if creds := joinCapped(c.Credentials, 5); creds != "" {
			p.kv("Credentials", "`%s`", escapePipes(creds))
		}
		if opts.Transcript && len(c.Example().Commands) > 0 {
			p.blank()
			p.line(fence + "console")
			ex := c.Example()
			for _, cmd := range ex.Commands {
				// Inside a fenced block a stray fence is the only way out.
				p.line("%s@honeypot:%s$ %s", cmd.User, cmd.Cwd, escapeFence(cmd.Line))
			}
			p.line(fence)
		}
		p.blank()
	}
	if len(clusters) > len(shown) {
		p.line("_…and %d more behaviour(s)._", len(clusters)-len(shown))
		p.blank()
	}
}

func (p *printer) writeDaily(st Stats) {
	if len(st.SessionsByDay) < 2 {
		return
	}
	p.line("## Sessions per day")
	p.blank()
	days := make([]string, 0, len(st.SessionsByDay))
	max := 0
	for d, n := range st.SessionsByDay {
		days = append(days, d)
		if n > max {
			max = n
		}
	}
	sort.Strings(days)
	for _, d := range days {
		n := st.SessionsByDay[d]
		bar := strings.Repeat("█", barWidth(n, max))
		p.line("    %s  %4d  %s", d, n, bar)
	}
	p.blank()
}

// barWidth scales a count to at most 40 characters, never zero for a
// non-zero count so a quiet day is still visible.
func barWidth(n, max int) int {
	if n <= 0 || max <= 0 {
		return 0
	}
	w := n * 40 / max
	if w < 1 {
		w = 1
	}
	return w
}

func joinCapped(vals []string, n int) string {
	if len(vals) == 0 {
		return ""
	}
	if len(vals) <= n {
		return strings.Join(vals, ", ")
	}
	return strings.Join(vals[:n], ", ") + fmt.Sprintf(" (+%d more)", len(vals)-n)
}

// short renders a duration the way a human would say it.
func short(d time.Duration) string {
	switch {
	case d <= 0:
		return "0s"
	case d < time.Minute:
		return fmt.Sprintf("%.0fs", d.Seconds())
	case d < time.Hour:
		return fmt.Sprintf("%dm%02ds", int(d.Minutes()), int(d.Seconds())%60)
	default:
		return fmt.Sprintf("%dh%02dm", int(d.Hours()), int(d.Minutes())%60)
	}
}

// printer writes Markdown and remembers the first write error.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) line(format string, a ...any) {
	if p.err != nil {
		return
	}
	_, p.err = fmt.Fprintf(p.w, format+"\n", a...)
}

func (p *printer) blank() { p.line("") }

func (p *printer) kv(label, format string, a ...any) {
	p.line("- **%s**: %s", label, fmt.Sprintf(format, a...))
}

func (p *printer) table(title, col string, c *Counter, n int) {
	rows := c.Top(n)
	if len(rows) == 0 {
		return
	}
	p.line("## %s", title)
	p.blank()
	p.line("| %s | count |", col)
	p.line("|---|---:|")
	for _, r := range rows {
		p.line("| `%s` | %d |", escapePipes(r.Value), r.Count)
	}
	if c.Distinct() > len(rows) {
		p.blank()
		p.line("_%d distinct values in total._", c.Distinct())
	}
	p.blank()
}

// fence is the Markdown code fence, named so the escaping below can refer
// to it without the literal appearing mid-string.
const fence = "```"

// escapeFence neutralises a code fence an attacker typed, so a command
// line cannot close the transcript block that quotes it and inject
// Markdown after it.
func escapeFence(s string) string {
	s = strings.ReplaceAll(s, fence, "'''")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}

// escapePipes keeps an attacker-controlled string from breaking the table
// it is printed in. The report renders untrusted text, so it must not be
// possible to inject Markdown through a command line or password.
func escapePipes(s string) string {
	s = strings.ReplaceAll(s, "`", "'")
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	return s
}
