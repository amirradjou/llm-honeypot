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

func readCast(t *testing.T, path string) (castHeader, [][]any) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64<<10), 8<<20)
	var hdr castHeader
	var events [][]any
	for i := 0; sc.Scan(); i++ {
		if i == 0 {
			if err := json.Unmarshal(sc.Bytes(), &hdr); err != nil {
				t.Fatalf("header: %v", err)
			}
			continue
		}
		var ev []any
		if err := json.Unmarshal(sc.Bytes(), &ev); err != nil {
			t.Fatalf("event %d: %v", i, err)
		}
		events = append(events, ev)
	}
	return hdr, events
}

func TestCastRecordsOutputAndResizes(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	sink := New(dir).Begin("c1", "192.0.2.1:5000", at)
	c := sink.Cast(0, 120, 30, "xterm-256color")
	if c == nil {
		t.Fatal("no cast")
	}
	c.Write([]byte("root@srv-web01:~# "))
	// "é" split across two writes must come out whole.
	c.Write([]byte{'c', 'a', 'f', 0xC3})
	c.Write([]byte{0xA9, '\r', '\n'})
	c.Resize(100, 40)
	c.Close()
	sink.End(nil, at.Add(time.Second))

	hdr, events := readCast(t, filepath.Join(dir, "sessions", "2026-11-16", "c1.cast"))
	if hdr.Version != 2 || hdr.Width != 120 || hdr.Height != 30 || hdr.Env["TERM"] != "xterm-256color" {
		t.Errorf("header = %+v", hdr)
	}
	var out strings.Builder
	var resized bool
	for _, ev := range events {
		switch ev[1] {
		case "o":
			out.WriteString(ev[2].(string))
		case "r":
			resized = ev[2] == "100x40"
		}
	}
	if out.String() != "root@srv-web01:~# café\r\n" || !resized {
		t.Errorf("output %q, resized %v", out.String(), resized)
	}
}

func TestCastStopsAtTheSizeLimit(t *testing.T) {
	dir := t.TempDir()
	at := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	sink := New(dir).Begin("c2", "192.0.2.1:5000", at)
	c := sink.Cast(1, 80, 24, "xterm")
	chunk := []byte(strings.Repeat("x", 64<<10))
	for i := 0; i < (MaxCastBytes/len(chunk))+5; i++ {
		if n, err := c.Write(chunk); n != len(chunk) || err != nil {
			t.Fatalf("write = %d %v", n, err)
		}
	}
	c.Close()
	info, err := os.Stat(filepath.Join(dir, "sessions", "2026-11-16", "c2-1.cast"))
	if err != nil || info.Size() > MaxCastBytes+64<<10 {
		t.Errorf("cast size = %v %v", info, err)
	}
}

func TestNilCastIsSafe(t *testing.T) {
	var c *Cast
	if n, err := c.Write([]byte("x")); n != 1 || err != nil {
		t.Errorf("nil write = %d %v", n, err)
	}
	c.Resize(1, 1)
	if err := c.Close(); err != nil {
		t.Error(err)
	}
}
