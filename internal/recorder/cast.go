package recorder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
	"unicode/utf8"
)

// MaxCastBytes caps one session's replay. A session that prints more than
// this keeps running; its recording just stops, with a marker saying so.
const MaxCastBytes = 2 << 20

// Cast records what an interactive session's terminal showed, as an
// asciinema v2 file (<conn>.cast next to the transcript). `asciinema play`
// replays it, and `agg` turns it into a GIF.
type Cast struct {
	mu      sync.Mutex
	f       *os.File
	start   time.Time
	written int
	full    bool
	pending []byte // an incomplete UTF-8 sequence held back for the next write
	now     func() time.Time
}

type castHeader struct {
	Version   int               `json:"version"`
	Width     int               `json:"width"`
	Height    int               `json:"height"`
	Timestamp int64             `json:"timestamp"`
	Env       map[string]string `json:"env,omitempty"`
	Title     string            `json:"title,omitempty"`
}

// Cast opens a replay file for an interactive session. index numbers the
// session channels on one connection; the first is <conn>.cast. It returns
// nil when the file cannot be created, and a nil *Cast discards writes.
func (s *Sink) Cast(index, cols, rows int, term string) *Cast {
	if s.jsonl == nil {
		return nil
	}
	name := s.connID + ".cast"
	if index > 0 {
		name = fmt.Sprintf("%s-%d.cast", s.connID, index)
	}
	f, err := os.OpenFile(filepath.Join(filepath.Dir(s.jsonl.Name()), name), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640)
	if err != nil {
		return nil
	}
	if cols <= 0 {
		cols = 80
	}
	if rows <= 0 {
		rows = 24
	}
	c := &Cast{f: f, start: time.Now(), now: time.Now}
	hdr, _ := json.Marshal(castHeader{
		Version: 2, Width: cols, Height: rows, Timestamp: c.start.Unix(),
		Env:   map[string]string{"TERM": term, "SHELL": "/bin/bash"},
		Title: "session " + s.connID,
	})
	_, _ = f.Write(append(hdr, '\n'))
	return c
}

// Write records terminal output. It never fails, so it can sit in an
// io.MultiWriter next to the attacker's channel.
func (c *Cast) Write(p []byte) (int, error) {
	if c == nil {
		return len(p), nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.full || c.f == nil {
		return len(p), nil
	}
	data := append(c.pending, p...)
	c.pending = nil
	// Hold back a rune split across two writes so it is not mangled.
	if cut := incompleteTail(data); cut > 0 {
		c.pending = append([]byte(nil), data[len(data)-cut:]...)
		data = data[:len(data)-cut]
	}
	if len(data) == 0 {
		return len(p), nil
	}
	if c.written+len(data) > MaxCastBytes {
		c.event("o", "\r\n[recording stopped: size limit reached]\r\n")
		c.full = true
		return len(p), nil
	}
	c.written += len(data)
	c.event("o", string(data))
	return len(p), nil
}

// Resize records a terminal window change.
func (c *Cast) Resize(cols, rows int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.full && c.f != nil {
		c.event("r", fmt.Sprintf("%dx%d", cols, rows))
	}
}

// Close flushes and closes the file.
func (c *Cast) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.f == nil {
		return nil
	}
	if len(c.pending) > 0 && !c.full {
		c.event("o", string(c.pending))
	}
	err := c.f.Close()
	c.f = nil
	return err
}

func (c *Cast) event(kind, data string) {
	t := c.now().Sub(c.start).Seconds()
	b, _ := json.Marshal([]any{float64(int64(t*1e6)) / 1e6, kind, data})
	_, _ = c.f.Write(append(b, '\n'))
}

// incompleteTail returns how many trailing bytes of b start a UTF-8
// sequence that has not finished yet.
func incompleteTail(b []byte) int {
	for i := 1; i <= 3 && i <= len(b); i++ {
		r := b[len(b)-i]
		if r < 0x80 {
			return 0 // ASCII: nothing pending
		}
		if r >= 0xC0 { // a lead byte: is its sequence complete?
			if !utf8.FullRune(b[len(b)-i:]) {
				return i
			}
			return 0
		}
	}
	return 0
}
