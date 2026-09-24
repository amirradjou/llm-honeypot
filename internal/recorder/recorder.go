package recorder

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType names a recorded event.
type EventType string

const (
	EventConnect    EventType = "connect"
	EventAuth       EventType = "auth"
	EventSession    EventType = "session"    // a shell or exec channel opened
	EventCommand    EventType = "command"    // one command line entered
	EventDownload   EventType = "download"   // a fetch attempt (wget/curl/...)
	EventModelCall  EventType = "model_call" // the model generated output
	EventDisconnect EventType = "disconnect"
)

// Event is one JSONL record. Unused fields are omitted.
type Event struct {
	Time   time.Time `json:"time"`
	Type   EventType `json:"type"`
	ConnID string    `json:"conn"`
	Seq    int       `json:"seq"`

	// connect / disconnect
	RemoteAddr string `json:"remote_addr,omitempty"`
	Client     string `json:"client,omitempty"`
	Error      string `json:"error,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`

	// auth
	Method   string `json:"method,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	KeyType  string `json:"key_type,omitempty"`
	KeyFP    string `json:"key_fp,omitempty"`
	Accepted *bool  `json:"accepted,omitempty"`

	// session
	PTY     bool   `json:"pty,omitempty"`
	Term    string `json:"term,omitempty"`
	ExecCmd string `json:"exec_cmd,omitempty"`

	// command
	Command  string `json:"command,omitempty"`
	Cwd      string `json:"cwd,omitempty"`
	AsUser   string `json:"as_user,omitempty"`
	ExitCode *int   `json:"exit_code,omitempty"`
	IOCs     *IOCs  `json:"iocs,omitempty"`

	// download
	Tool    string `json:"tool,omitempty"`
	URL     string `json:"url,omitempty"`
	SavedAs string `json:"saved_as,omitempty"`

	// model_call
	Trigger string `json:"trigger,omitempty"`
	Model   string `json:"model,omitempty"`
	Tokens  int    `json:"tokens,omitempty"`
}

// Recorder creates per-connection recordings under a data directory.
type Recorder struct {
	dir string
	mu  sync.Mutex
}

// New returns a Recorder writing under dir/sessions/<date>/.
func New(dir string) *Recorder { return &Recorder{dir: dir} }

// Sink is where a session's events go. A discarding sink is used when
// recording is disabled or a file cannot be opened, so the honeypot keeps
// running even if the disk is full.
type Sink struct {
	rec        *Recorder
	connID     string
	started    time.Time
	mu         sync.Mutex
	seq        int
	jsonl      *os.File
	transcript *os.File
	enc        *json.Encoder
}

// Begin opens the files for a connection and records the connect event.
func (r *Recorder) Begin(connID, remoteAddr string, at time.Time) *Sink {
	s := &Sink{rec: r, connID: connID, started: at}
	dayDir := filepath.Join(r.dir, "sessions", at.UTC().Format("2006-01-02"))
	if err := os.MkdirAll(dayDir, 0o750); err == nil {
		if f, err := os.OpenFile(filepath.Join(dayDir, connID+".jsonl"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
			s.jsonl = f
			s.enc = json.NewEncoder(f)
		}
		if f, err := os.OpenFile(filepath.Join(dayDir, connID+".log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640); err == nil {
			s.transcript = f
		}
	}
	s.write(Event{Type: EventConnect, RemoteAddr: remoteAddr, Time: at})
	s.transcriptf("=== connection %s from %s at %s ===\n", connID, remoteAddr, at.UTC().Format(time.RFC3339))
	return s
}

func (s *Sink) write(e Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	e.Seq = s.seq
	e.ConnID = s.connID
	if e.Time.IsZero() {
		e.Time = time.Now()
	}
	e.Type = orType(e.Type)
	if s.enc != nil {
		_ = s.enc.Encode(e)
	}
}

func orType(t EventType) EventType {
	if t == "" {
		return "event"
	}
	return t
}

func (s *Sink) transcriptf(format string, a ...any) {
	if s.transcript == nil {
		return
	}
	fmt.Fprintf(s.transcript, format, a...)
}

// Auth records one login attempt.
func (s *Sink) Auth(method, user, password, keyType, keyFP string, accepted bool) {
	acc := accepted
	s.write(Event{Type: EventAuth, Method: method, User: user, Password: password, KeyType: keyType, KeyFP: keyFP, Accepted: &acc})
	verdict := "FAILED"
	if accepted {
		verdict = "ACCEPTED"
	}
	if keyFP != "" {
		s.transcriptf("[auth] %-8s %s key %s (%s)\n", verdict, method, keyFP, user)
	} else {
		s.transcriptf("[auth] %-8s %s %s / %q\n", verdict, method, user, password)
	}
}

// Session records a shell or exec channel opening.
func (s *Sink) Session(pty bool, term, execCmd string) {
	s.write(Event{Type: EventSession, PTY: pty, Term: term, ExecCmd: execCmd})
	if execCmd != "" {
		s.transcriptf("[session] exec: %s\n", execCmd)
	} else {
		s.transcriptf("[session] interactive shell (pty=%v term=%s)\n", pty, term)
	}
}

// Command records one command line, its cwd, the effective user and (once
// known) its exit code and extracted IOCs.
func (s *Sink) Command(command, cwd, asUser string, exitCode int) {
	code := exitCode
	iocs := Extract(command)
	var iptr *IOCs
	if !iocs.Empty() {
		iptr = &iocs
	}
	s.write(Event{Type: EventCommand, Command: command, Cwd: cwd, AsUser: asUser, ExitCode: &code, IOCs: iptr})
	s.transcriptf("%s@%s:%s$ %s\n", asUser, "", cwd, command)
}

// Download records a fetch attempt.
func (s *Sink) Download(tool, url, method, savedAs string) {
	s.write(Event{Type: EventDownload, Tool: tool, URL: url, Method: method, SavedAs: savedAs})
	s.transcriptf("[download] %s %s %s -> %s\n", tool, method, url, savedAs)
}

// ModelCall records that the model generated output.
func (s *Sink) ModelCall(trigger, model string, tokens int) {
	s.write(Event{Type: EventModelCall, Trigger: trigger, Model: model, Tokens: tokens})
}

// End records disconnection and closes the files.
func (s *Sink) End(err error, at time.Time) {
	e := Event{Type: EventDisconnect, Time: at, DurationMS: at.Sub(s.started).Milliseconds()}
	if err != nil {
		e.Error = err.Error()
	}
	s.write(e)
	s.transcriptf("=== disconnected after %s ===\n\n", at.Sub(s.started).Round(time.Millisecond))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.jsonl != nil {
		_ = s.jsonl.Close()
	}
	if s.transcript != nil {
		_ = s.transcript.Close()
	}
}
