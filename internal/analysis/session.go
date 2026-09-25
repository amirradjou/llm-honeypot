// Package analysis turns the honeypot's raw recordings into something a
// human can read: reconstructed sessions, clusters of attacker behaviour,
// and the numbers behind the monthly "what the bots did" report.
package analysis

import (
	"bufio"
	"encoding/json"
	"errors"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/recorder"
)

// Auth is one login attempt.
type Auth struct {
	Method   string
	User     string
	Password string
	KeyFP    string
	Accepted bool
}

// Command is one command line the attacker ran.
type Command struct {
	At       time.Time
	Line     string
	Cwd      string
	User     string
	ExitCode int
	IOCs     recorder.IOCs
}

// dropDirs are the writable directories a dropper stages payloads in.
// Running something from one of them is "execute the payload", whatever
// the file happens to be called.
var dropDirs = []string{"/tmp/", "/var/tmp/", "/var/run/", "/run/", "/dev/shm/", "/mnt/", "/root/"}

// Parts returns the individual commands on this line. One recorded line
// usually chains several ("cd /tmp; wget ...; ./x").
func (c Command) Parts() []string { return splitLine(c.Line) }

// Names returns the command word of each part, normalised for clustering.
func (c Command) Names() []string {
	parts := c.Parts()
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if n := (Command{Line: p}).Name(); n != "" {
			out = append(out, n)
		}
	}
	return out
}

// Name is the command word used for fingerprinting, e.g. "wget" for
// "wget http://x -O y". A leading directory is stripped so /bin/busybox
// and busybox cluster together, and running a dropped file collapses to
// "./payload" so two bots that differ only in payload name still cluster
// as the same behaviour.
func (c Command) Name() string {
	f := strings.Fields(c.Line)
	if len(f) == 0 {
		return ""
	}
	name := f[0]
	if isPayloadExec(name) {
		return "./payload"
	}
	if i := strings.LastIndexByte(name, '/'); i >= 0 && i < len(name)-1 {
		name = name[i+1:]
	}
	return name
}

// isPayloadExec reports whether the command word runs a file the attacker
// put on disk, rather than a system binary.
func isPayloadExec(name string) bool {
	if strings.HasPrefix(name, "./") || strings.HasPrefix(name, "../") {
		return true
	}
	for _, d := range dropDirs {
		if strings.HasPrefix(name, d) {
			return true
		}
	}
	return false
}

// Download is an attempted fetch.
type Download struct {
	Tool    string
	URL     string
	SavedAs string
}

// Host is the hostname or IP in the URL, or "" if the string does not
// look like a URL at all.
func (d Download) Host() string {
	u := strings.TrimSpace(d.URL)
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	} else if strings.ContainsAny(u, " \t") {
		return "" // not a URL, do not invent a host from it
	}
	if i := strings.IndexAny(u, "/:"); i >= 0 {
		u = u[:i]
	}
	if i := strings.IndexAny(u, " \t"); i >= 0 {
		u = u[:i]
	}
	// Strip userinfo, e.g. user:pass@host (the colon split above already
	// removed a password, so only a bare user@ can remain).
	if i := strings.LastIndexByte(u, '@'); i >= 0 {
		u = u[i+1:]
	}
	return u
}

// Session is one reconstructed attacker connection.
type Session struct {
	ConnID   string
	Remote   string // ip:port as recorded
	RemoteIP string
	Start    time.Time
	End      time.Time
	Duration time.Duration

	Auths     []Auth
	Accepted  *Auth
	Commands  []Command
	Downloads []Download

	ModelCalls int
	// Interactive is true when the client asked for a pty.
	Interactive bool
	// Err is the disconnect error, if any.
	Err string
	// Incomplete marks a recording with no disconnect event (the honeypot
	// was killed, or the file is still being written).
	Incomplete bool
}

// Fingerprint is the ordered list of command names, joined — the signature
// used to cluster sessions that behave identically.
func (s *Session) Fingerprint() string {
	if len(s.Commands) == 0 {
		return "(no commands)"
	}
	var names []string
	for _, c := range s.Commands {
		names = append(names, c.Names()...)
	}
	if len(names) == 0 {
		return "(no commands)"
	}
	return strings.Join(names, " → ")
}

// CommandCount is how many commands ran, counting each one on a chained
// line separately.
func (s *Session) CommandCount() int {
	n := 0
	for _, c := range s.Commands {
		n += len(c.Parts())
	}
	return n
}

// FirstCommand returns the first command line, or "".
func (s *Session) FirstCommand() string {
	if len(s.Commands) == 0 {
		return ""
	}
	return s.Commands[0].Line
}

// Credentials returns the accepted "user:password", or "" if none.
func (s *Session) Credentials() string {
	if s.Accepted == nil {
		return ""
	}
	return s.Accepted.User + ":" + s.Accepted.Password
}

// Load reads every recording under dir (the honeypot's data directory) and
// returns the sessions, oldest first. Unreadable or malformed files are
// skipped rather than failing the whole run — a partially written file is
// normal when the honeypot is still running.
func Load(dir string) ([]*Session, error) {
	root := filepath.Join(dir, "sessions")
	var files []string
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // skip unreadable subtrees
		}
		if !d.IsDir() && strings.HasSuffix(p, ".jsonl") {
			files = append(files, p)
		}
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if len(files) == 0 {
		return nil, nil
	}
	sort.Strings(files)

	sessions := make([]*Session, 0, len(files))
	for _, f := range files {
		s, err := loadFile(f)
		if err != nil || s == nil {
			continue
		}
		sessions = append(sessions, s)
	}
	sort.Slice(sessions, func(i, j int) bool { return sessions[i].Start.Before(sessions[j].Start) })
	return sessions, nil
}

// loadFile reconstructs one session from its JSONL recording.
func loadFile(path string) (*Session, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	s := &Session{Incomplete: true}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e recorder.Event
		if err := json.Unmarshal(line, &e); err != nil {
			continue // a torn final line while the honeypot is writing
		}
		s.apply(e)
	}
	if s.ConnID == "" {
		return nil, nil
	}
	if s.End.IsZero() {
		// No disconnect recorded: fall back to the last event we saw.
		s.End = s.lastEventTime()
	}
	if s.Duration == 0 {
		s.Duration = s.End.Sub(s.Start)
	}
	return s, nil
}

func (s *Session) apply(e recorder.Event) {
	if s.ConnID == "" {
		s.ConnID = e.ConnID
	}
	switch e.Type {
	case recorder.EventConnect:
		s.Start = e.Time
		s.Remote = e.RemoteAddr
		if host, _, err := net.SplitHostPort(e.RemoteAddr); err == nil {
			s.RemoteIP = host
		} else {
			s.RemoteIP = e.RemoteAddr
		}
	case recorder.EventAuth:
		a := Auth{Method: e.Method, User: e.User, Password: e.Password, KeyFP: e.KeyFP}
		if e.Accepted != nil {
			a.Accepted = *e.Accepted
		}
		s.Auths = append(s.Auths, a)
		if a.Accepted {
			acc := a
			s.Accepted = &acc
		}
	case recorder.EventSession:
		if e.PTY {
			s.Interactive = true
		}
	case recorder.EventCommand:
		c := Command{At: e.Time, Line: e.Command, Cwd: e.Cwd, User: e.AsUser}
		if e.ExitCode != nil {
			c.ExitCode = *e.ExitCode
		}
		if e.IOCs != nil {
			c.IOCs = *e.IOCs
		}
		s.Commands = append(s.Commands, c)
	case recorder.EventDownload:
		s.Downloads = append(s.Downloads, Download{Tool: e.Tool, URL: e.URL, SavedAs: e.SavedAs})
	case recorder.EventModelCall:
		s.ModelCalls++
	case recorder.EventDisconnect:
		s.End = e.Time
		s.Err = e.Error
		s.Incomplete = false
		if e.DurationMS > 0 {
			s.Duration = time.Duration(e.DurationMS) * time.Millisecond
		}
	}
}

func (s *Session) lastEventTime() time.Time {
	last := s.Start
	if n := len(s.Commands); n > 0 && s.Commands[n-1].At.After(last) {
		last = s.Commands[n-1].At
	}
	return last
}
