// Package honeypot wires the SSH front door to the fake shell and the
// recorder. It implements sshd.Handler: every connection gets a recording
// and, once a channel opens, a shell session over a private clone of the
// machine.
package honeypot

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/recorder"
	"github.com/amirradjou/llm-honeypot/internal/shell"
	"github.com/amirradjou/llm-honeypot/internal/sshd"

	"golang.org/x/term"
)

// Handler is the honeypot's sshd.Handler.
type Handler struct {
	machine *machine.Machine
	rec     *recorder.Recorder
	interp  *shell.Interp
	log     *slog.Logger
	seed    int64

	mu    sync.Mutex
	sinks map[string]*recorder.Sink
	seq   int64
}

// New builds a Handler over a seeded machine and a recorder.
func New(m *machine.Machine, rec *recorder.Recorder, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	h := &Handler{
		machine: m,
		rec:     rec,
		interp:  shell.New(),
		log:     log,
		sinks:   map[string]*recorder.Sink{},
	}
	// The recorder captures every download the shell reports.
	h.interp.OnDownload = func(ctx *shell.Context, d shell.Download) {
		if sink := h.sinkFor(ctx.Sess); sink != nil {
			sink.Download(d.Tool, d.URL, d.Method, d.SavedAs)
		}
	}
	// Command recording: the interpreter's Hook fires just before each
	// command runs; we log it with the cwd and user at that moment. The
	// exit code is not known yet here, so commands are logged with -1 and
	// the transcript still shows the full session order.
	return h
}

func (h *Handler) sinkFor(sess *shell.Session) *recorder.Sink {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sinks[sessKey(sess)]
}

// sessKey ties a shell session back to its recording. We stash the conn id
// in the session environment under a private key at session creation.
func sessKey(sess *shell.Session) string { return sess.Getenv(connIDEnv) }

const connIDEnv = "__CONN_ID"

// Connected opens a recording for the connection.
func (h *Handler) Connected(c *sshd.Conn) {
	sink := h.rec.Begin(c.ID, addrString(c.RemoteAddr), c.StartedAt)
	h.mu.Lock()
	h.sinks[c.ID] = sink
	h.mu.Unlock()
	h.log.Info("connected", "conn", c.ID, "remote", addrString(c.RemoteAddr))
}

// AuthAttempt records a login attempt.
func (h *Handler) AuthAttempt(c *sshd.Conn, a sshd.AuthAttempt) {
	if sink := h.sink(c.ID); sink != nil {
		sink.Auth(string(a.Method), a.User, a.Password, a.KeyType, a.KeyFP, a.Accepted)
	}
}

func (h *Handler) sink(id string) *recorder.Sink {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.sinks[id]
}

// Session runs the fake shell for one channel.
func (h *Handler) Session(ctx context.Context, s *sshd.Session) {
	sink := h.sink(s.Conn.ID)
	user := s.Conn.User
	if user == "" {
		user = "root"
	}
	sess := shell.NewSession(h.machine, user, h.nextSeed())
	sess.Env[connIDEnv] = s.Conn.ID
	if s.PTY != nil {
		sess.Cols, sess.Rows = s.PTY.Cols, s.PTY.Rows
		sess.Env["TERM"] = s.PTY.Term
	}
	sess.Env["SSH_CLIENT"] = addrString(s.Conn.RemoteAddr) + " 22"
	sess.Env["SSH_CONNECTION"] = addrString(s.Conn.RemoteAddr) + " " + addrString(s.Conn.LocalAddr) + " 22"

	if sink != nil {
		sink.Session(s.PTY != nil, termOf(s), s.Command)
	}

	switch {
	case s.Command != "":
		h.runExec(sess, s, sink)
	case s.PTY != nil:
		h.runInteractive(ctx, sess, s, sink)
	default:
		h.runPiped(sess, s, sink)
	}
}

// runExec runs a single `ssh host "command"`.
func (h *Handler) runExec(sess *shell.Session, s *sshd.Session, sink *recorder.Sink) {
	code := h.runLine(sess, s.Command, s, s, sink)
	s.Exit(code)
}

// runPiped runs commands fed on stdin without a pty (ssh host < script).
func (h *Handler) runPiped(sess *shell.Session, s *sshd.Session, sink *recorder.Sink) {
	sc := bufio.NewScanner(s)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	code := 0
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		code = h.runLine(sess, line, s, s, sink)
	}
	s.Exit(code)
}

// runInteractive drives a full-screen line-editing shell.
func (h *Handler) runInteractive(ctx context.Context, sess *shell.Session, s *sshd.Session, sink *recorder.Sink) {
	t := term.NewTerminal(s, sess.Prompt())
	// Ctrl-C cancels the current line instead of closing the session, the
	// way a real shell does. Without this, x/term returns io.EOF for Ctrl-C
	// and the attacker is logged straight out.
	t.AutoCompleteCallback = func(line string, pos int, key rune) (string, int, bool) {
		if key == 0x03 { // Ctrl-C
			io.WriteString(t, "^C\n")
			return "", 0, true
		}
		return "", 0, false
	}
	if size := sess.Cols; size > 0 {
		_ = t.SetSize(sess.Cols, sess.Rows)
	}
	// Track window changes so wide `ls`/`top` stay aligned.
	go func() {
		for ws := range s.Resize {
			sess.Cols, sess.Rows = ws.Cols, ws.Rows
			_ = t.SetSize(ws.Cols, ws.Rows)
		}
	}()

	io.WriteString(t, loginBanner(h.machine, sess))

	for {
		select {
		case <-ctx.Done():
			s.Exit(0)
			return
		default:
		}
		line, err := t.ReadLine()
		if err == io.EOF {
			io.WriteString(t, "logout\n")
			s.Exit(sess.Status)
			return
		}
		if err != nil {
			s.Exit(sess.Status)
			return
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		sess.History = append(sess.History, line)
		exited, code := h.runInterpreter(sess, line, t, t, sink)
		if exited {
			io.WriteString(t, "logout\n")
			s.Exit(code)
			return
		}
		t.SetPrompt(sess.Prompt())
	}
}

// runLine runs one line for the non-interactive paths and returns its code.
func (h *Handler) runLine(sess *shell.Session, line string, out, errw io.Writer, sink *recorder.Sink) int {
	exited, code := h.runInterpreter(sess, line, out, errw, sink)
	_ = exited
	return code
}

// runInterpreter executes a line, records it, and reports whether the
// session should end (exit/logout) and with what code.
func (h *Handler) runInterpreter(sess *shell.Session, line string, out, errw io.Writer, sink *recorder.Sink) (exited bool, code int) {
	cwd, user := sess.Cwd, sess.User
	status, exited, exitCode := h.interp.Run(sess, line, strings.NewReader(""), out, errw)
	if sink != nil {
		final := status
		if exited {
			final = exitCode
		}
		sink.Command(line, cwd, user, final)
	}
	if exited {
		return true, exitCode
	}
	return false, status
}

// Disconnected ends the recording.
func (h *Handler) Disconnected(c *sshd.Conn, err error) {
	h.mu.Lock()
	sink := h.sinks[c.ID]
	delete(h.sinks, c.ID)
	h.mu.Unlock()
	if sink != nil {
		sink.End(err, time.Now())
	}
	h.log.Info("disconnected", "conn", c.ID, "err", err)
}

func (h *Handler) nextSeed() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.seq++
	return h.seq
}

func termOf(s *sshd.Session) string {
	if s.PTY != nil {
		return s.PTY.Term
	}
	return ""
}

func addrString(a net.Addr) string {
	if a == nil {
		return ""
	}
	return a.String()
}
