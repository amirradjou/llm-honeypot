package sshd

import (
	"context"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

// PTY holds what the client asked for in its pty-req.
type PTY struct {
	Term string
	Cols int
	Rows int
}

// WindowSize is delivered on Session.Resize when the client's terminal changes.
type WindowSize struct {
	Cols int
	Rows int
}

// Session is one "session" channel on an authenticated connection: either
// an interactive shell or a single exec command. The Handler reads
// attacker input from Session and writes the fake shell's output to it.
type Session struct {
	Conn *Conn
	// Index numbers session channels on the same connection from 0.
	Index int
	// PTY is nil when the client did not ask for a terminal (common for
	// bots that pipe commands in).
	PTY *PTY
	// Env holds variables the client asked to set via env requests.
	Env map[string]string
	// Command is the exec command, or "" for an interactive shell.
	Command string
	// Resize delivers window-change requests while the session runs.
	Resize <-chan WindowSize

	ch          ssh.Channel
	idleTimeout time.Duration
	idle        *time.Timer
	closeOnce   sync.Once
}

// Read pulls attacker input. Every successful read pushes the idle
// deadline out; a session that goes quiet is closed by the server.
func (s *Session) Read(p []byte) (int, error) {
	n, err := s.ch.Read(p)
	if n > 0 && s.idle != nil {
		s.idle.Reset(s.idleTimeout)
	}
	return n, err
}

// Write sends output to the attacker.
func (s *Session) Write(p []byte) (int, error) { return s.ch.Write(p) }

// Stderr is the channel's extended-data stream. A real sshd keeps a
// command's stderr apart from its stdout, and a bot that runs
// `ssh host cmd 2>/dev/null` notices when the two arrive mixed.
func (s *Session) Stderr() io.Writer { return s.ch.Stderr() }

// Exit reports the command's exit status and closes the channel. It is
// safe to call more than once.
func (s *Session) Exit(code int) {
	s.closeOnce.Do(func() {
		if s.idle != nil {
			s.idle.Stop()
		}
		_, _ = s.ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(code)}))
		_ = s.ch.Close()
	})
}

// Request payloads, as laid out in RFC 4254 section 6.
type (
	ptyRequest struct {
		Term          string
		Cols, Rows    uint32
		Width, Height uint32
		Modes         string
	}
	windowChangeRequest struct {
		Cols, Rows    uint32
		Width, Height uint32
	}
	envRequest struct {
		Name, Value string
	}
	execRequest struct {
		Command string
	}
)

// serveSession answers channel requests until the client asks for a shell
// or exec, then runs the Handler and reports the exit status.
func (s *Server) serveSession(ctx context.Context, conn *Conn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	resize := make(chan WindowSize, 4)
	sess := &Session{
		Conn:        conn,
		Index:       conn.nextSessionIndex(),
		Env:         map[string]string{},
		Resize:      resize,
		ch:          ch,
		idleTimeout: s.cfg.IdleTimeout,
	}
	defer sess.Exit(0)

	// Requests arrive on their own goroutine so that the Handler can block
	// on reads while window-change requests still get through.
	started := false
	done := make(chan struct{})
	run := func() {
		if started {
			return
		}
		started = true
		sess.idle = time.AfterFunc(s.cfg.IdleTimeout, func() {
			s.log.Info("session idle timeout", "conn", conn.ID, "session", sess.Index)
			_ = ch.Close()
		})
		go func() {
			defer close(done)
			s.handler.Session(ctx, sess)
		}()
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case req, ok := <-reqs:
			if !ok {
				// Channel closed by the client. If a handler is running it
				// will notice on its next read; wait for it so exit-status
				// and cleanup happen in order.
				if started {
					<-done
				}
				return
			}
			s.handleRequest(sess, req, resize, run)
		}
	}
}

func (s *Server) handleRequest(sess *Session, req *ssh.Request, resize chan<- WindowSize, run func()) {
	ok, start := false, false
	switch req.Type {
	case "pty-req":
		var r ptyRequest
		if err := ssh.Unmarshal(req.Payload, &r); err == nil {
			sess.PTY = &PTY{Term: r.Term, Cols: int(r.Cols), Rows: int(r.Rows)}
			ok = true
		}
	case "window-change":
		var r windowChangeRequest
		if err := ssh.Unmarshal(req.Payload, &r); err == nil {
			select {
			case resize <- WindowSize{Cols: int(r.Cols), Rows: int(r.Rows)}:
			default:
			}
			ok = true
		}
	case "env":
		var r envRequest
		if err := ssh.Unmarshal(req.Payload, &r); err == nil {
			sess.Env[r.Name] = r.Value
			ok = true
		}
	case "shell":
		ok = true
		start = true
	case "exec":
		var r execRequest
		if err := ssh.Unmarshal(req.Payload, &r); err == nil {
			sess.Command = r.Command
			ok = true
			start = true
		}
	case "subsystem", "x11-req", "auth-agent-req@openssh.com":
		// sftp, X11 and agent forwarding are refused, as they would be on a
		// hardened box. The refusal itself is normal-looking.
		ok = false
	case "signal":
		ok = true
	}
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
	// Start the command only after the reply: a command that finishes at
	// once would otherwise send exit-status and close the channel before
	// the client heard that its exec was accepted, and the client sees EOF.
	if start {
		run()
	}
}

func (c *Conn) nextSessionIndex() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	i := c.sessions
	c.sessions++
	return i
}
