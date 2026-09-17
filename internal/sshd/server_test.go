package sshd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"io"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// recordingHandler captures everything the server reports so tests can
// assert on it. Session behaviour is pluggable per test.
type recordingHandler struct {
	mu       sync.Mutex
	conns    []*Conn
	attempts []AuthAttempt
	sessions []*Session
	closed   []error
	serve    func(ctx context.Context, s *Session)
}

func (h *recordingHandler) Connected(c *Conn) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.conns = append(h.conns, c)
}

func (h *recordingHandler) AuthAttempt(_ *Conn, a AuthAttempt) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.attempts = append(h.attempts, a)
}

func (h *recordingHandler) Session(ctx context.Context, s *Session) {
	h.mu.Lock()
	h.sessions = append(h.sessions, s)
	h.mu.Unlock()
	if h.serve != nil {
		h.serve(ctx, s)
	}
}

func (h *recordingHandler) Disconnected(_ *Conn, err error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.closed = append(h.closed, err)
}

func (h *recordingHandler) waitDisconnected(t *testing.T, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		h.mu.Lock()
		got := len(h.closed)
		h.mu.Unlock()
		if got >= n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d disconnects", n)
}

func startServer(t *testing.T, cfg Config, h Handler) (addr string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AuthDelay == 0 {
		cfg.AuthDelay = time.Millisecond
	}
	srv := New(cfg, signer, h, slog.New(slog.NewTextHandler(io.Discard, nil)))
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Serve(ctx, ln) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Serve: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Serve did not return after cancel")
		}
	})
	return ln.Addr().String()
}

func dial(t *testing.T, addr string, cfg *ssh.ClientConfig) *ssh.Client {
	t.Helper()
	cfg.HostKeyCallback = ssh.InsecureIgnoreHostKey()
	cfg.Timeout = 5 * time.Second
	c, err := ssh.Dial("tcp", addr, cfg)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func TestServer_AcceptsAnyPasswordAndRecordsIt(t *testing.T) {
	h := &recordingHandler{}
	addr := startServer(t, Config{}, h)

	c := dial(t, addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("hunter2")}})
	_ = c.Close()
	h.waitDisconnected(t, 1)

	if len(h.attempts) != 1 {
		t.Fatalf("attempts = %d, want 1", len(h.attempts))
	}
	a := h.attempts[0]
	if a.Method != AuthPassword || a.User != "root" || a.Password != "hunter2" || !a.Accepted {
		t.Fatalf("unexpected attempt %+v", a)
	}
	if got := h.conns[0].User; got != "root" {
		t.Fatalf("conn.User = %q", got)
	}
	if got := h.conns[0].Password; got != "hunter2" {
		t.Fatalf("conn.Password = %q", got)
	}
	if !strings.HasPrefix(h.conns[0].ClientVersion, "SSH-2.0-Go") {
		t.Fatalf("ClientVersion = %q", h.conns[0].ClientVersion)
	}
}

func TestServer_AcceptAfterMakesTheBotWork(t *testing.T) {
	h := &recordingHandler{}
	addr := startServer(t, Config{AcceptAfter: 3}, h)

	// The client library retries password auth via a callback.
	tries := 0
	pw := ssh.RetryableAuthMethod(ssh.PasswordCallback(func() (string, error) {
		tries++
		return "guess" + string(rune('0'+tries)), nil
	}), 5)
	c := dial(t, addr, &ssh.ClientConfig{User: "admin", Auth: []ssh.AuthMethod{pw}})
	_ = c.Close()
	h.waitDisconnected(t, 1)

	if tries != 3 {
		t.Fatalf("client needed %d tries, want 3", tries)
	}
	accepted := 0
	for _, a := range h.attempts {
		if a.Accepted {
			accepted++
		}
	}
	if len(h.attempts) != 3 || accepted != 1 || !h.attempts[2].Accepted {
		t.Fatalf("attempts = %+v", h.attempts)
	}
}

func TestServer_KeyboardInteractiveIsAccepted(t *testing.T) {
	h := &recordingHandler{}
	addr := startServer(t, Config{}, h)

	ki := ssh.KeyboardInteractive(func(_, _ string, questions []string, _ []bool) ([]string, error) {
		answers := make([]string, len(questions))
		for i := range answers {
			answers[i] = "toor"
		}
		return answers, nil
	})
	c := dial(t, addr, &ssh.ClientConfig{User: "pi", Auth: []ssh.AuthMethod{ki}})
	_ = c.Close()
	h.waitDisconnected(t, 1)

	if len(h.attempts) != 1 || h.attempts[0].Method != AuthInteractive || h.attempts[0].Password != "toor" {
		t.Fatalf("attempts = %+v", h.attempts)
	}
}

func TestServer_PublicKeyIsRecordedButRejected(t *testing.T) {
	h := &recordingHandler{}
	addr := startServer(t, Config{}, h)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	c := dial(t, addr, &ssh.ClientConfig{
		User: "ubuntu",
		Auth: []ssh.AuthMethod{ssh.PublicKeys(signer), ssh.Password("fallback")},
	})
	_ = c.Close()
	h.waitDisconnected(t, 1)

	if len(h.attempts) != 2 {
		t.Fatalf("attempts = %+v", h.attempts)
	}
	key := h.attempts[0]
	if key.Method != AuthPublicKey || key.Accepted || key.KeyType != ssh.KeyAlgoED25519 ||
		key.KeyFP != ssh.FingerprintSHA256(signer.PublicKey()) {
		t.Fatalf("key attempt = %+v", key)
	}
	if !h.attempts[1].Accepted {
		t.Fatalf("password fallback should be accepted: %+v", h.attempts[1])
	}
}

func TestServer_ExecDeliversCommandAndExitStatus(t *testing.T) {
	h := &recordingHandler{serve: func(_ context.Context, s *Session) {
		_, _ = io.WriteString(s, "output for: "+s.Command+"\n")
		s.Exit(127)
	}}
	addr := startServer(t, Config{}, h)
	c := dial(t, addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")}})

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	out, err := sess.Output("uname -a")
	var exitErr *ssh.ExitError
	if err == nil {
		t.Fatal("expected a non-zero exit error")
	} else if !isExitError(err, &exitErr) || exitErr.ExitStatus() != 127 {
		t.Fatalf("err = %v, want exit 127", err)
	}
	if string(out) != "output for: uname -a\n" {
		t.Fatalf("out = %q", out)
	}
	if h.sessions[0].PTY != nil {
		t.Fatal("exec without pty should have nil PTY")
	}
}

func TestServer_ShellSeesPTYEnvAndResize(t *testing.T) {
	gotResize := make(chan WindowSize, 1)
	h := &recordingHandler{serve: func(_ context.Context, s *Session) {
		// Wait for the resize, then echo one line and exit.
		select {
		case ws := <-s.Resize:
			gotResize <- ws
		case <-time.After(5 * time.Second):
		}
		buf := make([]byte, 64)
		n, _ := s.Read(buf)
		_, _ = s.Write(buf[:n])
		s.Exit(0)
	}}
	addr := startServer(t, Config{}, h)
	c := dial(t, addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")}})

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.Setenv("LANG", "C.UTF-8"); err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestPty("xterm-256color", 24, 80, ssh.TerminalModes{}); err != nil {
		t.Fatal(err)
	}
	stdin, _ := sess.StdinPipe()
	stdout, _ := sess.StdoutPipe()
	if err := sess.Shell(); err != nil {
		t.Fatal(err)
	}
	if err := sess.WindowChange(50, 132); err != nil {
		t.Fatal(err)
	}
	select {
	case ws := <-gotResize:
		if ws.Cols != 132 || ws.Rows != 50 {
			t.Fatalf("resize = %+v", ws)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resize never arrived")
	}
	_, _ = io.WriteString(stdin, "hello\n")
	buf := make([]byte, 64)
	n, _ := stdout.Read(buf)
	if string(buf[:n]) != "hello\n" {
		t.Fatalf("echo = %q", buf[:n])
	}
	if err := sess.Wait(); err != nil {
		t.Fatalf("wait: %v", err)
	}

	s := h.sessions[0]
	if s.PTY == nil || s.PTY.Term != "xterm-256color" || s.PTY.Cols != 80 || s.PTY.Rows != 24 {
		t.Fatalf("PTY = %+v", s.PTY)
	}
	if s.Env["LANG"] != "C.UTF-8" {
		t.Fatalf("Env = %+v", s.Env)
	}
	if s.Command != "" {
		t.Fatalf("Command = %q, want empty for shell", s.Command)
	}
}

func TestServer_RejectsNonSessionChannelsAndSubsystems(t *testing.T) {
	h := &recordingHandler{}
	addr := startServer(t, Config{}, h)
	c := dial(t, addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")}})

	if _, _, err := c.OpenChannel("direct-tcpip", nil); err == nil {
		t.Fatal("direct-tcpip should be rejected")
	}
	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	if err := sess.RequestSubsystem("sftp"); err == nil {
		t.Fatal("sftp should be refused")
	}
}

func TestServer_ClientClosingSessionBeforeShellDoesNotHang(t *testing.T) {
	h := &recordingHandler{}
	addr := startServer(t, Config{}, h)
	c := dial(t, addr, &ssh.ClientConfig{User: "root", Auth: []ssh.AuthMethod{ssh.Password("x")}})

	sess, err := c.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	_ = sess.Close()
	_ = c.Close()
	h.waitDisconnected(t, 1) // would time out if serveSession were stuck
}

func isExitError(err error, target **ssh.ExitError) bool {
	e, ok := err.(*ssh.ExitError)
	if ok {
		*target = e
	}
	return ok
}
