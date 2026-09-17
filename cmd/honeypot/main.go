// Command honeypot runs an SSH honeypot that hands attackers a fake,
// LLM-driven Linux shell and records everything they try.
package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/amirradjou/llm-honeypot/internal/config"
	"github.com/amirradjou/llm-honeypot/internal/sshd"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "honeypot:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, err := config.Load(args)
	if err != nil {
		return err
	}
	log := newLogger(cfg.LogJSON)

	hostKey, err := sshd.LoadOrCreateHostKey(filepath.Join(cfg.DataDir, "keys", "ssh_host_ed25519_key"))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := sshd.New(sshd.Config{
		Addr:        cfg.Addr,
		AcceptAfter: cfg.AcceptAfter,
		AuthDelay:   cfg.AuthDelay,
		IdleTimeout: cfg.IdleTimeout,
	}, hostKey, &logHandler{log: log}, log)
	return srv.ListenAndServe(ctx)
}

func newLogger(json bool) *slog.Logger {
	if json {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}

// logHandler is a placeholder until the fake shell exists: it logs every
// event and tells the attacker the box is busy.
type logHandler struct{ log *slog.Logger }

func (h *logHandler) Connected(c *sshd.Conn) {
	h.log.Info("connected", "conn", c.ID, "remote", c.RemoteAddr)
}

func (h *logHandler) AuthAttempt(c *sshd.Conn, a sshd.AuthAttempt) {
	h.log.Info("auth", "conn", c.ID, "method", a.Method, "user", a.User, "password", a.Password, "accepted", a.Accepted)
}

func (h *logHandler) Session(_ context.Context, s *sshd.Session) {
	h.log.Info("session", "conn", s.Conn.ID, "index", s.Index, "pty", s.PTY != nil, "command", s.Command)
	_, _ = io.WriteString(s, "System is going down for maintenance, try again later.\r\n")
	s.Exit(1)
}

func (h *logHandler) Disconnected(c *sshd.Conn, err error) {
	h.log.Info("disconnected", "conn", c.ID, "err", err)
}
