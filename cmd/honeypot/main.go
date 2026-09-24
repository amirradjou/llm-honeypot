// Command honeypot runs an SSH honeypot that hands attackers a fake,
// LLM-driven Linux shell and records everything they try.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/amirradjou/llm-honeypot/internal/config"
	"github.com/amirradjou/llm-honeypot/internal/honeypot"
	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/profile"
	"github.com/amirradjou/llm-honeypot/internal/recorder"
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

	prof := profile.Default()
	if cfg.ProfilePath != "" {
		prof, err = profile.Load(cfg.ProfilePath)
		if err != nil {
			return err
		}
	}
	m, err := machine.New(prof, time.Now)
	if err != nil {
		return err
	}
	log.Info("machine ready", "hostname", prof.Hostname, "os", prof.OSPretty, "kernel", prof.Kernel)

	hostKey, err := sshd.LoadOrCreateHostKey(filepath.Join(cfg.DataDir, "keys", "ssh_host_ed25519_key"))
	if err != nil {
		return err
	}

	rec := recorder.New(cfg.DataDir)
	handler := honeypot.New(m, rec, log)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	srv := sshd.New(sshd.Config{
		Addr:        cfg.Addr,
		AcceptAfter: cfg.AcceptAfter,
		AuthDelay:   cfg.AuthDelay,
		IdleTimeout: cfg.IdleTimeout,
	}, hostKey, handler, log)

	log.Info("honeypot starting", "addr", cfg.Addr, "data", cfg.DataDir)
	return srv.ListenAndServe(ctx)
}

func newLogger(json bool) *slog.Logger {
	if json {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}
