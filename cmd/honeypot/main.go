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
	"time"

	"github.com/amirradjou/llm-honeypot/internal/config"
	"github.com/amirradjou/llm-honeypot/internal/honeypot"
	"github.com/amirradjou/llm-honeypot/internal/llm"
	"github.com/amirradjou/llm-honeypot/internal/machine"
	"github.com/amirradjou/llm-honeypot/internal/profile"
	"github.com/amirradjou/llm-honeypot/internal/recorder"
	"github.com/amirradjou/llm-honeypot/internal/sshd"
)

func main() {
	if err := dispatch(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "honeypot:", err)
		os.Exit(1)
	}
}

// dispatch routes to a subcommand. Anything that is not a known
// subcommand is treated as flags for `serve`, so the historical
// invocation (and the container entrypoint, which passes no arguments at
// all) keeps working unchanged.
func dispatch(args []string) error {
	if len(args) > 0 {
		switch args[0] {
		case "serve":
			return run(args[1:])
		case "report":
			return runReport(args[1:])
		case "dashboard":
			return runDashboard(args[1:])
		case "fetch":
			return runFetch(args[1:])
		case "help", "-h", "--help":
			usage(os.Stdout)
			return nil
		}
	}
	return run(args)
}

func usage(w io.Writer) {
	fmt.Fprint(w, `honeypot — an SSH honeypot with a fake, optionally LLM-driven shell

Usage:
  honeypot [serve] [flags]   run the honeypot (the default)
  honeypot report [flags]    summarise what the bots did, as Markdown
  honeypot dashboard [flags] serve that summary live (loopback by default)
  honeypot fetch [flags]     download recorded payloads into quarantine
                             (dry run unless -confirm; pulls live malware)
  honeypot help              show this message

Run `+"`honeypot <subcommand> -h`"+` for the flags of each.
`)
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

	if gen, err := buildGenerator(cfg, log); err != nil {
		return err
	} else if gen != nil {
		handler.UseGenerator(llm.NewCache(gen, 0))
	}

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

// buildGenerator constructs the model backend named by the config, or nil
// when llm is off. Returns an error only for an unknown backend name.
func buildGenerator(cfg config.Config, log *slog.Logger) (llm.Generator, error) {
	switch cfg.LLM {
	case "", "off", "none":
		return nil, nil
	case "anthropic":
		log.Info("llm backend", "backend", "anthropic", "model", orDefault(cfg.LLMModel, "claude-haiku-4-5"))
		return llm.NewAnthropic(llm.AnthropicOptions{Model: cfg.LLMModel}), nil
	case "ollama":
		log.Info("llm backend", "backend", "ollama", "model", orDefault(cfg.LLMModel, "qwen2.5:3b"))
		return llm.NewOllama(llm.OllamaOptions{Model: cfg.LLMModel}), nil
	default:
		return nil, fmt.Errorf("unknown llm backend %q (want off|anthropic|ollama)", cfg.LLM)
	}
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func newLogger(json bool) *slog.Logger {
	if json {
		return slog.New(slog.NewJSONHandler(os.Stderr, nil))
	}
	return slog.New(slog.NewTextHandler(os.Stderr, nil))
}
