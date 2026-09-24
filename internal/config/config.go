// Package config collects every runtime setting in one struct, filled from
// environment variables (container-friendly) and overridden by flags.
package config

import (
	"flag"
	"fmt"
	"os"
	"strconv"
	"time"
)

// Config is the whole honeypot's configuration.
type Config struct {
	// Addr is the SSH listen address.
	Addr string
	// DataDir holds the host key, session logs and transcripts.
	DataDir string
	// AcceptAfter is which password attempt succeeds (1 = first).
	AcceptAfter int
	// AuthDelay is the pause before answering an auth attempt.
	AuthDelay time.Duration
	// IdleTimeout ends a quiet session.
	IdleTimeout time.Duration
	// LogJSON switches the operational log to JSON lines.
	LogJSON bool
	// ProfilePath is an optional JSON machine profile; empty uses the
	// built-in default Ubuntu VPS.
	ProfilePath string
	// LLM selects the model backend for unknown commands and file
	// contents: "off" (default), "anthropic" or "ollama".
	LLM string
	// LLMModel overrides the backend's default model.
	LLMModel string
}

// Load reads env vars, then parses args as flags on top of them.
func Load(args []string) (Config, error) {
	c := Config{
		Addr:        envOr("HONEYPOT_ADDR", ":2222"),
		DataDir:     envOr("HONEYPOT_DATA_DIR", "./data"),
		AcceptAfter: 1,
		AuthDelay:   400 * time.Millisecond,
		IdleTimeout: 5 * time.Minute,
	}
	var err error
	if c.AcceptAfter, err = envInt("HONEYPOT_ACCEPT_AFTER", c.AcceptAfter); err != nil {
		return c, err
	}
	if c.AuthDelay, err = envDuration("HONEYPOT_AUTH_DELAY", c.AuthDelay); err != nil {
		return c, err
	}
	if c.IdleTimeout, err = envDuration("HONEYPOT_IDLE_TIMEOUT", c.IdleTimeout); err != nil {
		return c, err
	}
	c.LogJSON = os.Getenv("HONEYPOT_LOG_JSON") == "1"
	c.ProfilePath = os.Getenv("HONEYPOT_PROFILE")
	c.LLM = envOr("HONEYPOT_LLM", "off")
	c.LLMModel = os.Getenv("HONEYPOT_LLM_MODEL")

	fs := flag.NewFlagSet("honeypot", flag.ContinueOnError)
	fs.StringVar(&c.Addr, "addr", c.Addr, "SSH listen address (HONEYPOT_ADDR)")
	fs.StringVar(&c.DataDir, "data", c.DataDir, "data directory for keys and logs (HONEYPOT_DATA_DIR)")
	fs.IntVar(&c.AcceptAfter, "accept-after", c.AcceptAfter, "password attempt that succeeds (HONEYPOT_ACCEPT_AFTER)")
	fs.DurationVar(&c.AuthDelay, "auth-delay", c.AuthDelay, "delay before answering auth (HONEYPOT_AUTH_DELAY)")
	fs.DurationVar(&c.IdleTimeout, "idle-timeout", c.IdleTimeout, "close idle sessions after (HONEYPOT_IDLE_TIMEOUT)")
	fs.BoolVar(&c.LogJSON, "log-json", c.LogJSON, "log as JSON lines (HONEYPOT_LOG_JSON=1)")
	fs.StringVar(&c.ProfilePath, "profile", c.ProfilePath, "JSON machine profile (HONEYPOT_PROFILE); default is a built-in Ubuntu VPS")
	fs.StringVar(&c.LLM, "llm", c.LLM, "model backend for unknown commands/files: off|anthropic|ollama (HONEYPOT_LLM)")
	fs.StringVar(&c.LLMModel, "llm-model", c.LLMModel, "override the backend's default model (HONEYPOT_LLM_MODEL)")
	if err := fs.Parse(args); err != nil {
		return c, err
	}
	if c.AcceptAfter < 1 {
		return c, fmt.Errorf("accept-after must be >= 1, got %d", c.AcceptAfter)
	}
	return c, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) (int, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return n, nil
}

func envDuration(key string, def time.Duration) (time.Duration, error) {
	v := os.Getenv(key)
	if v == "" {
		return def, nil
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def, fmt.Errorf("%s: %w", key, err)
	}
	return d, nil
}
