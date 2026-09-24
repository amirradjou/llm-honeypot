package config

import (
	"testing"
	"time"
)

func TestLoad_EnvThenFlags(t *testing.T) {
	t.Setenv("HONEYPOT_ADDR", ":2200")
	t.Setenv("HONEYPOT_ACCEPT_AFTER", "3")
	t.Setenv("HONEYPOT_AUTH_DELAY", "1s")

	c, err := Load([]string{"-addr", ":2201"})
	if err != nil {
		t.Fatal(err)
	}
	if c.Addr != ":2201" {
		t.Errorf("flag should override env: Addr = %q", c.Addr)
	}
	if c.AcceptAfter != 3 || c.AuthDelay != time.Second {
		t.Errorf("env not applied: %+v", c)
	}
	if c.DataDir != "./data" || c.IdleTimeout != 5*time.Minute {
		t.Errorf("defaults not applied: %+v", c)
	}
}

func TestLoad_RejectsBadValues(t *testing.T) {
	t.Setenv("HONEYPOT_ACCEPT_AFTER", "zero")
	if _, err := Load(nil); err == nil {
		t.Error("expected error for non-numeric HONEYPOT_ACCEPT_AFTER")
	}
	t.Setenv("HONEYPOT_ACCEPT_AFTER", "")
	if _, err := Load([]string{"-accept-after", "0"}); err == nil {
		t.Error("expected error for accept-after 0")
	}
}
