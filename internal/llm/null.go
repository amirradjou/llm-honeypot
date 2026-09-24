package llm

import (
	"context"
	"errors"
)

// ErrNoBackend means no model is configured; callers fall back to the
// built-in default behaviour (command not found / empty file).
var ErrNoBackend = errors.New("llm: no backend configured")

// Null is the default backend: it declines everything, so the honeypot
// behaves exactly as it did before any model was wired in.
type Null struct{}

func (Null) Generate(context.Context, Request) (string, int, error) {
	return "", 0, ErrNoBackend
}

func (Null) Model() string { return "none" }
