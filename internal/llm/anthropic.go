package llm

import (
	"context"
	"fmt"
	"time"

	"github.com/anthropics/anthropic-sdk-go"
	"github.com/anthropics/anthropic-sdk-go/option"
)

// Anthropic generates output with the Claude API. It defaults to a small,
// fast model (Haiku) because the honeypot may call it often and only needs
// believable shell output, not deep reasoning; override with the model
// argument.
type Anthropic struct {
	client anthropic.Client
	model  string
	maxTok int64
	// timeout bounds a single generation so a slow model cannot stall a
	// session (the attacker would just see the fallback).
	timeout time.Duration
}

// AnthropicOptions configures the backend.
type AnthropicOptions struct {
	APIKey  string // empty → SDK resolves ANTHROPIC_API_KEY / profile
	Model   string // empty → claude-haiku-4-5
	Timeout time.Duration
}

// NewAnthropic builds the Claude-backed generator.
func NewAnthropic(opts AnthropicOptions) *Anthropic {
	var clientOpts []option.RequestOption
	if opts.APIKey != "" {
		clientOpts = append(clientOpts, option.WithAPIKey(opts.APIKey))
	}
	model := opts.Model
	if model == "" {
		model = "claude-haiku-4-5"
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 20 * time.Second
	}
	return &Anthropic{
		client:  anthropic.NewClient(clientOpts...),
		model:   model,
		maxTok:  2048,
		timeout: timeout,
	}
}

func (a *Anthropic) Model() string { return a.model }

func (a *Anthropic) Generate(ctx context.Context, req Request) (string, int, error) {
	ctx, cancel := context.WithTimeout(ctx, a.timeout)
	defer cancel()

	resp, err := a.client.Messages.New(ctx, anthropic.MessageNewParams{
		Model:     anthropic.Model(a.model),
		MaxTokens: a.maxTok,
		System: []anthropic.TextBlockParam{{
			Text:         systemPrompt,
			CacheControl: anthropic.NewCacheControlEphemeralParam(),
		}},
		Messages: []anthropic.MessageParam{
			anthropic.NewUserMessage(anthropic.NewTextBlock(buildUser(req))),
		},
	})
	if err != nil {
		return "", 0, fmt.Errorf("anthropic: %w", err)
	}
	if resp.StopReason == anthropic.StopReasonRefusal {
		return "", 0, fmt.Errorf("anthropic: refused (%s)", resp.StopDetails.Category)
	}

	var raw string
	for _, block := range resp.Content {
		if t, ok := block.AsAny().(anthropic.TextBlock); ok {
			raw += t.Text
		}
	}
	tokens := int(resp.Usage.InputTokens + resp.Usage.OutputTokens)
	if looksLikeRefusal(raw) {
		return "", tokens, fmt.Errorf("anthropic: out-of-character response")
	}
	return clean(raw), tokens, nil
}
