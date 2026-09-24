package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// Ollama generates output with a local Ollama server (http://localhost:11434
// by default), so the honeypot can run fully offline with a small local
// model — no API key, no data leaving the box.
type Ollama struct {
	baseURL string
	model   string
	http    *http.Client
	timeout time.Duration
}

// OllamaOptions configures the backend.
type OllamaOptions struct {
	BaseURL string // empty → http://localhost:11434
	Model   string // empty → qwen2.5:3b
	Timeout time.Duration
}

// NewOllama builds the Ollama-backed generator.
func NewOllama(opts OllamaOptions) *Ollama {
	base := opts.BaseURL
	if base == "" {
		base = "http://localhost:11434"
	}
	model := opts.Model
	if model == "" {
		model = "qwen2.5:3b"
	}
	timeout := opts.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &Ollama{baseURL: base, model: model, http: &http.Client{Timeout: timeout}, timeout: timeout}
}

func (o *Ollama) Model() string { return o.model }

type ollamaChatReq struct {
	Model    string              `json:"model"`
	Messages []ollamaChatMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Options  map[string]any      `json:"options,omitempty"`
}

type ollamaChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChatResp struct {
	Message         ollamaChatMessage `json:"message"`
	PromptEvalCount int               `json:"prompt_eval_count"`
	EvalCount       int               `json:"eval_count"`
	Error           string            `json:"error"`
}

func (o *Ollama) Generate(ctx context.Context, req Request) (string, int, error) {
	body, err := json.Marshal(ollamaChatReq{
		Model:  o.model,
		Stream: false,
		Options: map[string]any{
			"temperature": 0.4,
			"num_predict": 1024,
		},
		Messages: []ollamaChatMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: buildUser(req)},
		},
	})
	if err != nil {
		return "", 0, err
	}
	ctx, cancel := context.WithTimeout(ctx, o.timeout)
	defer cancel()

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/api/chat", bytes.NewReader(body))
	if err != nil {
		return "", 0, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := o.http.Do(httpReq)
	if err != nil {
		return "", 0, fmt.Errorf("ollama: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("ollama: status %d", resp.StatusCode)
	}

	var out ollamaChatResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", 0, fmt.Errorf("ollama: decode: %w", err)
	}
	if out.Error != "" {
		return "", 0, fmt.Errorf("ollama: %s", out.Error)
	}
	tokens := out.PromptEvalCount + out.EvalCount
	if looksLikeRefusal(out.Message.Content) {
		return "", tokens, fmt.Errorf("ollama: out-of-character response")
	}
	return clean(out.Message.Content), tokens, nil
}
