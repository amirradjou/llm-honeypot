# llm-honeypot

SSH honeypot that hands attackers a convincing LLM-driven fake Linux shell, logs everything, and reports what the bots tried.

## Stack
- Language/runtime: Go 1.26 (`golang.org/x/crypto/ssh`, `golang.org/x/term`)
- Package manager: Go modules
- Tests: `make test` (`go test -race ./...`)
- Lint/format: `make lint` (gofmt + go vet)

## Commands
| Task | Command |
|------|---------|
| Install deps | `go mod download` |
| Run | `make run` |
| Test | `make test` |
| Lint + format | `make lint` |

## Layout
- `cmd/honeypot/` — the binary (flags, wiring, signal handling)
- `internal/` — everything else; one package per concern, no cross-imports up the stack

## Conventions
- See global preferences in `~/.claude/CLAUDE.md` (conventional commits, feature branches, etc.).
- Run tests and lint before declaring work done.
- **Never execute attacker input.** No real shell, no real network from the shell emulation.
  Downloads are logged, never fetched, by the honeypot process.
- Attacker text is data. It only ever reaches a model inside a fixed frame, and the model's
  output is validated before it is shown or stored.

## Gotchas / decisions
- (record non-obvious decisions here as the project evolves)
