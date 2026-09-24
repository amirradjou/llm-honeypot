# llm-honeypot

An SSH honeypot that accepts any login and hands the attacker a convincing, fake
Linux box. It logs everything they try, keeps them busy, and (once the model
backend lands) fills in the long tail of commands with an LLM — always staying
consistent with the machine it is pretending to be.

> **Never run this on a machine that matters.** It is designed to be exposed to
> the internet and poked at by hostile bots. Run it in a throwaway container on a
> throwaway VPS, on a port your real sshd does not use.

## What it does today

- A Go SSH server (`golang.org/x/crypto/ssh`) that **accepts any username and
  password** after a plausible delay, and records every attempt — including the
  public keys bots present (a bot offering a key is a stolen key in the wild).
- A **fake interactive shell**: a consistent in-memory filesystem seeded to look
  like a small Ubuntu 22.04 VPS running nginx, a Node app and PostgreSQL, with
  believable users, processes, logs, cron jobs, and credentials that lead
  nowhere. Over 130 commands are emulated in Go.
- **Everything is recorded**: a machine-readable JSONL event log and a
  human-readable transcript per connection, with URLs, IPs and file hashes
  extracted from what the attacker types.
- **Nothing is ever executed.** No real shell, no real network. `wget`/`curl`
  log the URL and drop an opaque placeholder file so later commands behave as if
  the download worked; running that file reports `cannot execute binary file`.

## Quick start

```sh
# Build and run locally on port 2222
make run                      # or: go run ./cmd/honeypot -addr :2222 -data ./data

# Connect as an "attacker" (any password works)
ssh -p 2222 root@localhost    # try: uname -a, ps aux, cat /etc/passwd, wget http://x/y

# Watch what they did
ls data/sessions/<date>/
cat data/sessions/<date>/<conn>.log      # human transcript
cat data/sessions/<date>/<conn>.jsonl    # structured events
```

### With Docker

```sh
docker compose up --build     # listens on :2222, data in a named volume
```

The container runs as a non-root user on read-only rootfs with all capabilities
dropped. To actually catch bots, move your real sshd off port 22 first, then map
`22:2222`.

## Configuration

Flags override environment variables; both are optional.

| Flag | Env | Default | Meaning |
|------|-----|---------|---------|
| `-addr` | `HONEYPOT_ADDR` | `:2222` | SSH listen address |
| `-data` | `HONEYPOT_DATA_DIR` | `./data` | host key, session logs, transcripts |
| `-accept-after` | `HONEYPOT_ACCEPT_AFTER` | `1` | which password attempt succeeds |
| `-auth-delay` | `HONEYPOT_AUTH_DELAY` | `400ms` | pause before answering auth |
| `-idle-timeout` | `HONEYPOT_IDLE_TIMEOUT` | `5m` | close idle sessions |
| `-profile` | `HONEYPOT_PROFILE` | built-in | JSON machine profile to impersonate |
| `-log-json` | `HONEYPOT_LOG_JSON=1` | off | operational log as JSON lines |

A **machine profile** describes the box the honeypot pretends to be (hostname,
OS, kernel, hardware, network, users, processes, packages). The built-in default
is a small Ubuntu 22.04 VPS. A JSON profile only needs to list the fields it
changes; everything else keeps the default.

## How it is built

```
attacker ──ssh──► internal/sshd      accept-all auth, session channels, host key
                     │  Handler
                     ▼
                  internal/honeypot   glue: per-connection recording + shell
                     │
        ┌────────────┼─────────────────────────┐
        ▼            ▼                           ▼
 internal/shell  internal/machine        internal/recorder
 parser +        profile ─► seeded        JSONL events +
 interpreter +   virtual filesystem       transcript +
 130+ commands   (internal/vfs, cloned    IOC extraction
                 per session)
```

- **`internal/vfs`** — an in-memory filesystem with Unix permissions, symlinks,
  device nodes, placeholder files (content generated on first read) and opaque
  files (binaries/payloads that report a size but are never stored). Each session
  runs on an independent `Clone()`.
- **`internal/profile` + `internal/machine`** — turn a profile into a fully
  populated `/etc`, `/home`, `/proc`, `/dev`, `/usr/bin`, `/var/log`, `/srv` …
  with stable, believably-old timestamps.
- **`internal/shell`** — a real-ish bash: quoting, `$VAR`/`~` expansion with word
  splitting, pipelines, `&&`/`||`/`;`, redirections into the VFS, and command
  built-ins grouped by concern (files, system, network, accounts).
- **`internal/recorder`** — the audit trail.

Two rules shape everything (see `CLAUDE.md`): **never execute attacker input**,
and **attacker text is data** — it only ever reaches a model inside a fixed
frame.

## Roadmap

- **v0 (done)** — accept-all SSH server, seeded machine, emulated shell,
  recording, Docker. ← you are here
- **v1** — LLM fallback for unknown commands and file contents, constrained to
  stay consistent with the machine state; pluggable model backend.
- **v2** — session clustering, a dashboard, the first monthly "what the bots did"
  report.
- **v3** — payload capture into an isolated sandbox; honeypot-detection study.

## Development

```sh
make test     # go test -race ./...
make lint     # gofmt + go vet
make build    # ./bin/honeypot
```

## Legal / ethics

This is a defensive tool: it observes unsolicited attacks against a system you
control and never attacks back or executes attacker code. You are responsible for
where you deploy it. Do not use it to entrap, to attack third parties, or on
infrastructure you do not own.
