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
- `x/term.Terminal.Write` already converts `\n` → `\r\n`; do not double it. `ReadLine` returns
  `io.EOF` for **both** Ctrl-D and Ctrl-C, so the shell must filter byte 0x03 before the
  Terminal (map it to 0x15 kill-line + `\r`) or Ctrl-C logs the attacker out.
- `sshd.Handler` is the only seam between the SSH layer and the rest. Auth callbacks run
  before `Session`, so failed-only connections still reach `Connected`/`AuthAttempt`/`Disconnected`.
- Real OpenSSH clients try publickey first, then keyboard-interactive (not password); both are
  handled. Disconnect reason 11 is a clean close, normalised to `nil`.
- The VFS is a *template*: `Clone()` it per session. Placeholder files (`Info.Placeholder`)
  have no content until a generator fills them; write the result back with `WriteFile`.
- Downloads are never fetched. Plan: `wget`/`curl` log the URL and create an opaque file;
  running it prints `cannot execute binary file: Exec format error`.

## Status (2026-09-17) — branch `feat/v0`, nothing merged yet
Done and tested: `internal/sshd` (accept-all server, sessions, host key), `internal/config`,
`internal/profile` (default Ubuntu 22.04 VPS), `internal/vfs` (files, dirs, symlinks, devices,
permissions, placeholders, dynamic files, clone). `cmd/honeypot` runs the server with a
**placeholder handler** that only logs and says "down for maintenance".

## Next steps, in order (one commit each, tests alongside)
1. `internal/machine` — seed a template VFS from the profile: `/etc` (passwd, group, shadow
   0640 gid 42, hostname, hosts, os-release, lsb-release, resolv.conf, fstab, crontab, ssh/,
   sudoers 0440, nginx/ with sites-enabled symlink, postgresql/ placeholders), `/root` and
   `/home/*` (.bashrc, .profile, juicy .bash_history, .ssh/authorized_keys), `/srv/bakery`
   (package.json, `.env` with fake creds), `/var/log/*`, `/proc` (cpuinfo, meminfo, version,
   dynamic uptime/loadavg), `/dev` nodes, `/usr/bin` + `/usr/sbin` fake ELF executables with
   `/bin` `/sbin` `/lib` symlinks (merged-usr), `/boot`. Stable pseudo-random old mtimes from a
   hash of the path so `ls -l` looks lived-in and is identical across restarts.
   `Machine{Profile, FS, BootTime}` with `Uptime()` and `NewSessionFS()`.
2. `internal/shell` — parser (single/double quotes, backslash, `;` `&&` `||` `|` `&`,
   `>` `>>` `<` into the VFS, `$VAR`/`${VAR}`, `~`), interpreter with per-session cwd/env/
   history, `Command func(*Context) int` registry, pipelines via buffered stdout→stdin.
   Three modes: PTY (Terminal, prompt `root@host:~# `), no-PTY shell (read lines, no echo,
   no prompt), exec (`s.Command`). Unknown command → `-bash: x: command not found` (127)
   until the model fallback exists.
3. Commands, grouped commits: navigation (ls -la/-lh, cd, pwd); files (cat, head, tail,
   echo -e/-n with \x escapes, touch, mkdir -p, rm -rf, cp, mv, chmod, chown, wc, grep,
   which, find basic); system (uname, whoami, id, hostname, uptime, w, who, last, ps aux,
   free -m, df -h, nproc, lscpu, env, export, unset, history, clear, exit/logout, date,
   sleep capped, true/false); network (wget, curl, tftp, ftpget → log URL, create opaque
   file; ifconfig, ip a, netstat -tulpn); accounts (passwd, chpasswd, useradd, usermod →
   succeed silently + log); `busybox` (Mirai probes `busybox ECCHI` → `ECCHI: applet not
   found`); `sh -c` / `bash -c`, `sudo`, `crontab -l`.
4. `internal/recorder` — events (connect, auth, pty, env, command, output, download,
   file_write, model_call, disconnect) to `data/sessions/<date>/<conn-id>.jsonl` plus a
   plain-text transcript; extract URLs, IPs, sha256-looking hashes from commands.
5. `internal/honeypot` — the `sshd.Handler` that glues machine + shell + recorder; replace
   the placeholder in `cmd/honeypot/main.go`. Manual check with the real `ssh` client
   (`sshpass -p x ssh -p 2222 root@127.0.0.1`) in both PTY and `ssh -T` modes.
6. `Dockerfile` (distroless/static, no cgo) + `compose.yaml`; README: running, config,
   safety notes; open the v0 PR (merge with a merge commit to keep the steps).
7. **v1** — `internal/llm`: load the `claude-api` skill *before* writing it. `Generator`
   interface, `null` / `anthropic` (anthropic-sdk-go, default `claude-haiku-4-5` for cost) /
   `ollama` backends; fixed prompt frame (profile + state + recent commands, attacker
   command as data); validator strips fences and drops anything that breaks character;
   fallback for unknown commands and placeholder files with write-back into the session
   VFS; a shared generation cache keyed by (profile, command) so every attacker sees the
   same `lscpu`. Then SQLite store (`modernc.org/sqlite`) and a `sessions` subcommand.
8. Register in HQ (`/hq add`), update `~/.claude/memory/projects-overview.md`.
