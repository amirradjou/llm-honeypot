# Guide

The [README](../README.md) shows what the honeypot does. This page is the
reference: how to run it, every flag, what it records, and how the pictures and
numbers in the README were made.

- [Running it](#running-it)
- [Configuration](#configuration)
- [What gets recorded](#what-gets-recorded)
- [Reading the results](#reading-the-results)
- [The dashboard](#the-dashboard)
- [Capturing payloads](#capturing-payloads)
- [The model backend (optional)](#the-model-backend-optional)
- [The fidelity check](#the-fidelity-check)
- [Lab traffic and the demo GIF](#lab-traffic-and-the-demo-gif)
- [How it is built](#how-it-is-built)
- [Development](#development)

## Running it

> **Never run this on a machine that matters.** It is designed to be exposed to
> the internet and poked at by hostile bots. Run it in a throwaway container on a
> throwaway VPS, on a port your real sshd does not use.

```sh
make run                      # or: go run ./cmd/honeypot -addr :2222 -data ./data
ssh -p 2222 root@localhost    # any password works
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
| `-llm` | `HONEYPOT_LLM` | `off` | model backend: `off`, `anthropic`, `ollama` |
| `-llm-model` | `HONEYPOT_LLM_MODEL` | per backend | override the model id |

The `dashboard` subcommand also reads `HONEYPOT_DASHBOARD_ADDR`.

## What gets recorded

Every connection gets files under `data/sessions/<date>/`:

| File | What is in it |
|---|---|
| `<conn>.jsonl` | One JSON event per line: connect, every auth attempt (with passwords and key fingerprints), session, command (with cwd, user, exit code and extracted URLs/IPs/hashes), download, model call, disconnect. This is what `report` and `dashboard` read. |
| `<conn>.log` | The same session as a readable transcript. |
| `<conn>.cast` | Interactive sessions only: exactly what the attacker's terminal showed, as an [asciinema](https://asciinema.org) v2 recording, capped at 2 MiB. |

Replay a session in your terminal, or turn it into a GIF:

```sh
asciinema play data/sessions/2026-11-16/<conn>.cast
uv run scripts/cast2gif.py data/sessions/2026-11-16/<conn>.cast session.gif
```

## Reading the results

```sh
honeypot report [-data ./data] [-o report.md] [-top 10] [-clusters 5] [-transcript]
                [-geoip-country FILE] [-geoip-asn FILE]
```

`report` only reads, so it is safe to run while the honeypot is live. The output
covers, in order: an overview (sessions per day, dwell-time percentiles, commands
per session), how many sessions look like a bot that suspected something, ranked
tables of credentials / first commands / command names / source IPs / payload
hosts and families, the behaviour clusters, and a per-day bar chart.

**Clustering** groups sessions by the exact sequence of commands they ran. Two
normalisations make that useful: a leading path is stripped (so `/bin/busybox`
and `busybox` match) and running a file out of a writable drop directory
collapses to `./payload`, so two bots that differ only in the binary they fetched
show up as one behaviour rather than two. Chained lines are split with the
honeypot's own shell parser, so `cd /tmp; wget …; chmod +x x; ./x` counts as four
commands and clusters on all four.

**Where they come from.** With an IP database the report and the dashboard also
rank the source countries and networks (`AS14061 DigitalOcean, LLC`). Lookups are
done locally against MaxMind-format files, so no attacker IP is ever sent to a
third party. `scripts/get-geoip.sh` downloads this month's
[DB-IP Lite](https://db-ip.com/db/lite.php) country and ASN databases (free, no
account) into `./geoip/`; GeoLite2 files work too. DB-IP Lite is CC BY 4.0, so
the report and the page end with its credit line.

```sh
scripts/get-geoip.sh
./bin/honeypot report -geoip-country geoip/dbip-country-lite.mmdb -geoip-asn geoip/dbip-asn-lite.mmdb
```

The flags can also come from `HONEYPOT_GEOIP_COUNTRY` and `HONEYPOT_GEOIP_ASN`.

**Honeypot detection.** The report separates sessions that authenticated and ran
nothing (`Silent`) from those that ran a single look-around command and left
within ten seconds (`Probes`). A rising share of either is the signal that the
disguise is slipping.

## The dashboard

```sh
honeypot dashboard [-addr 127.0.0.1:8080] [-data ./data] [-refresh 5s]
                   [-geoip-country FILE] [-geoip-asn FILE]
```

Serves `/` (the page), `/report.md` and `/healthz`. The page is entirely
self-contained — no scripts, no external assets — so it works on an isolated host
and cannot phone home, and it refreshes itself with a `<meta refresh>` derived
from the read interval.

It **binds to loopback by default**, and that is the right default: the page is a
summary of hostile activity, sitting on a machine deliberately inviting
attackers. Reach it over a tunnel rather than publishing it:

```sh
ssh -L 8080:127.0.0.1:8080 you@honeypot-host
```

A non-loopback bind is honoured but prints a warning.

## Capturing payloads

The honeypot never fetches anything an attacker points at — it logs the URL and
moves on. `honeypot fetch` is the separate, deliberate step that goes and gets
them for analysis:

```sh
honeypot fetch                  # dry run: lists what it would download
honeypot fetch -confirm         # actually downloads, into <data>/payloads
```

**Read this before using `-confirm`.** It pulls live malware onto the machine
that runs it, and each request tells the attacker's server that somebody is
looking at them — which can get your address flagged, blocked, or targeted. Run
it somewhere disposable, or not at all. The dry run exists so the dangerous thing
is never the default.

What it does to keep that bounded:

- **Refuses private and local addresses.** Loopback, RFC1918, link-local
  (including cloud metadata at `169.254.169.254`), CGNAT, documentation and
  reserved ranges are all blocked. The check runs in the dialer, against the
  address actually being connected to, so DNS rebinding cannot walk past it.
- **http and https only**, redirects re-checked at every hop and bounded.
- **Size-capped** (8 MiB by default), with truncation recorded rather than
  silently filling the disk; compression is disabled so a small response cannot
  expand past the cap.
- **Content-addressed storage**: one binary served from twenty hosts is stored
  once with twenty URLs against it, which is how a payload family becomes
  visible.
- **Nothing is ever executed.** Blobs are written `0600`, with no execute bit,
  into a `0700` quarantine directory.

## The model backend (optional)

With `-llm off` (the default) the honeypot is entirely deterministic Go code.
Turning a backend on only affects two things: commands with no Go implementation,
and the few files seeded as placeholders (the shop's source, `.viminfo` and the
like). Those have built-in content too, so with the model off they read the
same way `ls -l` sizes them; with it on, the model may rewrite them on first read.

```sh
# Claude (needs ANTHROPIC_API_KEY, or `ant auth login`)
./bin/honeypot -llm anthropic                       # default model: claude-haiku-4-5
./bin/honeypot -llm anthropic -llm-model <model-id>    # any Claude model your key can use

# Fully local, nothing leaves the box
ollama pull qwen2.5:3b
./bin/honeypot -llm ollama -llm-model qwen2.5:3b
```

Haiku is the default because this output is high-volume and only needs to be
believable, not clever. A small local model works for offline testing but its
output is noticeably weaker — expect a stronger model to be much more convincing.

**Prompt-injection handling.** Every attacker input is hostile and some of it is
aimed at the model, so:

- The prompt frame is fixed, the attacker's command sits inside
  `<attacker_input>` tags, and the rules are restated *after* the data as well as
  before it. The tag itself is defanged if it appears in attacker text, so the
  frame cannot be closed early.
- A command line containing injection phrasing ("ignore all previous
  instructions", "you are now…", "reveal your instructions") is **never sent to
  the model at all**. Such a line is not a real Linux command, so the shell
  answers it the way bash really would — `command not found` — which is both
  safer and more convincing than anything a model would invent. The attempt is
  recorded as `declined-injection`.
- Generated output is validated: code fences and markdown artifacts stripped,
  refusals and out-of-character replies rejected (the honeypot then falls back to
  its built-in behaviour), and a hard 16 KiB cap per response.
- Identical requests are cached, so two attackers running `lscpu` see the same
  CPU and reading a file twice returns the same bytes.

The load-bearing protection, though, is structural: the model only ever produces
*text that is shown to the attacker*. It has no tools, cannot touch the real
filesystem or network, and nothing it emits is ever executed. A successful
injection gets an attacker some words on their own terminal, nothing more.

A **machine profile** describes the box the honeypot pretends to be (hostname,
OS, kernel, hardware, network, users, processes, packages). The built-in default
is a small Ubuntu 22.04 VPS. A JSON profile only needs to list the fields it
changes; everything else keeps the default.

What the default box has installed is recorded, not invented:
[`scripts/record-refdata.sh`](../scripts/record-refdata.sh) builds a 22.04 cloud
server with the profile's packages ([`tools/refdata/Dockerfile`](../tools/refdata/Dockerfile))
and copies out its package database (`dpkg -l`, `dpkg -s`, `apt list --installed`
and `/var/lib/dpkg/status` all read it), its `/usr/bin` and `/usr/sbin` (names,
sizes, modes, symlinks), its kernel files and stock configs such as
`/etc/services` and `ssh_config`, into `internal/machine/refdata`. Re-run it
after changing the package list; never edit the recorded files by hand.

The logs (`auth.log`, `syslog`, `kern.log`, nginx, PostgreSQL, the shop's own
log, `dpkg.log`) are generated from the profile up to the box's clock and
refreshed for each new session. Every event is a function of its time slot, so
two sessions agree, and the admins' logins in `auth.log` are the ones `last`
shows. Client addresses come from the documentation ranges (RFC 5737); nothing
about the host the honeypot runs on appears in them.

## The fidelity check

Bots spot honeypots by running ordinary commands and looking for answers a real
server never gives. `make fidelity` measures that directly: every line of
[`tools/fidelity/corpus.txt`](../tools/fidelity/corpus.txt) runs once in a fresh
honeypot (over real SSH, one connection per line) and once in a fresh
`ubuntu:22.04` container with the packages a small server has and no network
([`tools/fidelity/Dockerfile`](../tools/fidelity/Dockerfile)). A line matches when
the exit code is the same and stdout and stderr are empty or non-empty on both
sides; lines marked `exact` must also print the same stdout. Download lines
cannot run without a network, so they only have to avoid looking broken.

```sh
make fidelity     # writes docs/fidelity.md, docs/fidelity.json and docs/fidelity.svg
```

The corpus is hand-written in the shape of what SSH bots commonly send (recon
one-liners, key planting, Mirai-style busybox probes, miner set-up, clean-up) plus
the shell syntax those lines rely on. It is not a capture of real traffic, and a
container is not a booted VM, so lines that depend on systemd, utmp or the
profile's own files are left out. The latest report, including every line that
still differs, is [docs/fidelity.md](fidelity.md).

## Lab traffic and the demo GIF

The README's pictures come from the honeypot itself, driven by two small tools
that only ever talk to a honeypot on this machine (they refuse any other
address).

**The dashboard screenshot** is lab data, not real attacks. `tools/lab` plays
scripted bots modelled on commonly reported behaviour (SSH-key planters, recon
one-liners, Mirai-style probes, miner droppers, scanners that give up) from many
loopback addresses:

```sh
./bin/honeypot -addr 127.0.0.1:2222 -data /tmp/lab -accept-after 2 &
go run ./tools/lab -addr 127.0.0.1:2222 -sessions 400 -bots 60
./bin/honeypot dashboard -data /tmp/lab        # http://127.0.0.1:8080
```

**The demo GIF** is the honeypot's own recording of one session. `tools/demo`
types [`tools/demo/session.txt`](../tools/demo/session.txt) at a steady pace into
an interactive shell; the honeypot writes the `.cast`; `scripts/cast2gif.py`
renders it. The text on every frame is what the honeypot sent; only the clock is
evened out (keystrokes 50 ms apart, long pauses capped, the end dissolving into
the start):

```sh
./bin/honeypot -addr 127.0.0.1:2222 -data /tmp/demo &
go run ./tools/demo -addr 127.0.0.1:2222
uv run scripts/cast2gif.py /tmp/demo/sessions/*/*.cast docs/demo.gif
```

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
 190 commands    (internal/vfs, cloned    IOC extraction
      │          per session)
      ▼
 internal/llm    model backend for unknown commands and placeholder
                 files: fixed prompt frame, injection pre-filter,
                 output validation, consistency cache

 internal/analysis   reads the recordings back: sessions → clusters →
 (honeypot report)   statistics → the Markdown report
```

- **`internal/vfs`** — an in-memory filesystem with Unix permissions, symlinks,
  device nodes, placeholder files (built-in content a model may replace on
  first read) and opaque
  files (binaries/payloads that report a size but are never stored). Each session
  runs on an independent `Clone()`.
- **`internal/profile` + `internal/machine`** — turn a profile into a fully
  populated `/etc`, `/home`, `/proc`, `/dev`, `/usr/bin`, `/var/log`, `/srv` …
  with stable, believably-old timestamps.
- **`internal/shell`** — a bash that parses each line into a syntax tree and
  expands words as each command runs: quoting, parameter and command
  substitution, arithmetic, globbing against the VFS, pipelines, `if`/`for`/
  `while`/`case`/functions, redirections and fd duplication into the VFS, and
  190 commands (bash builtins plus coreutils, procps, awk, sed and friends).
  Per-line limits on loop iterations, nesting depth and bytes moved keep a
  hostile line from hanging a session.
- **`internal/recorder`** — the audit trail: events, transcript and the `.cast`
  screen replay.
- **`internal/analysis`** — reads the audit trail back: reconstructs sessions,
  clusters them into behaviours, computes the statistics, and renders both the
  Markdown report and the dashboard.
- **`internal/capture`** — the quarantine store and the guarded fetcher behind
  `honeypot fetch`. The only code in the project that touches the network, and
  only when asked.

Two rules shape everything in this codebase:

1. **Never execute attacker input.** There is no real shell, no real network from
   the emulation, and no path by which anything an attacker types runs. Downloads
   are logged, never fetched.
2. **Attacker text is data.** It reaches a model only inside a fixed frame, never
   as an instruction, and what comes back is validated before it is shown.

## Development

```sh
make test     # go test -race ./...
make lint     # gofmt + go vet
make build    # ./bin/honeypot
make fidelity # compare with a real Ubuntu 22.04 container (needs Docker)
```
