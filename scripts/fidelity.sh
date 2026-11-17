#!/usr/bin/env bash
# Rebuild the README's fidelity numbers: run every line of
# tools/fidelity/corpus.txt in a fresh honeypot and in a stock Ubuntu 22.04
# container, then write docs/fidelity.md and docs/fidelity.svg.
#
# Needs Go and Docker. The honeypot listens on loopback only and is stopped
# when the script exits.
set -euo pipefail

cd "$(dirname "$0")/.."
port="${FIDELITY_PORT:-2399}"
image="llm-honeypot-fidelity-ref"

docker build -q -t "$image" tools/fidelity >/dev/null
go build -o bin/honeypot ./cmd/honeypot

data="$(mktemp -d)"
./bin/honeypot -addr "127.0.0.1:${port}" -data "$data" >"$data/honeypot.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2>/dev/null || true' EXIT

for _ in $(seq 50); do
  if (exec 3<>"/dev/tcp/127.0.0.1/${port}") 2>/dev/null; then break; fi
  sleep 0.1
done

go run ./tools/fidelity \
  -addr "127.0.0.1:${port}" \
  -image "$image" \
  -baseline docs/fidelity-before.json \
  -json docs/fidelity.json \
  -svg docs/fidelity.svg \
  -label "Model backend off (the default). Before = the code before the fidelity work (commit dc80abf)." \
  -o docs/fidelity.md
