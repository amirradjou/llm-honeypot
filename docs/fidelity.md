# Fidelity check

Bot-style command lines from [`tools/fidelity/corpus.txt`](../tools/fidelity/corpus.txt), each run once in the honeypot over SSH and once in a fresh Ubuntu 22.04 container ([`tools/fidelity/Dockerfile`](../tools/fidelity/Dockerfile), no network). A line matches when the exit code is the same and stdout and stderr are empty or non-empty on both sides; `exact` lines must also print the same stdout. Download lines (`net`) cannot run on a box with no network, so they only have to avoid looking broken.

Model backend off (the default). Before = the code before the fidelity work (commit dc80abf).

**90 of 90 lines behave like Ubuntu 22.04 (100%). Giveaways: 0.**

A giveaway is an answer no stock server gives: `command not found` for a tool Ubuntu ships, a syntax error on valid bash, binary garbage on the terminal.

| Group | Lines | Before | Now |
|---|---:|---:|---:|
| All lines | 90 | 47 | 90 |
| recon | 28 | 22 | 28 |
| key planting | 3 | 2 | 3 |
| passwords | 3 | 2 | 3 |
| busybox probes | 8 | 3 | 8 |
| droppers | 5 | 4 | 5 |
| miner set-up | 8 | 3 | 8 |
| clean-up | 3 | 3 | 3 |
| shell syntax | 22 | 4 | 22 |
| is it a honeypot? | 10 | 4 | 10 |
