# Fidelity check

Bot-style command lines from [`tools/fidelity/corpus.txt`](../tools/fidelity/corpus.txt), each run once in the honeypot over SSH and once in a fresh Ubuntu 22.04 container ([`tools/fidelity/Dockerfile`](../tools/fidelity/Dockerfile), no network). A line matches when the exit code is the same and stdout and stderr are empty or non-empty on both sides; `exact` lines must also print the same stdout. Download lines (`net`) cannot run on a box with no network, so they only have to avoid looking broken.

Held-out set, written after the corpus.txt fixes and run once on commit 1425163 plus the interactive-shell change; model backend off.

**59 of 65 lines behave like Ubuntu 22.04 (90%). Giveaways: 3.**

A giveaway is an answer no stock server gives: `command not found` for a tool Ubuntu ships, a syntax error on valid bash, binary garbage on the terminal.

| Group | Lines | Match |
|---|---:|---:|
| recon | 17 | 15 |
| persistence | 5 | 3 |
| busybox probes | 4 | 4 |
| droppers | 4 | 4 |
| miner set-up | 6 | 5 |
| clean-up | 4 | 4 |
| shell syntax | 15 | 15 |
| is it a honeypot? | 10 | 9 |

## Differences

| Command | Why | Honeypot said | Ubuntu said |
|---|---|---|---|
| `getconf LONG_BIT` | exit 127, Ubuntu 0; stdout empty, Ubuntu not empty; stderr not empty, Ubuntu em… | exit 127: `bash: line 1: getconf: command not found` | exit 0: `64` |
| `whereis bash` | exit 127, Ubuntu 0; stdout empty, Ubuntu not empty; stderr not empty, Ubuntu em… | exit 127: `bash: line 1: whereis: command not found` | exit 0: `bash: /usr/bin/bash` |
| `mkdir -p /root/.ssh && chmod 700 /root/.ssh && ls -ld /root/.ssh \| c…` | exit 1, Ubuntu 0; stdout empty, Ubuntu not empty; stderr not empty, Ubuntu empty | exit 1: `cut: -c1-10: No such file or directory` | exit 0: `drwx------` |
| `echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCholdout test" >> ~/.ssh/…` | exit 0, Ubuntu 1; stdout not empty, Ubuntu empty; stderr empty, Ubuntu not empty | exit 0: `2` | exit 1: `bash: line 1: /root/.ssh/authorized_keys: No such file or d…` |
| `sysctl -n vm.nr_hugepages` | exit 127, Ubuntu 0; stdout empty, Ubuntu not empty; stderr not empty, Ubuntu em… | exit 127: `bash: line 1: sysctl: command not found` | exit 0: `0` |
| `stat -c %s /bin/ls` | exit 1, Ubuntu 0; stderr not empty, Ubuntu empty | exit 1: `stat: cannot stat '%s': No such file or directory` | exit 0: `138216` |
