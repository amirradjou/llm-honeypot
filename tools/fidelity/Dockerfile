# The reference machine for the fidelity check: a stock Ubuntu 22.04 with the
# packages a small 22.04 server has installed, plus the bits of state the
# honeypot's default profile claims (a root crontab, two users). Bot command
# lines run here with --network none, one fresh container per line.
FROM ubuntu:22.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      busybox-static cron curl e2fsprogs file iproute2 iputils-ping kmod less \
      lsb-release net-tools netcat-openbsd openssh-server procps psmisc python3 \
      sudo vim-tiny wget \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash martin \
 && useradd -m -s /bin/bash deploy \
 && printf '@reboot /root/scripts/warm-cache.sh\n' | crontab -

WORKDIR /root
