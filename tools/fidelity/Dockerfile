# The reference machine for the fidelity check: a stock Ubuntu 22.04 with the
# packages a small 22.04 server has installed, plus the bits of state the
# honeypot's default profile claims (a root crontab, two users, an auth.log
# with sshd in it, which a container's missing syslog daemon never writes).
# Bot command lines run here with --network none, one fresh container per line.
FROM ubuntu:22.04

RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      busybox-static cron curl e2fsprogs file iproute2 iputils-ping kmod less \
      lsb-release net-tools netbase netcat-openbsd openssh-server procps psmisc python3 \
      sudo vim-tiny wget \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash martin \
 && useradd -m -s /bin/bash deploy \
 && printf '@reboot /root/scripts/warm-cache.sh\n' | crontab - \
 && printf '%s\n' \
      'Nov 16 06:25:01 srv-web01 CRON[2211]: pam_unix(cron:session): session opened for user root(uid=0) by (uid=0)' \
      'Nov 16 06:31:12 srv-web01 sshd[2240]: Invalid user admin from 192.0.2.10 port 40122' \
      'Nov 16 06:31:14 srv-web01 sshd[2240]: Failed password for invalid user admin from 192.0.2.10 port 40122 ssh2' \
      'Nov 16 09:12:40 srv-web01 sshd[2391]: Accepted publickey for martin from 198.51.100.23 port 52814 ssh2' \
      >/var/log/auth.log \
 && chgrp adm /var/log/auth.log && chmod 640 /var/log/auth.log

WORKDIR /root
