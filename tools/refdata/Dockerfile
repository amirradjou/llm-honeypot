# The box the default profile describes, built only to record reference data
# (package list, /usr/bin, stock config files) that the honeypot embeds. It is
# never run as a target. scripts/record-refdata.sh builds it and copies the
# files out; see internal/machine/refdata/.
#
# A 22.04 cloud VPS: ubuntu-minimal/standard/server, cloud-init and the
# virtual kernel, plus what the profile says the admin added (nginx, Node.js
# 20 from NodeSource, PostgreSQL 14, certbot, fail2ban, ufw, net-tools ...). Recommends are installed, as apt does by default.
FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y ubuntu-minimal ubuntu-standard ubuntu-server cloud-init linux-virtual \
 && apt-get install -y ca-certificates curl gnupg \
 && mkdir -p /etc/apt/keyrings \
 && curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
      | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
 && echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_20.x nodistro main" \
      > /etc/apt/sources.list.d/nodesource.list \
 && apt-get update \
 && apt-get install -y nginx nodejs postgresql-14 certbot python3-certbot-nginx \
      git wget vim htop ufw fail2ban rsync unzip openssh-server cron logrotate snapd \
      net-tools
