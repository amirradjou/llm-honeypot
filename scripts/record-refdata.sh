#!/usr/bin/env bash
# Record the reference data the default profile is built from: the package
# database, /usr/bin and /usr/sbin, stock config files and install logs of a
# real Ubuntu 22.04 VPS with the profile's packages (tools/refdata/Dockerfile).
# Writes internal/machine/refdata/. Re-run after changing the Dockerfile or the
# profile's package list; never edit the recorded files by hand.
#
# Needs Docker. Building the image needs the network (apt); the recording run
# itself uses --network none.
set -euo pipefail

cd "$(dirname "$0")/.."
image="llm-honeypot-refdata"
out="internal/machine/refdata"

docker build -q -t "$image" tools/refdata >/dev/null

rm -rf "$out"
mkdir -p "$out/files"

# Plain-text stock files, copied byte for byte.
files=(
  /etc/services /etc/protocols /etc/login.defs /etc/adduser.conf
  /etc/nsswitch.conf /etc/ld.so.conf /etc/bash.bashrc /etc/ssh/ssh_config
  /etc/nginx/mime.types /etc/nginx/fastcgi_params /etc/nginx/proxy_params
  /etc/nginx/snippets/fastcgi-php.conf /etc/nginx/snippets/snakeoil.conf
  /etc/pam.d/sshd /etc/pam.d/common-auth /etc/pam.d/common-password
  /etc/postgresql/14/main/postgresql.conf /etc/postgresql/14/main/pg_ident.conf
)

docker run --rm --network none -i "$image" bash -s >"$out/bundle.tar" <<EOF
set -euo pipefail
cd /tmp
mkdir -p rec/files
for f in ${files[*]}; do
  mkdir -p "rec/files\$(dirname "\$f")"
  cp "\$f" "rec/files\$f"
done
cp /var/lib/dpkg/status rec/status
cp /var/lib/dpkg/available rec/available
dpkg -l >rec/dpkg-l.txt
apt list --installed 2>/dev/null >rec/apt-list-installed.txt
cp /var/log/bootstrap.log rec/bootstrap.log
kver=\$(ls /lib/modules | sort -V | tail -n 1)
echo "\$kver" >rec/kernel-release
grep -h UTS_VERSION /usr/src/linux-headers-"\$kver"/include/generated/compile.h \
  | sed 's/.*UTS_VERSION "\(.*\)"/\1/' >rec/kernel-version
cp /boot/config-"\$kver" rec/kernel-config
# the head only: the whole map is 6 MB and nobody reads past the top
head -n 3000 /boot/System.map-"\$kver" >rec/kernel-system-map
dpkg-query -W -f='\${Version}\n' openssh-server >rec/openssh-version
sed -n 's/^VERSION="\(.*\)"/\1/p' /etc/os-release >rec/os-version
# type, mode, size, owner, group, path, link target (with the alternatives
# the links point through)
find /usr/bin /usr/sbin /etc/alternatives -mindepth 1 -maxdepth 1 -printf '%y\t%m\t%s\t%u\t%g\t%p\t%l\n' | sort -t "\$(printf '\t')" -k6 >rec/bins.tsv
stat -L -c '%s %n' /boot/vmlinuz-"\$kver" /boot/initrd.img-"\$kver" /usr/share/misc/magic.mgc /etc/ld.so.cache >rec/sizes.txt
tar -C rec -cf - .
EOF
tar -C "$out" -xf "$out/bundle.tar"
rm "$out/bundle.tar"

# The big ones are stored compressed; the machine package inflates them once.
for f in status available kernel-system-map dpkg-l.txt apt-list-installed.txt bootstrap.log kernel-config bins.tsv; do
  gzip -9n "$out/$f"
done
echo "recorded into $out: $(zcat "$out/dpkg-l.txt.gz" | grep -c '^ii') packages, kernel $(cat "$out/kernel-release")"
