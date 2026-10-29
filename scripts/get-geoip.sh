#!/usr/bin/env bash
# Downloads this month's DB-IP Lite country and ASN databases (CC BY 4.0, no account needed) for
# `honeypot report|dashboard -geoip-country … -geoip-asn …`. DB-IP publishes on the 1st of each
# month; if this month's files are not out yet, last month's are used.
#
#   scripts/get-geoip.sh [DIR]     # default ./geoip
set -euo pipefail

dir="${1:-geoip}"
mkdir -p "$dir"

fetch() { # kind month
  local url="https://download.db-ip.com/free/dbip-$1-lite-$2.mmdb.gz"
  curl -fsSL --retry 2 "$url" -o "$dir/dbip-$1-lite.mmdb.gz.part"
}

for kind in country asn; do
  month="$(date -u +%Y-%m)"
  if ! fetch "$kind" "$month"; then
    month="$(date -u -d "$(date -u +%Y-%m-01) -1 month" +%Y-%m)"
    fetch "$kind" "$month"
  fi
  gunzip -c "$dir/dbip-$kind-lite.mmdb.gz.part" > "$dir/dbip-$kind-lite.mmdb"
  rm "$dir/dbip-$kind-lite.mmdb.gz.part"
  echo "$dir/dbip-$kind-lite.mmdb ($month)"
done
