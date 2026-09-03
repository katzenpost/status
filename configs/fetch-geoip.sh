#!/bin/sh
# SPDX-FileCopyrightText: Copyright (C) 2025 Katzenpost developers
# SPDX-License-Identifier: AGPL-3.0-only
#
# Fetch the free, no-account DB-IP City Lite GeoIP database into the user's
# data directory (no root needed). Idempotent: it only downloads once per
# calendar month. Safe to run from cron/a systemd timer.
#
#   ./configs/fetch-geoip.sh
#
# then pass the printed path to the renderer:
#
#   katzenpost-status ... --visualize --geoip-db <printed path>
#
# AS/operator names come from --asn-whois (no database), so this fetches only
# the City database.
set -eu

DATADIR="${XDG_DATA_HOME:-$HOME/.local/share}/katzenpost-status"
DEST="$DATADIR/GeoLite2-City.mmdb"
STAMP="$DATADIR/.geoip-month"
mkdir -p "$DATADIR"

MONTH="$(date +%Y-%m)"
if [ -f "$DEST" ] && [ "$(cat "$STAMP" 2>/dev/null || echo none)" = "$MONTH" ]; then
    echo "GeoIP City DB already current for $MONTH: $DEST"
    echo "--geoip-db $DEST"
    exit 0
fi

prev_month() {
    date -d 'first day of last month' +%Y-%m 2>/dev/null || date -v-1m +%Y-%m
}

tmp="$(mktemp "$DATADIR/.geoip.XXXXXX")"
trap 'rm -f "$tmp" "$tmp.gz"' EXIT

fetch() {
    url="https://download.db-ip.com/free/dbip-city-lite-$1.mmdb.gz"
    echo "Downloading $url"
    curl -fL --retry 3 -o "$tmp.gz" "$url"
}

got="$MONTH"
if ! fetch "$MONTH"; then
    got="$(prev_month)"
    echo "This month's file is not published yet; trying $got"
    fetch "$got"
fi

gunzip -c "$tmp.gz" > "$tmp"
mv -f "$tmp" "$DEST"
printf '%s\n' "$got" > "$STAMP"
trap - EXIT
rm -f "$tmp.gz"

echo "Installed GeoIP City DB ($got): $DEST"
echo "--geoip-db $DEST"
