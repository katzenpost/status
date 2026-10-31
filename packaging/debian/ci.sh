#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
debs="$tmp/debs"
mkdir -p "$debs"
target="$root/packaging/debian/targets.mk"
thinclient_url=$(sed -n 's/^THINCLIENT_URL := //p' "$target")
thinclient_rev=$(sed -n 's/^THINCLIENT_REV := //p' "$target")

cd "$root"
packaging/container/python-debs-build.sh "$debs"
packaging/container/dep-deb.sh "$debs" "$thinclient_url" "$thinclient_rev"

set -- "$debs"/python3-cbor2_*.deb "$debs"/python3-katzenpost-thinclient_*.deb
if grep -Fq 'ipwhois' pyproject.toml; then
	set -- "$@" "$debs"/python3-ipwhois_*.deb
fi
apt-get install -y --no-install-recommends "$@"

make deb-build
package=$(find .. -maxdepth 1 -type f -name 'katzenpost-status_*_all.deb' \
	-printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
test -n "$package"
apt-get install -y --no-install-recommends "$package"
make deb-test
make deb-lint
make deb-repro
