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

set --
for package in \
	python3-cbor2 python3-click python3-rich python3-pygments \
	python3-tomli python3-maxminddb python3-ipwhois \
	python3-rjsmin python3-katzenpost-thinclient; do
	for dependency in "$debs"/"$package"_*.deb; do
		[ -f "$dependency" ] && set -- "$@" "$dependency"
	done
done
apt-get install -y --no-install-recommends "$@"

make deb-build
package=$(find .. -maxdepth 1 -type f -name 'katzenpost-status_*_all.deb' \
	-printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
test -n "$package"
apt-get install -y --no-install-recommends "$package"
make deb-test
make deb-lint
make deb-repro
