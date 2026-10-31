#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
debs="$tmp/debs"
mkdir -p "$debs"
if [ -n "${DEB_OUTPUT_DIR:-}" ]; then
	output=$DEB_OUTPUT_DIR
	case $output in
		/*) ;;
		*) output="$root/$output" ;;
	esac
else
	set -- $(. /etc/os-release; printf '%s %s\n' "$ID" "$VERSION_ID")
	output="$root/dist/debs/$1-$2-$(dpkg --print-architecture)/main"
fi
mkdir -p "$output"
target="$root/packaging/debian/targets.mk"
thinclient_url=$(sed -n 's/^THINCLIENT_URL := //p' "$target")
thinclient_rev=$(sed -n 's/^THINCLIENT_REV := //p' "$target")

cd "$root"
packaging/container/python-debs-build.sh "$debs"
packaging/container/dep-deb.sh "$debs" "$thinclient_url" "$thinclient_rev"

for dependency in "$debs"/*.deb; do
	[ -f "$dependency" ] || continue
	lintian --no-tag-display-limit "$dependency"
done

set -- "$debs"/*.deb
[ -f "$1" ]
apt-get install -y --no-install-recommends "$@"
dpkg-query -W -f='${Status}\n' python3-katzenpost-thinclient | \
	grep -Fxq 'install ok installed'

make deb-build
package=$(find .. -maxdepth 1 -type f -name 'katzenpost-status_*_all.deb' \
	-printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
test -n "$package"
apt-get install -y --no-install-recommends "$package"
make deb-test
make deb-lint
make deb-repro
cp "$debs"/*.deb "$output/"
cp "$package" "$output/"
printf 'package closure saved to %s\n' "$output"
