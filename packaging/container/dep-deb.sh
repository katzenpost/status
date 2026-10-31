#!/bin/sh
set -eu

out=${1:?usage: dep-deb.sh OUTDIR URL REV}
url=${2:?usage: dep-deb.sh OUTDIR URL REV}
rev=${3:?usage: dep-deb.sh OUTDIR URL REV}

mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
for build in first second; do
	tree="$work/$build"
	git clone --quiet "$url" "$tree"
	git -C "$tree" cat-file -e "$rev^{commit}"
	git -C "$tree" -c advice.detachedHead=false switch --detach "$rev"
	if [ "$build" = first ]; then
		mk-build-deps -ir -t "apt-get -y --no-install-recommends" \
			"$tree/debian/control"
	fi
	SOURCE_DATE_EPOCH=$(dpkg-parsechangelog -l "$tree/debian/changelog" -STimestamp)
	export SOURCE_DATE_EPOCH
	make -C "$tree" deb-build
	package=$(find "$tree/dist" -maxdepth 1 -type f \
		-name 'python3-katzenpost-thinclient_*.deb' -print -quit)
	test -n "$package"
	cp "$package" "$work/$build.deb"
done
first_sha=$(sha256sum "$work/first.deb" | cut -d' ' -f1)
second_sha=$(sha256sum "$work/second.deb" | cut -d' ' -f1)
printf 'python3-katzenpost-thinclient first  %s\n' "$first_sha"
printf 'python3-katzenpost-thinclient second %s\n' "$second_sha"
test "$first_sha" = "$second_sha"
package=$(dpkg-deb -f "$work/first.deb" Package)
version=$(dpkg-deb -f "$work/first.deb" Version)
arch=$(dpkg-deb -f "$work/first.deb" Architecture)
cp "$work/first.deb" "$out/${package}_${version}_${arch}.deb"
