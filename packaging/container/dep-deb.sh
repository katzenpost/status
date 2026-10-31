#!/bin/sh
set -eu

out=${1:?usage: dep-deb.sh OUTDIR URL REV}
url=${2:?usage: dep-deb.sh OUTDIR URL REV}
rev=${3:?usage: dep-deb.sh OUTDIR URL REV}

mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM
git clone --quiet "$url" "$work/src"
git -C "$work/src" cat-file -e "$rev^{commit}"
git -C "$work/src" -c advice.detachedHead=false switch --detach "$rev"
mk-build-deps -ir -t "apt-get -y --no-install-recommends" \
	"$work/src/debian/control"
SOURCE_DATE_EPOCH=$(dpkg-parsechangelog -STimestamp)
export SOURCE_DATE_EPOCH
make -C "$work/src" deb-build
cp "$work/src"/dist/*.deb "$out"/
