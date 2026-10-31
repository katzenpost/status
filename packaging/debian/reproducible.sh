#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
for build in first second; do
	mkdir "$tmp/$build"
	tar -C "$root" \
		--exclude=.git --exclude=.venv --exclude=.pytest_cache \
		--exclude=.mypy_cache --exclude=.ruff_cache --exclude=.coverage \
		--exclude=debian/.debhelper --exclude=debian/katzenpost-status \
		--exclude=debian/files --exclude=debian/*.substvars \
		-cf - . | tar -C "$tmp/$build" -xf -
	(
		cd "$tmp/$build"
		dpkg-buildpackage -b -us -uc
	)
	deb=$(find "$tmp" -maxdepth 1 -name 'katzenpost-status_*_all.deb' -print -quit)
	test -n "$deb"
	cp "$deb" "$tmp/$build.deb"
	rm -f "$deb"
done
a=$(sha256sum "$tmp/first.deb" | cut -d' ' -f1)
b=$(sha256sum "$tmp/second.deb" | cut -d' ' -f1)
printf 'first  %s\nsecond %s\n' "$a" "$b"
test "$a" = "$b"
