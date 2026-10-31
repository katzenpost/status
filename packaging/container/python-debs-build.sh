#!/bin/sh
set -eu

out=${1:?usage: python-debs-build.sh OUTDIR}
root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
mk="$root/packaging/debian/targets.mk"
value() {
	name=$1
	sed -n "s/^$name := //p" "$mk"
}

SOURCE_DATE_EPOCH=$(dpkg-parsechangelog -l "$root/debian/changelog" -STimestamp)
export SOURCE_DATE_EPOCH
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

build_deb() {
	package=$1
	version=$2
	archive=$3
	depends=$4
	wheels="$work/wheels-$package"
	pkg="$work/pkg-$package"
	mkdir -p "$wheels" "$pkg/DEBIAN" "$pkg/usr/lib/python3/dist-packages"
	"$work/venv/bin/python" -m pip wheel --disable-pip-version-check --no-deps \
		--no-build-isolation --wheel-dir "$wheels" "$archive"
	wheel=$(find "$wheels" -maxdepth 1 -name '*.whl' -print -quit)
	test -n "$wheel"
	unzip -q "$wheel" -d "$pkg/usr/lib/python3/dist-packages"
	arch=all
	if find "$pkg/usr/lib/python3/dist-packages" -name '*.so' -print -quit | grep -q .; then
		arch=$(dpkg --print-architecture)
	fi
	cat > "$pkg/DEBIAN/control" <<EOF
Package: $package
Version: $version-1
Architecture: $arch
Maintainer: Katzenpost <packages@katzenpost.network>
Depends: $depends
Section: python
Priority: optional
Description: $package built from its pinned upstream source
 Python runtime module for the Katzenpost status service.
EOF
	dpkg-deb --build --root-owner-group "$pkg" \
		"$out/${package}_${version}-1_${arch}.deb"
}

setuptools_url=$(value SETUPTOOLS_WHEEL_URL)
setuptools_sha=$(value SETUPTOOLS_WHEEL_SHA256)
setuptools_version=$(value SETUPTOOLS_VERSION)
setuptools_wheel="$work/setuptools-${setuptools_version}-py3-none-any.whl"
curl -fsSL "$setuptools_url" -o "$setuptools_wheel"
printf '%s  %s\n' "$setuptools_sha" "$setuptools_wheel" | sha256sum -c -
python3 -m venv "$work/venv"
"$work/venv/bin/python" -m pip install --disable-pip-version-check \
	--no-index --no-deps "$setuptools_wheel"
"$work/venv/bin/python" -c \
	"from importlib.metadata import version; assert version('setuptools') == '$setuptools_version'"

cbor2_version=$(value CBOR2_VERSION)
cbor2_url=$(value CBOR2_URL)
cbor2_sha=$(value CBOR2_SHA256)
cbor2_archive="$work/cbor2-$cbor2_version.tar.gz"
curl -fsSL "$cbor2_url" -o "$cbor2_archive"
printf '%s  %s\n' "$cbor2_sha" "$cbor2_archive" | sha256sum -c -
build_deb python3-cbor2 "$cbor2_version" "$cbor2_archive" "python3 (>= 3.12~)"

if grep -Eq '"ipwhois([<=>~! ]|\")' "$root/pyproject.toml"; then
	ipwhois_version=$(value IPWHOIS_VERSION)
	ipwhois_url=$(value IPWHOIS_URL)
	ipwhois_sha=$(value IPWHOIS_SHA256)
	ipwhois_archive="$work/ipwhois-$ipwhois_version.tar.gz"
	curl -fsSL "$ipwhois_url" -o "$ipwhois_archive"
	printf '%s  %s\n' "$ipwhois_sha" "$ipwhois_archive" | sha256sum -c -
	build_deb python3-ipwhois "$ipwhois_version" "$ipwhois_archive" \
		"python3 (>= 3.12~), python3-defusedxml (>= 0.7.1), python3-dnspython (>= 2.0.0)"
fi

sha256sum "$out"/python3-cbor2_*.deb "$out"/python3-ipwhois_*.deb 2>/dev/null || \
	sha256sum "$out"/python3-cbor2_*.deb
