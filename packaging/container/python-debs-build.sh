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

minimum_version() {
	dist=$1
	sed -n "s/^[[:space:]]*\"$dist>=\\([^,<>\"]*\\).*$/\\1/p" \
		"$root/pyproject.toml" | head -1
}

ensure_deb() {
	dist=$1
	package=$2
	minimum=$3
	version=$4
	url=$5
	sha=$6
	depends=$7
	if ! grep -Fq "\"$dist" "$root/pyproject.toml"; then
		return
	fi
	candidate=$(apt-cache policy "$package" | sed -n 's/^[[:space:]]*Candidate: //p')
	if [ -n "$candidate" ] && [ "$candidate" != '(none)' ] && \
		dpkg --compare-versions "$candidate" ge "$minimum"; then
		return
	fi
	archive="$work/${package##*-}-$version.tar.gz"
	curl -fsSL "$url" -o "$archive"
	printf '%s  %s\n' "$sha" "$archive" | sha256sum -c -
	build_deb "$package" "$version" "$archive" "$depends"
}

setuptools_url=$(value SETUPTOOLS_WHEEL_URL)
setuptools_sha=$(value SETUPTOOLS_WHEEL_SHA256)
setuptools_version=$(value SETUPTOOLS_VERSION)
setuptools_wheel="$work/setuptools-${setuptools_version}-py3-none-any.whl"
curl -fsSL "$setuptools_url" -o "$setuptools_wheel"
printf '%s  %s\n' "$setuptools_sha" "$setuptools_wheel" | sha256sum -c -
python3 -m venv --system-site-packages "$work/venv"
"$work/venv/bin/python" -m pip install --disable-pip-version-check \
	--no-index --no-deps "$setuptools_wheel"
"$work/venv/bin/python" -c \
	"from importlib.metadata import version; assert version('setuptools') == '$setuptools_version'"

cbor2_min=$(minimum_version cbor2)
thinclient_cbor2_min=$(value THINCLIENT_CBOR2_MIN)
if dpkg --compare-versions "$cbor2_min" ge "$thinclient_cbor2_min"; then
	cbor2_required=$cbor2_min
else
	cbor2_required=$thinclient_cbor2_min
fi
ensure_deb cbor2 python3-cbor2 "$cbor2_required" \
	"$(value CBOR2_VERSION)" "$(value CBOR2_URL)" \
	"$(value CBOR2_SHA256)" "python3 (>= 3.12~)"

ensure_deb click python3-click "$(minimum_version click)" \
	"$(value CLICK_VERSION)" "$(value CLICK_URL)" \
	"$(value CLICK_SHA256)" "python3 (>= 3.12~)"
ensure_deb rich python3-rich "$(minimum_version rich)" \
	"$(value RICH_VERSION)" "$(value RICH_URL)" \
	"$(value RICH_SHA256)" \
	"python3 (>= 3.12~), python3-markdown-it-py (>= 2.2.0), python3-pygments (>= 2.13.0)"
ensure_deb pygments python3-pygments "$(minimum_version pygments)" \
	"$(value PYGMENTS_VERSION)" "$(value PYGMENTS_URL)" \
	"$(value PYGMENTS_SHA256)" "python3 (>= 3.12~)"
ensure_deb tomli python3-tomli "$(minimum_version tomli)" \
	"$(value TOMLI_VERSION)" "$(value TOMLI_URL)" \
	"$(value TOMLI_SHA256)" "python3 (>= 3.12~)"
ensure_deb maxminddb python3-maxminddb "$(minimum_version maxminddb)" \
	"$(value MAXMINDDB_VERSION)" "$(value MAXMINDDB_URL)" \
	"$(value MAXMINDDB_SHA256)" "python3 (>= 3.12~)"
ensure_deb ipwhois python3-ipwhois "$(minimum_version ipwhois)" \
	"$(value IPWHOIS_VERSION)" "$(value IPWHOIS_URL)" \
	"$(value IPWHOIS_SHA256)" \
	"python3 (>= 3.12~), python3-defusedxml (>= 0.7.1), python3-dnspython (>= 2.0.0)"
ensure_deb rjsmin python3-rjsmin "$(minimum_version rjsmin)" \
	"$(value RJSMIN_VERSION)" "$(value RJSMIN_URL)" \
	"$(value RJSMIN_SHA256)" "python3 (>= 3.12~)"

find "$out" -maxdepth 1 -type f -name 'python3-*.deb' -exec sha256sum {} +
