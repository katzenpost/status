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
export TZ=UTC
export LC_ALL=C.UTF-8
export PYTHONHASHSEED=0
umask 022
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT HUP INT TERM

build_deb() {
	package=$1
	version=$2
	archive=$3
	depends=$4
	source=$5
	build_one() {
		build=$1
		buildroot="$work/$package-$build"
		wheels="$buildroot/wheels"
		pkg="$buildroot/pkg"
		mkdir -p "$wheels" "$pkg/DEBIAN" "$pkg/usr/lib/python3/dist-packages"
		if [ "$package" = python3-cbor2 ]; then
			SETUPTOOLS_SCM_PRETEND_VERSION="$version" \
				CFLAGS="${CFLAGS:-} -ffile-prefix-map=/tmp=." \
				"$work/venv/bin/python" -m pip wheel --no-cache-dir \
				--disable-pip-version-check --no-deps --no-build-isolation \
				--wheel-dir "$wheels" "$archive"
		else
			CFLAGS="${CFLAGS:-} -ffile-prefix-map=/tmp=." \
				"$work/venv/bin/python" -m pip wheel --no-cache-dir \
				--disable-pip-version-check --no-deps --no-build-isolation \
				--wheel-dir "$wheels" "$archive"
		fi
		wheel=$(find "$wheels" -maxdepth 1 -name '*.whl' -print -quit)
		test -n "$wheel"
		unzip -q "$wheel" -d "$pkg/usr/lib/python3/dist-packages"
		metadata=$(find "$pkg/usr/lib/python3/dist-packages" -maxdepth 2 \
			-name METADATA -print -quit)
		test -n "$metadata"
		license=$(sed -n -e 's/^License-Expression: //p' \
			-e 's/^License: //p' "$metadata" | head -1)
		test -n "$license"
		license_dir=$(dirname "$metadata")/licenses
		if [ ! -d "$license_dir" ]; then
			license_dir=$(dirname "$metadata")
		fi
		licenses="$buildroot/licenses.txt"
		find "$license_dir" -maxdepth 2 -type f \
			\( -iname 'license*' -o -iname 'copying*' \) -print | \
			sort > "$buildroot/license-files"
		test -s "$buildroot/license-files"
		copyright=$(grep -hiE '^[[:space:]]*copyright' \
			$(cat "$buildroot/license-files") | head -1 || true)
		if [ -z "$copyright" ]; then
			copyright=$(sed -n -e 's/^Author: //p' \
				-e 's/^Author-email: //p' "$metadata" | head -1)
		fi
		test -n "$copyright"
		case "$license" in
			Apache-2.0)
				copyright=$(printf '%s' "$copyright" | \
					sed -E 's/^[[:space:]]*Copyright[[:space:]]*//I; s/^[[:space:]]*\(c\)[[:space:]]*//I; s/[[:space:]]+by[[:space:]]+/ /I; s/^[[:space:]]+//; s/[[:space:]]+$//')
				;;
		esac
		while IFS= read -r license_file; do
			cat "$license_file" >> "$licenses"
			printf '\n' >> "$licenses"
		done < "$buildroot/license-files"
		mkdir -p "$pkg/usr/share/doc/$package/licenses"
		cp -a "$license_dir/." "$pkg/usr/share/doc/$package/licenses/"
		{
			printf 'Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/\n'
			printf 'Upstream-Name: %s\n' "$package"
			printf 'Source: %s\n\n' "$source"
			printf 'Files: *\nCopyright: %s\nLicense: %s\n' "$copyright" "$license"
			if [ "$license" != Apache-2.0 ]; then
				sed 's/^/ /' "$licenses"
			fi
		} > "$pkg/usr/share/doc/$package/copyright"
		changelog_date=$(date -Ru -d "@$SOURCE_DATE_EPOCH")
		cat > "$pkg/usr/share/doc/$package/changelog.Debian" <<EOF
$package ($version-1) unstable; urgency=low

  * Build from pinned upstream source.

 -- Katzenpost <packages@katzenpost.network>  $changelog_date
EOF
		gzip -n -9 "$pkg/usr/share/doc/$package/changelog.Debian"
		arch=all
		pkg_depends=$depends
		if find "$pkg/usr/lib/python3/dist-packages" -name '*.so' -print -quit | grep -q .; then
			arch=$(dpkg --print-architecture)
			python_version=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
			python_major=${python_version%%.*}
			python_minor=${python_version#*.}
			python_next_minor=$((python_minor + 1))
			pkg_depends=$(printf '%s' "$pkg_depends" | \
				sed -E 's/(^|, *)python3 \([^)]*\)//; s/^, *//; s/, *$//')
			python_bounds="python3 (>= ${python_version}~), python3 (<< ${python_major}.${python_next_minor}~)"
			if [ -n "$pkg_depends" ]; then
				pkg_depends="$python_bounds, $pkg_depends"
			else
				pkg_depends=$python_bounds
			fi
			shlibs_file="$buildroot/shlibs"
			: > "$shlibs_file"
			while IFS= read -r native; do
				native_deps=$(dpkg-shlibdeps -O -e "$native" | \
					sed -n 's/^shlibs:Depends=//p')
				if [ -n "$native_deps" ]; then
					printf '%s\n' "$native_deps" >> "$shlibs_file"
				fi
			done <<EOF
$(find "$pkg/usr/lib/python3/dist-packages" -name '*.so' -print | sort)
EOF
			shlibs=$(sort -u "$shlibs_file" | paste -sd, -)
			if [ -n "$shlibs" ]; then
				pkg_depends="$pkg_depends, $shlibs"
			fi
		fi
		cat > "$pkg/DEBIAN/control" <<EOF
Package: $package
Version: $version-1
Architecture: $arch
Maintainer: Katzenpost <packages@katzenpost.network>
Depends: $pkg_depends
Section: python
Priority: optional
Description: Python runtime module for the Katzenpost status service
 Built from pinned upstream source.
EOF
		find "$pkg" -type d -exec chmod 0755 {} +
		find "$pkg" -type f -exec chmod 0644 {} +
		find "$pkg/usr/lib/python3/dist-packages" -name '*.so' \
			-exec strip --strip-unneeded {} +
		dpkg-deb --build --root-owner-group "$pkg" \
			"$buildroot/${package}_${version}-1_${arch}.deb"
	}
	build_one first
	build_one second
	first="$work/$package-first/${package}_${version}-1_$(dpkg --print-architecture).deb"
	second="$work/$package-second/${package}_${version}-1_$(dpkg --print-architecture).deb"
	if [ ! -f "$first" ]; then
		first="$work/$package-first/${package}_${version}-1_all.deb"
		second="$work/$package-second/${package}_${version}-1_all.deb"
	fi
	first_sha=$(sha256sum "$first" | cut -d' ' -f1)
	second_sha=$(sha256sum "$second" | cut -d' ' -f1)
	printf '%s first  %s\n%s second %s\n' "$package" "$first_sha" "$package" "$second_sha"
	test "$first_sha" = "$second_sha"
	cp "$first" "$out/"
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
	build_deb "$package" "$version" "$archive" "$depends" "$url"
}

for backend in SETUPTOOLS PACKAGING FLIT_CORE POETRY_CORE; do
	version=$(value "${backend}_VERSION")
	url=$(value "${backend}_WHEEL_URL")
	sha=$(value "${backend}_WHEEL_SHA256")
	name=$(printf '%s' "$backend" | tr '[:upper:]' '[:lower:]')
	wheel="$work/${name}-${version}-py3-none-any.whl"
	curl -fsSL "$url" -o "$wheel"
	printf '%s  %s\n' "$sha" "$wheel" | sha256sum -c -
done
python3 -m venv --system-site-packages "$work/venv"
"$work/venv/bin/python" -m pip install --disable-pip-version-check \
	--no-index --no-deps "$work"/setuptools-*.whl \
	"$work"/packaging-*.whl "$work"/flit_core-*.whl \
	"$work"/poetry_core-*.whl
"$work/venv/bin/python" -c \
	"from importlib.metadata import version; assert version('setuptools') == '$(value SETUPTOOLS_VERSION)'; assert version('packaging') == '$(value PACKAGING_VERSION)'; assert version('flit_core') == '$(value FLIT_CORE_VERSION)'; assert version('poetry-core') == '$(value POETRY_CORE_VERSION)'"

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
	"python3 (>= 3.12~), python3-markdown-it (>= 2.2.0), python3-pygments (>= 2.13.0)"
ensure_deb tomli python3-tomli "$(minimum_version tomli)" \
	"$(value TOMLI_VERSION)" "$(value TOMLI_URL)" \
	"$(value TOMLI_SHA256)" "python3 (>= 3.12~)"

find "$out" -maxdepth 1 -type f -name 'python3-*.deb' -exec sha256sum {} +
