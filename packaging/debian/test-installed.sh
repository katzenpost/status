#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
package=$(find "$(dirname "$root")" -maxdepth 1 -type f \
	-name 'katzenpost-status_*_all.deb' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
test -n "$package"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
dpkg-deb -x "$package" "$tmp"
dpkg-deb -e "$package" "$tmp/control"
test -x "$tmp/usr/bin/katzenpost-status"
test -f "$tmp/usr/lib/systemd/system/katzenpost-status.service"
test -f "$tmp/usr/lib/systemd/system/katzenpost-status.timer"
grep -Fxq '/etc/default/katzenpost-status' "$tmp/control/conffiles"
test ! -e "$tmp/usr/lib/systemd/system/kpclientd.service"
grep -Fq 'ExecStart=/usr/bin/katzenpost-status ' \
	"$tmp/usr/lib/systemd/system/katzenpost-status.service"
grep -Fq 'OnCalendar=*:0/15' \
	"$tmp/usr/lib/systemd/system/katzenpost-status.timer"
if grep -Eq 'uv|/var/lib/katzenpost-status/src|/usr/local/bin' \
	"$tmp/usr/lib/systemd/system/katzenpost-status.service"; then
	echo 'service depends on uv, a source checkout, or a non-system path' >&2
	exit 1
fi
PYTHONPATH="$tmp/usr/lib/python3/dist-packages" \
	"$tmp/usr/bin/katzenpost-status" --help >/dev/null
PYTHONPATH="$tmp/usr/lib/python3/dist-packages" \
	python3 -c 'from ipwhois import IPWhois'
if [ -f "$root/src/katzenpost_status/viz.py" ]; then
	PYTHONPATH="$tmp/usr/lib/python3/dist-packages" \
		python3 - "$root" "$tmp/render" <<'PY'
import json
import sys
from pathlib import Path
from katzenpost_status import viz

root = Path(sys.argv[1])
out = Path(sys.argv[2]) / "visualize.html"
snapshot = json.loads((root / "testdata/consensus_namenlos.json").read_text())
doc = snapshot["doc"]
dirauth_status = {name: (True, 5.0) for name in snapshot["dirauths"]}
viz.generate_viz(
    doc,
    str(out),
    survey_results={},
    dirauth_status=dirauth_status,
    network_name="package-render-check",
    epoch=doc["Epoch"],
    epoch_time_str=snapshot["captured_epoch_time"],
    write_history=False,
)
assert out.is_file()
assert out.with_name("visualize.data.json").is_file()
assets = out.parent / viz.ASSETS_SUBDIR
assert (assets / viz.APP_JS_NAME).is_file()
assert (assets / "three.min.js").is_file()
payload = json.loads(out.with_name("visualize.data.json").read_text())
assert payload["network_name"] == "package-render-check"
PY
fi
if [ -d "$root/src/katzenpost_status/assets" ]; then
	test -d "$tmp/usr/lib/python3/dist-packages/katzenpost_status/assets"
	source_assets=$(find "$root/src/katzenpost_status/assets" -type f | wc -l)
	installed_assets=$(find \
		"$tmp/usr/lib/python3/dist-packages/katzenpost_status/assets" \
		-type f | wc -l)
	test "$source_assets" -eq "$installed_assets"
fi
if [ "${SYSTEMD_VERIFY:-0}" = 1 ]; then
	systemd-analyze verify \
		"$tmp/usr/lib/systemd/system/katzenpost-status.service" \
		"$tmp/usr/lib/systemd/system/katzenpost-status.timer" \
		2>"$tmp/systemd-verify.log" || {
		cat "$tmp/systemd-verify.log" >&2
		exit 1
	}
fi
if [ -d "$tmp/etc/systemd" ] && \
	find "$tmp/etc/systemd" \( -type l -o -path '*.wants/*' \) | grep -q .; then
	echo 'package enables a systemd unit during installation' >&2
	exit 1
fi
printf 'installed package checks passed: %s\n' "$(basename "$package")"
