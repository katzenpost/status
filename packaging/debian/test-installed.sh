#!/bin/sh
set -eu

root=$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)
package=$(find "$(dirname "$root")" -maxdepth 1 -type f \
	-name 'katzenpost-status_*_all.deb' -printf '%T@ %p\n' | sort -nr | head -1 | cut -d' ' -f2-)
test -n "$package"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
dpkg-query -W -f='${Status}\n' katzenpost-status | grep -Fxq 'install ok installed'
dpkg-query -W -f='${Status}\n' python3-katzenpost-thinclient | grep -Fxq 'install ok installed'
test -x /usr/bin/katzenpost-status
test -f /usr/lib/systemd/system/katzenpost-status.service
test -f /usr/lib/systemd/system/katzenpost-status.timer
grep -Fxq '/etc/default/katzenpost-status' /var/lib/dpkg/info/katzenpost-status.conffiles
test ! -e /usr/lib/systemd/system/kpclientd.service
grep -Fq 'ExecStart=/usr/bin/katzenpost-status ' \
	/usr/lib/systemd/system/katzenpost-status.service
grep -Fq 'OnCalendar=*:0/15' \
	/usr/lib/systemd/system/katzenpost-status.timer
if grep -Eq 'uv|/var/lib/katzenpost-status/src|/usr/local/bin' \
	/usr/lib/systemd/system/katzenpost-status.service; then
	echo 'service depends on uv, a source checkout, or a non-system path' >&2
	exit 1
fi
if dpkg-query -L katzenpost-status | \
	grep -Eq '/(katzenpost_thinclient|ipwhois|pprintpp)(/|\.py$)'; then
	echo 'status package contains a dependency module' >&2
	exit 1
fi
/usr/bin/katzenpost-status --help >/dev/null
python3 - "$tmp/thinclient.toml" <<'PY'
import sys
from importlib import metadata
from pathlib import Path

from katzenpost_thinclient import Config, ThinClient

config_path = Path(sys.argv[1])
config_path.write_text('[Dial.Tcp]\nAddress = "127.0.0.1:64331"\nNetwork = "tcp"\n')
config = Config(str(config_path))
client = ThinClient(config)
assert config.dial.tcp.address == "127.0.0.1:64331"
assert metadata.version("cbor2") == "5.9.0"
for name in (
    "start", "stop", "get_services", "new_keypair", "encrypt_write",
    "start_resending_encrypted_message", "cancel_resending_encrypted_message",
):
    assert callable(getattr(client, name)), name
PY
if python3 -c 'import importlib.util; assert importlib.util.find_spec("pprintpp") is None'; then
	:
else
	echo 'pprintpp must not be installed as a runtime dependency' >&2
	exit 1
fi
thinclient_module=$(python3 -c 'import katzenpost_thinclient; print(katzenpost_thinclient.__file__)')
test "$(dpkg-query -S "$thinclient_module" | cut -d: -f1)" = python3-katzenpost-thinclient
cbor2_module=$(python3 -c 'import cbor2; print(cbor2.__file__)')
test "$(dpkg-query -S "$cbor2_module" | cut -d: -f1)" = python3-cbor2
if grep -Fq 'ipwhois' "$root/pyproject.toml"; then
	python3 -c 'from ipwhois import IPWhois'
	ipwhois_module=$(python3 -c 'import ipwhois; print(ipwhois.__file__)')
	test "$(dpkg-query -S "$ipwhois_module" | cut -d: -f1)" = python3-ipwhois
fi
if [ -f "$root/src/katzenpost_status/viz.py" ]; then
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
else
	python3 - "$tmp/render" <<'PY'
import sys
from pathlib import Path
from katzenpost_status.status import generate_report

out = Path(sys.argv[1]) / "status.html"
out.parent.mkdir(parents=True, exist_ok=True)
config = out.parent / "authority.toml"
config.write_text("Server = {}\nSphinxGeometry = {}\n")
generate_report({}, str(config), str(out), quiet=True)
assert out.is_file()
assert "Status and Health" in out.read_text()
PY
fi
if [ -d "$root/src/katzenpost_status/assets" ]; then
	test -d /usr/lib/python3/dist-packages/katzenpost_status/assets
	source_assets=$(find "$root/src/katzenpost_status/assets" -type f | wc -l)
	installed_assets=$(find \
		/usr/lib/python3/dist-packages/katzenpost_status/assets \
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
if find /etc/systemd/system \( -type l -o -path '*.wants/*' \) \
	-name '*katzenpost-status*' | grep -q .; then
	echo 'package enables a systemd unit during installation' >&2
	exit 1
fi
printf 'installed package checks passed: %s\n' "$(basename "$package")"
