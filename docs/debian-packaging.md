# Debian packages

`make deb-build` builds an architecture independent package. `make deb-test`
extracts the built package and runs its installed command and systemd unit
checks. `make deb-ci` runs those checks, lintian, and two clean builds in
independent source directories. The supported CI targets are Ubuntu 24.04,
Ubuntu 26.04, and Debian 13 (trixie).

The package installs `/usr/bin/katzenpost-status`, the status service, and its
15-minute timer. It creates a locked system account and state directory. It
does not enable or start the timer. Edit `/etc/default/katzenpost-status` for
the host's configuration paths and output location, then enable the timer:

```sh
systemctl enable --now katzenpost-status.timer
```

The Python thinclient sources pinned by the project are included with the
package. The package also includes the narrow `pprintpp` and `ipwhois` modules
that are absent from the target distributions, while their other Python
dependencies come from distribution packages. The installed command does not
need uv, a checkout, pip, or runtime downloads. GeoIP and RDAP support remain
available when the corresponding visualize dependencies and data files are
installed.

The uv workflow keeps the upstream minimum versions in `pyproject.toml`. Debian
maps the dependencies to each release's `python3-*` packages because the
application uses long-standing APIs: CBOR `loads`/`dumps`, Click commands and
options, Rich consoles/tables, Tomli loading, and MaxMindDB readers. The target
matrix installs the built package and renders a page from the checked-in public
consensus fixture; this verifies those APIs on the distro versions without
claiming a live network probe.

Before installing on a host with hand-written units in
`/etc/systemd/system/katzenpost-status.service` or
`/etc/systemd/system/katzenpost-status.timer`, review and move those files.
Files in `/etc/systemd/system` take precedence over the packaged units in
`/usr/lib/systemd/system`, so a manual service can continue to run uv or point
at a source checkout after package installation. Installing the package does
not replace or remove those local files.
