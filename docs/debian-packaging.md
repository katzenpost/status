# Debian packages

`make deb-build` builds the status package after its runtime package closure is
installed. `make deb-ci` builds the pinned thinclient and missing Python runtime
dependencies as separate Debian packages, installs the closure, builds and
installs the status package, exercises the installed command and fixtures, runs
lintian, and compares two independent builds. The supported CI targets are
Ubuntu 24.04, Ubuntu 26.04, and Debian 13 (trixie).

The package installs `/usr/bin/katzenpost-status`, the status service, and its
15-minute timer. It creates a locked system account and state directory. It
does not enable or start the timer. Edit `/etc/default/katzenpost-status` for
the host's configuration paths and output location, then enable the timer:

```sh
systemctl enable --now katzenpost-status.timer
```

The status package depends on a separately built `python3-katzenpost-thinclient`
package from the upstream revision pinned in `pyproject.toml`. The closure
compares distro package versions with the declared minimums and builds
hash-pinned source DEBs only where a distro package is missing or too old.
Depending on the target and branch, this can include cbor2, Click, Rich,
Pygments, Tomli, MaxMindDB, and IPWhois; their remaining runtime dependencies
come from distro packages. Pinned build backends and setuptools-scm are used
only to build those packages. No Python dependency source is included in the
status DEB. The installed command does not need uv, a source checkout, pip, or
runtime downloads. GeoIP and RDAP support remain available when the
corresponding visualize dependencies and data files are installed.

The uv workflow and package closure use the same pinned thinclient source. The
container build keeps the declared Python minimums and supplies `cbor2` 5.9.0
when the distro package is below the thinclient or visualize minimum. The target
matrix installs each separately owned package and renders a page from the
checked-in public consensus fixture; this exercises those runtime APIs without
claiming a live network probe.

The status service requires a running `kpclientd` reachable through its
configured Unix socket or TCP address. The daemon may run on the same host or a
remote host; package installation does not install or configure a local daemon.

Before installing on a host with hand-written units in
`/etc/systemd/system/katzenpost-status.service` or
`/etc/systemd/system/katzenpost-status.timer`, review and move those files.
Files in `/etc/systemd/system` take precedence over the packaged units in
`/usr/lib/systemd/system`, so a manual service can continue to run uv or point
at a source checkout after package installation. Installing the package does
not replace or remove those local files.
