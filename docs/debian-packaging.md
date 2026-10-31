# Debian packages

The package supports Ubuntu 24.04, Ubuntu 26.04, and Debian 13 (trixie).
This change packages the main branch. Visualize support needs a separate
change.

Run `make deb-ci` in the target system's build container as root.
The command builds the pinned thinclient as a separate Debian package.
It uses system packages for other runtime dependencies when their versions
meet the application requirements.
It builds separate packages from hash-pinned sources when system versions are
too old.
Build tools stay outside the runtime packages.

The command installs all required packages and tests the installed
application.
It renders a report from test data without a live network daemon.
It runs Lintian and compares two independent builds of each generated package.
These tests do not prove live network operation.

The command saves the tested packages in
`dist/debs/<distribution>-<version>-<architecture>/main`.
Set `DEB_OUTPUT_DIR` to use another directory.
Install these packages on a matching system with this command:

```sh
apt install ./dist/debs/<distribution>-<version>-<architecture>/main/*.deb
```

The installed `/usr/bin/katzenpost-status` command needs no uv, pip, Git
checkout, or runtime download.
The uv development workflow uses the same pinned thinclient source.
The status package contains no third-party Python modules.

The package creates a locked `katzenpost-status` account and
`/var/lib/katzenpost-status`.
It installs a service and a 15-minute timer.
During the first installation, it does not start or enable either unit.
Edit `/etc/default/katzenpost-status` to set the configuration paths and
report path.
Then enable the timer:

```sh
systemctl enable --now katzenpost-status.timer
```

The service needs a running `kpclientd` daemon at the configured Unix socket
or TCP address.
The daemon can run on this host or another host.
This package does not install or configure that daemon.

Before installation, inspect any existing status service and timer files in
`/etc/systemd/system`.
Move these files to a backup directory if the packaged units must replace
them.
Local unit files override the packaged files in `/usr/lib/systemd/system`.
The package preserves these local files, so they can continue to use uv or a
source checkout.
