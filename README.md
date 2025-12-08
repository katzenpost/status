# katzenpost-status

*minxnet diagnostics and status page for katzenpost mix networks*

---

![example status image](status.png "Status")


works with Katzenpost version v0.0.41 or later


## Installation / Depedencies

**katzenpost-status** depends on the katzenpost thinclient which requires you
to run a katzenpost client2 daemon. Build `kpclientd`:

```bash
git clone https://github.com/katzenpost/katzenpost.git
cd katzenpost/cmd/kpclientd
go build -v
```

Run the client daemon first:

```bash
./kpclientd -c /home/human/client2.toml
```

Install `ping` and `tcptraceroute` for the network survey feature:
```bash
apt install tcptraceroute iputils-ping
```

### Commandline Usage

```
Usage: katzenpost-status [OPTIONS]

Options:
  --config TEXT        Path to the thin client TOML config file.  [required]
  --htmlout TEXT       Path to output HTML file.
  --dirauthconf TEXT   Path to the directory authority configuration TOML
                       file.  [required]
  --network-name TEXT  Name of the network deployment (outer panel title).
  --ping / --no-ping   Send a ping via echo service and show result.
  --verbose            Verbose output (includes Rich tables and debug
                       logging).
  --quiet              Suppress all console output (except exit code).
  --help               Show this message and exit.
```


### Example Usage

This example uses the `uv` tool:
```bash
uv venv
uv sync
uv run katzenpost-status --config ~/.local/katzenpost/thinclient.toml --dirauthconf ~/.local/katzenpost/authority.toml --htmlout ~/.local/katzenpost/status.html --ping 
```

# Example deployment for status.namenlos.network
As an example we provide a full set of services to regularly update the status
page for the namenlos network.

## Add a `katzenpost-status` user that can update the status web page
```bash
useradd --system --home /var/lib/katzenpost-status \
  --shell /usr/sbin/nologin --user-group katzenpost-status
mkdir -p /var/www/status.namenlos.network
chown katzenpost-status:katzenpost-status /var/www/status.namenlos.network
chmod 0755 /var/www/status.namenlos.network
```

## Add service and timer configurations

```bash
cp configs/kpclientd.service /etc/systemd/system/kpclientd.service
cp configs/katzenpost-status.service /etc/systemd/system/katzenpost-status.service
cp configs/katzenpost-status.timer /etc/systemd/system/katzenpost-status.timer
```

### Reload systemd services
After installing the configuration files and reloading system, enable the services:
```
systemctl daemon-reload
systemctl enable --now kpclientd.service
systemctl enable --now katzenpost-status.timer
```

# License

AGPLv3
