# status

*minxnet diagnostics and status page for katzenpost mix networks*

---

works with Katzenpost version v0.0.41 or later

## Installation / Depedencies

**worldmap** depends on the thinclient which requires you
to run a katzenpost client2 daemon. Build `kpclientd`:

```bash
git clone https://github.com/katzenpost/katzenpost.git
cd katzenpost/client2/cmd/kpclientd
go build
```

Run the client daemon first:

```bash
./kpclientd -c /home/human/client2.toml
```

Our thinclient currently requires that your client2 config
has the follow settings:

```toml
ListenNetwork = "unix"
ListenAddress = "@katzenpost"
```

which ensures that the client2 daemon listens on the "@katzenpost"
abstract unix domain socket for thinclient connections.


### Commandline Usage

```
Usage: status.py [OPTIONS]

Options:
  --htmlout TEXT      Path to output HTML file.
  --dirauthconf TEXT  Path to the directory authority configuration TOML file.
                      [required]
  --help              Show this message and exit.
```


# License

AGPLv3
