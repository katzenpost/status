# status

*minxnet diagnostics and status page for katzenpost mix networks*

---

![example status image](status.png "Status")


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


### Commandline Usage

```
Usage: status [OPTIONS]

Options:
  --config TEXT       Path to the thin client TOML config file.  [required]
  --htmlout TEXT      Path to output HTML file.
  --dirauthconf TEXT  Path to the directory authority configuration TOML file.
                      [required]
  --help              Show this message and exit.
```


### Example Usage


```bash

status --config ~/code/mymixnet/configs/thinclient.toml --dirauthconf ~/code/mymixnet/configs/dirauth1.toml --htmlout network_status.html
```


# License

AGPLv3
