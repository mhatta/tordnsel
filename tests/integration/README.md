# Integration test against a private Tor network

`run.sh` builds a small Tor network with [chutney](https://gitlab.torproject.org/tpo/core/chutney)
(four directory authorities, three exits with different exit policies and exit
addresses, one client), runs TorDNSEL against the client with active exit
testing, and checks the DNS and HTTP answers, including that an exit whose
traffic leaves from an address other than the advertised one is found by
active testing.

```sh
git clone https://gitlab.torproject.org/tpo/core/chutney.git
cabal build
sudo tests/integration/run.sh chutney $(cabal list-bin tordnsel)
```

With a build made by `runhaskell Setup.hs build`, the binary is
`dist/build/tordnsel/tordnsel`.

## Requirements

- `tor` and `tor-gencert` (Tor 0.4.8 or newer)
- `dig`, `curl` and `ip` (iproute2)
- Python 3 with the modules chutney needs:
  - `asyncore` and `asynchat`, removed from the standard library in
    Python 3.12 and needed by every chutney version so far
  - in addition, for current chutney from GitLab: `tomli_w`, `typeguard`,
    `paramiko` and `rpyc`

  On Debian sid:

  ```sh
  sudo apt install tor bind9-dnsutils curl iproute2 \
    python3-asyncore python3-standard-asynchat \
    python3-tomli-w python3-typeguard python3-paramiko python3-rpyc
  ```

  (On Ubuntu 26.04 the asyncore package is `python3-pyasyncore`.)

  The script runs under `sudo`, so modules installed with `pip install --user`
  are not seen; install them with apt (or system-wide).

## Notes

- Root is needed to add 10.200.0.{1,11,12,13,99} to the loopback interface.
  Run as a normal user with `SUDO=sudo` to use sudo for just that step.
- The script uses ports 5000-5007, 7000-7003, 8000-8007, 9000-9007, 15353 and
  18080 on the loopback interface.
- `KEEP=1` keeps the working directory (TorDNSEL's log, the Tor nodes' logs
  and data) instead of deleting it.
- A run takes a few minutes, mostly waiting for the network to bootstrap and
  for the exit tests (which run every 20 seconds or so).
- `chutney/` holds the network definition and torrc templates, copied over a
  fresh copy of chutney at each run; your chutney clone is not modified.
