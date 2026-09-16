# wow2-server

A server for the online mode of Worms Open Warfare 2 on PSP (`ULES00819`).
The official Demonware servers were shut down years ago; this reimplements
the auth and lobby services the game talks to, so consoles can sign in, find
each other and play. Sign-in, the game browser, hosting, joining, full
matches, chat, leaderboards, daily awards, ranked play, clans, buddies,
match invites and host migration all work, on the PPSSPP emulator and on
retail hardware.

Python 3.11 or newer, nothing else.

## Install

```bash
git clone https://github.com/tazua/wow2server.git
cd wow2server
./setup.sh
.venv/bin/wow2-server
```

That makes a `.venv`, installs the server into it, writes `wow2-server.toml`
and creates `wow2-data/`. As a system service instead:

```bash
sudo ./setup.sh --system --dns <SERVER_IP> --open-firewall
```

`--system` installs under `/opt/wow2-server` with a `wow2` user, the config at
`/etc/wow2-server.toml`, data in `/var/lib/wow2-server`, and starts the systemd
units. `--dns` adds the DNS responder a retail PSP needs. `--open-firewall`
opens the ports in ufw or firewalld. `packaging/` has the units and a
Containerfile.

## Point the game at it

The game resolves eight `demonware.net` names, listed in `wow2/nsdns-names`.
On an emulator, put them in `/etc/hosts`, all pointing at the server:

```
<SERVER_IP> worms-180.auth.mmp3.demonware.net worms-180.lsg.mmp3.demonware.net
<SERVER_IP> stun.us.demonware.net stun.eu.demonware.net stun.jp.demonware.net stun.au.demonware.net
<SERVER_IP> worms.stun.us.demonware.net worms.stun.eu.demonware.net
```

A PSP has no hosts file, so it needs a DNS server that answers those names:
`wow2-nsdns`, a second process beside the server. `--system --dns` installs
it as a service; without `--system`, run it yourself as root:

```bash
sudo .venv/bin/wow2-nsdns --bind <SERVER_IP> --answer <SERVER_IP>
```

Then set the PSP's DNS server to that address: Settings, Network Settings,
your connection, Address Settings, Custom, DNS Setting, Manual. The PSP's own
connection test will say there is no internet; the game works. Without the
responder the game says "Unable to connect to WormNet" before it has sent
the server a single packet.

Ports: TCP 3074, UDP 3074, UDP 3078, UDP 53 for the DNS responder, and UDP
40000-40031 if the relay is on.

## Configure

Everything is in `wow2-server.toml`, and every value in the file is already
the default. The one worth knowing about: players behind mobile or
carrier-grade NAT cannot reach each other directly, and `[nat] relay = true`
makes the server carry the match instead. Accounts are created by the game
itself the first time a player signs in; `wow2-account` is the operator's
tool for the credential store.

## Documentation

- [DOCS.md](DOCS.md): the protocol, configuration, accounts, what the server
  stores, the checks, and what has and has not been tested.
- [RPCS.md](RPCS.md): every lobby opcode, its request and reply layout, which
  screen fires it, and how the server handles it.

## Licence

MIT, see `LICENSE`.

This is an independent reimplementation of a network service for a game whose
official servers no longer exist, written from the client's behaviour on the
wire. It contains no game code, assets or data, and is not affiliated with or
endorsed by Team17, Demonware or Activision.
