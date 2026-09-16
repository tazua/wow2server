# wow2-server

A server for the online mode of Worms Open Warfare 2 on PSP — the PAL disc
(`ULES00819`) and the US disc (`ULUS10260`), which are the same client on the
wire.
The official Demonware servers were shut down years ago; this reimplements
the auth and lobby services the game talks to, so consoles can sign in, find
each other and play. Sign-in, the game browser, hosting, joining, full
matches, chat, leaderboards, daily awards, ranked play, clans, buddies,
match invites and host migration all work, on the PPSSPP emulator and on
retail hardware.

Python 3.11 or newer, nothing else.

## Install

A deployment is two processes: the game server, and a DNS responder that
answers the eight `demonware.net` names the game looks up. A real PSP cannot
reach the server without the responder; an emulator on the same machine can
use `/etc/hosts` instead.

**On a server, for real consoles** (any Linux with systemd):

```bash
git clone https://github.com/tazua/wow2server.git
cd wow2server
sudo ./setup.sh --system --dns <SERVER_IP> --open-firewall
```

That installs both processes as systemd units under `/opt/wow2-server`
(running as a `wow2` user, config in `/etc/wow2-server.toml`, data in
`/var/lib/wow2-server`), starts them, and opens the ports in ufw or
firewalld. `<SERVER_IP>` is the public address the consoles will be told.
Check with `systemctl status wow2-server wow2-nsdns@<SERVER_IP>`.

**In the checkout, for a local test** (an emulator, or a PSP on your LAN):

```bash
git clone https://github.com/tazua/wow2server.git
cd wow2server
./setup.sh
.venv/bin/wow2-server
```

This starts only the game server, in the foreground, with a `.venv`,
`wow2-server.toml` and `wow2-data/` in the checkout. If a PSP is to connect,
also run the responder, as root, in a second terminal:

```bash
sudo .venv/bin/wow2-nsdns --bind <SERVER_IP> --answer <SERVER_IP>
```

Nothing is opened in the firewall in this mode. Both forms can be re-run
after a `git pull`; an existing config file is kept. `packaging/` has the
units and a Containerfile.

## Point the game at it

On a PSP, set the connection's DNS server to `<SERVER_IP>`: Settings,
Network Settings, your connection, Address Settings, Custom, DNS Setting,
Manual. The PSP's own connection test will say there is no internet, because
the responder answers nothing but the eight names; the game works. Without
the responder the game says "Unable to connect to WormNet" before it has sent
the server a single packet.

On an emulator, either do the same in the emulator's network settings, or
put the names in `/etc/hosts`, all pointing at the server:

```
<SERVER_IP> worms-180.auth.mmp3.demonware.net worms-180.lsg.mmp3.demonware.net
<SERVER_IP> stun.us.demonware.net stun.eu.demonware.net stun.jp.demonware.net stun.au.demonware.net
<SERVER_IP> worms.stun.us.demonware.net worms.stun.eu.demonware.net
```

Ports: TCP 3074, UDP 3074, UDP 3078, UDP 53 for the responder, and UDP
40000-40031 if the relay is on.

## Configure

Everything is in `wow2-server.toml`, and every value in the file is already
the default. The one worth knowing about: players behind mobile or
carrier-grade NAT cannot reach each other directly, and `[nat] relay = true`
makes the server carry the match instead. Accounts are created by the game
itself the first time a player signs in; `wow2-account` is the operator's
tool for the credential store, and `wow2-db` (`check`, `backup`, `export`)
for the SQLite file that holds every store.

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
