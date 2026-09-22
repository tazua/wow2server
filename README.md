# wow2-server

A server for the online mode of Worms Open Warfare 2 on PSP — the PAL disc
(`ULES00819`) and the US disc (`ULUS10260`), which are the same client on the
wire.
The official Demonware servers were shut down years ago; this reimplements
the auth and lobby services the game talks to, so consoles can sign in, find
each other and play. Sign-in, the game browser, hosting, joining, full
matches, chat, leaderboards, daily awards, ranked play, clans, buddies,
match invites and host migration all work, on the PPSSPP emulator and on
retail hardware. A public server running this code is already up, with
players on it — see below if you want to play rather than deploy.

Python 3.11 or newer, nothing else.

## You do not have to run one to play

A public server built from this code has been up since September 2026, and
the players are on Discord: **https://discord.gg/xPeXxye8Z** (Wormhole).
One DNS address on the console and the game's online mode works as it did
in 2007 — hosting, the browser, ranked play, clans, chat. Come and get a
match rather than playing alone against your own server.

Set the console's **primary DNS** to either of these; both reach the same
server:

- `67.222.156.250` — PS Rewired, a DNS service for revived PSP games in
  general. It answers for other titles too, and the PSP's own connection
  test passes.
- `199.247.2.103` — the game server's own responder. It answers the four
  `demonware.net` names this game asks for and nothing else, so the PSP's
  connection test says there is no internet; the game works anyway.

On a PSP: Settings, Network Settings, Infrastructure Mode, your connection,
Address Settings, Custom, DNS Setting, Manual, Primary DNS, and leave the
rest automatic. In PPSSPP: Settings, Networking, turn Networking on, then
the DNS server field.

Then Wireless MP, Infrastructure, and follow the prompts. Your online name
is the name of the local profile you are playing on, so play on a real
profile rather than Guest; the password the game asks for the first time is
a new one, 6 to 12 characters. The PAL and US discs play together.

A profile that was ever online on the original Demonware servers carries an
account no new server has ever seen, and the game will say the name or
password is incorrect whatever you type. The Discord's #old-profiles channel
and its password bot exist for exactly that.

## Run your own

A deployment is two processes: the game server, and a DNS responder that
answers the four `demonware.net` names the game looks up. A real PSP cannot
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
after a `git pull` to upgrade: an existing config file and data directory
are kept, the service form restarts the units, and a data directory from a
version before 0.3 has its JSON stores imported into `wow2.sqlite3` at that
first start (one log line per file). `packaging/` has the units and a
Containerfile.

## Point the game at it

On a PSP, set the connection's DNS server to `<SERVER_IP>`: Settings,
Network Settings, your connection, Address Settings, Custom, DNS Setting,
Manual. The PSP's own connection test will say there is no internet, because
the responder answers nothing but the four names; the game works. Without
the responder the game says "Unable to connect to WormNet" before it has sent
the server a single packet.

On an emulator, either do the same in the emulator's network settings, or
put the names in `/etc/hosts`, all pointing at the server:

```
<SERVER_IP> worms.stun.us.demonware.net worms.stun.eu.demonware.net
<SERVER_IP> worms-180.auth.mmp3.demonware.net worms-180.lsg.mmp3.demonware.net
```

Those four are the whole list, and all four are needed: the game resolves
the two `worms.stun` names before anything else and gives up if they fail.
The generic `stun.<region>.demonware.net` names also present in the binary
are the SDK's compiled-in defaults, which the game replaces with the
`worms.stun` pair before it starts networking -- no console has ever asked
for one, so a DNS operator who already serves another Demonware title on
those names can leave them where they are. PPSSPP resolves each name once
per launch, so after changing the list restart it.

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

**Discord.** With two webhook URLs in the `[discord]` section the server
keeps a channel showing the open lobbies, edited in place as they come and
go, and pings a role when somebody hosts. No bot; DOCS.md has the details.

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
