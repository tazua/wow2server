# wow2-server

The auth and lobby servers for Worms Open Warfare 2 (PSP, `ULES00819`), rebuilt
from scratch. The official ones were shut down years ago.

With this running, two consoles sign in as separate players, one hosts a game,
the other finds it in the browser and joins, and they play a full match:
weapons, crates, mines, worms going in the water. It carries on through the
results and awards screens and into the next game. Chat works both ways, and so
do leaderboards, daily awards, the ranked wager and its payout, clan creation,
the buddy list, match invites and host migration.

All of that has been played, not inferred from the code. Most of it was built
against the PPSSPP emulator on a LAN; a retail PSP has since signed in, hosted
and browsed against a real server over the internet. Players behind carrier NAT
cannot reach each other directly, so the server can carry the match itself, which
is off by default. Read [Before you deploy](#before-you-deploy) before promising
anyone anything.

## What it speaks

The game uses four separate channels. Three of them are the server's job:

| channel | what it carries | state |
|---|---|---|
| TCP 3074, auth | account creation, login, change password | works |
| TCP 3074, LSG | the lobby: matchmaking, stats, friends, clans, storage, profiles, messaging | works; every RPC the client fires gets an answer |
| UDP 3074, bdDiscovery | IP discovery and the NAT introduction | works; carrier NAT defeats the introduction, so there is also a relay |
| UDP 3075, peer | the match itself, host to joiner | peer to peer by default; the server can relay it when punching fails |

Every lobby RPC the client can make goes through a single dispatch function,
with the service and opcode as immediate operands. So you can scan the game's
executable and enumerate the whole surface instead of waiting to see what shows
up on the wire. There are 45 call sites and all of them are answered.

## Install

```bash
apt install rhash python3-venv      # or: pacman -S rhash
git clone https://github.com/tazua/wow2server.git
cd wow2server
python3 -m venv .venv && .venv/bin/pip install .
.venv/bin/wow2-server
```

`rhash` has to be there. Tiger192 is the hash the whole auth path is built on,
no Python standard library provides it, and the server shells out to the binary.
Without it every login proof comes out wrong and nobody can sign in, with
nothing else looking broken.

There is a systemd unit and a Containerfile in `packaging/`.

### Pointing the game at it

The client resolves `*.demonware.net`, so on an emulator `/etc/hosts` is enough.
Real hardware needs a DNS server: on the PSP go to Settings, Network Settings,
your connection, Address Settings, Custom, DNS Setting, Manual, and point it at
a resolver that answers those names. `nsdns.py` is included for that.

```bash
sudo .venv/bin/python -m wow2.nsdns --bind 0.0.0.0 --answer <SERVER_IP>
```

It answers eight names and returns NXDOMAIN for everything else, so it is no use
to anyone as an open resolver. Two things will then look broken and aren't. The
PSP's own "Test Connection" fails its internet check, because it cannot resolve
anything outside those eight names. And on connect the game pushes about a
hundred bytes of NAT/STUN struct at the auth port, where it makes no sense as a
message; the server logs it and resynchronises past it.

Open TCP 3074, UDP 3074 and UDP 53. Open only the TCP port and sign-in will
work while the game browser stays empty forever, which looks like a matchmaking
bug when it is a firewall.

## Configure

```bash
cp wow2-server.example.toml wow2-server.toml     # then edit
WOW2_CONFIG=/etc/wow2-server.toml wow2-server
```

Every value in that file is already the built-in default, so an empty file and
no file behave the same. The server prints its effective configuration at
startup, which is worth reading when something is set in two places.

Two settings matter for a real deployment:

```toml
[accounts]
shared_password_fallback = false   # see below

[logging]
hexdumps = false                   # or the disk fills
level = "info"
```

`hexdumps` dumps every packet. That is how the protocol got reverse engineered
in the first place, and it is also why a session log reaches hundreds of
megabytes.

The `WOW2_*` environment variables are not configuration. Each one turns a
single behaviour off so you can bisect a protocol failure over a few minutes,
and they are kept out of the config file so that nobody deploys with one set.

## Accounts

The client creates its own account the first time it signs in, and the server
stores `Tiger192(password)`, which is the same key the login proof is built
with. So the credential store holds digests and never a password, and there is
nothing to learn from reading the file. Changing a password from the game's own
User profile edit screen works and rewrites the digest.

The client never sends a password proof. It says which account it is, and then
the server has to prove it knows that account by encrypting the login reply with
the credential. A server that does not have it cannot produce a reply the client
will accept. That is how the protocol works, and it took a while to believe.

### First connection, and a trap

`shared_password_fallback` defaults to true, which lets an account with no stored
credential sign in using a shared password. Leave it on and anyone who knows a
username can get in, so a deployment wants it false.

Turn it off too early, though, and you can lock yourself out. An account only
gets a stored credential when it is created or when its password changes, and a
console that already has a WormNet account saved goes straight to login and
never sends a create. So:

1. Start with `shared_password_fallback = true`.
2. Sign in. If the console creates a new account, the server picks up its name
   and credential on its own and you are done.
3. If it reuses an old account, run Change password once on the console. That
   writes the credential.
4. Set the option to false and restart.

## Before you deploy

What is known and what isn't.

NAT traversal has been measured rather than guessed at. A retail PSP on mobile
data and an emulator on a domestic line, both against a server on a VPS: sign-in,
the lobby, hosting and the game browser all work across two different NATs. The
join does not. The introduction broker runs and relays correctly in both
directions and the punch still fails, because each console's NAT mapping was
created by talking to the server while the punch arrives from the other console.
Carrier-grade NAT drops that, and most mobile connections are carrier-grade NAT.

So the server can carry the match itself instead:

```toml
[nat]
relay = true
relay_port_base = 40000
relay_ports = 32          # open these in the firewall too
```

Each console is handed a UDP socket on the server and told that socket is its own
public address, so the two only ever exchange packets with us. That works behind
any NAT, including symmetric, because every packet a console receives comes from
an address it has itself sent to. A full match has been played through it. The
cost is about 7 datagrams per second each way per pair, so a four-player match is
roughly 50 KB/s.

Two caveats worth knowing before you turn it on. The relay ports have to be open
in the firewall and nothing warns you if they are not: sign-in, hosting and the
browser all work, and only the join fails. And it is all-or-nothing per
deployment rather than per session, because the address a console publishes is
decided when it signs in, before anyone knows whether a punch would have worked.

With the relay off there is still a rig-shaped assumption in the broker: peer
addresses are resolved by matching on the port alone, which is fine with two
consoles and will not be with several. With it on, the lookup is exact.

It has been fuzzed but never attacked. 24 million mutated-message parser calls
finished without a crash, and there are per-connection caps on concurrency,
message rate and bytes. It has not had a security review.

Everything here came from one client and one title. Other Demonware games of
that era share the framing but not the opcode numbering.

Real hardware works. A PSP on 6.61 ARK-4 signs in, browses, hosts and creates
ranked lobbies against a server on a VPS. Nearly all the development was done
against the PPSSPP emulator, though, so hardware coverage is thin: one console,
one firmware, one evening.

Scale has not been tested either. The target was ten players at once. It is a
single-process asyncio server and the stores are JSON, re-read per request, which
keeps the databases editable by hand while the server runs and will not hold up
under hundreds of players without a different backend.

## Layout

| path | what |
|---|---|
| `wow2/authserver.py` | the server: transport, framing, crypto, every service handler |
| `wow2/bdproto.py` | the bd wire codec (bit mode, 5-bit type tags) |
| `wow2/serverconfig.py` | deployment configuration |
| `wow2/nsdns.py` | the small DNS responder for pointing consoles here |
| `packaging/` | systemd unit, Containerfile |

This repository holds the server on its own. The development rig that produced
it drives PPSSPP over its debugger protocol, reads the game's screen by template
matching, and plays the game end to end without a human. That, and the
reverse-engineering notes, are kept separately.

## Licence

MIT, see `LICENSE`.

This is an independent reimplementation of a network service for a game whose
official servers no longer exist. It was written by observing the client's
behaviour on the wire and by disassembling the retail binary to work out message
formats. It contains no game code, no game assets, no ISO and no extracted game
data, and it is not affiliated with or endorsed by Team17, Demonware or
Activision.
