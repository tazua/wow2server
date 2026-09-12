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

**`RPCS.md` is the reference table**: every opcode, what it is, its request
layout, its reply shape, and which screen fires it.

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

**A PSP has no `/etc/hosts`.** The only way to point real hardware at your server
is to set a DNS server in its network profile, so a deployment runs two
processes, not one. `wow2-nsdns` is the second:

```bash
sudo wow2-nsdns --bind <SERVER_IP> --answer <SERVER_IP>
```

Bind it to the public address rather than `0.0.0.0`: on Debian and Ubuntu,
systemd-resolved holds `127.0.0.53:53` and will otherwise refuse the bind. There
is a unit for it in `packaging/`, where the address is the instance name so there
is nothing to edit:

```bash
sudo systemctl enable --now wow2-nsdns@<SERVER_IP>
```

On the console: Settings, Network Settings, your connection, Address Settings,
Custom, DNS Setting, Manual.

It answers eight names and returns NXDOMAIN for everything else, so it is no use
to anyone as an open resolver. Two things will then look broken and aren't. The
PSP's own "Test Connection" fails its internet check, because it cannot resolve
anything outside those eight names. And on connect the game pushes about a
hundred bytes of NAT/STUN struct at the auth port, where it makes no sense as a
message; the server logs it and resynchronises past it.

Open TCP 3074, UDP 3074 and UDP 53, plus the relay ports if you turn the relay
on. Each one fails in a way that looks like something else: without UDP 3074 the
game browser stays empty forever and reads like a matchmaking bug, without UDP 53
a real console never gets as far as sending a packet, and without the relay ports
everything works except the join.

### The NAT type probe

Before it does anything else the game runs a three-test STUN probe against those
`stun.*` names, to work out what kind of NAT it is behind. The server answers it,
which takes one extra UDP port:

```toml
[nat]
nat_type = true
nat_type_alt_port = 3078          # test 3's reply leaves from here
```

It has to be a different port from the main one. The client accepts test 3's
reply from any source, so answering it from port 3074 would mean the reply always
arrives and every console reported the same NAT type whatever it was actually
behind.

**It needs no firewall rule.** The console sends all three tests to the main
port, and the alternate one is only an address to answer *from*, so outbound UDP
is all it requires.

If the machine has a **second public address**, name it and consoles behind a
full-cone NAT will find that out:

```toml
nat_type_alt_address = "203.0.113.11"
```

Only set that if the address really is a different one. Answering from the
address the console already talks to would pass the client's check and report an
open NAT for one that is merely address-restricted, and that is the one wrong
answer that costs something: it tells the console the direct path will work. The
server compares and refuses rather than over-report.

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

An account gets a stored credential when it is **created**, and only then. That
is the trap, and it is sharper than it looks. A console tells the server its name
exactly once, in the create-account message. Every later message, including
Change password, identifies the account by its **handle**, `Tiger192(name)[:8]`,
which is a one-way hash. So a server that never saw the create, or that lost its
store, can never learn the name again, and the console has no way to tell it.
Change password answers 704 in that state.

Only an operator who knows the name can fix it, with `wow2-account`:

```bash
wow2-account list                  # what the store holds, and what it is missing
wow2-account handle player1b         # match a name against a handle from the log
wow2-account set player1b            # prompts for the password, stores the digest
```

So, in order:

1. Start with `shared_password_fallback = true`.
2. Sign in. If the console creates a new account, the server picks up its name
   and credential on its own and you are done.
3. If it reuses an account the store does not know, the log says so:
   `login handle <hex> is not an account we know`. Run `wow2-account set <name>`
   with the password that console uses.
4. Set the option to false and restart.

**Back the store up before you delete anything.** `accounts.json` is the only
copy of every credential, and losing it means asking every player for their
username and password by hand.

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
| `RPCS.md` | every opcode: request layout, reply shape, the screen that fires it |

### What the server writes

Everything lands in the data directory (`[paths] data_dir`, default `capture/`).
Accounts, leaderboards, clans, friends, messages, profiles and uploaded files are
the stores you would expect.

Profiles are the one store with a subtlety worth knowing. A console asks the
server to *create* its public profile at every sign-in, and the answer to that
decides what happens next: answer "created" and the console uploads over
whatever you hold, answer `BD_PROFILE_ALREADY_EXISTS` and it downloads yours
instead. This server does the second once a record exists, so a profile edited
on the server survives — except longitude and latitude, and six bits of two
other fields, which the console always supplies itself. Set
`WOW2_NO_PROFILE_EXISTS=1` to go back to upload-only.

Uploaded files are the other one worth a note. Rows live in `storage-db.json`
and the bytes beside them, and the owner of a row is written as a 16-hex-digit
account id. If you hand-edit that file, use hex: the list and fetch paths match
on the string, so a decimal id makes a file invisible to the screen meant to
show it. The game uploads there by itself, from `Upload flag`, from a shared
scheme, and from `Take snapshot` on a leaderboard, and reads them back from the
matching screen under a user profile.

One file is diagnostic rather than state:

| file | what |
|---|---|
| `request-census.json` | every typed field the client has sent, per RPC, with the distinct values each has carried, and whether a handler read them all |

That last one exists because the failure it catches is silent: a reply field of
the right type in the right position carrying a wrong value produces no error on
either side. The server decodes each request twice — once generically, once as
its handler read it — and logs `*** UNREAD REQUEST FIELD` when those differ. It
is also how the request layouts in `RPCS.md` are measured rather than guessed.
Set `WOW2_NO_CENSUS=1` to turn it off.

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
