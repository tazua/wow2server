# wow2-server documentation

What the game speaks, what the server does with it, and how to run it.
[RPCS.md](RPCS.md) is the per-opcode reference for the lobby; this file is
everything around it.

Contents: [Protocol](#protocol) · [Configuration](#configuration) ·
[Accounts](#accounts) · [What the server stores](#what-the-server-stores) ·
[NAT and the relay](#nat-and-the-relay) · [Checks](#checks) ·
[Limits and what has been tested](#limits-and-what-has-been-tested)

## Protocol

The game uses four channels. Three are the server's job; the fourth is peer
to peer unless the relay is on.

| channel | carries | server |
|---|---|---|
| TCP 3074, auth | create account, login, change password | answers |
| TCP 3074, LSG | the lobby: sessions, stats, friends, clans, storage, profiles, messaging, pushes | answers every RPC the client can make |
| UDP 3074, bdDiscovery | address discovery, the NAT type probe, the bdNAT introduction | answers and relays |
| UDP 3075, peer | the match itself | not involved, or carries it through the relay |

### Framing and encryption

Every TCP message is `[u32 LE length][body]`. A zero length is a keepalive
ping, answered with a zero length. A length of 180 is not a length: it is
the buffer-size announcement `[u32 180][u32 free]` the lobby client sends
first, which is how the server knows a connection is the LSG and not the
auth port.

The body starts with a flag byte. `0` means the rest is a plain bd bit
stream: a service byte, then typed fields, each carrying a 5-bit type tag
before its bits (`wow2/bdproto.py` is the codec). `1` means encrypted:
`[u8 1][u32 seed]` then 3DES-CBC ciphertext under a 24-byte key with the IV
`Tiger192(seed as LE u32)[:8]`. Server replies open with the signature
`0xDEADBEEF` in the plaintext, which is the client's check that the key was
right; a reply that fails it closes the connection.

Tiger192 is the hash under everything: the account id, the IVs, the keys.
It is implemented in `wow2/tiger.py`.

### The auth port

| type | message | reply |
|---:|---|---|
| `0x00` | create account: `[seed][title id][64 zero bits][96 bytes ciphertext]` under a constant key the client ships; plaintext is `[magic][username, 64 bytes][Tiger192(password), 24 bytes]` | `0x01` with a code |
| `0x0a` | login: `[seed][title id][64-bit handle]`, the handle being `Tiger192(username)[:8]` | `0x0b`: `[seed]`, a 128-byte ticket encrypted under `Tiger192(password)`, and a 128-byte proof in clear |
| `0x02` | change password: `[seed][title id][64-bit handle]` and 32 bytes encrypted under the current `Tiger192(password)`, holding the new digest | `0x03` with a code; the server verifies the current password by decrypting and finding the magic |

The codes are the client's own: 700 no error, 707 name exists, 704 bad
account, 716 incorrect password; the full list is in `wow2/authserver.py`.

Authentication runs the other way from what you might expect. The login
request carries no password proof. It names the account, and the server
proves it holds the credential by encrypting the ticket with it. The ticket
holds the 24-byte session key; the clear proof beside it holds an opaque
handle. The lobby connection presents the proof and is bound provisionally;
the first RPC that decrypts under the ticket's key completes the binding. So
a connection that has only seen the reply, and not opened the ticket, is
served nothing. A refused login is answered with a key the sender cannot
have, and it is indistinguishable on the wire from a wrong password. A
handle and its key are honoured for 120 s after the login reply (a console
presents its handle within a few seconds) and the tables that hold them are
bounded at 65,536 entries, so a flood of sign-ins costs memory only up to
that bound.

There is no lockout, and there cannot be one on this protocol: the server
never sees a wrong password. Whoever names an account gets its ticket, and
a wrong guess is discovered by the client, offline, so a password can be
attacked on the attacker's own machine at whatever speed it has (one
Tiger192 and one 3DES block per candidate, against a known first block).
The password's length is the defence. The game allows 6 to 12 characters;
six digits fall in well under a second, twelve mixed characters do not
fall. Tell your players.

Names are case-insensitive: the game signs in with a hash of the
lowercased profile name, so `Lukas1` and `lukas1` are one account, stored
and shown to others in the case it was first registered in. (A server
from before schema 2 had hashed names as typed, and a name with a capital
letter could register and never sign in; the first start on the new code
recomputes every handle and says so in the log.) `wow2-account` takes a
name in any case.

A player who "cannot sign in, it says the name is already in use" is
almost always a player whose console types a password other than the one
the account was created with: the create is answered 707, the sign-in the
game re-issues gets a ticket their console cannot open. The log has what
you need without either password. Their `create-account request` line
carries `pwhash=`, the digest of what they are typing now, and

```
wow2-account set NAME --hash <that pwhash>
```

makes the account theirs again under that password, with no restart.

Names are first come, first served, and nothing needs a console to claim
one: the create-account request is encrypted under a constant the game
ships, this package carries it because the server decrypts with it, and
`wow2.lsgauth` sends creates by script. A squatted name costs its owner a
different profile name, and a script could otherwise file names as fast as
the message caps allow, so `limits.max_creates_per_ip_per_hour` (20) holds
each address to that many. A squatting run is visible after the fact in
the `accounts` table (`first_seen`, `last_ip`), and `wow2-account remove
NAME` frees a name.

### The lobby

The LSG connection presents the proof in its first message (service 7). After
that every message is an encrypted RPC: `[u32 0][u8 service][tc bit][u8 op]`
and the request's typed fields. The server answers each one with a TaskReply,
type 1: `[u64 transaction][u32 error][u8 op]`, then for most ops
`[u32 count]` and the result rows. The client blocks on every RPC with no
timeout, so an unanswered request parks the game at "Signing in..." for ever.

Type 2 is a push: a message the server sends unprompted (a buddy invite
arriving, a clan event, "signed in elsewhere"). Type 4 carries the connection
id at connect.

There are seven services and 45 opcodes the client can fire. Each one is in
[RPCS.md](RPCS.md) with its request layout as measured off the wire, its
reply shape, the screen that fires it and notes on the handling. Two facts
the table depends on:

- A reply row's shape decides everything. A malformed row drops the
  connection; a well-formed row with a wrong value is applied silently, and
  a reply that omits a count the client reads, or adds one it does not, puts
  every field one place late.
- Identity is the account, never the address. The 64-bit account id in
  every friends, clan, stats and storage row is `Tiger192(name)[:8]`; the
  server derives it from the bound connection's name and takes it from no
  request field.

The server enforces what the client does not: a session can be updated or
deleted only by the connection that created it; clan invites, cancels,
removals, promotions and transfers need the rank the game shows them for; an
invite to someone who has blocked the sender is dropped; an account signing
in a second time signs the first console out; a duplicate account name is
refused rather than overwritten.

### UDP

`bdDiscovery` on UDP 3074 answers three things, all small:

| request | reply | purpose |
|---|---|---|
| `1e 02 00` | `1f 02 00` + 6-byte address | tells the console its public address (with the relay on: its mailbox) |
| `14 02 00` + flags | `15 02 00` + two addresses, from the main port or the alternate one | the three-test NAT type probe |
| 29-byte bdNAT packet, type `0x0a` | the same 29 bytes, type `0x0b`, sent to the console it names | the introduction: "tell that host I want to talk to it" |

Keepalives (type `0x0e`) arrive every 15 s and are how the server learns
where each console's socket really is. Nothing inside a bdNAT packet is ever
rewritten: a 10-byte HMAC covers it under a key only the originator holds,
so the server changes the transport, never the bytes.

## Configuration

`wow2-server.toml`, found at `$WOW2_CONFIG`, `./wow2-server.toml`, the
checkout's own, or `/etc/wow2-server.toml`, in that order. The environment
wins over the file (`WOW2_PORT`, `WOW2_DATA_DIR`, ...). Every key in the
example file is its default; no file at all gives the same values. The
server prints what is in force at startup.

| key | default | what |
|---|---|---|
| `server.bind`, `server.port` | `0.0.0.0`, `3074` | auth TCP, LSG TCP and discovery UDP all use the one port |
| `accounts.shared_password_fallback` | `false` | let an account with no stored credential sign in on one shared password. A migration stopgap; see Accounts |
| `accounts.create_mode` | `refuse_duplicates` | answer 707 to a create for a name that already has a credential |
| `logging.level` | `info` | `debug` logs every message body |
| `logging.hexdumps` | `false` | dump every packet to the session log; hundreds of MB per session |
| `limits.*` | 100 msg/s, 16 connections per address, 4 MB per connection | per-connection caps; flood protection, not a lockout (see Authentication) |
| `limits.max_creates_per_ip_per_hour` | `20` | the next create-account from that address is answered 710 (*Unable to create online profile*) until the hour turns; `0` turns it off. A create for a name that already has a credential is answered 707 first, so a sign-in is never blocked by it |
| `nat.relay` | `false` | carry matches through the server; see below |
| `nat.relay_port_base`, `nat.relay_ports` | `40000`, `32` | one UDP port per console ONLINE (held until `relay_idle_timeout` of silence); a console that arrives when all are taken plays direct instead, so size it to the players you expect online together |
| `nat.relay_idle_timeout` | `600` | seconds before an idle mailbox is reclaimed |
| `nat.public_address` | unset | what to tell consoles the server's address is; set it behind a NAT or on a multi-homed host |
| `nat.nat_type`, `nat.nat_type_alt_port` | `true`, `3078` | answer the NAT type probe; test 3's reply leaves from the alternate port |
| `nat.nat_type_alt_address` | unset | a second public address, if there really is one |
| `stats.starting_rating` | `400` | what a player with no ranked row is served, so their first stake is 40 |
| `storage.data_dir` | `wow2-data/` beside the checkout, `/var/lib/wow2-server` as a service | where everything below lives |
| `discord.lobby_webhook` | unset | a Discord webhook URL; the channel gets one message that always shows the open lobbies. See Discord |
| `discord.announce_webhook`, `discord.mention` | unset | a webhook URL that gets a message when a lobby opens, and what to put in front of it (`<@&ROLE_ID>` or `@here`) |
| `discord.title` | `Open lobbies` | the board's heading |
| `discord.announce_text`, `closed_text`, `empty_text`, `offline_text` | built-in wording | templates for what the poster says; the example file lists each one's fields |
| `discord.announce_cooldown` | `300` | seconds before the same host name pings again; inside it a new lobby edits the previous announcement back to open |

The `WOW2_*` environment variables beyond those are not configuration. Each
switches one behaviour back to an older one so a protocol failure can be
bisected, and nothing should be deployed with one set. The ones a reader of
the source will trip over, because a constant sits behind each:

| switch | what it puts back |
|---|---|
| `WOW2_FIXED_SESSION_KEY=1` | one constant lobby session key for every sign-in, `rigconfig.SESSION_KEY` (`0x42` x 24). Off, every sign-in gets 24 random bytes from `secrets`, the constant is never issued, and a connection presenting it is refused like any key the server did not issue. |
| `WOW2_SHARED_PASSWORD_FALLBACK=1` | `accounts.shared_password_fallback` from the environment: an account with no stored credential signs in on `rigconfig.ACCOUNT_PASSWORD` (`123456`, in this repository). Off by default; see Accounts. |
| `WOW2_CREATE_MODE=success` | the takeover: 700 to every create-account, and the request replaces whatever credential that name had. |
| `WOW2_LSG_NO_KEY_CHECK=1`, `WOW2_NO_PROOF_HANDLE=1`, `WOW2_NO_EVICT=1` | the lobby credential checks described under Authentication, one at a time; they exist for the suites' negative controls (`lsgauth --revert`). |

There is no server-side master key. The ticket in a login reply is encrypted
under that account's own `Tiger192(password)`, the lobby key is random per
sign-in, and the constant the create-account message is encrypted with
(`BD_BOOTSTRAP_KEY`) is the game's, read out of its binary: every copy of the
game holds it, so it is not a secret and cannot be changed on the server.
The 8 KB constant in `wow2/tiger.py` is the Tiger hash's four published
S-boxes, the same table every Tiger implementation carries.

## Accounts

The game creates the account itself. The first time a profile signs in, the
console sends a create-account message with the profile's name and
`Tiger192(password)`, and that digest is what the server stores; it is also
the key the login reply is encrypted with, so the store holds no passwords
and reading it teaches nothing. Changing the password from the game's
User profile edit screen rewrites the digest.

The online name is the local player profile's name, and nothing is typed for
it. Two players who both call a profile `lukas1` are asking for one account;
the second create is refused with 707, the game retries it as a sign-in
under the second player's password, that fails, and the console shows
"Online profile name lukas1 is already in use". The first player is
untouched.

After the create, a console never sends its name again: every later message
carries the one-way handle. So a server that lost its store, or never saw
the create, cannot recover the name on its own; the player sees "The online
profile name or password is incorrect" and the log says `login handle <hex>
is not an account we know` or `has no stored credential`. This is also what
a reinstall looks like: a console that made its account against the old
data directory is refused by the new one until the operator restores
the `accounts` table or re-creates the account. Only the operator can fix it:

```bash
wow2-account list              # every account, and whether it has a credential
wow2-account handle <name>     # the handle a name produces, to match against the log
wow2-account set <name>        # prompts for the password, stores the digest
wow2-account remove <name>     # forget a credential
```

`shared_password_fallback = true` is the stopgap for exactly that migration:
every account without a credential may sign in on one shared password
(`WOW2_PASSWORD`, default `123456`, which is in this repository). With it on,
anyone who knows a name is in. Leave it off.

Back up the database (`wow2-db backup PATH`, safe while the server runs)
before deleting anything. It is the only copy of every credential. On a
system install run it as root (`sudo /opt/wow2-server/bin/wow2-db backup
/var/backups/wow2.sqlite3`): the CLI hands the store's files back to the
service user afterwards, and `/var/backups` is not writable by that user.

To start over, stop the server and remove `wow2.sqlite3` (with its `-wal`
and `-shm` files) and the `storage/` directory from the data directory; the
next start makes an empty database. Every profile that has already been
online then fails to sign in until `wow2-account set NAME` gives it a
credential again, because the game creates an online account once and
never again for that profile. To wipe the game and keep the accounts,
delete from every table except `accounts`, `names` and `meta` instead.

## What the server stores

Everything is in the data directory. The seven stores are one SQLite file,
`wow2.sqlite3`, read per request, so a row can be changed while the server
runs (`sqlite3 wow2.sqlite3`, or `wow2-account`) and the change shows on the
next screen. A data directory from a version before 0.3 holds them as JSON
files; the server imports those the first time it starts, one line in the log
per file, and renames each to `<name>.imported-<date>`.

| what | where |
|---|---|
| accounts: name, credential digest, handle, user id | `accounts` |
| leaderboards: one row per (board, entity) with the score and name; the rank is derived on read | `stats` |
| ranked wagers: open pots, stakes, payouts | `pots` |
| clans, members, ranks, outstanding invites | `teams`, `team_members`, `team_proposals` |
| buddies, invites, blocks, the mailbox, and every name seen | `friends`, `friend_invites`, `blocks`, `messages`, `names` |
| player profiles, keyed by account id | `profiles` |
| uploaded files (flags, shared schemes and landscapes, leaderboard snapshots) | `storage`, with the bytes in `storage/` |
| every leaderboard upload as received | `stats-uploads.jsonl` |
| diagnostic: every typed field the client has sent, per RPC, and whether a handler read it | `request-census.json` |
| one log per server run | `session-*.log` |

```bash
wow2-db check                 # integrity, row counts, which stores were imported when
wow2-db backup PATH           # a consistent copy, safe while the server runs
wow2-db export DIR            # the stores as JSON files, for an editor or a diff
wow2-db import DIR            # JSON files -> a fresh database
```

On a system install run these as the service user (`sudo -u wow2 ...`), or
as root: a root-run command gives the database files back to the service
user, so it cannot lock the server out of its own store.

Three things about the stores that are not obvious:

- Rank is computed on read from the score order and never stored. Board 5
  is the ranked rating, boards 2 and 3 weekly and monthly, board 1 games
  started, 9 to 24 the daily awards. Board 1 rows carry a `tail` the client
  round-trips (its completion history); clearing it rewrites a player's
  percentage.
- A storage row's owner is a 16-hex-digit account id, or NULL for a global
  file. If you insert rows by hand keep it hex; a decimal id makes the file
  invisible to the screen meant to show it. Two rows cannot share an id: the
  primary key refuses the second.
- A console asks to *create* its profile at every sign-in. The server
  answers "already exists" once it holds one, which makes the console
  download the server's copy instead of uploading over it, so a profile
  edited on the server survives, except longitude, latitude and six bits of
  two fields the console always supplies itself.

Writes are atomic (a temp file renamed over the target). A store that exists
and does not parse is kept aside as `<name>.corrupt-<timestamp>` and every
later write to it is refused for the life of the process, so a bad file
costs an empty screen and a loud log line, never the data.

## NAT and the relay

Consoles on two different domestic connections find each other through the
introduction on UDP 3074 and then talk directly. Behind carrier-grade NAT,
which is most mobile data, the introduction relays correctly and the punch
still fails: each console's mapping was created by talking to the server,
and the other console's packet arrives from somewhere else.

```toml
[nat]
relay = true
```

With the relay on, every console is handed a UDP socket on the server and
told that socket is its own public address. Both consoles then only ever
exchange packets with the server, which works behind any NAT, including
symmetric. It costs about 7 datagrams per second each way per pair, roughly
50 KB/s for four players. It is all-or-nothing per deployment, because the
address a console publishes is decided at sign-in, before anyone knows
whether a punch would have worked. The relay ports must be open in the
firewall, and nothing warns you if they are not: sign-in, hosting and the
browser all work and only the join fails. `setup.sh --open-firewall` opens
the range the config declares when it sees `relay = true`.

What it costs: the match's own traffic, on the server, for every match. That
is little bandwidth but it is the server's latency instead of the direct
path's, and it makes the server part of the match: with the relay off a
running match survives the server going away, with it on it does not.

The NAT type probe needs no firewall rule of its own. All three tests arrive
at the main port; the alternate port is only an address to answer from.

## Discord

The server can keep a community Discord informed through webhooks — no bot
and nothing that has to stay online. A webhook is made in the channel's
settings (*Integrations → Webhooks → New Webhook → Copy Webhook URL*) and
pasted into the `[discord]` section of `wow2-server.toml`; leaving the
section empty turns the feature off.

With `lobby_webhook` set the server posts one message to that channel at
startup and edits it from then on: one line per live session — host, `N/M`
players, ranked or friendly, when it opened — with full lobbies last, or
*No open lobbies*; *Server offline* in red on a clean stop. Every create,
update, delete and expiry the server sees repaints it, a burst coalesced
into one edit two seconds later, so a lobby filling up is one edit and not
four. The message id is kept in the store, so a restart edits the same
message; a message somebody deleted is re-posted. With `announce_webhook`
set, each lobby opened is a fresh message (`@role 🎮 **name** opened a
ranked lobby (1/4)`), struck through when the lobby closes; `mention` is
what goes in front, typically a role people give themselves to be pinged.
A host name pings at most once per `announce_cooldown` (five minutes);
inside that window a new lobby from the same host edits the struck-through
announcement back to open, with the new lobby's mode and count, and an edit
notifies nobody. All four texts are templates in the
config (`announce_text`, `closed_text`, `empty_text`, `offline_text`), so a
server whose webhook is a character can give it lines; a template with a
field that does not exist is named at startup and the built-in wording is
used.

Discord being down costs nothing: the posting runs on its own thread, a
request that fails is logged once a minute and the next session change
repaints the whole board, a rate limit is waited out, and a webhook that
answers 401 or 403 (a wrong URL) or 404 (deleted on Discord's side; the
pings webhook is checked at start, the board's at its first post) turns the
feature off for the run with one line in the log that says which. Make a
new webhook in the channel's *Integrations*, put its URL in `[discord]` and
restart. A webhook URL is a secret — whoever holds it can post to the
channel — so keep the config file to the operator.

`lobbyboardtest.py` is the feature's own suite: 40 checks against a fake
webhook endpoint in the same process, no Discord needed.

## Checks

Five suites ship with the server. Three start their own server on a spare
port with a scratch data directory, so they can run on an installed copy
without touching its data, and each of those has a `--revert` that runs
against the older behaviour and must fail; the fourth exercises the store
module on a scratch directory, the fifth the Discord board against a fake
webhook endpoint.

```bash
.venv/bin/python -m wow2.lsgauth      # the credential path, 27 checks
.venv/bin/python -m wow2.blocktest    # a block stops all three invites, 7 checks
.venv/bin/python -m wow2.ownertest    # identity, ownership, clans, storage, profiles, UDP, relay and login-table bounds, the create limit, 72 checks
.venv/bin/python -m wow2.storetest    # the SQLite store: the import keeps everything, the rules hold, 33 checks
.venv/bin/python -m wow2.lobbyboardtest   # the Discord board: what it posts, coalescing, Discord down, 43 checks
.venv/bin/python -m wow2.loadtest --consoles 32 --lifetime 200   # capacity, see below
.venv/bin/python -m wow2.dbcli roundtrip DIR   # a directory of JSON stores in and out, field by field
```

## Limits and what has been tested

Everything in the game's Infrastructure mode has been played, not inferred:
two consoles sign in as separate players, host, browse, join, play a full
match through the results and awards screens and into the next one, and the
leaderboards, daily awards, ranked wager and payout, clans, buddies, match
invites, storage, host migration and the relay have each been driven end to
end. A five-console lobby was measured refusing its fifth joiner (the host
does that, over the peer channel). The development rig was eight PPSSPP
instances; retail hardware is one PSP on 6.61 ARK-4 for one evening,
which signed in, browsed, hosted and created ranked lobbies against a server
on a VPS. The US disc (`ULUS10260`, 1.02) was compared against the PAL one
(`ULES00819`, 1.01) it was all derived from: the Demonware SDK, the network
layer and every data table are identical modulo relocation, the eleven code
changes are in the front end, and a US console has hosted for and joined a
PAL console on the emulator rig. Nothing is configured per region.

Every one of the client's 45 lobby RPCs is answered, and the reply layouts
were bisected on the wire against the real client. The parsers have taken
24 million mutated messages without a crash. Two things cannot be produced by
playing and are recorded as such: a drawn match (the game deals a drawn
round again) and the client's UPnP path (needs a real router).

The credential and authorization paths have been checked from the side a
console cannot take, and one outside code review (2026-09-16) has been worked
through; its six real findings, all in the class of a handler trusting a
request field, are fixed and each has a check. It has not had a full
security review, and the sensible assumption is that a second careful
reader finds one or two more of the same kind, none reachable from a retail
console.

Scale was measured with synthetic consoles (`python -m wow2.loadtest`), on a
workstation; a small VPS is slower by its CPU. With 200 accounts on file, 32
consoles signing in at the same instant all finish within 0.2 s and the
process sustains about 2,800 RPCs a second, against a sign-in of some 20
RPCs, a match start of 5 and a signed-in console that is otherwise nearly
silent; with 10,000 accounts on file, 32 finish in 0.5 s and 128 in 2.0 s,
none timing out. (Before the SQLite store the stores were JSON files re-read
per request, and 10,000 lifetime accounts made every sign-in time out; that
is why the store exists.) What remains per request is proportional to the
size of one leaderboard, in milliseconds. One asyncio process, one file on
disk: that is what keeps the stores editable while the server runs.

This repository holds the server alone. The rig that produced it, which
drives the emulator over its debugger protocol and reads the game's screen,
and the reverse-engineering notes are kept separately.
