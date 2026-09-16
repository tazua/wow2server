#!/usr/bin/env python3
"""§65 -- does the server check WHO is asking before it acts? No emulator.

    .venv/bin/python tools/ownertest.py            # the suite
    .venv/bin/python tools/ownertest.py --revert   # the pre-§65 server; the
                                                   # ownership checks must FAIL
    .venv/bin/python tools/ownertest.py --keep     # leave the scratch dir

WHY A SYNTHETIC PEER. Every check here needs a client that does something a
retail console never does: read another account's leaderboard row before its
own, update a session it did not create, invite to a clan it does not
administer, send a datagram that is not a bdNAT packet. `blocktest.py`
already had the peer -- a signed-in LSG connection that can send any service
RPC under the ticket key -- so this borrows it and adds the reply reader.

WHAT THE 2026-09-16 EXTERNAL REVIEW FOUND (reviews/), against the current
code, and what each section proves:

  identity   `Stats op 4` used to LEARN a connection's account id from the
             first entity it asked about, and `account_for()` served that
             ahead of the derivation -- in memory and in `accounts.json`. A
             console reads itself first, so the rig never saw it; anything
             else could name another account's id and be filed as that
             account for every identity-keyed op. The derivation is the only
             source now.
  sessions   `Sessions op 2`/`op 3` took any live session id from any bound
             connection; the ids are sequential and every search reply lists
             them. Host only now. And EVERY TCP close expired every session
             hosted from that address -- another player behind the same
             router signing in took the host's lobby down. The host's own
             LSG connection is what expires it now.
  clans      `Teams op 6` (invite) and `op 25` (cancel) checked that the clan
             existed and nothing about the caller. Administrator or owner
             now, like op 4 has been since Phase 40. The accept's Caccept
             goes to the proposal's inviter, not to whoever the request names.
  storage    `Storage op 1` filed the row and returned the id after the blob
             write had FAILED. An error now, no row.
  udp        the bdNAT endpoint table, the unrecognised-datagram sample ring
             and its per-source files all grew without bound; the relay made
             a Console object for any endpoint that ever spoke and reclaimed
             only mailbox owners; a 29-byte datagram from anywhere naming a
             mailbox port in addrA re-pointed that console's return path.

Standing up a whole server per run is the cheap part (~1 s) and it buys a
data dir nobody else is writing, which is the only way a check can assert on
`teams-db.json` and mean it. The udp/relay checks that need the tables
themselves run in-process against the modules.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import bdproto as bd                                                # noqa: E402
from lsgauth import Peer, bufsize_announce, lsg_connect, login, tiger192  # noqa: E402
from blocktest import (Console as _Console, _rpc, encrypt_rpc,      # noqa: E402
                       req_buddy_invite, req_clan_invite, PASSWORD)

PORT = 3876
ACCOUNTS = ["alice1", "bob222", "carol3"]
CLAN_ID = 0xC1A0C1A0C1A0C1A1
CLAN_NAME = "ownerclan"
ADDR25 = bytes.fromhex("0a000001030c") + b"\x00" * 12 + bytes.fromhex("c0a80101030c") + b"\x01"


# --------------------------------------------------------------- request bodies
def req_stats_read(board: int, entities: list[int]) -> bytes:
    """Stats op 4 -- [u8 0][i32 board][u32 count][u64 entity]..."""
    w = _rpc(4, 4)
    w.i32(board)
    w.u32(len(entities))
    for e in entities:
        w.u64(e)
    return w.getvalue()


def _session_info(w: bd.BdWriter, name: str, sid: bytes | None = None) -> None:
    """The bdMatchMakingInfo the create/update handlers read generically: the
    25-byte address, the session id (update only), the host name, and the
    settings ints (`[1]` roster, `[6]` play mode, `[10]` maxPlayers)."""
    w.blob(ADDR25)
    if sid is not None:
        w.blob(sid)
    w.str_(name, 32)
    for i in range(11):
        w.i32({1: 1, 10: 4}.get(i, 0))


def req_session_create(name: str) -> bytes:
    w = _rpc(5, 1)
    _session_info(w, name)
    return w.getvalue()


def req_session_update(sid: bytes, name: str) -> bytes:
    w = _rpc(5, 2)
    _session_info(w, name, sid)
    return w.getvalue()


def req_session_delete(sid: bytes) -> bytes:
    w = _rpc(5, 3)
    w.blob(sid)
    return w.getvalue()


def req_session_get(sid: bytes) -> bytes:
    w = _rpc(5, 4)
    w.blob(sid)
    return w.getvalue()


def req_clan_cancel(target: int, team_id: int) -> bytes:
    """Teams op 25 -- [u8 0][u64 gamerId][u64 teamId]. Gamer FIRST."""
    w = _rpc(3, 25)
    w.u64(target)
    w.u64(team_id)
    return w.getvalue()


def req_clan_accept(team_id: int, inviter: int) -> bytes:
    """Teams op 8 -- [u8 0][u64 teamId][u64 inviter]."""
    w = _rpc(3, 8)
    w.u64(team_id)
    w.u64(inviter)
    return w.getvalue()


def req_storage_upload(name: str, data: bytes) -> bytes:
    """Storage op 1 -- [u8 0][bool published][str name][bool private][blob]."""
    w = _rpc(10, 1)
    w.bool_(True)
    w.str_(name, 128)
    w.bool_(False)
    w.blob(data)
    return w.getvalue()


# ------------------------------------------------------------------- the peers
def decrypt(frame: bytes, key: bytes) -> bytes | None:
    """The plaintext of an encrypted server frame, or None."""
    from authserver import session_cbc_decrypt, tiger_iv
    if not frame or frame[0] != 1:
        return None
    seed = int.from_bytes(frame[1:5], "little")
    try:
        pt = session_cbc_decrypt(frame[5:], key, tiger_iv(seed))
    except Exception:
        return None
    return pt if struct.unpack_from("<I", pt, 0)[0] == 0xDEADBEEF else None


def task_reply(frames: list, key: bytes):
    """(err, reader positioned at the result count) of the first TaskReply in
    `frames`, or (None, None)."""
    for kind, body in frames:
        pt = decrypt(body, key) if kind == "msg" else None
        if pt is None or pt[4] != 1:
            continue
        r = bd.BdReader(pt[5:])
        r.bitmode = True
        r.read_type_checked_bit()
        r.type_checked = True
        r.u64()                                 # transaction id
        err = r.u32()
        r.u8()                                  # op id
        return err, r
    return None, None


def push_types(frames: list, key: bytes) -> list[int]:
    """The type ids of every push message in `frames`."""
    out = []
    for kind, body in frames:
        pt = decrypt(body, key) if kind == "msg" else None
        if pt is None or pt[4] != 2:
            continue
        r = bd.BdReader(pt[5:])
        r.bitmode = True
        r.read_type_checked_bit()
        r.type_checked = True
        out.append(r.u32())
    return out


class Console(_Console):
    """blocktest's peer, plus the replies."""

    def call(self, payload: bytes, timeout: float = 1.5):
        """Send one RPC; return (err, reader) of its reply -- and keep any push
        that arrived alongside in `self.pushes`."""
        self.seed += 1
        self.p.send(encrypt_rpc(self.key, self.seed, payload))
        frames = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            got = self.p.frames(timeout=0.3)
            if not got:
                if frames:
                    break
                continue
            frames += got
        self.pushes = getattr(self, "pushes", []) + push_types(frames, self.key)
        return task_reply(frames, self.key)

    def drain(self, timeout: float = 0.8) -> list[int]:
        """Push types that arrived since the last call."""
        got = []
        deadline = time.time() + timeout
        while time.time() < deadline:
            f = self.p.frames(timeout=0.2)
            if not f:
                break
            got += f
        self.pushes = getattr(self, "pushes", []) + push_types(got, self.key)
        out, self.pushes = self.pushes, []
        return out


def session_live(c: Console, sid: bytes):
    """(live?, host name) as `Sessions op 4` reports it to `c`."""
    err, r = c.call(req_session_get(sid))
    if r is None:
        return None, None
    n = r.u32()
    if n == 0:
        return False, None
    fields = bd.read_fields(r)
    names = [v for t, v in fields if isinstance(v, str)]
    return True, (names[0] if names else "")


# ------------------------------------------------------------------ the server
class Server:
    """The isolated server, with its log captured in a thread -- the UDP
    checks make it print more than a pipe buffer holds."""

    def __init__(self, tmp: Path, revert: bool):
        env = dict(os.environ,
                   WOW2_PORT=str(PORT),
                   WOW2_DATA_DIR=str(tmp),
                   WOW2_HEXDUMPS="1",           # so the sample-file cap is exercised
                   WOW2_LOG_LEVEL="info",
                   WOW2_SHARED_PASSWORD_FALLBACK="false",
                   WOW2_NO_NAT_TYPE="1",
                   WOW2_NAT_RELAY="0")
        if revert:
            env["WOW2_LEARN_ACCOUNT_ID"] = "1"
            env["WOW2_NO_SESSION_OWNER"] = "1"
            env["WOW2_NO_CLAN_ADMIN_CHECK"] = "1"
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
        except OSError:
            pass
        else:
            raise SystemExit(f"something already listens on 127.0.0.1:{PORT}; "
                             f"stop it first -- the checks would test THAT server")
        self.proc = subprocess.Popen([sys.executable, str(HERE / "authserver.py")],
                                     env=env, stdout=subprocess.PIPE,
                                     stderr=subprocess.STDOUT, text=True, bufsize=1)
        self.lines: list[str] = []
        self._t = threading.Thread(target=self._pump, daemon=True)
        self._t.start()
        for _ in range(100):
            try:
                socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
                return
            except OSError:
                pass
            if self.proc.poll() is not None:
                print("\n".join(self.lines))
                raise SystemExit("server died on startup")
            time.sleep(0.1)
        raise SystemExit("server never listened")

    def _pump(self):
        for line in self.proc.stdout:
            self.lines.append(line.rstrip("\n"))

    def grep(self, pat: str) -> list[str]:
        rx = re.compile(pat)
        return [ln for ln in self.lines if rx.search(ln)]

    def stop(self):
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def seed(tmp: Path) -> None:
    """Three accounts with credentials; a clan alice1 owns with bob222 as an
    ordinary member and carol3 outside it."""
    tmp.mkdir(parents=True, exist_ok=True)
    accounts, names = {}, {}
    for i, a in enumerate(ACCOUNTS):
        ent = int.from_bytes(tiger192(a.encode())[:8], "little")
        accounts[a] = {"pwhash": tiger192(PASSWORD.encode()).hex(),
                       "user_id": 300 + i,
                       "handle": tiger192(a.encode())[:8].hex(),
                       "first_seen": "2026-09-16T00:00:00",
                       "last_seen": "2026-09-16T00:00:00"}
        names[f"{ent:016x}"] = a
    (tmp / "accounts.json").write_text(json.dumps(accounts, indent=2))
    (tmp / "friends-db.json").write_text(json.dumps(
        {"names": names, "friends": [], "invites": [], "blocked": [],
         "messages": []}, indent=2))
    ids = [int.from_bytes(tiger192(a.encode())[:8], "little") for a in ACCOUNTS]
    (tmp / "teams-db.json").write_text(json.dumps(
        {"teams": {f"{CLAN_ID:016x}": {"name": CLAN_NAME,
                                       "owner": f"{ids[0]:016x}",
                                       "members": [f"{ids[0]:016x}", f"{ids[1]:016x}"],
                                       "proposals": []}}},
        indent=2))


def jload(tmp: Path, name: str) -> dict:
    p = tmp / name
    return json.loads(p.read_text()) if p.exists() else {}


def proposals(tmp: Path) -> list:
    return jload(tmp, "teams-db.json")["teams"][f"{CLAN_ID:016x}"].get("proposals", [])


def mail_types(tmp: Path, entity: int) -> list[int]:
    return sorted(m.get("type") for m in jload(tmp, "friends-db.json").get("messages", [])
                  if m.get("to") == f"{entity:016x}")


# ------------------------------------------------------------------- the suite
class Checks:
    def __init__(self):
        self.failed = 0
        self.total = 0

    def __call__(self, ok: bool, what: str, detail: str = "") -> None:
        print(f"{'PASS' if ok else 'FAIL'}  {what}"
              + (f"\n        {detail}" if detail and not ok else ""))
        self.total += 1
        if not ok:
            self.failed += 1


def run_server_checks(tmp: Path, srv: Server, check: Checks) -> None:
    alice = Console("127.0.0.1", PORT, ACCOUNTS[0])
    bob = Console("127.0.0.1", PORT, ACCOUNTS[1])
    carol = Console("127.0.0.1", PORT, ACCOUNTS[2])

    # ------------------------------------------------------------ identity
    print("\n-- identity: bob's FIRST leaderboard read names alice, then bob acts")
    err, r = bob.call(req_stats_read(1, [alice.entity]))
    check(err == 0, "the read itself is served (setup)", f"err={err}")
    bob.call(req_buddy_invite(carol.entity))
    inv = [i for i in jload(tmp, "friends-db.json").get("invites", [])
           if i.get("to") == f"{carol.entity:016x}"]
    check(bool(inv) and inv[0].get("from") == f"{bob.entity:016x}",
          "bob's buddy invite is filed FROM bob, not from the account he read first",
          f"invites: {json.dumps(inv)}")
    row = jload(tmp, "accounts.json").get(ACCOUNTS[1], {})
    check(row.get("account_id") in (None, bob.entity),
          "...and accounts.json did not record alice's id against bob",
          f"row: {json.dumps(row)}")
    check(bool(srv.grep(r"!!!! bob222 asked about account")),
          "...and the server said so (the !!!! line)")
    carol.drain()

    # ------------------------------------------------------------ sessions
    print("\n-- sessions: alice hosts; bob and a stranger's connection try things")
    err, r = alice.call(req_session_create("alice-lobby"))
    n = r.u32() if r is not None else 0
    sid = r.blob() if n else b""
    check(err == 0 and len(sid) == 8, "alice creates a session (setup)",
          f"err={err} n={n}")
    live, host = session_live(carol, sid)
    check(live and host == "alice-lobby", "...which the browser lists under her name (setup)",
          f"live={live} host={host!r}")

    bob.call(req_session_update(sid, "bob-took-it"))
    live, host = session_live(carol, sid)
    check(live and host == "alice-lobby",
          "an UPDATE from a connection that is not the host changes nothing",
          f"live={live} host={host!r}")
    bob.call(req_session_delete(sid))
    live, host = session_live(carol, sid)
    check(bool(live), "a DELETE from a connection that is not the host removes nothing",
          f"live={live}")

    alice.call(req_session_update(sid, "alice-lobby-2"))
    live, host = session_live(carol, sid)
    check(live and host == "alice-lobby-2", "CONTROL: the host's own update is applied",
          f"live={live} host={host!r}")

    # another connection from the SAME address (a second console behind the
    # router signing in): its auth connection opens, is answered, and closes.
    login("127.0.0.1", PORT, ACCOUNTS[2])
    time.sleep(0.5)
    live, host = session_live(carol, sid)
    check(bool(live), "another TCP connection from the same address closing does not expire it",
          f"live={live}")

    alice.close()
    time.sleep(0.6)
    live, host = session_live(carol, sid)
    check(live is False, "CONTROL: the host's LSG connection going away DOES expire it",
          f"live={live}")

    alice = Console("127.0.0.1", PORT, ACCOUNTS[0])
    err, r = alice.call(req_session_create("alice-again"))
    sid2 = r.blob() if r is not None and r.u32() else b""
    alice.call(req_session_delete(sid2))
    live, host = session_live(carol, sid2)
    check(len(sid2) == 8 and live is False, "CONTROL: the host's own delete removes it",
          f"sid={sid2.hex()} live={live}")

    # ------------------------------------------------------------ clans
    print("\n-- clans: alice owns, bob is a member, carol is outside")
    bob.call(req_clan_invite(CLAN_ID, carol.entity))
    check(not proposals(tmp) and 13 not in mail_types(tmp, carol.entity),
          "an ordinary MEMBER cannot file a clan invite",
          f"proposals={proposals(tmp)} carol's mail={mail_types(tmp, carol.entity)}")
    carol.call(req_clan_invite(CLAN_ID, bob.entity))
    check(not proposals(tmp), "a NON-MEMBER cannot file one either",
          f"proposals={proposals(tmp)}")
    alice.call(req_clan_invite(CLAN_ID, carol.entity))
    check(len(proposals(tmp)) == 1 and 13 in mail_types(tmp, carol.entity),
          "CONTROL: the owner's invite is filed and delivered",
          f"proposals={proposals(tmp)} carol's mail={mail_types(tmp, carol.entity)}")
    carol.drain()

    bob.call(req_clan_cancel(carol.entity, CLAN_ID))
    check(len(proposals(tmp)) == 1, "an ordinary member cannot CANCEL the owner's invite",
          f"proposals={proposals(tmp)}")
    alice.call(req_clan_cancel(carol.entity, CLAN_ID))
    check(not proposals(tmp), "CONTROL: the owner cancels it",
          f"proposals={proposals(tmp)}")

    bob.drain()
    carol.call(req_clan_accept(CLAN_ID, bob.entity))       # no proposal on file
    members = jload(tmp, "teams-db.json")["teams"][f"{CLAN_ID:016x}"]["members"]
    check(f"{carol.entity:016x}" not in members and 14 not in bob.drain(),
          "an accept with no proposal admits nobody and notifies nobody",
          f"members={members}")

    alice.call(req_clan_invite(CLAN_ID, carol.entity))
    alice.drain(); bob.drain(); carol.drain()
    carol.call(req_clan_accept(CLAN_ID, bob.entity))       # names bob as the inviter
    to_alice, to_bob = alice.drain(), bob.drain()
    members = jload(tmp, "teams-db.json")["teams"][f"{CLAN_ID:016x}"]["members"]
    check(f"{carol.entity:016x}" in members, "CONTROL: an accept with a proposal admits",
          f"members={members}")
    check(14 in to_alice and 14 not in to_bob,
          "...and the Caccept goes to the account that INVITED, not the one the request names",
          f"pushes: alice={to_alice} bob={to_bob}")

    # ------------------------------------------------------------ storage
    print("\n-- storage: the blob directory cannot be made")
    (tmp / "storage").write_bytes(b"not a directory")
    err, r = alice.call(req_storage_upload("xyzzy.ufd", b"F" * 64))
    rows = jload(tmp, "storage-db.json").get("files", [])
    check(err not in (0, None), "an upload whose blob cannot be written is answered with an error",
          f"err={err}")
    check(not rows, "...and no row is filed for it", f"rows={rows}")
    (tmp / "storage").unlink()
    err, r = alice.call(req_storage_upload("xyzzy.ufd", b"F" * 64))
    fid = r.u64() if r is not None and err == 0 else 0
    rows = jload(tmp, "storage-db.json").get("files", [])
    blob = tmp / "storage" / f"{fid:x}-xyzzy.ufd"
    check(err == 0 and fid and len(rows) == 1 and blob.exists(),
          "CONTROL: with the directory writable the upload is filed and its id returned",
          f"err={err} fid={fid:#x} rows={len(rows)} blob={blob.exists()}")

    # ------------------------------------------------------------ udp
    print("\n-- udp: a flood of datagrams that are not bdNAT, then of forged keepalives")
    files_before = len(list(tmp.glob("udp-unknown-*")))
    socks = []
    for i in range(200):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.sendto(b"\x77" * 40, ("127.0.0.1", PORT))
        socks.append(s)
    time.sleep(1.0)
    files = len(list(tmp.glob("udp-unknown-*"))) - files_before
    printed = len(srv.grep(r"UNRECOGNISED"))
    check(files <= 16, f"200 sources of unrecognised datagrams make at most 16 sample files ({files})")
    check(printed <= 20, f"...and at most 20 full log entries a minute ({printed})")
    keep = bytes([0x0E, 0x02, 0x00]) + bytes(26)
    for s in socks:
        s.sendto(keep, ("127.0.0.1", PORT))
    for i in range(120):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind(("127.0.0.1", 0))
        s.sendto(keep, ("127.0.0.1", PORT))
        socks.append(s)
    time.sleep(1.0)
    known = [int(m.group(1)) for m in
             (re.search(r"now (\d+) known", ln) for ln in srv.grep(r"console registered"))
             if m]
    check(known and max(known) <= 257,
          f"320 forged keepalives leave at most 256 endpoints registered (peak {max(known) if known else '?'})")
    for s in socks:
        s.close()

    for c in (alice, bob, carol):
        c.close()


def run_relay_checks(check: Checks) -> None:
    """In-process: the relay's own tables, no sockets bound."""
    import natrelay
    print("\n-- relay: the console table and who a datagram is attributed to")
    natrelay._log = lambda *_a, **_k: None          # the module's own chatter
    rl = natrelay.Relay()
    rl.enabled = True
    for port in range(40100, 40132):
        mb = natrelay.Mailbox(rl, port)
        rl.mailboxes.append(mb)
        rl.by_port[port] = mb

    for p in range(5000, 5040):
        rl.mailbox_for(("10.9.9.9", p))
    mine = [c for c in rl.consoles.values() if c.key[0] == "10.9.9.9"]
    in_use = sum(1 for mb in rl.mailboxes if mb.owner)
    check(len(mine) <= natrelay.PER_ADDRESS_MAX and in_use <= natrelay.PER_ADDRESS_MAX,
          f"40 endpoints from ONE address hold at most {natrelay.PER_ADDRESS_MAX} mailboxes "
          f"({len(mine)} consoles, {in_use} in use)")

    for i in range(1, 40):
        rl.mailbox_for((f"10.1.0.{i}", 3075))
    in_use = sum(1 for mb in rl.mailboxes if mb.owner)
    check(in_use == 32 and len(rl.consoles) == 32,
          f"a full pool holds 32 consoles and makes none without a mailbox "
          f"({len(rl.consoles)} consoles for {in_use} mailboxes)")

    now = time.time()
    for c in rl.consoles.values():
        c.last = now - natrelay.IDLE_TIMEOUT - 1
    gone = rl.sweep(now)
    check(gone == 32 and not rl.consoles and not any(mb.owner for mb in rl.mailboxes),
          f"the idle sweep forgets every console past the timeout ({gone} forgotten)")

    a = rl.mailbox_for(("10.0.0.1", 3075)).owner
    b = rl.mailbox_for(("10.0.0.2", 3075)).owner
    rl.link(a, b)
    b.seen[a.mailbox.port] = ("10.0.0.2", 3075)
    pkt = (bytes([0x0D, 0x02, 0x00]) + bytes(10) + bytes(4)
           + socket.inet_aton("127.0.0.1") + b.mailbox.port.to_bytes(2, "little")
           + socket.inet_aton("127.0.0.1") + a.mailbox.port.to_bytes(2, "little"))
    who = rl.sender_for(a.mailbox, ("10.0.0.3", 6000), pkt)
    a.mailbox.datagram_received(pkt, ("10.0.0.3", 6000))
    check(who is None and b.seen[a.mailbox.port] == ("10.0.0.2", 3075),
          "a bdNAT-shaped datagram from a THIRD address naming b's mailbox is not "
          "taken for b, and b's return path stays",
          f"who={who} seen={b.seen}")
    who = rl.sender_for(a.mailbox, ("10.0.0.2", 7000), pkt)
    check(who is b, "CONTROL: the same datagram from b's own address (new port: a "
          "symmetric NAT) IS b", f"who={who}")
    a.mailbox.datagram_received(pkt, ("10.0.0.2", 7000))
    check(b.seen[a.mailbox.port] == ("10.0.0.2", 7000),
          "...and moves b's return path to the new port", f"seen={b.seen}")


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--revert", action="store_true",
                    help="WOW2_LEARN_ACCOUNT_ID=1 WOW2_NO_SESSION_OWNER=1 "
                         "WOW2_NO_CLAN_ADMIN_CHECK=1: the identity, session and "
                         "clan checks must FAIL (the storage, udp and relay "
                         "fixes have no switch)")
    ap.add_argument("--keep", action="store_true",
                    help="leave the scratch data dir and print its path")
    ap.add_argument("--no-server", action="store_true",
                    help="only the in-process relay checks")
    a = ap.parse_args()

    check = Checks()
    tmp = Path(tempfile.mkdtemp(prefix="wow2-ownertest-"))
    if not a.no_server:
        seed(tmp)
        srv = Server(tmp, a.revert)
        try:
            run_server_checks(tmp, srv, check)
        finally:
            srv.stop()
    run_relay_checks(check)
    print(f"\n{'REVERTED -- ' if a.revert else ''}"
          f"{check.total - check.failed}/{check.total} checks passed")
    if a.keep:
        print(f"scratch dir kept: {tmp}")
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
