#!/usr/bin/env python3
"""§65 -- does the server check WHO is asking before it acts? No emulator.

    .venv/bin/python tools/ownertest.py            # the suite
    .venv/bin/python tools/ownertest.py --revert   # the pre-§65 server; the
                                                   # ownership checks must FAIL
    .venv/bin/python tools/ownertest.py --keep     # leave the scratch dir
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
from lsgauth import (Peer, bufsize_announce, create_account, lsg_connect,  # noqa: E402
                     login, present, tiger192)
from blocktest import (Console as _Console, _rpc, encrypt_rpc,      # noqa: E402
                       req_buddy_invite, req_clan_invite, PASSWORD)

PORT = 3876
ACCOUNTS = ["alice1", "bob222", "carol3", "dave4"]
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
    settings ints (`[1]` roster, `[6]` play mode, `[10]` maxPlayers).
    """
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


def req_session_search(want: int, start: int = 0) -> bytes:
    """Sessions op 5 -- [u8 0][i32 1][i32 numResults][i32 startIndex]... as the
    browser sends it (the rest of its filters are 'Any').
    """
    w = _rpc(5, 5)
    w.i32(1)
    w.i32(want)
    w.i32(start)
    for v in (0, 0, 0, 0, 0, 0, 0, 0):
        w.i32(v)
    return w.getvalue()


def search_rows(c: Console, want: int, start: int = 0):
    """The host names a search returns to `c`, in reply order."""
    err, r = c.call(req_session_search(want, start))
    if r is None:
        return None
    n = r.u32()
    names = []
    for _ in range(n):
        fields = bd.read_fields(r, limit=30)
        names.append([v for t, v in fields if isinstance(v, str)])
        break
    flat = [v for group in names for v in group]
    return n, flat


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


def req_clan_create(name: str) -> bytes:
    """Teams op 1 -- [u8 0][str name]. The reply is ONE u64, the id, no count."""
    w = _rpc(3, 1)
    w.str_(name, 64)
    return w.getvalue()


def req_clan_pair(op: int, team_id: int, gamer: int) -> bytes:
    """Ops 3 / 26 (promote / demote), 4 (remove), 5 (leave / disband / remove),
    27 (transfer): [u8 0][u64 teamId][u64 gamerId].
    """
    w = _rpc(3, op)
    w.u64(team_id)
    w.u64(gamer)
    return w.getvalue()


def req_clan_noargs(op: int) -> bytes:
    """Ops 20 (my memberships) and 24 (proposals to me): the lead-in only."""
    return _rpc(3, op).getvalue()


def req_clan_members(team_id: int) -> bytes:
    """Teams op 21 -- [u8 0][u64 teamId]."""
    w = _rpc(3, 21)
    w.u64(team_id)
    return w.getvalue()


def memberships(r) -> list[tuple[int, str, int]]:
    """The op 20 rows: [u32 n] then [u64 id][str name][u8 owner]."""
    out = []
    try:
        for _ in range(r.u32() if r is not None else 0):
            out.append((r.u64(), r.str_(64), r.u8()))
    except EOFError:
        pass
    return out


def roster(r) -> dict[int, tuple[bool, int]]:
    """The op 21 rows: [u32 n] then [u64 id][str name][bool owner][u8 rank]."""
    out = {}
    try:
        for _ in range(r.u32() if r is not None else 0):
            eid, _name, owner, rank = r.u64(), r.str_(64), r.bool_(), r.u8()
            out[eid] = (owner, rank)
    except EOFError:
        pass
    return out


def req_storage_upload(name: str, data: bytes) -> bytes:
    """Storage op 1 -- [u8 0][bool published][str name][bool private][blob]."""
    w = _rpc(10, 1)
    w.bool_(True)
    w.str_(name, 128)
    w.bool_(False)
    w.blob(data)
    return w.getvalue()


def req_storage_by_id(op: int, fid: int, data: bytes | None = None) -> bytes:
    """Storage op 2 (overwrite: [u8 0][u64 id][blob]), op 4 (delete) and
    op 5 (fetch): [u8 0][u64 id].
    """
    w = _rpc(10, op)
    w.u64(fid)
    if data is not None:
        w.blob(data)
    return w.getvalue()


def req_storage_list(op: int, owner: int = 0, start: int = 0, count: int = 128) -> bytes:
    """Storage op 7 ([u8 0][u64 owner][u32 start][u16 count]) / op 8 (no owner)."""
    w = _rpc(10, op)
    if op == 7:
        w.u64(owner)
    w.u32(start)
    w.u16(count)
    return w.getvalue()


def storage_rows_of(r) -> dict[int, dict]:
    """The op 7/8 rows by id: [u32 n] then [u32 size][u64 id][u32 created]
    [u32 modified][bool private][bool][u64 owner][str name].
    """
    out = {}
    try:
        for _ in range(r.u32() if r is not None else 0):
            size, fid, created, modified = r.u32(), r.u64(), r.u32(), r.u32()
            private, _b, owner, name = r.bool_(), r.bool_(), r.u64(), r.str_(127)
            out[fid] = {"size": size, "created": created, "modified": modified,
                        "private": private, "owner": owner, "name": name}
    except EOFError:
        pass
    return out


def storage_fetch(r) -> tuple[dict, bytes] | None:
    """The op 5 row: [u32 cap][u64 id][u32][u32][bool][bool][u64 owner][str][blob]."""
    if r is None:
        return None
    try:
        cap, fid, created, modified = r.u32(), r.u64(), r.u32(), r.u32()
        private, _b, owner, name = r.bool_(), r.bool_(), r.u64(), r.str_(127)
        return ({"cap": cap, "id": fid, "created": created, "modified": modified,
                 "owner": owner, "name": name}, r.blob())
    except EOFError:
        return None


PROFILE_FIELDS = [(bd.BD_SINT64, 11), (bd.BD_SINT64, 22), (bd.BD_SINT64, 33),
                  (bd.BD_SINT64, 44), (bd.BD_F64, -15.5), (bd.BD_F64, 62.25),
                  (bd.BD_SINT64, 66), (bd.BD_STR, "hello"), (bd.BD_SINT32, 8)]


def req_profile_write(op: int, fields=PROFILE_FIELDS) -> bytes:
    """Profile op 1 (create) / op 4 (upload): [u8 0] then the nine typed fields."""
    w = _rpc(8, op)
    for t, v in fields:
        if t == bd.BD_SINT64:
            w.i64(v)
        elif t == bd.BD_F64:
            w.f64(v)
        elif t == bd.BD_STR:
            w.str_(v, 64)
        else:
            w.i32(v)
    return w.getvalue()


def req_profile_read(entity: int) -> bytes:
    """Profile op 2 -- [u8 0][u64 entity]. ONE row, no count."""
    w = _rpc(8, 2)
    w.u64(entity)
    return w.getvalue()


def profile_row(r) -> tuple[int, list] | None:
    if r is None:
        return None
    try:
        ent = r.u64()
        return ent, [(t, v) for t, v in bd.read_fields(r)]
    except EOFError:
        return None


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
    `frames`, or (None, None).
    """
    for kind, body in frames:
        pt = decrypt(body, key) if kind == "msg" else None
        if pt is None or pt[4] != 1:
            continue
        r = bd.BdReader(pt[5:])
        r.bitmode = True
        r.read_type_checked_bit()
        r.type_checked = True
        r.u64()
        err = r.u32()
        r.u8()
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
        that arrived alongside in `self.pushes`.
        """
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
    checks make it print more than a pipe buffer holds.
    """

    def __init__(self, tmp: Path, revert: bool):
        env = dict(os.environ,
                   WOW2_PORT=str(PORT),
                   WOW2_DATA_DIR=str(tmp),
                   WOW2_HEXDUMPS="1",
                   WOW2_LOG_LEVEL="info",
                   WOW2_SHARED_PASSWORD_FALLBACK="false",
                   WOW2_NO_NAT_TYPE="1",
                   WOW2_NAT_RELAY="0",
                   WOW2_PROOFS_MAX="50",
                   WOW2_MAX_CREATES_PER_IP_PER_HOUR="3")
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
    ordinary member and carol3 outside it.
    """
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


def store_row(tmp: Path, sql: str, args=()):
    """One row out of the scratch server's own SQLite store (§66). A second
    connection to the file the server has open is what WAL is for.
    """
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        return conn.execute(sql, args).fetchone()
    finally:
        conn.close()


def store_rows(tmp: Path, sql: str, args=()) -> list:
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        return conn.execute(sql, args).fetchall()
    finally:
        conn.close()


def teams_json(tmp: Path) -> dict:
    """The clan store in the JSON file's shape, exported from the scratch
    server's own SQLite store (§66 step 5)."
    """
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        return store.export_teams(conn)
    finally:
        conn.close()


def storage_json(tmp: Path) -> dict:
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        return store.export_storage(conn)
    finally:
        conn.close()


def proposals(tmp: Path) -> list:
    return teams_json(tmp)["teams"][f"{CLAN_ID:016x}"].get("proposals", [])


def friends_json(tmp: Path) -> dict:
    """The social store in the JSON file's shape, exported from the scratch
    server's own SQLite store (§66 step 4)."
    """
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        return store.export_friends(conn)
    finally:
        conn.close()


def clan_mail(tmp: Path, entity: int, team_id: int) -> list[int]:
    """The ids of the mailbox rows that carry THIS clan's invite for `entity`."""
    blob = team_id.to_bytes(8, "little").hex()
    return [m.get("id") for m in friends_json(tmp).get("messages", [])
            if m.get("to") == f"{entity:016x}" and m.get("session") == blob]


def mail_types(tmp: Path, entity: int) -> list[int]:
    return sorted(m.get("type") for m in friends_json(tmp).get("messages", [])
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
    inv = [i for i in friends_json(tmp).get("invites", [])
           if i.get("to") == f"{carol.entity:016x}"]
    check(bool(inv) and inv[0].get("from") == f"{bob.entity:016x}",
          "bob's buddy invite is filed FROM bob, not from the account he read first",
          f"invites: {json.dumps(inv)}")
    row = store_row(tmp, "SELECT name, handle, user_id FROM accounts WHERE name = ?",
                    (ACCOUNTS[1],))
    check(row is not None and row["handle"] == tiger192(ACCOUNTS[1].encode())[:8].hex(),
          "...and the account store still keys bob by his own handle (the schema "
          "has no learned id to record alice's under)",
          f"row: {dict(row) if row else None}")
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

    err, r = alice.call(req_session_create("alice-first"))
    sid_a1 = r.blob() if r is not None and r.u32() else b""
    err, r = alice.call(req_session_create("alice-second"))
    sid_a2 = r.blob() if r is not None and r.u32() else b""
    live1, _ = session_live(carol, sid_a1)
    live2, _ = session_live(carol, sid_a2)
    check(live1 is False and live2 is True,
          "a second create from the same host REPLACES its first session",
          f"first live={live1} second live={live2}")
    bob.call(req_session_create("bob-lobby"))
    carol.call(req_session_create("carol-lobby"))
    got = search_rows(carol, want=2)
    got_all = search_rows(carol, want=25)
    got_page = search_rows(carol, want=2, start=2)
    check(got is not None and got[0] == 2 and got_all[0] == 3 and got_page[0] == 1,
          "a search returns the page the browser asked for (2 of 3, then the 1 left)",
          f"want2={got and got[0]} want25={got_all and got_all[0]} start2={got_page and got_page[0]}")
    check(got_all is not None and got_all[1][:1] == ["carol-lobby"],
          "...newest lobby first", f"first row's strings: {got_all and got_all[1][:2]}")
    for c, sid in ((alice, sid_a2),):
        c.call(req_session_delete(sid))

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
    carol.call(req_clan_accept(CLAN_ID, bob.entity))
    members = teams_json(tmp)["teams"][f"{CLAN_ID:016x}"]["members"]
    check(f"{carol.entity:016x}" not in members and 14 not in bob.drain(),
          "an accept with no proposal admits nobody and notifies nobody",
          f"members={members}")

    alice.call(req_clan_invite(CLAN_ID, carol.entity))
    alice.drain(); bob.drain(); carol.drain()
    carol.call(req_clan_accept(CLAN_ID, bob.entity))
    to_alice, to_bob = alice.drain(), bob.drain()
    members = teams_json(tmp)["teams"][f"{CLAN_ID:016x}"]["members"]
    check(f"{carol.entity:016x}" in members, "CONTROL: an accept with a proposal admits",
          f"members={members}")
    check(14 in to_alice and 14 not in to_bob,
          "...and the Caccept goes to the account that INVITED, not the one the request names",
          f"pushes: alice={to_alice} bob={to_bob}")

    # ------------------------------------------------- the clan lifecycle
    print("\n-- clans: create, roster and ranks, promote, demote, transfer, remove, "
          "leave, disband (the verbs the retail C-cases drive)")
    dave = Console("127.0.0.1", PORT, ACCOUNTS[3])
    alice.drain()
    carol.call(req_clan_pair(5, CLAN_ID, 0))
    members = teams_json(tmp)["teams"][f"{CLAN_ID:016x}"]["members"]
    check(f"{carol.entity:016x}" not in members and 16 in alice.drain(),
          "op 5 with gamer 0 from a member is LEAVE; the owner gets a Cleft",
          f"members={members}")
    dave.drain()
    err, r = carol.call(req_clan_create("newclan"))
    new_id = r.u64() if r is not None and err == 0 else 0
    rec = teams_json(tmp)["teams"].get(f"{new_id:016x}")
    check(err == 0 and new_id and rec and rec["owner"] == f"{carol.entity:016x}"
          and rec["members"] == [f"{carol.entity:016x}"],
          "op 1 creates a clan owned by the caller and returns its id",
          f"err={err} id={new_id:#x} rec={rec}")
    err, r = carol.call(req_clan_noargs(20))
    mine = memberships(r)
    check(any(t == new_id and n == "newclan" and o == 1 for t, n, o in mine),
          "op 20 lists it for the owner with the owner flag", f"rows={mine}")
    carol.call(req_clan_invite(new_id, dave.entity))
    dave.drain()
    dave.call(req_clan_accept(new_id, carol.entity))
    carol.drain()
    err, r = dave.call(req_clan_noargs(20))
    check(sorted(t for t, _n, _o in memberships(r)) == sorted([new_id]),
          "op 20 lists it for the member too", f"rows={memberships(r)}")
    err, r = carol.call(req_clan_members(new_id))
    ros = roster(r)
    check(ros.get(carol.entity) == (True, 2) and ros.get(dave.entity) == (False, 0),
          "op 21: the owner is flagged with rank 2, a member rank 0", f"roster={ros}")
    dave.call(req_clan_pair(3, new_id, carol.entity))
    carol.call(req_clan_pair(3, new_id, dave.entity))
    ros = roster(carol.call(req_clan_members(new_id))[1])
    check(ros.get(dave.entity) == (False, 1) and 17 in dave.drain(),
          "op 3 by the owner promotes to rank 1 and the member gets a Cadmin; "
          "op 3 by a member is refused", f"roster={ros}")
    carol.call(req_clan_pair(26, new_id, dave.entity))
    ros = roster(carol.call(req_clan_members(new_id))[1])
    check(ros.get(dave.entity) == (False, 0) and 39 in dave.drain(),
          "op 26 demotes back to rank 0 with a Cordinary", f"roster={ros}")
    dave.call(req_clan_pair(27, new_id, dave.entity))
    carol.call(req_clan_pair(27, new_id, dave.entity))
    rec = teams_json(tmp)["teams"][f"{new_id:016x}"]
    ros = roster(carol.call(req_clan_members(new_id))[1])
    check(rec["owner"] == f"{dave.entity:016x}" and ros.get(dave.entity) == (True, 2)
          and ros.get(carol.entity) == (False, 0) and 28 in dave.drain(),
          "op 27 by the owner hands the clan over: the new owner is rank 2, the old "
          "one an ordinary member, and a Cowner goes to the new owner", f"rec={rec}")
    carol.call(req_clan_pair(4, new_id, dave.entity))
    rec = teams_json(tmp)["teams"][f"{new_id:016x}"]
    check(len(rec["members"]) == 2, "op 4 by an ordinary member is refused",
          f"members={rec['members']}")
    dave.call(req_clan_pair(4, new_id, carol.entity))
    rec = teams_json(tmp)["teams"][f"{new_id:016x}"]
    check(rec["members"] == [f"{dave.entity:016x}"] and 18 in carol.drain(),
          "op 4 by the owner removes the member, who gets a Ckicked",
          f"members={rec['members']}")
    dave.call(req_clan_invite(new_id, carol.entity))
    carol.drain()
    dave.call(req_clan_pair(5, new_id, 0))
    check(f"{new_id:016x}" not in teams_json(tmp)["teams"]
          and not clan_mail(tmp, carol.entity, new_id),
          "op 5 with gamer 0 from the OWNER disbands the clan and withdraws its "
          "outstanding invite from the invitee's mailbox",
          f"teams={list(teams_json(tmp)['teams'])} carol's rows for the clan="
          f"{clan_mail(tmp, carol.entity, new_id)}")
    dave.drain(); carol.drain(); alice.drain()

    # ------------------------------------------------------------ storage
    print("\n-- storage: the blob directory cannot be made")
    (tmp / "storage").write_bytes(b"not a directory")
    err, r = alice.call(req_storage_upload("xyzzy.ufd", b"F" * 64))
    rows = storage_json(tmp).get("files", [])
    check(err not in (0, None), "an upload whose blob cannot be written is answered with an error",
          f"err={err}")
    check(not rows, "...and no row is filed for it", f"rows={rows}")
    (tmp / "storage").unlink()
    err, r = alice.call(req_storage_upload("xyzzy.ufd", b"F" * 64))
    fid = r.u64() if r is not None and err == 0 else 0
    rows = storage_json(tmp).get("files", [])
    blob = tmp / "storage" / f"{fid:x}-xyzzy.ufd"
    check(err == 0 and fid and len(rows) == 1 and blob.exists(),
          "CONTROL: with the directory writable the upload is filed and its id returned",
          f"err={err} fid={fid:#x} rows={len(rows)} blob={blob.exists()}")

    # ------------------------------------------- storage and profiles round trip
    print("\n-- storage and profiles: the rows and bytes round-trip through the store "
          "(the retail D- and P-cases' server half)")
    listed = storage_rows_of(alice.call(req_storage_list(7, alice.entity))[1])
    row = listed.get(fid)
    check(row is not None and row["size"] == 64 and row["owner"] == alice.entity
          and row["name"] == "xyzzy.ufd" and row["created"] > 1_700_000_000,
          "op 7 lists the upload with its size, owner and a real created time",
          f"row={row}")
    err, r = alice.call(req_storage_by_id(2, fid, b"G" * 96))
    got = storage_fetch(alice.call(req_storage_by_id(5, fid))[1])
    check(err == 0 and got is not None and got[1] == b"G" * 96 and got[0]["cap"] == 96
          and got[0]["id"] == fid and got[0]["modified"] >= got[0]["created"],
          "op 2 replaces the bytes in place; op 5 fetches the row with the new bytes "
          "and the capacity in front", f"err={err} got={got and got[0]}")
    err_b, _ = bob.call(req_storage_by_id(2, fid, b"H" * 8))
    got = storage_fetch(alice.call(req_storage_by_id(5, fid))[1])
    check(got is not None and got[1] == b"G" * 96,
          "op 2 from another account is refused and the bytes stand (D9)",
          f"bytes={got and got[1][:4]}")
    bob.call(req_storage_by_id(4, fid))
    check(fid in storage_rows_of(alice.call(req_storage_list(7, alice.entity))[1]),
          "op 4 from another account removes nothing (D9)")
    alice.call(req_storage_by_id(4, fid))
    listed = storage_rows_of(alice.call(req_storage_list(7, alice.entity))[1])
    got = storage_fetch(alice.call(req_storage_by_id(5, fid))[1])
    check(fid not in listed and got is not None and got[1] == b"" and got[0]["id"] == fid,
          "op 4 by the owner removes the row; a later op 5 for the id is still ONE row, "
          "with an empty blob", f"listed={list(listed)} got={got and got[0]}")

    err, r = carol.call(req_profile_write(1))
    check(err == 0, "a first Profile op 1 (create) is answered 0", f"err={err}")
    carol.call(req_profile_write(4))
    err, r = carol.call(req_profile_write(1))
    check(err == 800, "...and the second answers 800 BD_PROFILE_ALREADY_EXISTS, so the "
                      "console downloads instead of uploading (P1)", f"err={err}")
    got = profile_row(alice.call(req_profile_read(carol.entity))[1])
    check(got is not None and got[0] == carol.entity
          and got[1] == [(t, v) for t, v in PROFILE_FIELDS],
          "op 2 hands back the nine typed fields verbatim (P3's server half)",
          f"got={got}")
    got = profile_row(alice.call(req_profile_read(dave.entity))[1])
    check(got is not None and got[0] == dave.entity and len(got[1]) == 9
          and got[1][7] == (bd.BD_STR, "dave4"),
          "op 2 for an account with no profile is the empty placeholder with the "
          "name in its one string field", f"got={got}")

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
    import authserver
    cap = authserver.NAT_PEERS_MAX
    check(known and max(known) <= cap + 1,
          f"320 forged keepalives register at most NAT_PEERS_MAX={cap} endpoints "
          f"(peak {max(known) if known else '?'})")
    for s in socks:
        s.close()
    now = time.time()
    authserver.NAT_PEERS.clear()
    for i in range(500):
        authserver.NAT_PEERS[("10.7.7.7", 20000 + i)] = now - authserver.NAT_PEER_TTL - 1
    authserver.NAT_PEERS[("10.7.7.8", 3075)] = now
    authserver.nat_peers_sweep(now)
    check(list(authserver.NAT_PEERS) == [("10.7.7.8", 3075)],
          f"...and the sweep drops every endpoint silent for {authserver.NAT_PEER_TTL:.0f} s "
          f"and keeps the live one ({len(authserver.NAT_PEERS)} left)")
    for i in range(cap + 10):
        authserver.NAT_PEERS[("10.7.7.9", i)] = now
    authserver.nat_peers_sweep(now)
    check(len(authserver.NAT_PEERS) == cap,
          f"...and past the cap the oldest go ({len(authserver.NAT_PEERS)} kept)")
    authserver.NAT_PEERS.clear()

    # ------------------------------------------------------------ logins
    print("\n-- logins: a flood of sign-ins for a real account, and what it leaves behind")
    proofs = [login("127.0.0.1", PORT, "alice1")[1] for _ in range(80)]
    closed, replies = present("127.0.0.1", PORT, proofs[0])
    check(closed and not replies,
          "after 80 logins with WOW2_PROOFS_MAX=50 the FIRST handle is gone: "
          "presenting it is refused")
    closed, replies = present("127.0.0.1", PORT, proofs[-1])
    check(bool(replies) and not closed,
          "...and the LAST one still signs in (provisional bind)")
    now = time.time()
    authserver.ISSUED_SESSION_KEYS.clear()
    authserver.PROOF_HANDLES.clear()
    for i in range(300):
        k = i.to_bytes(24, "little")
        authserver.ISSUED_SESSION_KEYS[k, "alice1"] = now - authserver.PROOF_TTL - 1
        authserver.PROOF_HANDLES[k] = ("alice1", k, now - authserver.PROOF_TTL - 1)
    live = b"\xaa" * 24
    authserver.ISSUED_SESSION_KEYS[live, "alice1"] = now
    authserver.PROOF_HANDLES[live] = ("alice1", live, now)
    authserver.proofs_sweep(now, force=True)
    check(list(authserver.ISSUED_SESSION_KEYS) == [(live, "alice1")]
          and list(authserver.PROOF_HANDLES) == [live],
          f"the sweep drops every key and handle older than PROOF_TTL "
          f"({authserver.PROOF_TTL:.0f} s) and keeps the live pair")
    check(authserver.session_key_is_ours("alice1", live)
          and not authserver.session_key_is_ours("bob222", live),
          "...and a live key is ours only for the account it was issued to")
    authserver.ISSUED_SESSION_KEYS[live, "alice1"] = now - authserver.PROOF_TTL - 1
    check(not authserver.session_key_is_ours("alice1", live),
          "...and an expired key is refused at the bind even before a sweep")
    cap = authserver.PROOFS_MAX
    for i in range(cap + 10):
        authserver.PROOF_HANDLES[i.to_bytes(24, "big")] = ("alice1", live, now)
    authserver.proofs_sweep(now, force=True)
    check(len(authserver.PROOF_HANDLES) == cap
          and (cap + 9).to_bytes(24, "big") in authserver.PROOF_HANDLES,
          f"past PROOFS_MAX={cap} the oldest handles go and the newest stay")
    authserver.ISSUED_SESSION_KEYS.clear()
    authserver.PROOF_HANDLES.clear()

    # ------------------------------------------------------------ creates
    print("\n-- creates: one address registering names by script")
    codes = [create_account("127.0.0.1", PORT, f"squat0{i}", PASSWORD) for i in range(1, 5)]
    check(codes == [700, 700, 700, 710],
          "with WOW2_MAX_CREATES_PER_IP_PER_HOUR=3 the fourth create in an hour is "
          "answered 710 (the client draws 'Unable to create online profile')",
          f"codes={codes}")
    names = {r[0] for r in store_rows(tmp, "SELECT name FROM accounts WHERE name LIKE 'squat%'")}
    check(names == {"squat01", "squat02", "squat03"},
          "...and the store holds the three that were allowed", f"names={sorted(names)}")
    code = create_account("127.0.0.1", PORT, "alice1", PASSWORD)
    check(code == 707,
          "...while a create for a name that already has a credential is still 707, "
          "so the limit never blocks the sign-in it re-issues as", f"code={code}")
    now = time.time()
    authserver.CREATES_PER_IP.clear()
    authserver.serverconfig.MAX_CREATES_PER_IP_PER_HOUR = 3
    authserver.CREATES_PER_IP["10.9.9.9"] = [now - 3599, now - 1800, now - 10]
    check(not authserver.create_allowed("10.9.9.9", now)
          and authserver.create_allowed("10.9.9.9", now + 2),
          "in-process: three creates inside the hour refuse a fourth; the oldest "
          "leaving the window allows it")
    authserver.CREATES_PER_IP.clear()
    for i in range(authserver.CREATES_ADDRESSES_MAX + 5):
        authserver.CREATES_PER_IP[f"10.0.{i >> 8}.{i & 255}"] = [now - 3700]
    authserver.create_allowed("10.255.255.255", now)
    check(len(authserver.CREATES_PER_IP) == 1,
          f"...and past {authserver.CREATES_ADDRESSES_MAX} addresses the ones with "
          f"nothing inside the hour are dropped ({len(authserver.CREATES_PER_IP)} kept)")
    authserver.serverconfig.MAX_CREATES_PER_IP_PER_HOUR = 0
    check(authserver.create_allowed("10.9.9.9", now) and not authserver.CREATES_PER_IP.get("10.9.9.9"),
          "...and 0 turns the limit off without counting")
    authserver.CREATES_PER_IP.clear()

    for c in (alice, bob, carol):
        c.close()


def run_search_relay_checks(check: Checks) -> None:
    """In-process: the address a search reply hands a joiner when the relay
    carries the match and several consoles share one public IP (§71c)."""
    import authserver
    import natrelay
    print("\n-- search: the host's relay address when three consoles share one public IP")
    rl = natrelay.RELAY
    was_enabled, was_log = rl.enabled, natrelay._log
    natrelay._log = lambda *_a, **_k: None
    rl.enabled = True
    for port in range(40200, 40208):
        mb = natrelay.Mailbox(rl, port)
        rl.mailboxes.append(mb)
        rl.by_port[port] = mb
    ip = "91.0.0.1"
    consoles = [rl.mailbox_for((ip, p)).owner for p in (3074, 61256, 46927)]
    host = consoles[1]
    ours = authserver.server_address_for(ip)
    blob = (socket.inet_aton("10.42.0.2") + (3074).to_bytes(2, "little") + bytes(12)
            + socket.inet_aton(ours) + host.mailbox.port.to_bytes(2, "little") + b"\x01")
    rec = {"id": 0x5705, "host_ip": ip, "secret": b"WOW2SESS" + bytes(8),
           "info": [(bd.BD_BLOB, bytes(8)), (bd.BD_BLOB, bytes(16)), (bd.BD_BLOB, blob),
                    (bd.BD_STR, "testuser")]}
    got = authserver.relay_endpoint_for_host(rec, ip)
    check(got == (ours, host.mailbox.port),
          f"the host is found by the public part of its own address, the mailbox our "
          f"discovery reply gave it, not guessed among the three from its IP (got {got})")
    out = [v for t, v in authserver.info_with_session_id(rec, ip) if isinstance(v, bytes) and len(v) == 25][0]
    check(out[0:4] == out[18:22] == socket.inet_aton(ours)
          and int.from_bytes(out[22:24], "little") == host.mailbox.port,
          "...and the joiner is handed SERVER:mailbox in both endpoints, never its own "
          "public IP with the mailbox port")
    other = rl.mailbox_for(("91.0.0.2", 5000)).owner
    forged = blob[:18] + socket.inet_aton(ours) + other.mailbox.port.to_bytes(2, "little") + b"\x01"
    got = authserver.relay_endpoint_for_host({**rec, "info": [(bd.BD_BLOB, forged)]}, ip)
    check(got is None,
          "a host naming ANOTHER address's mailbox as its own is not matched to it "
          "(and three consoles on its IP leave nothing to guess)")
    for c in list(rl.consoles.values()):
        rl.forget(c)
    rl.consoles.clear()
    for port in range(40200, 40208):
        mb = rl.by_port.pop(port)
        rl.mailboxes.remove(mb)
    rl.enabled, natrelay._log = was_enabled, was_log


def run_relay_checks(check: Checks) -> None:
    """In-process: the relay's own tables, no sockets bound."""
    import natrelay
    print("\n-- relay: the console table and who a datagram is attributed to")
    natrelay._log = lambda *_a, **_k: None
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
    run_search_relay_checks(check)
    print(f"\n{'REVERTED -- ' if a.revert else ''}"
          f"{check.total - check.failed}/{check.total} checks passed")
    if a.keep:
        print(f"scratch dir kept: {tmp}")
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
