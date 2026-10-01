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
                     login, login_request, present, tiger192)
from blocktest import (Console as _Console, _rpc, encrypt_rpc,      # noqa: E402
                       req_buddy_invite, req_clan_invite, req_match_invite, PASSWORD)

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


def req_stats_write(board: int, entity: int, score: int) -> bytes:
    """Stats op 1 -- [u8 0][u8 0][i32 board][u64 entity][i64 score][i32][i64][i64]."""
    w = _rpc(4, 1)
    w.u8(0)
    w.i32(board)
    w.u64(entity)
    w.i64(score)
    w.i32(0)
    w.i64(0)
    w.i64(0)
    return w.getvalue()


def stats_score(c, board: int, entity: int) -> int | None:
    """The score `c` is served for `entity` on `board` (Stats op 4)."""
    err, r = c.call(req_stats_read(board, [entity]))
    if r is None or not r.u32():
        return None
    r.u32()
    r.u64()
    return r.i64()


def _session_info(w: bd.BdWriter, name: str, sid: bytes | None = None,
                  points: int = 0) -> None:
    """The bdMatchMakingInfo the way a console sends it (§80g): the 25-byte
    address, the 8-byte session id and 16-byte key (garbage on a create), nine
    ints, the host name, five ints, four i64s, the name again and an int. Of the
    fifteen ints, `[1]` is the roster, `[6]` the play mode, `[10]` maxPlayers.
    """
    w.blob(ADDR25)
    w.blob(sid if sid is not None else bytes(8))
    w.blob(bytes(16))
    for v in (0, 1, 0, 0, 0, 0, points, 0, 0):
        w.i32(v)
    w.str_(name, 64)
    for v in (0, 4, 0, 0, 0):
        w.i32(v)
    for _ in range(4):
        w.i64(0)
    w.str_(name, 64)
    w.i32(0)


def req_session_create_short(name: str) -> bytes:
    """The create this suite used to send: thirteen fields, not a console's 24."""
    w = _rpc(5, 1)
    w.blob(ADDR25)
    w.str_(name, 32)
    for i in range(11):
        w.i32({1: 1, 10: 4}.get(i, 0))
    return w.getvalue()


def req_session_create(name: str, points: int = 0) -> bytes:
    w = _rpc(5, 1)
    _session_info(w, name, points=points)
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
    """(rows, the host name of each) a search returns to `c`, in reply order."""
    err, r = c.call(req_session_search(want, start))
    if r is None:
        return None
    n = r.u32()
    names = []
    for _ in range(n):
        fields = bd.read_fields(r, limit=24)
        names.append(next((v for t, v in fields if isinstance(v, str)), ""))
    return n, names


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


def req_stats_page(board: int, pivot: int, start_rank: int, count: int) -> bytes:
    """Stats op 5 -- [u8 0][i32 board][u64 pivot][u64 start rank][i64 count]."""
    w = _rpc(4, 5)
    w.i32(board)
    w.u64(pivot)
    w.u64(start_rank)
    w.i64(count)
    return w.getvalue()


def req_message_delete(mid: int) -> bytes:
    """Messaging op 4 -- [u8 0][u64 message id]."""
    w = _rpc(6, 4)
    w.u64(mid)
    return w.getvalue()


def req_storage_upload(name: str, data: bytes, private: bool = False) -> bytes:
    """Storage op 1 -- [u8 0][bool published][str name][bool private][blob]."""
    w = _rpc(10, 1)
    w.bool_(True)
    w.str_(name, 128)
    w.bool_(private)
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
                   WOW2_MAX_CREATES_PER_IP_PER_HOUR="3",
                   WOW2_MAX_FILES_PER_ACCOUNT="4",
                   WOW2_MAX_STORAGE_MB="1")
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


def store_exec(tmp: Path, sql: str, args=()) -> None:
    import store
    conn = store.connect(tmp / store.DB_NAME)
    try:
        conn.execute(sql, args)
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
    carol.call(req_clan_accept(new_id, dave.entity))
    dave.call(req_clan_pair(3, new_id, carol.entity))
    dave.drain(); carol.drain()
    carol.call(req_clan_pair(4, new_id, dave.entity))
    carol.call(req_clan_pair(5, new_id, dave.entity))
    dave.call(req_clan_pair(4, new_id, dave.entity))
    rec = teams_json(tmp)["teams"][f"{new_id:016x}"]
    check(rec["owner"] == f"{dave.entity:016x}" and f"{dave.entity:016x}" in rec["members"]
          and 18 not in dave.drain(),
          "nobody removes the clan's OWNER: not an administrator by op 4 or op 5, "
          "not the owner itself (§80v)", f"rec={rec}")
    dave.call(req_clan_pair(4, new_id, carol.entity))
    rec = teams_json(tmp)["teams"][f"{new_id:016x}"]
    check(f"{carol.entity:016x}" not in rec["members"] and 18 in carol.drain(),
          "CONTROL: the owner removes an administrator", f"members={rec['members']}")
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
    run_storage_checks(tmp, check, alice, bob, dave)

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

    # ------------------------------------------------------------ shapes
    print("\n-- shapes: what is replayed to other consoles has the shape a console sends")
    err, r = carol.call(req_session_create_short("carol-short"))
    names = search_rows(bob, want=25)[1]
    check(err == 106 and "carol-short" not in names,
          "a session create that is not the 24 fields a console sends is answered "
          "106 (BD_PARAM_PARSE_ERROR) and never reaches a browser",
          f"err={err} listed={names}")
    err, r = carol.call(req_session_create("carol-shaped"))
    sid_c = r.blob() if r is not None and r.u32() else b""
    live, host = session_live(bob, sid_c)
    check(err == 0 and live and host == "carol-shaped",
          "CONTROL: the same create in a console's shape is listed", f"err={err} live={live}")
    w = _rpc(5, 2)
    w.blob(sid_c)
    w.str_("carol-garbage", 32)
    carol.call(w.getvalue())
    live, host = session_live(bob, sid_c)
    check(live and host == "carol-shaped",
          "an update in another shape is ignored and the record stays as it was",
          f"host={host!r}")
    carol.call(req_session_delete(sid_c))
    err, _r = carol.call(req_profile_write(4, PROFILE_FIELDS[:3]))
    err2, r = bob.call(req_profile_read(carol.entity))
    row = profile_row(r) if r is not None else None
    check(err == 106 and row is not None and len(row[1]) == 9,
          "a profile upload of three fields is answered 106 and a viewer is still "
          "served nine", f"err={err} row={row}")

    # ------------------------------------------------------------ scores
    print("\n-- scores: a console writes its own rows, and its own clan's")
    mine = stats_score(carol, 5, bob.entity) or 0
    bob.call(req_stats_write(5, 0, mine - 7))
    check(stats_score(carol, 5, bob.entity) == mine - 7,
          "CONTROL: bob's upload for himself (entity 0, as a console sends it) is stored")
    before = stats_score(carol, 5, alice.entity)
    bob.call(req_stats_write(5, alice.entity, 10))
    after = stats_score(carol, 5, alice.entity)
    check(after == before and not store_rows(
              tmp, "SELECT name FROM stats WHERE board = 5 AND entity = ? AND name = ?",
              (f"{alice.entity:016x}", ACCOUNTS[1])),
          "an upload from bob naming alice's account changes neither her score nor "
          "the name on her row", f"before={before} after={after}")
    carol.call(req_stats_write(30, CLAN_ID, 123456))
    check(stats_score(bob, 30, CLAN_ID) != 123456,
          "carol (in no clan) uploading for alice's clan is not stored")
    bob.call(req_stats_write(30, CLAN_ID, 4242))
    check(stats_score(carol, 30, CLAN_ID) == 4242,
          "CONTROL: bob, a member, uploading for his own clan is stored")
    bob.call(req_stats_write(4242, 0, 9))
    check(not store_rows(tmp, "SELECT * FROM stats WHERE board = 4242"),
          "a board no console writes is not stored")

    # ------------------------------------------------------------ the push route
    print("\n-- the push route: a login that names alice is not alice's connection")
    dave = Console("127.0.0.1", PORT, ACCOUNTS[3])
    alice.drain()
    err, r = alice.call(req_session_create("alice-held"))
    sid_h = r.blob() if r is not None and r.u32() else b""
    imp = Peer("127.0.0.1", PORT)
    imp.send(login_request(tiger192(ACCOUNTS[0].encode())[:8]))
    imp.frames(timeout=2.0)
    imp.send(bufsize_announce())
    time.sleep(0.3)
    dave.call(req_buddy_invite(alice.entity))
    to_alice = alice.drain()
    to_imp = imp.frames(timeout=0.8)
    check(bool(to_alice) and not to_imp,
          "a push for alice reaches alice's own connection, not one that sent a "
          "login naming her (which needs no password) and a BUFSIZE",
          f"to alice={to_alice} to the other connection={len(to_imp)} frame(s)")
    imp.close()
    time.sleep(0.6)
    live, _ = session_live(carol, sid_h)
    check(len(sid_h) == 8 and live is True,
          "...and that connection closing leaves alice's session live",
          f"sid={sid_h.hex()} live={live}")
    alice.call(req_session_delete(sid_h))

    run_range_checks(tmp, check, alice)
    run_pot_checks(tmp, check, alice, bob, carol, dave)
    run_invite_checks(tmp, check, alice, bob, carol, dave)
    run_answer_checks(tmp, check, bob, carol, dave)
    dave.close()

    for c in (alice, bob, carol):
        c.close()


def mail_rows(tmp: Path, to: int, type_id: int | None = None, sender: int | None = None) -> list:
    return [m for m in friends_json(tmp).get("messages", [])
            if m.get("to") == f"{to:016x}"
            and (type_id is None or m.get("type") == type_id)
            and (sender is None or m.get("from") == f"{sender:016x}")]


def run_invite_checks(tmp: Path, check: Checks, alice, bob, carol, dave) -> None:
    print("\n-- invites: a mailbox row per invite, not per call (§80m)")
    carol.drain()
    lobby = (0x5799).to_bytes(8, "little")
    for _ in range(30):
        alice.call(req_match_invite(carol.entity, lobby))
    rows = mail_rows(tmp, carol.entity, 5, alice.entity)
    check(len(rows) == 1,
          "thirty match invites from alice to carol for one lobby file one mailbox row",
          f"{len(rows)} rows")
    for i in range(20):
        alice.call(req_match_invite(carol.entity, (0x5800 + i).to_bytes(8, "little")))
    rows = mail_rows(tmp, carol.entity, 5, alice.entity)
    check(len(rows) == 1 and rows[0].get("session") == (0x5813).to_bytes(8, "little").hex(),
          "...and twenty lobbies one after another leave one row, the newest",
          f"{len(rows)} rows")
    pushed = carol.drain(1.5).count(5)
    check(pushed <= 2,
          f"...and carol, online, was pushed {pushed} of those fifty, not fifty")
    bob.call(req_match_invite(carol.entity, lobby))
    check(len(mail_rows(tmp, carol.entity, 5, bob.entity)) == 1,
          "CONTROL: bob's invite to carol is a row of its own")

    err, r = dave.call(req_clan_create("invclan"))
    tid = r.u64() if r is not None else 0
    for _ in range(20):
        dave.call(req_clan_invite(tid, carol.entity))
    rows = clan_mail(tmp, carol.entity, tid)
    pushed = carol.drain(1.5).count(13)
    check(tid and len(rows) == 1 and pushed == 1,
          "twenty clan invites from dave to carol file one row and push once",
          f"clan 0x{tid:x}: {len(rows)} rows, {pushed} pushes")
    dave.call(req_clan_pair(5, tid, 0))

    import store
    store.startup(log=lambda *_a, **_k: None, stores=(), data_dir=tmp, import_files=False)
    with store.tx() as conn:
        first = int(store.meta_get(conn, "next_msg", "1"))
        for i in range(30):
            conn.execute("INSERT INTO messages (id, to_e, type, from_e, from_name, session, "
                         "clan, at) VALUES (?, ?, 1, ?, ?, '', '', ?)",
                         (first + i, f"{bob.entity:016x}", f"{0xF00D0000 + i:016x}",
                          f"stranger{i}", store.now_iso()))
        store.meta_set(conn, "next_msg", str(first + 30))
    store.close()
    alice.call(req_match_invite(bob.entity, lobby))
    rows = mail_rows(tmp, bob.entity)
    check(len(rows) == 25 and any(m.get("from") == f"{alice.entity:016x}" for m in rows),
          "a mailbox holding thirty takes alice's invite and keeps the 25 newest, "
          "which is what a console reads at sign-in", f"{len(rows)} rows")


def run_storage_checks(tmp: Path, check: Checks, alice, bob, dave) -> None:
    print("\n-- storage: names, the caps, ids, private files, the server's files (§80o)")

    def held(c) -> list:
        return [f.get("name") for f in storage_json(tmp).get("files", [])
                if f.get("owner") == f"{c.entity:016x}"]

    def upload(c, name, data, private=False) -> tuple[int, int]:
        err, r = c.call(req_storage_upload(name, data, private))
        return err, (r.u64() if r is not None and err == 0 else 0)

    errs = [upload(dave, n, b"N" * 16)[0] for n in ("bad\x01.ss0", "../up.ufd", "")]
    check(errs == [1001] * 3 and not held(dave),
          "a name no console sends -- a control character, a path, an empty one -- is "
          "answered 1001 and files nothing", f"errs={errs} rows={held(dave)}")

    fids = [upload(dave, f"dav{i}cc.ss{i}", b"S" * 32)[1] for i in range(4)]
    err, _ = upload(dave, "dav4cc.ss4", b"S" * 32)
    check(all(fids) and err == 1002 and len(held(dave)) == 4,
          "with WOW2_MAX_FILES_PER_ACCOUNT=4 dave's fifth file is answered 1002 and "
          "not filed", f"fids={fids} err={err} rows={held(dave)}")
    err, again = upload(dave, "dav0cc.ss0", b"T" * 40)
    check(err == 0 and again == fids[0],
          "...while a name dave already holds is still replaced in place",
          f"err={err} id={again:#x}")
    dave.call(req_storage_by_id(4, fids[3]))
    err, new = upload(dave, "dav4cc.ss4", b"S" * 32)
    check(err == 0 and new and "dav4cc.ss4" in held(dave),
          "CONTROL: once dave deletes one, the fifth is filed", f"err={err}")

    err, first = upload(alice, "reuse1.ss0", b"R" * 8)
    alice.call(req_storage_by_id(4, first))
    err, second = upload(alice, "reuse2.ss0", b"R" * 8)
    check(first and second and second != first,
          "a deleted file's id is not handed out again (a console may still hold it)",
          f"first={first:#x} second={second:#x}")
    blob = tmp / "storage" / f"{second:x}-reuse2.ss0"
    store_exec(tmp, "INSERT INTO storage (id, name, owner, file, private, size) "
               "VALUES (?, 'twin.ss1', ?, ?, 0, 8)",
               (0x7a00, f"{alice.entity:016x}", blob.name))
    alice.call(req_storage_by_id(4, second))
    kept = blob.exists()
    alice.call(req_storage_by_id(4, 0x7a00))
    check(kept and not blob.exists(),
          "op 4 deletes a file's bytes once no row names them, and not before",
          f"kept while the twin named it={kept}, after both={blob.exists()}")

    err, priv = upload(alice, "priv1.ss0", b"P" * 24, private=True)
    seen = storage_rows_of(bob.call(req_storage_list(7, alice.entity))[1])
    got = storage_fetch(bob.call(req_storage_by_id(5, priv))[1])
    check(priv and priv not in seen and got is not None and got[1] == b""
          and got[0]["owner"] == 0,
          "alice's private file is in neither bob's list of her files nor his fetch "
          "by id", f"listed={priv in seen} fetched={got and got[1][:4]}")
    mine = storage_rows_of(alice.call(req_storage_list(7, alice.entity))[1])
    got = storage_fetch(alice.call(req_storage_by_id(5, priv))[1])
    check(priv in mine and got is not None and got[1] == b"P" * 24,
          "CONTROL: alice lists and fetches it")

    (tmp / "storage" / "7b00-readme.txt").write_bytes(b"hello")
    store_exec(tmp, "INSERT INTO storage (id, name, owner, file, private, size) "
               "VALUES (?, 'readme.txt', NULL, '7b00-readme.txt', 0, 5)", (0x7b00,))
    bob.call(req_storage_by_id(2, 0x7b00, b"pwned"))
    bob.call(req_storage_by_id(4, 0x7b00))
    got = storage_fetch(alice.call(req_storage_by_id(5, 0x7b00))[1])
    check(got is not None and got[1] == b"hello",
          "the server's own file (no owner) can be neither overwritten nor deleted "
          "by a console", f"bytes={got and got[1]}")

    store_exec(tmp, "INSERT INTO storage (id, name, owner, file, private, size) "
               "VALUES (?, 'big.bin', ?, NULL, 0, ?)",
               (0x7c00, f"{0xB16:016x}", 1024 * 1024 - 1000))
    time.sleep(1.1)
    err, _ = upload(bob, "big1cc.ss0", b"B" * 4000)
    check(err == 1002 and not held(bob),
          "with WOW2_MAX_STORAGE_MB=1 and the server nearly full, bob's 4 KB is "
          "answered 1002 and not filed", f"err={err} rows={held(bob)}")
    store_exec(tmp, "DELETE FROM storage WHERE id = ?", (0x7c00,))
    time.sleep(1.1)
    err, _ = upload(bob, "big1cc.ss0", b"B" * 4000)
    check(err == 0 and held(bob) == ["big1cc.ss0"],
          "CONTROL: with room again it is filed", f"err={err}")


def req_buddy_answer(op: int, inviter: int) -> bytes:
    """Friends op 2 (accept) / op 3 (decline) -- [u8 0][u64 the inviter]."""
    w = _rpc(9, op)
    w.u64(inviter)
    return w.getvalue()


def buddies(tmp: Path, a: int, b: int) -> bool:
    return sorted((f"{a:016x}", f"{b:016x}")) in friends_json(tmp).get("friends", [])


def run_range_checks(tmp: Path, check: Checks, c) -> None:
    print("\n-- an id or a rank past 2^63 is one no row has (§80af)")
    big = (1 << 63, (1 << 64) - 1)

    def rows(err, r):
        return r.u32() if r is not None and err == 0 else None

    c.call(req_stats_write(20, c.entity, 7))
    n = rows(*c.call(req_stats_page(20, 0, 1, 10)))
    check(bool(n), "CONTROL: a page of board 20 from rank 1 is served", f"rows={n}")
    got = [rows(*c.call(req_stats_page(20, 0, v, 10))) for v in big]
    check(got == [0, 0], "Stats op 5 from rank 2^63 and 2^64-1 is answered with an empty "
          "page, as any rank past the board's end (it raised, and nothing was sent)",
          f"rows={got}")
    before = len(friends_json(tmp).get("messages", []))
    errs = [c.call(req_message_delete(v))[0] for v in big]
    check(errs == [0, 0] and len(friends_json(tmp).get("messages", [])) == before,
          "Messaging op 4 for message 2^63 and 2^64-1 is answered and deletes nothing",
          f"errs={errs}")
    got = []
    for v in big:
        err, r = c.call(req_storage_by_id(5, v))
        got.append(r.u32() if r is not None and err == 0 else None)
    check(got == [0, 0], "Storage op 5 for file 2^63 and 2^64-1 is answered as no such file",
          f"sizes={got}")
    files = len(storage_json(tmp).get("files", []))
    errs = [c.call(req_storage_by_id(op, v, b"X" * 8 if op == 2 else None))[0]
            for op in (2, 4) for v in big]
    check(errs == [0] * 4 and len(storage_json(tmp).get("files", [])) == files,
          "Storage op 2 and op 4 for those ids are answered and change nothing",
          f"errs={errs}")
    n = rows(*c.call(req_stats_page(20, 0, 1, 10)))
    check(bool(n), "CONTROL: the same connection is still served afterwards", f"rows={n}")


def run_answer_checks(tmp: Path, check: Checks, bob, carol, dave) -> None:
    print("\n-- buddies: an answer needs an invite (§80n)")
    for c in (bob, carol, dave):
        c.drain()
    was = buddies(tmp, bob.entity, dave.entity)
    bob.call(req_buddy_answer(2, dave.entity))
    check(not was and not buddies(tmp, bob.entity, dave.entity)
          and 2 not in dave.drain(),
          "bob 'accepting' an invite dave never sent makes nobody his buddy and "
          "tells dave nothing")
    bob.call(req_buddy_answer(3, carol.entity))
    check(3 not in carol.drain(),
          "...and 'declining' one carol never sent tells carol nothing")
    dave.call(req_buddy_invite(bob.entity))
    bob.drain()
    bob.call(req_buddy_answer(2, dave.entity))
    check(buddies(tmp, bob.entity, dave.entity) and 2 in dave.drain(),
          "CONTROL: dave invites bob, bob accepts: buddies, and dave is told")


def pot_doc(tmp: Path, sid: bytes, state: str = "live") -> dict | None:
    """The pot row for a session, live (open or pending) or settled."""
    rows = store_rows(tmp, "SELECT state, doc FROM pots WHERE session = ? ORDER BY seq",
                      (f"{int.from_bytes(sid, 'little'):x}",))
    rows = [r for r in rows if (r["state"] == "settled") == (state == "settled")]
    return json.loads(rows[-1]["doc"]) if rows else None


def stake_of(c, board: int) -> tuple[int, int]:
    """(served, what a console uploads for its stake): max(10, s - s // 10)."""
    served = stats_score(c, board, c.entity) or 0
    return served, max(10, served - served // 10)


def run_pot_checks(tmp: Path, check: Checks, alice, bob, carol, dave) -> None:
    print("\n-- pot: a stake goes into its own match, a payout comes out of its own pot")
    err, r = alice.call(req_session_create("alice-ranked", points=1))
    s1 = r.blob() if r is not None and r.u32() else b""
    err, r = carol.call(req_session_create("carol-ranked", points=1))
    s2 = r.blob() if r is not None and r.u32() else b""
    check(len(s1) == len(s2) == 8, "alice and then carol host a ranked lobby (setup)")
    bob.call(req_session_search(25))
    games = stats_score(alice, 1, alice.entity) or 0
    alice.call(req_stats_write(1, 0, games + 1))
    stakes = {}
    for c in (alice, bob):
        served, after = stake_of(c, 2)
        c.call(req_stats_write(2, 0, after))
        stakes[(c.account, 2)] = served - after
    for c in (alice, bob):
        served, after = stake_of(c, 5)
        c.call(req_stats_write(5, 0, after))
        stakes[(c.account, 5)] = served - after
    pot1, pot2 = pot_doc(tmp, s1) or {}, pot_doc(tmp, s2) or {}
    staked = set(pot1.get("stakes", {}))
    check(staked == {f"{alice.entity:016x}", f"{bob.entity:016x}"}
          and not pot2.get("stakes"),
          "alice's match started; her stake and bob's (who was shown it) go into "
          "HER lobby's pot, not the newer ranked lobby carol hosts",
          f"alice's pot {sorted(staked)}, carol's {sorted(pot2.get('stakes', {}))}")
    side = sum(v for (n, b), v in stakes.items() if b == 2)
    rating = sum(v for (n, b), v in stakes.items() if b == 5)

    weekly = stats_score(carol, 2, bob.entity) or 0
    bob.call(req_stats_write(2, 0, weekly + side + 100))
    check(stats_score(carol, 2, bob.entity) == weekly + side,
          f"bob's Weekly payout of {side + 100} out of a Weekly pot of {side} stores "
          f"the pot and no more", f"stored {stats_score(carol, 2, bob.entity)}")
    bob.call(req_stats_write(2, 0, weekly + 2 * side))
    check(stats_score(carol, 2, bob.entity) == weekly + side,
          "...and the same pot cannot be paid on Weekly twice")
    before = stats_score(carol, 5, bob.entity) or 0
    bob.call(req_stats_write(5, 0, before + rating + 500))
    check(stats_score(carol, 5, bob.entity) == before + rating,
          f"bob's payout of {rating + 500} out of a pot of {rating} stores the pot "
          f"and no more", f"stored {stats_score(carol, 5, bob.entity)}")
    check((pot_doc(tmp, s1, "settled") or {}).get("settled") == "client",
          "...and settles alice's lobby's pot as the client's payout")
    bob.call(req_stats_write(5, 0, before + 2 * rating))
    check(stats_score(carol, 5, bob.entity) == before + rating,
          "a second payout from the same pot is not stored")
    rich = stats_score(carol, 5, dave.entity) or 0
    dave.call(req_stats_write(5, 0, rich + 100000))
    check(stats_score(carol, 5, dave.entity) == rich,
          "dave, in no match, raising his own rating by 100,000 is not stored")
    dave.call(req_stats_write(5, 0, rich - 1))
    check(stats_score(carol, 5, dave.entity) == rich - 1,
          "CONTROL: dave lowering his own rating is his own business, and stored")

    alice.call(req_stats_write(1, 0, games + 1))
    alice.call(req_stats_write(1, 0, games + 2))
    served, after = stake_of(bob, 3)
    bob.call(req_stats_write(3, 0, after))
    side3 = ((pot_doc(tmp, s1) or {}).get("stakes", {})
             .get(f"{bob.entity:016x}", {}).get("boards", {}).get("3", {}))
    check(side3.get("stake") == served - after,
          "the lobby's SECOND match: bob's Monthly stake, which arrives before any "
          "rating stake, opens the new pot instead of being dropped",
          f"recorded {side3}")
    for sid, host in ((s1, alice), (s2, carol)):
        host.call(req_session_delete(sid))
    run_pot_replay(tmp, check, carol, dave)


def run_pot_replay(tmp: Path, check: Checks, host, joiner) -> None:
    """The real client's start and end of a finished ranked match (TESTPLAN T3,
    2026-09-13, consoles 5 and 6), replayed number for number: whatever the
    payout bound is, it must not trim a payout a console really makes."""
    import statsdb
    import store
    print("\n-- pot: a real client's ranked match, start to payout (T3), replayed")
    store.startup(log=lambda *_a, **_k: None, stores=(), data_dir=tmp, import_files=False)
    seeds = {2: (500, 200), 3: (400, 100), 4: (300, 50), 5: (1234, 777)}
    for b, (h, j) in seeds.items():
        statsdb.put(b, host.entity, h, host.account)
        statsdb.put(b, joiner.entity, j, joiner.account)
    store.close()
    err, r = host.call(req_session_create("t3-replay", points=1))
    sid = r.blob() if r is not None and r.u32() else b""
    joiner.call(req_session_search(25))
    games = stats_score(host, 1, host.entity) or 0
    host.call(req_stats_write(1, 0, games + 1))
    start = {2: (450, 180), 3: (360, 90), 4: (270, 45), 5: (1111, 700)}
    for b in (2, 3, 4, 5):
        host.call(req_stats_write(b, 0, start[b][0]))
        joiner.call(req_stats_write(b, 0, start[b][1]))
    host.call(req_stats_write(1, 0, games + 1))
    end = {2: 520, 3: 410, 4: 305, 5: 1311}
    for b in (2, 3, 4, 5):
        host.call(req_stats_write(b, 0, end[b]))
    got = {b: stats_score(joiner, b, host.entity) for b in (2, 3, 4, 5)}
    lost = {b: stats_score(host, b, joiner.entity) for b in (2, 3, 4, 5)}
    pot = pot_doc(tmp, sid, "settled") or {}
    check(got == end and lost == {b: start[b][1] for b in (2, 3, 4, 5)},
          "CONTROL: the winner's four payouts (+70 +50 +35 +200) are stored to the "
          "point and the loser keeps what it staked from",
          f"winner {got}, loser {lost}")
    check(pot.get("settled") == "client" and pot.get("pot") == 200
          and all(got[b] + lost[b] == sum(seeds[b]) for b in (2, 3, 4, 5)),
          "CONTROL: the pot is the client's payout of 200, zero-sum on every board",
          f"pot {pot.get('settled')} {pot.get('pot')}")
    host.call(req_session_delete(sid))


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


NAT_STRUCT = bytes.fromhex(
    "000217171717171700000000000000000200000004000000088f73098032c808"
    "7862c108030000006862c108f469ef08804f9e40000000000000000000000000"
    "1a000000804f9e4000000000")


class FakeTransport:
    def __init__(self, peer: tuple[str, int]):
        self.peer, self.out, self.closed = peer, bytearray(), False

    def get_extra_info(self, _what):
        return self.peer

    def write(self, data: bytes) -> None:
        self.out += data

    def close(self) -> None:
        self.closed = True


def feed(conn, data: bytes, chunk: int) -> tuple[float, int]:
    """Hand `data` to the connection `chunk` bytes per read, as the event loop
    would, until it closes. (seconds the reads took, bytes taken).
    """
    t0 = time.perf_counter()
    n = 0
    for i in range(0, len(data), chunk):
        if conn.t.closed:
            break
        conn.data_received(data[i:i + chunk])
        n = i + chunk
    return time.perf_counter() - t0, min(n, len(data))


def run_framing_checks(check: Checks) -> None:
    """In-process: what a connection's bytes cost before they are messages."""
    import authserver
    print("\n-- framing: bytes that are not messages cost the sender, not the server")
    was_log = authserver.log
    authserver.log = lambda *_a, **_k: None

    def conn(ip: str):
        c = authserver.AuthConnection()
        c.connection_made(FakeTransport((ip, 5000)))
        return c

    c = conn("10.77.0.1")
    took, n = feed(c, b"\xff" * (256 * 1024), 1460)
    check(c.t.closed and took < 0.5,
          f"256 KB that never frame, in 1460-byte reads, close the connection after "
          f"{n} bytes in {took:.3f} s (it used to hold the event loop for seconds)")
    c = conn("10.77.0.2")
    took, n = feed(c, b"\xff" * 4096, 1)
    check(c.t.closed and n <= authserver.bd.JUNK_TRIES + 4,
          f"...and one byte at a time, after {n} reads ({took:.3f} s)")
    c = conn("10.77.0.3")
    big = (60000).to_bytes(4, "little") + b"\x01" + bytes(59999)
    took, n = feed(c, big, 1)
    check(took < 1.0,
          f"a 60 KB frame trickled one byte per read costs {took:.3f} s, not a "
          f"copy of the whole buffer per byte")
    for chunks in ([NAT_STRUCT, bytes.fromhex("b4000000ffff0000") + bytes(4)],
                   [NAT_STRUCT + bytes.fromhex("b4000000ffff0000") + bytes(4)],
                   [NAT_STRUCT[:40], NAT_STRUCT[40:] + bytes.fromhex("b4000000ffff0000"),
                    bytes(4)]):
        c = conn("10.77.0.4")
        for part in chunks:
            c.data_received(part)
        check(not c.t.closed and bytes(c.t.out) == bytes(4) and c.is_lsg,
              f"CONTROL: the console's own {len(b''.join(chunks)) - 12}-byte NAT "
              f"struct ahead of real frames ({len(chunks)} read(s)) is still "
              f"resynchronised past: the announce and the ping after it are served",
              f"closed={c.t.closed} out={bytes(c.t.out).hex()} lsg={c.is_lsg}")
        authserver.LSG_CONNS.pop("10.77.0.4", None)
    authserver.log = was_log


def run_census_checks(check: Checks) -> None:
    """In-process: what a signed-in peer can make the request census hold and
    how often it can make the server rewrite it (§80p)."""
    import authserver as A
    print("\n-- census: what a request can make the server record, and rewrite")
    was = (A.log, A._jsave, A._CENSUS_LOADED, A._CENSUS_SAVED_AT,
           dict(A.REQ_CENSUS), set(A._CENSUS_LOGGED))
    writes: list[int] = []
    A.log = lambda *_a, **_k: None
    A._jsave = lambda _path, data: writes.append(len(json.dumps(data)))
    A._CENSUS_LOADED, A._CENSUS_SAVED_AT = True, 0.0
    A.REQ_CENSUS.clear()
    A._CENSUS_LOGGED.clear()

    def note(svc: int, op: int, w, answered: bool) -> None:
        dec = {"enc": 0, "plain": w.getvalue()}
        try:
            A.census_note(svc, op, dec, answered=answered)
        except TypeError:
            A.census_note(svc, op, dec)
    try:
        for i in range(300):
            w = _rpc(200 + i // 100, i % 100)
            w.u64(i)
            note(200 + i // 100, i % 100, w, False)
        check(not A.REQ_CENSUS,
              "300 requests for ops the server does not answer make no census key",
              f"{len(A.REQ_CENSUS)} keys")
        writes.clear()
        for i in range(2000):
            w = _rpc(8, 1)
            for j in range(40):
                w.u64(i * 40 + j)
            note(8, 1, w, True)
        check(len(writes) <= 2,
              f"2,000 requests with new values in 40 fields rewrite the census "
              f"{len(writes)} time(s), not once each")
        for i in range(30):
            w = _rpc(8, 4)
            for j in range(400):
                w.str_(f"{i:04d}-{j:04d}-" + "z" * 40, 64)
            note(8, 4, w, True)
        size = len(json.dumps(A.REQ_CENSUS.get("8:4", {})))
        check(len(A.REQ_CENSUS.get("8:4", {}).get("fields", [])) <= 32 and size < 32 * 1024,
              f"a request of 400 long fields is recorded as 32 at most ({size} bytes)")
        check("8:1" in A.REQ_CENSUS and A.REQ_CENSUS["8:1"]["count"] == 2000,
              "CONTROL: an op the server answers is recorded and counted")
    finally:
        (A.log, A._jsave, A._CENSUS_LOADED, A._CENSUS_SAVED_AT) = was[:4]
        A.REQ_CENSUS.clear()
        A.REQ_CENSUS.update(was[4])
        A._CENSUS_LOGGED.clear()
        A._CENSUS_LOGGED.update(was[5])


def run_census_file_checks(check: Checks) -> None:
    """In-process: a census file that does not parse is kept, not overwritten
    by the next flush (§80ah)."""
    import authserver as A
    print("\n-- census: a damaged file is kept aside, not written over (§80ah)")
    was = (A.log, A.REQ_CENSUS_PATH, A._CENSUS_LOADED, dict(A.REQ_CENSUS))
    A.log = lambda *_a, **_k: None
    d = Path(tempfile.mkdtemp(prefix="wow2-census-"))
    try:
        A.REQ_CENSUS_PATH = d / "request-census.json"
        A.REQ_CENSUS_PATH.write_text(json.dumps({"8:1": {"count": 7}}))
        A.REQ_CENSUS.clear()
        A.census_load()
        A.REQ_CENSUS["8:4"] = {"count": 1}
        A.census_flush()
        kept = json.loads(A.REQ_CENSUS_PATH.read_text())
        check(kept.get("8:1", {}).get("count") == 7 and "8:4" in kept,
              "CONTROL: a census file that parses is carried over and written back "
              "with what is new")
        damaged = b'{"8:1": {"count": 7}, "8:5": {"cou'
        A.REQ_CENSUS_PATH.write_bytes(damaged)
        A.REQ_CENSUS.clear()
        A.census_load()
        A.REQ_CENSUS["8:4"] = {"count": 1}
        A.census_flush()
        survived = [f.name for f in d.iterdir() if f.read_bytes() == damaged]
        check(bool(survived),
              "a census file that does not parse survives the next flush (kept aside "
              "as .corrupt-*), instead of being replaced by this run's census",
              f"files: {sorted(f.name for f in d.iterdir())}")
    finally:
        A._UNREADABLE.pop(str(d / "request-census.json"), None)
        (A.log, A.REQ_CENSUS_PATH, A._CENSUS_LOADED) = was[:3]
        A.REQ_CENSUS.clear()
        A.REQ_CENSUS.update(was[3])
        shutil.rmtree(d, ignore_errors=True)


def run_reflection_checks(check: Checks) -> None:
    """In-process: what discovery and the NAT type probe send to a source nothing
    authenticated, which a forger chooses (§80s)."""
    import authserver as A
    print("\n-- udp: discovery and the NAT type probe as a reflector")
    sent: list = []

    class T:
        def sendto(self, data, addr):
            sent.append((data, addr))
    d = A.Discovery()
    d.connection_made(T())
    was_log = A.log
    A.log = lambda *_a, **_k: None
    for name in ("_udp_reply_minute", "_udp_log_minute"):
        win = getattr(A, name, None)
        if win is not None:
            win[:] = [time.time(), 0, {}, 0]
    disc = bytes([0x1E, 0x02, 0x00])
    try:
        d.datagram_received(disc, ("203.0.113.5", 3075))
        d.datagram_received(bytes([0x14, 0x02, 0x00, 0x00]), ("203.0.113.5", 3075))
        check([len(x) for x, _a in sent] == [9, 15],
              "CONTROL: a console's discovery and NAT type test 1 are answered",
              f"{[x.hex() for x, _a in sent]}")
        sent.clear()
        for _ in range(500):
            d.datagram_received(disc, ("198.51.100.7", 4444))
        check(len(sent) <= 60,
              f"500 discoveries forged from one address are answered {len(sent)} time(s), "
              f"not 500 (9 bytes out for 3 in)")
        for i in range(200):
            for _ in range(30):
                d.datagram_received(disc, (f"198.51.{101 + i // 200}.{i % 200}", 4444))
        check(len(sent) <= 3000,
              f"...and 6,000 more from 200 addresses {len(sent)} in all this minute")
    finally:
        A.log = was_log
        for name in ("_udp_reply_minute", "_udp_log_minute"):
            win = getattr(A, name, None)
            if win is not None:
                win[:] = [0.0, 0, {}, 0]


def run_log_checks(check: Checks) -> None:
    """In-process: what reaches the disk for traffic nobody authenticated."""
    import authserver
    print("\n-- logs: what reaches the disk for traffic nobody authenticated")
    said: list[str] = []
    was_log, was_cap = authserver.log, authserver.CAP
    authserver.log = lambda m, *_a, **_k: said.append(m)
    udp_log = getattr(authserver, "udp_log", None)
    if udp_log is None:
        check(False, "lines about datagrams have a budget per address")
    else:
        authserver._udp_log_minute[:] = [time.time(), 0, {}, 0]
        for _ in range(500):
            udp_log("10.66.0.1", "x")
        one = len(said)
        for i in range(30):
            for _ in range(100):
                udp_log(f"10.66.1.{i}", "y")
        check(one == authserver.UDP_LOG_PER_ADDRESS
              and len(said) == authserver.UDP_LOG_TOTAL,
              f"lines about datagrams: {one} of 500 from one address, "
              f"{len(said)} in a minute from 31")
    said.clear()
    peers = {(f"10.{i >> 16 & 255}.{i >> 8 & 255}.{i & 255}", 3074): time.time()
             for i in range(16000)}
    authserver.NAT_PEERS.clear()
    authserver.NAT_PEERS.update(peers)
    if hasattr(authserver, "_udp_log_minute"):
        authserver._udp_log_minute[:] = [time.time(), 0, {}, 0]
    d = authserver.Discovery()
    d.connection_made(FakeTransport(("0.0.0.0", 3074)))
    intro = (bytes([authserver.NAT_INTRO_REQ, 2, 0]) + bytes(10) + (7).to_bytes(4, "little")
             + authserver.bd_addr("10.200.0.1", 1) + authserver.bd_addr("10.200.0.2", 2))
    d.datagram_received(intro, ("10.66.2.1", 5000))
    longest = max((len(m) for m in said), default=0)
    check(longest < 300,
          f"a bdNAT introduction naming nobody, with 16,000 consoles known, logs "
          f"{longest} characters at most (it printed the whole table)")
    authserver.NAT_PEERS.clear()
    scratch = Path(tempfile.mkdtemp(prefix="wow2-logs-"))
    authserver.CAP = scratch
    was_mb, was_keep = (authserver.serverconfig.SESSION_LOG_MB if hasattr(
        authserver.serverconfig, "SESSION_LOG_MB") else None,
        getattr(authserver.serverconfig, "SESSION_LOGS_KEEP", None))
    authserver.serverconfig.SESSION_LOG_MB = 1
    authserver.serverconfig.SESSION_LOGS_KEEP = 2
    sl = authserver._SessionLog()
    line = "z" * 99 + "\n"
    for _ in range(35000):
        sl.write(line)
    sizes = sorted(p.stat().st_size for p in scratch.glob("session-*.log"))
    check(len(sizes) == 2 and sizes[-1] <= 1024 * 1024 + 100,
          f"3.5 MB through a session log capped at 1 MB, keeping 2: {len(sizes)} "
          f"file(s), the largest {sizes[-1] if sizes else 0} bytes")
    if was_mb is not None:
        authserver.serverconfig.SESSION_LOG_MB, authserver.serverconfig.SESSION_LOGS_KEEP = was_mb, was_keep
    was_hex = authserver._HEXDUMPS[0]
    authserver._HEXDUMPS[0] = False
    c = authserver.AuthConnection()
    c.connection_made(FakeTransport(("10.66.3.1", 5000)))
    c.data_received(NAT_STRUCT + bytes.fromhex("b4000000ffff0000") + bytes(4))
    check(not list(scratch.glob("unframed-*.bin")),
          "with hexdumps off, bytes that do not frame are logged, not saved to a file")
    authserver.LSG_CONNS.pop("10.66.3.1", None)
    authserver._HEXDUMPS[0] = was_hex
    authserver.CAP, authserver.log = was_cap, was_log
    shutil.rmtree(scratch, ignore_errors=True)


def run_auto_id_checks(check: Checks) -> None:
    """In-process: what a source address leaves behind in the identity table
    (§80w)."""
    import authserver
    print("\n-- identities: what a source address leaves behind")
    was_log, was_ids = authserver.log, dict(authserver._AUTO_IDS)
    was_next = list(getattr(authserver, "_auto_next", []))
    authserver.log = lambda *_a, **_k: None
    try:
        authserver._AUTO_IDS.clear()
        first = authserver.identity_for("192.0.2.1")
        again = authserver.identity_for("192.0.2.1")
        rig = authserver.identity_for("10.42.0.2"), authserver.identity_for("10.42.0.9")
        check(first == again and rig == (authserver.IDENTITIES["10.42.0.2"], ("player9", 9)),
              "CONTROL: an address keeps its placeholder, and a rig address its own identity",
              f"first={first} again={again} rig={rig}")
        for i in range(10000):
            authserver.identity_for(f"198.18.{i // 256}.{i % 256}")
        cap = getattr(authserver, "AUTO_IDS_MAX", 4096)
        held = len(authserver._AUTO_IDS)
        nums = [n for _name, n in authserver._AUTO_IDS.values()]
        check(held <= cap and len(set(nums)) == len(nums),
              f"10,000 source addresses leave at most {cap} placeholders, no two "
              f"sharing a number", f"held={held}")
    finally:
        authserver._AUTO_IDS.clear()
        authserver._AUTO_IDS.update(was_ids)
        if was_next:
            authserver._auto_next[:] = was_next
        authserver.log = was_log


def run_nsdns_checks(check: Checks) -> None:
    """In-process: what the DNS responder answers, and to whom (§80y)."""
    import nsdns
    print("\n-- nsdns: a query is answered, as the authority, within a budget")
    names = {n.lower() for n in nsdns.DEFAULT_NAMES}
    served, here = "worms-180.auth.mmp3.demonware.net", "203.0.113.7"
    respond = getattr(nsdns, "respond", None)
    if hasattr(nsdns, "_minute"):
        nsdns._minute[:] = [0.0, 0, {}, 0]

    def query(name: str, qtype: int = 1, flags: int = 0x0100, tid: int = 0x1234) -> bytes:
        return (struct.pack(">HHHHHH", tid, flags, 1, 0, 0, 0)
                + b"".join(bytes([len(x)]) + x.encode() for x in name.split("."))
                + b"\x00" + struct.pack(">HH", qtype, 1))

    def ask(msg: bytes, ip: str = "192.0.2.53") -> bytes | None:
        if respond is not None:
            out = respond(msg, ip, names, here)
            return out[0] if out else None
        q = nsdns.parse_question(msg)
        if not q:
            return None
        name, qtype, qend = q
        hit = qtype == 1 and name.lower() in names
        return nsdns.build_reply(msg, qend, here if hit else None)

    def flags(r: bytes) -> int:
        return struct.unpack(">H", r[2:4])[0]

    def answers(r: bytes) -> int:
        return struct.unpack(">H", r[6:8])[0]

    nsdns.print = lambda *_a, **_k: None
    try:
        a = ask(query(served))
        check(a is not None and answers(a) == 1 and a.endswith(socket.inet_aton(here)),
              "CONTROL: an A query for a served name gets the configured address")
        check(a is not None and flags(a) & 0x0400 and flags(a) & 0x0080,
              "...as the authority for it (AA), and as the console's resolver (RA), "
              "the way dnsmasq answers a local name", f"flags={a and hex(flags(a))}")
        aaaa = ask(query(served, 28))
        check(aaaa is not None and flags(aaaa) & 0x000F == 0 and answers(aaaa) == 0,
              "an AAAA query for a served name is NOERROR with no record -- the name "
              "exists -- not NXDOMAIN", f"flags={aaaa and hex(flags(aaaa))}")
        check(ask(query(served, flags=0x8580)) is None,
              "a RESPONSE (QR set) is not answered, so two responders cannot be set "
              "echoing at each other")
        got = sum(ask(query(served, tid=i), ip="198.51.100.9") is not None for i in range(500))
        check(got == 60, "500 queries forged from one address are answered 60 times",
              f"answered {got}")
        more = sum(ask(query(served, tid=i), ip=f"198.51.{101 + i // 250}.{i % 250}") is not None
                   for i in range(6000))
        check(got + more <= 3000, "...and 6,000 more from 240 addresses bring the "
              "minute to at most 3,000", f"{got + more} in all")
    finally:
        del nsdns.print


def run_unit_checks(check: Checks) -> None:
    """Offline: who the three systemd units run as, and what they may not do (§80aa)."""
    units = HERE.parent / "packaging"
    print("\n-- the systemd units and setup.sh: a user each, the sandbox, the install's umask")
    if not (units / "wow2-server.service").is_file():
        print("(no packaging/ beside this copy; the unit checks are skipped)")
        return

    def read(name: str) -> dict[str, list[str]]:
        out: dict[str, list[str]] = {}
        section = ""
        for line in (units / name).read_text().splitlines():
            line = line.strip()
            if not line or line.startswith(("#", ";")):
                continue
            if line.startswith("["):
                section = line
            elif section == "[Service]" and "=" in line:
                k, v = line.split("=", 1)
                out.setdefault(k.strip(), []).append(v.strip())
        return out

    def one(u: dict, k: str) -> str:
        return (u.get(k) or [""])[-1]

    srv, bot, dns = (read(n) for n in ("wow2-server.service", "wow2-discordbot.service",
                                       "wow2-nsdns@.service"))
    check(one(srv, "ExecStart").endswith("/wow2-server")
          and one(bot, "ExecStart").endswith("/wow2-discordbot")
          and "--bind %i" in one(dns, "ExecStart")
          and one(srv, "ReadWritePaths") == one(bot, "ReadWritePaths") == "/var/lib/wow2-server",
          "CONTROL: each unit runs its program, and the server and the bot write the "
          "one data directory")
    check(one(bot, "User") not in ("", one(srv, "User")) and one(bot, "Group") == one(srv, "Group"),
          "the password bot runs as a user of its own in the server's group, so the server "
          "cannot read its environment, which holds the token",
          f"server {one(srv, 'User')}:{one(srv, 'Group')}, bot {one(bot, 'User')}:{one(bot, 'Group')}")
    check(one(dns, "DynamicUser") == "true" and not one(dns, "User"),
          "the DNS responder runs as a user that exists while it runs, not the one that "
          "owns the credentials", f"User={one(dns, 'User')!r} DynamicUser={one(dns, 'DynamicUser')!r}")
    want = {"UMask": "0077", "NoNewPrivileges": "true", "PrivateTmp": "true",
            "PrivateDevices": "true", "ProtectSystem": "strict", "ProtectHome": "true",
            "ProtectProc": "invisible", "ProcSubset": "pid", "ProtectClock": "true",
            "ProtectHostname": "true", "ProtectKernelTunables": "true",
            "ProtectKernelModules": "true", "ProtectKernelLogs": "true",
            "ProtectControlGroups": "true", "RestrictNamespaces": "true",
            "RestrictRealtime": "true", "RestrictSUIDSGID": "true", "RemoveIPC": "true",
            "LockPersonality": "true", "SystemCallArchitectures": "native"}
    for name, u in (("server", srv), ("bot", bot), ("DNS responder", dns)):
        miss = [f"{k}={v}" for k, v in want.items() if one(u, k) != v]
        calls = u.get("SystemCallFilter", [])
        if "@system-service" not in calls or "~@privileged @resources" not in calls:
            miss.append("SystemCallFilter=@system-service ~@privileged @resources")
        check(not miss, f"the {name}'s unit carries the whole sandbox", "missing: " + ", ".join(miss))
    check(srv.get("CapabilityBoundingSet") == [""] == bot.get("CapabilityBoundingSet")
          and one(dns, "CapabilityBoundingSet") == "CAP_NET_BIND_SERVICE",
          "...the server and the bot hold no capability at all, the responder only the one "
          "port 53 needs")
    setup = next((f for f in (HERE.parent / "setup.sh", HERE.parent / "publish" / "setup.sh")
                  if f.is_file()), None)
    if setup is not None:
        lines = [ln.split("#", 1)[0] for ln in setup.read_text().splitlines()]

        def at(pattern: str) -> int | None:
            return next((i for i, ln in enumerate(lines) if re.search(pattern, ln)), None)
        mask, venv, heal = at(r"SYSTEM.*umask 022"), at(r"-m venv"), at(r'SYSTEM.*chmod -R a\+rX "\$VENV"')
        check(None not in (mask, venv, heal) and mask < venv < heal,
              "setup.sh --system installs under umask 022 whatever root's is, and opens a venv "
              "an older run left unreadable, so the service users can import it (§80ab)",
              f"umask at line {mask}, venv at line {venv}, chmod at line {heal}")


def run_config_checks(check: Checks) -> None:
    """Subprocesses: which wow2-server.toml an installed copy reads (§80ac)."""
    print("\n-- the config file: never the working directory's for an installed copy")
    base = getattr(sys, "_base_executable", sys.executable)
    scratch = Path(tempfile.mkdtemp(prefix="wow2-ownertest-config-"))
    try:
        inst, here, loc = scratch / "installed", scratch / "cwd", scratch / "local"
        for d in (inst, here, loc):
            d.mkdir()
        stray = here / "wow2-server.toml"
        stray.write_text('[storage]\ndata_dir = "/nowhere"\n')
        (loc / "wow2-server.toml").write_text('[storage]\ndata_dir = "/local"\n')
        env = {k: v for k, v in os.environ.items() if not k.startswith("WOW2_")}
        env.update(WOW2_ROOT=str(inst), PYTHONPATH=str(HERE))

        def config_path(python: str, **extra) -> str:
            r = subprocess.run([python, "-c", "import os, serverconfig as c; "
                                "print(c.PATH and os.path.abspath(c.PATH))"],
                               cwd=here, env={**env, **extra}, capture_output=True, text=True)
            return r.stdout.strip() or r.stderr.strip()[-200:]

        got = config_path(base, WOW2_CONFIG=str(stray))
        check(got == str(stray), "CONTROL: WOW2_CONFIG names the file read", got)
        got = config_path(base)
        check(got != str(stray), "an installed copy run from a directory holding a "
              "wow2-server.toml does not read it, so a CLI run from the checkout edits "
              "the server's store (the system config, or the defaults)", got)
        subprocess.run([base, "-m", "venv", "--without-pip", str(loc / ".venv")], check=True)
        got = config_path(str(loc / ".venv" / "bin" / "python"))
        check(got == str(loc / "wow2-server.toml"), "...and a venv reads the config beside "
              "it, from any directory (a local install's checkout)", got)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def run_firewall_checks(check: Checks) -> None:
    """Subprocesses: setup.sh's own firewall block, run against configs (§80ad)."""
    print("\n-- the firewall: setup.sh opens what the configuration binds")
    setup = next((f for f in (HERE.parent / "setup.sh", HERE.parent / "publish" / "setup.sh")
                  if f.is_file()), None)
    if setup is None:
        print("(no setup.sh beside this copy; the firewall checks are skipped)")
        return
    lines = setup.read_text().splitlines()
    start = next(i for i, ln in enumerate(lines) if ln.startswith("# ---") and "firewall" in ln)
    end = next(i for i, ln in enumerate(lines) if i > start and ln.strip() == 'say "firewall"')
    scratch = Path(tempfile.mkdtemp(prefix="wow2-ownertest-fw-"))
    try:
        (scratch / "bin").mkdir()
        (scratch / "wow2").symlink_to(HERE)
        python = scratch / "bin" / "python"
        python.write_text(f'#!/bin/sh\nPYTHONPATH={scratch} exec '
                          f'{getattr(sys, "_base_executable", sys.executable)} "$@"\n')
        python.chmod(0o755)
        script = scratch / "fw.sh"
        script.write_text("set -euo pipefail\ndie() { echo \"DIE: $*\"; exit 1; }\n"
                          f'SYSTEM=1; DNS_ADDR=""; CONF="$1"; HERE=/nonexistent; VENV={scratch}\n'
                          + "\n".join(lines[start:end]) + '\necho "$PORTS"\n')

        def opened(toml: str) -> set[str]:
            conf = scratch / "wow2-server.toml"
            conf.write_text(toml)
            env = {k: v for k, v in os.environ.items() if not k.startswith("WOW2_")}
            r = subprocess.run(["bash", str(script), str(conf)], env=env,
                               capture_output=True, text=True)
            return set((r.stdout.strip().splitlines() or [""])[-1].split())

        base = {"3074/tcp", "3074/udp", "3078/udp"}
        got = opened("")
        check(got == base, "CONTROL: the default configuration opens 3074 TCP and UDP and 3078 UDP",
              f"opened {sorted(got)}")
        got = opened("[nat]\nrelay = true\nrelay_port_base = 40_000\n")
        check(got == base | {"40000-40031/udp"}, "a relay base written 40_000 (TOML allows "
              "it) opens 40000-40031, not 40-71", f"opened {sorted(got)}")
        got = opened("nat.relay = true\n")
        check(got == base | {"40000-40031/udp"}, "the relay turned on with a dotted key "
              "opens its range", f"opened {sorted(got)}")
        got = opened("[server]\nport = 3999\n")
        check(got == {"3999/tcp", "3999/udp", "3078/udp"}, "a server moved to port 3999 "
              "has 3999 opened, not 3074", f"opened {sorted(got)}")
    finally:
        shutil.rmtree(scratch, ignore_errors=True)


def run_credential_lock_checks(check: Checks) -> None:
    """In-process: a create and a password change decide under the lock that
    writes, so the password bot, another process, cannot write in between (§80ae)."""
    import sqlite3
    import authserver as A
    from lsgauth import change_password_request, create_request, read_reply_error
    print("\n-- credentials: a create or a change writes what it decided (§80ae)")
    was_log = A.log
    A.log = lambda *_a, **_k: None
    path = A.store.db().execute("PRAGMA database_list").fetchone()[2]

    def bot_writes(name: str, password: str) -> bool:
        """A credential written from another connection, as the bot's /claim or
        staff's /reset; False when the write lock is held (the bot waits for it)."""
        c = sqlite3.connect(path, timeout=0, isolation_level=None)
        c.row_factory = sqlite3.Row
        try:
            c.execute("BEGIN IMMEDIATE")
            A._write_credential(c, name, A.tiger192(password.encode()), "")
            c.execute("COMMIT")
            return True
        except sqlite3.OperationalError:
            return False
        finally:
            c.close()

    def ask(data: bytes, between: str, write) -> tuple[int | None, list[bool]]:
        """Send one auth request; `write` runs when the handler calls `between`,
        which it does after deciding and before writing."""
        landed: list[bool] = []
        real = getattr(A, between)

        def hooked(*args, **kw):
            landed.append(write())
            return real(*args, **kw)
        setattr(A, between, hooked)
        c = A.AuthConnection()
        c.connection_made(FakeTransport(("10.88.0.1", 5000)))
        try:
            c.data_received(data)
        finally:
            setattr(A, between, real)
            c.connection_lost(None)
        frames, _rest, _skipped = bd.parse_frame(bytes(c.t.out))
        errs = [read_reply_error(bd.unwrap_message(d)[1]) for k, d in frames if k == "msg"]
        return (errs[0] if errs else None), landed

    def held(name: str) -> bytes | None:
        return A.stored_credential(name)

    check(bot_writes("racer0", "botpass0") and held("racer0") == A.tiger192(b"botpass0"),
          "CONTROL: with nothing being decided, the other connection's write goes in at once")
    err, landed = ask(create_request("racer5", "console5"), "create_allowed",
                      lambda: bot_writes("racer5", "botpass5"))
    check(err == A.BD_AUTH_NO_ERROR and landed == [False]
          and held("racer5") == A.tiger192(b"console5"),
          "a password the bot writes for a name while a console's create for it is "
          "being decided cannot land in between: it waits for the create's lock, and "
          "then finds the name taken",
          f"err={err} the bot's write landed={landed}")
    err, _ = ask(create_request("racer0", "console0"), "create_allowed", lambda: True)
    check(err == A.BD_AUTH_CREATE_USERNAME_EXISTS and held("racer0") == A.tiger192(b"botpass0"),
          "CONTROL: a create for a name the bot already wrote is 707, unchanged",
          f"err={err}")
    A.set_account_password("racer6", A.tiger192(b"first666"))
    err, landed = ask(change_password_request("racer6", "first666", "second66"),
                      "auth_payload_decrypt", lambda: bot_writes("racer6", "staff666"))
    check(err == A.BD_AUTH_NO_ERROR and landed == [False]
          and held("racer6") == A.tiger192(b"second66"),
          "staff's /reset cannot land between a password change's check of the old "
          "password and its write of the new one, to be overwritten in silence; it "
          "waits, and the reset comes after the change",
          f"err={err} the reset landed={landed}")
    err, _ = ask(change_password_request("racer6", "wrongpw1", "third666"),
                 "auth_payload_decrypt", lambda: True)
    check(err == A.BD_AUTH_INCORRECT_PASSWORD and held("racer6") == A.tiger192(b"second66"),
          "CONTROL: a change under a password that is not the current one is 716 and "
          "changes nothing", f"err={err}")
    A.log = was_log


def run_fallback_change_checks(check: Checks) -> None:
    """In-process: the shared password changes a password with no credential
    on file only while the fallback is on (§80ag)."""
    import authserver as A
    from lsgauth import change_password_request, read_reply_error
    print("\n-- a password change needs the password on file, or the fallback (§80ag)")
    was_log, was_fallback = A.log, A.serverconfig.SHARED_PASSWORD_FALLBACK
    A.log = lambda *_a, **_k: None

    def change(name: str, new: str, fallback: bool) -> int | None:
        A.serverconfig.SHARED_PASSWORD_FALLBACK = fallback
        c = A.AuthConnection()
        c.connection_made(FakeTransport(("10.88.0.2", 5000)))
        try:
            c.data_received(change_password_request(name, A.ACCOUNT_PASSWORD, new))
        finally:
            c.connection_lost(None)
        frames, _rest, _skipped = bd.parse_frame(bytes(c.t.out))
        errs = [read_reply_error(bd.unwrap_message(d)[1]) for k, d in frames if k == "msg"]
        return errs[0] if errs else None

    try:
        err = change("player7", "fallbk77", True)
        check(err == A.BD_AUTH_NO_ERROR
              and A.stored_credential("player7") == A.tiger192(b"fallbk77"),
              "CONTROL: with the fallback on (the rig's), an account with no password on "
              "file changes it under the shared password", f"err={err}")
        err = change("player8", "fallbk88", False)
        check(err == A.BD_AUTH_INCORRECT_PASSWORD and A.stored_credential("player8") is None,
              "with it off, the same change is 716 and stores nothing: the shared password "
              "opens nothing, a sign-in or a change", f"err={err}")
    finally:
        A.log, A.serverconfig.SHARED_PASSWORD_FALLBACK = was_log, was_fallback


def run_clan_rule_checks(check: Checks) -> None:
    """In-process: who may remove whom from a clan, cell by cell against the
    client's own Remove row (§80v)."""
    import authserver
    print("\n-- clans: who may remove whom (the client's Remove row)")
    rule = getattr(authserver, "clan_remove_refusal", None)
    own, adm, adm2, mem, mem2, out = (f"{i:016x}" for i in range(1, 7))
    rec = {"owner": own, "members": [own, adm, adm2, mem, mem2],
           "ranks": {adm: 1, adm2: 1}}
    table = {(adm, mem): True, (adm, adm2): False, (adm, own): False, (adm, adm): False,
             (own, mem): True, (own, adm): True, (own, own): False,
             (mem, mem2): False, (mem, adm): False, (out, mem): False}
    wrong = [(a, t) for (a, t), ok in table.items()
             if rule is None or (rule(rec, a, t) == "") != ok]
    check(not wrong,
          "an administrator removes ordinary members only, the owner members and "
          "administrators, nobody the owner or themselves, a member or an outsider "
          "nobody", f"wrong cells: {wrong}" if rule else "no clan_remove_refusal()")


def run_search_started_checks(check: Checks) -> None:
    """In-process: a game in progress is not offered to the browser."""
    import authserver
    print("\n-- search: a session whose game has started is not listed")
    was_log, was = authserver.log, dict(authserver.SESSIONS)
    authserver.log = lambda *_a, **_k: None
    authserver.SESSIONS.clear()
    authserver.SESSIONS[0x5701] = {"id": 0x5701, "name": "wormy", "host": "wormy",
                                   "players": 2, "max_players": 4, "info": []}
    authserver.SESSIONS[0x5702] = {"id": 0x5702, "name": "snailhead", "host": "snailhead",
                                   "players": 1, "max_players": 4, "info": []}
    n, _ = authserver.sessions_search_results({})
    check(n == 2, f"CONTROL: two open lobbies are both listed ({n})")
    authserver.host_reported_game("wormy", 0, 1)
    n, _ = authserver.sessions_search_results({})
    check(n == 1, "a lobby whose host reported a game started is left out of the "
          f"search, so nobody is offered a join the host will refuse ({n})")
    authserver.host_reported_game("wormy", 1, 1)
    n, _ = authserver.sessions_search_results({})
    check(n == 2, f"...and listed again once the host reports the game over ({n})")
    authserver.host_reported_game("wormy", 1, 2)
    n, _ = authserver.sessions_search_results({})
    check(n == 1, f"...and hidden again when the same session starts its next game ({n})")
    authserver.SESSIONS.clear()
    authserver.SESSIONS.update(was)
    authserver.log = was_log


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

    joiner = rl.mailbox_for(("185.0.0.1", 31236)).owner
    host = rl.mailbox_for(("49.0.0.35", 24438)).owner
    other = rl.mailbox_for(("49.0.0.1", 15040)).owner
    rl.link(joiner, host)
    rl.link(joiner, other)
    joiner.seen[host.mailbox.port] = ("185.0.0.1", 31236)
    dtls = bytes([0x16]) + bytes(99)
    sent = []
    host.mailbox.transport = type("T", (), {"sendto": lambda _s, d, a: sent.append(a)})()
    who = rl.sender_for(joiner.mailbox, ("49.0.0.35", 24500), dtls)
    check(who is host,
          "a host whose router moved it to a new port is still the host when the "
          "joiner's mailbox has another peer on a DIFFERENT address (the public "
          "server, 2026-10-01: every join dropped with 'cannot tell who')",
          f"who={who}")
    joiner.mailbox.datagram_received(dtls, ("49.0.0.35", 24500))
    check(host.seen.get(joiner.mailbox.port) == ("49.0.0.35", 24500)
          and sent == [("185.0.0.1", 31236)],
          "...and its datagram is carried to the joiner and its new port learned",
          f"seen={host.seen} sent={sent}")
    twin = rl.mailbox_for(("49.0.0.35", 24600)).owner
    rl.link(joiner, twin)
    who = rl.sender_for(joiner.mailbox, ("49.0.0.35", 24700), dtls)
    check(who is None,
          "two of the mailbox's peers behind that address leave nothing to guess (§71c)",
          f"who={who}")

    print("\n-- relay: a return path in use is not moved (§80r)")
    h = rl.mailbox_for(("49.0.1.35", 24438)).owner
    j = rl.mailbox_for(("185.0.1.1", 31236)).owner
    rl.link(j, h)
    got: list[bytes] = []
    h.mailbox.transport = type("T", (), {"sendto": lambda _s, d, a: got.append(d)})()
    j.seen[h.mailbox.port] = ("185.0.1.1", 31236)
    port = j.mailbox.port

    def age(c, s: float) -> None:
        at = getattr(c, "seen_at", None)
        if at is not None and port in at:
            at[port] -= s

    j.mailbox.datagram_received(b"\x16host", ("49.0.1.35", 24438))
    j.mailbox.datagram_received(b"\x16fake", ("49.0.1.35", 9999))
    check(h.seen.get(port) == ("49.0.1.35", 24438) and got == [b"\x16host"],
          "while the host talks to the joiner's mailbox, a datagram from another port "
          "on its address is not carried and does not move its return path",
          f"seen={h.seen.get(port)} carried={got}")
    age(h, 400)
    j.mailbox.datagram_received(b"\x16moved", ("49.0.1.35", 24500))
    check(h.seen.get(port) == ("49.0.1.35", 24500) and got[-1] == b"\x16moved",
          "CONTROL: after 400 s of silence (§79's router) the host from a new port is "
          "learned and carried", f"seen={h.seen.get(port)}")
    age(h, 400)
    j.mailbox.datagram_received(b"\x16fake", ("49.0.1.35", 9999))
    j.mailbox.datagram_received(b"\x16back", ("49.0.1.35", 24500))
    j.mailbox.datagram_received(b"\x16fake", ("49.0.1.35", 9999))
    check(h.seen.get(port) == ("49.0.1.35", 24500) and got[-1] == b"\x16back",
          "a port that takes an idle path loses it the moment the host speaks from its "
          "own again, and cannot take it back while the host talks",
          f"seen={h.seen.get(port)} last carried={got[-1]}")

    import authserver
    one = rl.mailbox_for(("127.0.0.1", 3075)).owner
    two = rl.mailbox_for(("10.42.0.2", 3074)).owner
    rl.link(two, one)
    aliases = getattr(natrelay, "HOST_ALIASES", {})
    want = getattr(authserver, "relay_host_aliases", dict)()
    aliases.update({"10.42.0.1": "127.0.0.1"})
    who = rl.sender_for(two.mailbox, ("10.42.0.1", 3075), dtls)
    check(who is one,
          "the rig: console 1 (127.0.0.1 to 3074) dialling console 2's mailbox from "
          "the bridge address is console 1, so the host's replies reach the joiner "
          "(§79's rule turned every such join into 'no longer available')",
          f"who={who}")
    check(rl.sender_for(two.mailbox, ("10.42.0.3", 3074), dtls) is None,
          "CONTROL: a third console's address is still nobody")
    aliases.pop("10.42.0.1", None)
    check(want == ({"10.42.0.1": "127.0.0.1"} if authserver.BRIDGE_UP
                   and not authserver.NO_SELF_REWRITE and not natrelay.PUBLIC_ADDRESS
                   else {}),
          "...and the server names the bridge as loopback exactly when it hands "
          "loopback consoles the bridge address", f"{want}")


def _pool(natrelay, base: int, n: int):
    rl = natrelay.Relay()
    rl.enabled = True
    for port in range(base, base + n):
        mb = natrelay.Mailbox(rl, port)
        rl.mailboxes.append(mb)
        rl.by_port[port] = mb
    return rl


def _held(c, born: float, last: float | None = None) -> None:
    """Back-date a console: it took its mailbox at `born`, last spoke at `last`."""
    try:
        c.born = born
    except AttributeError:
        pass
    c.last = born if last is None else last


def run_relay_pool_checks(check: Checks) -> None:
    """In-process: who may hold a relay mailbox, and for how long (§80j)."""
    import authserver
    import natrelay
    print("\n-- relay: a mailbox lives on its own console's traffic, and one nobody "
          "signed in for gives way")
    lines: list[str] = []
    natrelay._log = lambda msg, *_a, **_k: lines.append(msg)
    natrelay._udp_log = lambda _ip, msg: lines.append(msg)
    grace = getattr(natrelay, "GRACE", 300.0)
    silence = getattr(natrelay, "SILENCE", 90.0)
    nop = lambda *_a, **_k: None
    now = time.time()

    rl = _pool(natrelay, 40300, 16)
    getattr(rl, "note_sign_in", nop)("10.80.0.1")
    a = rl.mailbox_for(("10.80.0.1", 3075)).owner
    b = rl.mailbox_for(("10.80.0.2", 3075)).owner
    _held(a, now - natrelay.IDLE_TIMEOUT + 30)
    stamp = a.last
    for _ in range(5):
        a.mailbox.datagram_received(b"\x16" + bytes(40), ("203.0.113.9", 4444))
    check(a.last == stamp,
          "datagrams to a mailbox from nobody we know do not keep it alive",
          f"its last word moved {a.last - stamp:.0f}s")
    rl.sweep(now + 60)
    check(a.key not in rl.consoles,
          "...so it is forgotten once its own console has been silent past "
          f"relay_idle_timeout ({natrelay.IDLE_TIMEOUT:.0f}s), whoever else writes to it")
    a = rl.mailbox_for(("10.80.0.1", 3075)).owner
    _held(a, now - natrelay.IDLE_TIMEOUT + 30)
    rl.mailbox_for(a.key)
    rl.sweep(now + 60)
    check(a.key in rl.consoles,
          "CONTROL: its own console's keepalive keeps it")
    sent = []
    b.mailbox.transport = type("T", (), {"sendto": lambda _s, d, to: sent.append(to)})()
    rl.link(a, b)
    a.seen[b.mailbox.port] = a.key
    _held(b, now - 100)
    a.mailbox.datagram_received(b"\x16" + bytes(40), b.key)
    check(b.last >= now and sent == [a.key],
          "CONTROL: a peer's datagram is carried and keeps the PEER alive",
          f"sent={sent}")

    rl = _pool(natrelay, 40320, 16)
    flood = [rl.mailbox_for((f"10.81.0.{i}", 3075)).owner for i in range(1, 5)]
    for c in flood:
        _held(c, now - silence - 5)
    talking = rl.mailbox_for(("10.81.1.1", 3075)).owner
    _held(talking, now - silence - 5, now)
    rl.sweep(now)
    check(not any(c.key in rl.consoles for c in flood),
          f"a mailbox nobody has signed in for is forgotten after {silence:.0f}s of its "
          f"console's silence, not {natrelay.IDLE_TIMEOUT:.0f}s "
          "(a console sends a keepalive every 15 s from discovery on)")
    check(talking.key in rl.consoles,
          "CONTROL: one whose console keeps up its keepalive is kept while it signs in")

    rl = _pool(natrelay, 40340, 16)
    flood = [rl.mailbox_for((f"198.18.0.{i}", 3075)).owner for i in range(1, 17)]
    for k, c in enumerate(flood):
        _held(c, now - grace - 100 + k, now)
    oldest = flood[0].mailbox.port
    got = rl.mailbox_for(("10.82.0.1", 3075))
    check(got is not None and got.port == oldest and flood[0].key not in rl.consoles,
          "a full pool gives a newcomer the mailbox held longest with no sign-in "
          f"from its address, once held past {grace:.0f}s -- even while its "
          "keepalives keep coming", f"got {got and got.port}, oldest {oldest}")
    rl = _pool(natrelay, 40360, 16)
    flood = [rl.mailbox_for((f"198.18.1.{i}", 3075)).owner for i in range(1, 17)]
    got = rl.mailbox_for(("10.82.0.2", 3075))
    check(got is None and len(rl.consoles) == 16,
          f"CONTROL: inside the {grace:.0f}s nobody's mailbox is taken for a newcomer "
          "from an address that has never signed in")
    getattr(rl, "note_sign_in", nop)("10.83.0.1")
    getattr(rl, "note_sign_out", nop)("10.83.0.1")
    got = rl.mailbox_for(("10.83.0.1", 3075))
    check(got is not None and len(rl.consoles) == 16,
          "a console from an address that signed in within the day takes one at once, "
          "however fresh the flood")

    rl = _pool(natrelay, 40380, 16)
    proven = []
    for i in range(1, 9):
        getattr(rl, "note_sign_in", nop)(f"10.84.0.{i}")
        proven.append(rl.mailbox_for((f"10.84.0.{i}", 3075)).owner)
    stale = [rl.mailbox_for((f"198.18.2.{i}", 3075)).owner for i in range(1, 9)]
    for c in proven + stale:
        _held(c, now - grace - 100, now)
    ports = {c.key: c.mailbox.port for c in proven}
    took = [rl.mailbox_for((f"198.19.0.{i}", 3075)) for i in range(1, 31)]
    check(all(rl.consoles.get(k) is not None and rl.consoles[k].mailbox.port == p
              for k, p in ports.items()),
          "eight consoles whose addresses are signed in keep their mailboxes through "
          "thirty newcomers")
    check(sum(1 for t in took if t) == 8 and not any(c.key in rl.consoles for c in stale),
          "...and the newcomers get exactly the eight nobody signed in for",
          f"{sum(1 for t in took if t)} placed")

    rl = _pool(natrelay, 40400, 16)
    cap = natrelay.PER_ADDRESS_MAX
    same = [rl.mailbox_for(("10.85.0.1", 5000 + i)).owner for i in range(cap)]
    for k, c in enumerate(same):
        _held(c, now - 600, now - k)
    got = rl.mailbox_for(("10.85.0.1", 6000))
    check(got is None and all(c.key in rl.consoles for c in same),
          f"a new endpoint at an address whose {cap} consoles are all talking evicts "
          "none of them")
    same[3].last = now - silence - 10
    got = rl.mailbox_for(("10.85.0.1", 6001))
    check(got is not None and same[3].key not in rl.consoles,
          f"CONTROL: one silent past {silence:.0f}s is recycled for it (a restarted "
          "console behind the same router)")

    rl = _pool(natrelay, 41000, 512)
    for i in range(512):
        rl.mailbox_for((f"198.18.{4 + i // 250}.{i % 250 + 1}", 3075))
    lines.clear()
    t0 = time.perf_counter()
    for i in range(20000):
        rl.mailbox_for((f"100.{64 + i // 65536}.{i // 256 % 256}.{i % 256}", 3075))
    each = (time.perf_counter() - t0) / 20000 * 1e6
    check(len(lines) <= 2 and len(rl.consoles) == 512,
          f"20,000 discoveries turned away by a full pool write {len(lines)} log "
          f"line(s), not one each")
    check(each < 10,
          f"...and cost {each:.1f} us each, not a scan of the pool each")

    print("\n-- relay: a completed sign-in vouches for its address")
    was_log = authserver.log
    authserver.log = lambda *_a, **_k: None
    trusted = getattr(natrelay.RELAY, "trusted", lambda _ip: False)
    try:
        conn = authserver.AuthConnection()
        conn.connection_made(FakeTransport(("10.86.0.1", 5555)))
        conn.is_lsg = True
        conn.pending_ident = ("relayhook", 4242)
        before = trusted("10.86.0.1")
        conn.complete_bind("ownertest")
        during = trusted("10.86.0.1")
        conn.connection_lost(None)
        after = trusted("10.86.0.1")
    finally:
        authserver.log = was_log
    check(not before and during and after and not trusted("10.86.0.2"),
          "a completed bind marks its address for the relay, and the mark outlives "
          "the connection", f"before={before} during={during} after={after}")


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
                    help="only the in-process checks (relay, search, framing, logs, census, reflection, clan rules, identities, DNS, units, config file, firewall, credential locks, the fallback's password change)")
    a = ap.parse_args()

    check = Checks()
    tmp = Path(tempfile.mkdtemp(prefix="wow2-ownertest-"))
    # before seed() first imports serverconfig, or the in-process checks log into the tree
    os.environ.setdefault("WOW2_DATA_DIR", str(tmp / "inproc"))
    if not a.no_server:
        seed(tmp)
        srv = Server(tmp, a.revert)
        try:
            run_server_checks(tmp, srv, check)
        finally:
            srv.stop()
    run_relay_checks(check)
    run_relay_pool_checks(check)
    run_search_relay_checks(check)
    run_search_started_checks(check)
    run_framing_checks(check)
    run_log_checks(check)
    run_census_checks(check)
    run_census_file_checks(check)
    run_reflection_checks(check)
    run_clan_rule_checks(check)
    run_auto_id_checks(check)
    run_nsdns_checks(check)
    run_unit_checks(check)
    run_config_checks(check)
    run_firewall_checks(check)
    run_credential_lock_checks(check)
    run_fallback_change_checks(check)
    print(f"\n{'REVERTED -- ' if a.revert else ''}"
          f"{check.total - check.failed}/{check.total} checks passed")
    if a.keep:
        print(f"scratch dir kept: {tmp}")
    else:
        shutil.rmtree(tmp, ignore_errors=True)
    return 1 if check.failed else 0


if __name__ == "__main__":
    sys.exit(main())
