#!/usr/bin/env python3
"""The SQLite store: one file, `wow2.sqlite3`, in the data directory (§66).

The connection, the schema, the JSON importer and exporter, and the rules
every caller follows: one connection per process, one transaction per handler
(`with store.tx():`), refuse to start on a damaged database or an unreadable
JSON file, import each JSON store once and rename it aside. tools/README.md
"The SQLite store" has the schema and the operator's side.
"""
from __future__ import annotations

import contextlib
import datetime
import json
import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import serverconfig                                             # noqa: E402
from tiger import tiger192                                      # noqa: E402

DB_NAME = "wow2.sqlite3"
SCHEMA_VERSION = 2

STORES: dict[str, str] = {
    "accounts": "accounts.json",
    "friends": "friends-db.json",
    "teams": "teams-db.json",
    "profiles": "profile-db.json",
    "storage": "storage-db.json",
    "stats": "stats-db.json",
    "pots": "pot.json",
}

TABLES: dict[str, tuple[str, ...]] = {
    "accounts": ("accounts",),
    "friends": ("names", "friends", "friend_invites", "blocks", "messages"),
    "teams": ("teams", "team_members", "team_proposals"),
    "profiles": ("profiles",),
    "storage": ("storage",),
    "stats": ("stats",),
    "pots": ("pots",),
}

MIGRATED: tuple[str, ...] = tuple(STORES)

TEAM_ID_BASE = 0x00C1A0_0000_0000

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL);

-- The credential store. `account_id` is gone: it is Tiger192(name)[:8] and
-- nothing else decides it (§65). A row with no pwhash is a name an older
-- server noticed in passing, not an account anybody created; `handle` is the
-- 8 bytes a login request carries, and the unique index is what turns the
-- login's scan of every account into a lookup.
CREATE TABLE IF NOT EXISTS accounts (
    name       TEXT PRIMARY KEY,
    pwhash     TEXT,
    handle     TEXT UNIQUE,
    user_id    INTEGER UNIQUE,
    first_seen TEXT,
    last_seen  TEXT,
    last_ip    TEXT);

-- entity -> display name, for every account any list reply has to label.
CREATE TABLE IF NOT EXISTS names (
    entity TEXT PRIMARY KEY,
    name   TEXT NOT NULL);

-- A buddy pair, stored with a < b so the unique index catches both orders.
-- `seq` keeps the list in the order it was made; it is the rowid.
CREATE TABLE IF NOT EXISTS friends (
    seq INTEGER PRIMARY KEY,
    a   TEXT NOT NULL,
    b   TEXT NOT NULL,
    UNIQUE (a, b));

CREATE TABLE IF NOT EXISTS friend_invites (
    seq       INTEGER PRIMARY KEY,
    from_e    TEXT NOT NULL,
    from_name TEXT,
    to_e      TEXT NOT NULL,
    to_name   TEXT,
    at        TEXT,
    UNIQUE (from_e, to_e));

CREATE TABLE IF NOT EXISTS blocks (
    seq      INTEGER PRIMARY KEY,
    by_e     TEXT NOT NULL,
    who_e    TEXT NOT NULL,
    who_name TEXT,
    at       TEXT,
    UNIQUE (by_e, who_e));

-- The mailbox. Ids come from meta.next_msg, never from the rowid, because a
-- NOTIFICATION takes an id and files no row (notify_id, clan_notify).
CREATE TABLE IF NOT EXISTS messages (
    id        INTEGER PRIMARY KEY,
    to_e      TEXT NOT NULL,
    type      INTEGER NOT NULL,
    from_e    TEXT,
    from_name TEXT,
    session   TEXT,
    clan      TEXT,
    at        TEXT);
CREATE INDEX IF NOT EXISTS messages_to ON messages (to_e);

CREATE TABLE IF NOT EXISTS teams (
    id      TEXT PRIMARY KEY,
    name    TEXT NOT NULL,
    owner   TEXT,
    created TEXT);

-- rank is NULL unless promote/demote set one: team_rank() still answers
-- owner = 2 / member = 0 for a NULL, exactly as it did for a missing key.
CREATE TABLE IF NOT EXISTS team_members (
    seq    INTEGER PRIMARY KEY,
    team   TEXT NOT NULL,
    entity TEXT NOT NULL,
    rank   INTEGER,
    UNIQUE (team, entity));
CREATE INDEX IF NOT EXISTS team_members_entity ON team_members (entity);

CREATE TABLE IF NOT EXISTS team_proposals (
    seq       INTEGER PRIMARY KEY,
    team      TEXT NOT NULL,
    to_e      TEXT NOT NULL,
    from_e    TEXT,
    from_name TEXT,
    at        TEXT,
    UNIQUE (team, to_e));

-- fields is the JSON list of [type, value] pairs the console uploaded; the
-- server hands the same typed fields back and models none of them.
CREATE TABLE IF NOT EXISTS profiles (
    entity TEXT NOT NULL,
    kind   TEXT NOT NULL,
    name   TEXT,
    at     TEXT,
    fields TEXT NOT NULL,
    PRIMARY KEY (entity, kind));

-- One row per file; the bytes are storage/<file>. The primary key is D7:
-- two rows can never share a file id again, because op 5 reaches only the
-- first and op 1's replace step deleted them all. owner NULL = global.
CREATE TABLE IF NOT EXISTS storage (
    id       INTEGER PRIMARY KEY,
    name     TEXT NOT NULL,
    owner    TEXT,
    file     TEXT,
    private  INTEGER NOT NULL DEFAULT 0,
    size     INTEGER,
    created  INTEGER,
    modified INTEGER);
CREATE INDEX IF NOT EXISTS storage_owner ON storage (owner);

-- tail is board 1's [i32][i64 A][i64 B] completion history as the JSON list
-- of [typename, value] pairs the upload carried, NULL on every other board.
-- period is the ISO week / month / year a Weekly, Monthly or Yearly row was
-- written in (§74); a row from an earlier period is read as no row at all.
CREATE TABLE IF NOT EXISTS stats (
    board  INTEGER NOT NULL,
    entity TEXT NOT NULL,
    score  INTEGER NOT NULL,
    name   TEXT,
    tail   TEXT,
    period TEXT,
    PRIMARY KEY (board, entity));
CREATE INDEX IF NOT EXISTS stats_board_score ON stats (board, score DESC);

-- The ranked bank. One live (open or pending) row per session; a session
-- can settle more than once over the life of the server, because session
-- ids restart at 0x5701 with the process, so settled rows are a log.
CREATE TABLE IF NOT EXISTS pots (
    seq     INTEGER PRIMARY KEY,
    session TEXT NOT NULL,
    state   TEXT NOT NULL,
    doc     TEXT NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS pots_live ON pots (session) WHERE state != 'settled';
CREATE INDEX IF NOT EXISTS pots_state ON pots (state);

-- Which Discord user set a name's password through the bot (discordbot.py),
-- so that the same person may reset it again. Additive: a server that
-- predates it ignores the table, so the schema version did not move.
CREATE TABLE IF NOT EXISTS discord_claims (
    handle  TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    name    TEXT NOT NULL,
    at      TEXT NOT NULL);
"""


class StoreError(Exception):
    """The store cannot be used as found. The caller stops; nothing is written."""


# ---------------------------------------------------------------- connection

def path(data_dir: Path | None = None) -> Path:
    return Path(data_dir or serverconfig.DATA_DIR) / DB_NAME


def connect(db_path: Path | str) -> sqlite3.Connection:
    """Open (creating if needed) one database and make sure its schema is there."""
    p = Path(db_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(p), isolation_level=None)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA busy_timeout = 5000")
        conn.execute("PRAGMA journal_mode = WAL")
        conn.execute("PRAGMA synchronous = NORMAL")
        have = conn.execute("SELECT name FROM sqlite_master WHERE type = 'table' "
                            "AND name = 'meta'").fetchone()
        version = int(meta_get(conn, "schema_version", "0")) if have else 0
    except sqlite3.DatabaseError as e:
        conn.close()
        raise StoreError(f"{p} cannot be opened as a database ({e}). Nothing is "
                         f"written to it; restore a `wow2-db backup` copy, or move "
                         f"it aside to start empty.") from e
    _same_owner_as_directory(p)
    if version > SCHEMA_VERSION:
        conn.close()
        raise StoreError(f"{p} is schema version {version}; this server knows "
                         f"{SCHEMA_VERSION}. Newer software wrote it.")
    with tx(conn):
        for statement in _statements(SCHEMA):
            conn.execute(statement)
        _add_columns(conn, "stats", ("period",))
        if 0 < version < 2:
            _rehandle(conn)
        if version < SCHEMA_VERSION:
            meta_set(conn, "schema_version", str(SCHEMA_VERSION))
    return conn


def _add_columns(conn: sqlite3.Connection, table: str, columns: tuple[str, ...]) -> None:
    """CREATE TABLE IF NOT EXISTS leaves an existing table as it was; a column
    added later goes on with ALTER. Additive, so the schema version does not move."""
    have = {r["name"] for r in conn.execute(f"PRAGMA table_info({table})")}
    for col in columns:
        if col not in have:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} TEXT")


def _rehandle(conn: sqlite3.Connection) -> None:
    """Schema 1 -> 2: handles were Tiger192 of the name AS TYPED; the client
    hashes it lowercased, so a name with a capital letter could never sign in.
    Recompute every handle; where two rows differ only by case, the one whose
    old handle already matched the derivation is the one that ever worked.
    """
    rows = conn.execute("SELECT name, handle FROM accounts").fetchall()
    by_new: dict[str, list] = {}
    for r in rows:
        by_new.setdefault(account_handle(r["name"]), []).append(r)
    for new, group in by_new.items():
        if len(group) > 1:
            keep = next((r for r in group if r["handle"] == new), group[0])
            for r in group:
                if r is not keep:
                    conn.execute("DELETE FROM accounts WHERE name = ?", (r["name"],))
                    print(f"  !! store: accounts {r['name']!r} and {keep['name']!r} are one "
                          f"account to the client (same lowercased name); {r['name']!r} "
                          f"could never sign in and is dropped", flush=True)
            group = [keep]
        r = group[0]
        if r["handle"] != new:
            conn.execute("UPDATE accounts SET handle = ? WHERE name = ?", (new, r["name"]))
            print(f"  store: account {r['name']!r} handle {r['handle']} -> {new} "
                  f"(the client hashes the lowercased name)", flush=True)


def _statements(script: str) -> list[str]:
    """The statements of a script, one at a time, comments and all."""
    # not executescript(): that commits the transaction tx() may hold open
    out, buf = [], ""
    for line in script.splitlines(keepends=True):
        buf += line
        if sqlite3.complete_statement(buf):
            out.append(buf.strip())
            buf = ""
    if buf.strip():
        out.append(buf.strip())
    return out


def _same_owner_as_directory(p: Path) -> None:
    """Give the database and its -wal/-shm to the data directory's owner when run as
    root, or a root-run CLI leaves the service unable to open its own store."""
    if os.name != "posix" or os.geteuid() != 0:
        return
    try:
        want = p.parent.stat()
    except OSError:
        return
    for f in (p, p.with_name(p.name + "-wal"), p.with_name(p.name + "-shm")):
        try:
            st = f.stat()
        except OSError:
            continue
        if (st.st_uid, st.st_gid) != (want.st_uid, want.st_gid):
            try:
                os.chown(f, want.st_uid, want.st_gid)
            except OSError:
                pass


_CONN: sqlite3.Connection | None = None
_LOG = print


def set_logger(fn) -> None:
    """Where the import and its warnings are written (the server's log)."""
    global _LOG
    _LOG = fn


def db() -> sqlite3.Connection:
    """The process's connection to the configured data directory's store."""
    global _CONN
    if _CONN is None:
        startup(import_files=False)
    return _CONN


def close() -> None:
    global _CONN
    if _CONN is not None:
        _CONN.close()
        _CONN = None


@contextlib.contextmanager
def tx(conn: sqlite3.Connection | None = None):
    """One transaction. Nest freely: only the outermost begins and commits."""
    conn = conn or db()
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
    except BaseException:
        conn.execute("ROLLBACK")
        raise
    conn.execute("COMMIT")


def meta_get(conn: sqlite3.Connection, key: str, default: str | None = None) -> str | None:
    row = conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
    return row[0] if row else default


def meta_set(conn: sqlite3.Connection, key: str, value: str) -> None:
    conn.execute("INSERT INTO meta (key, value) VALUES (?, ?) "
                 "ON CONFLICT (key) DO UPDATE SET value = excluded.value", (key, value))


def quick_check(conn: sqlite3.Connection) -> str:
    """'ok', or SQLite's own description of the damage."""
    rows = conn.execute("PRAGMA quick_check").fetchall()
    return "; ".join(str(r[0]) for r in rows) or "ok"


def entity_hex(entity: int) -> str:
    return f"{int(entity):016x}"


def canonical_name(name: str) -> str:
    """The name as the client hashes it: ASCII-lowercased (§71d)."""
    return name.encode().lower().decode()


def account_handle(name: str) -> str:
    """Tiger192(lowercased name)[:8], hex -- the 8 bytes a login request carries."""
    return tiger192(canonical_name(name).encode())[:8].hex()


def now_iso() -> str:
    return datetime.datetime.now().isoformat(timespec="seconds")


def _stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


# ---------------------------------------------------------------- the server

def startup(log=None, stores: tuple[str, ...] | None = None,
            data_dir: Path | None = None, import_files: bool = True) -> sqlite3.Connection:
    """What the server calls at startup: connect, check, import what it reads."""
    data_dir = Path(data_dir or serverconfig.DATA_DIR)
    log = log or _LOG
    global _CONN
    if _CONN is None:
        conn = connect(path(data_dir))
        verdict = quick_check(conn)
        if verdict != "ok":
            conn.close()
            raise StoreError(f"{path(data_dir)} fails PRAGMA quick_check: {verdict}. "
                             f"Refusing to start on a damaged store; restore a "
                             f"`wow2-db backup` copy or repair it first.")
        _CONN = conn
    migrate(_CONN, stores if stores is not None else MIGRATED, data_dir, log,
            import_files=import_files)
    return _CONN


def migrate(conn: sqlite3.Connection, stores: tuple[str, ...], data_dir: Path,
            log=print, import_files: bool = True) -> None:
    """Import each named store's JSON file once, then rename it aside."""
    for s in stores:
        jpath = data_dir / STORES[s]
        when = meta_get(conn, f"imported:{s}")
        if when:
            if jpath.exists():
                log(f"  (!! {jpath.name} is present, but {s} was imported into "
                    f"{DB_NAME} on {when}; the file is IGNORED -- the server reads "
                    f"SQLite now. Move it away, or `wow2-db import` it into a "
                    f"fresh database on purpose.)")
            continue
        if jpath.exists() and not import_files:
            raise StoreError(
                f"{jpath} has not been imported into {DB_NAME} yet. This build's "
                f"server does that at its first start; restart it, or run "
                f"`wow2-db import {data_dir}` to move the file in now. Refusing to "
                f"read an empty {s} table in its place.")
        held = sum(table_count(conn, t) for t in TABLES[s])
        if held:
            raise StoreError(
                f"the {s} tables hold {held} row(s) but no import is recorded "
                f"for {s} -- somebody edited meta or copied tables by hand. "
                f"Refusing to import {jpath.name} on top of them.")
        counts: dict[str, int] = {}
        d = load_json(jpath) if jpath.exists() else None
        with tx(conn):
            if d is not None:
                counts = IMPORTERS[s](conn, d, data_dir, log)
            meta_set(conn, f"imported:{s}", now_iso())
        if d is None:
            if import_files:
                log(f"  store: no {jpath.name} to import; {s} starts empty in {DB_NAME}")
            continue
        aside = jpath.with_name(f"{jpath.name}.imported-{_stamp()}")
        try:
            os.replace(jpath, aside)
            where = aside.name
        except OSError as e:
            where = f"(could not be renamed: {e})"
        log(f"  store: imported {jpath.name} -> "
            + ", ".join(f"{t} {n}" for t, n in counts.items())
            + f"; the file is now {where}")


def table_count(conn: sqlite3.Connection, table: str) -> int:
    return int(conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def load_json(p: Path) -> dict:
    """Parse one JSON store, or refuse. A file that does not parse is the only
    copy of its data and is never moved, renamed or written over.
    """
    try:
        raw = p.read_text()
    except OSError as e:
        raise StoreError(f"{p} could not be read: {e}") from e
    try:
        d = json.loads(raw)
    except ValueError as e:
        raise StoreError(f"{p} does not parse as JSON ({e}). Fix it or move it "
                         f"aside; it will not be imported and will not be touched.") from e
    if not isinstance(d, dict):
        raise StoreError(f"{p}: the top level is {type(d).__name__}, not an object")
    return d


# ------------------------------------------------------------------ importers

def _hex_owner(v) -> str | None:
    """A storage owner however the row spelt it: 16-hex, decimal, int, or none."""
    if v in (None, "", 0):
        return None
    if isinstance(v, int):
        return entity_hex(v)
    s = str(v).strip()
    try:
        return entity_hex(int(s, 16) if len(s) == 16 else int(s))
    except ValueError:
        return None


def import_accounts(conn, d: dict, data_dir: Path, log=print) -> dict[str, int]:
    n = 0
    for name, row in d.items():
        if not isinstance(row, dict) or not name:
            log(f"  (!! accounts.json: {name!r} is not an account row -- skipped)")
            continue
        handle = account_handle(name)
        if row.get("handle") and row["handle"] != handle:
            log(f"  (!! accounts.json: {name!r} carries handle {row['handle']} but "
                f"Tiger192(name)[:8] is {handle}; the derivation wins)")
        uid = int(row.get("user_id") or 0) or None
        conn.execute("INSERT INTO accounts (name, pwhash, handle, user_id, first_seen, "
                     "last_seen, last_ip) VALUES (?, ?, ?, ?, ?, ?, ?)",
                     (name, row.get("pwhash") or None, handle, uid,
                      row.get("first_seen"), row.get("last_seen"), row.get("last_ip")))
        n += 1
    return {"accounts": n}


def _message_ids(msgs: list, next_msg: int) -> tuple[list[tuple[int, dict]], int]:
    """(id, message) for each mailbox row, and the next free id."""
    out, used = [], set()
    for m in msgs:
        if not isinstance(m, dict):
            continue
        try:
            mid = int(m.get("id") or 0)
        except (TypeError, ValueError):
            mid = 0
        if mid <= 0 or mid in used:
            mid = max(next_msg, mid + 1)
        used.add(mid)
        next_msg = max(next_msg, mid + 1)
        out.append((mid, m))
    return out, next_msg


def _stats_rows(d: dict) -> list[tuple[str, int, str, int, str, list | None]]:
    """(key, board, entity hex, score, name, tail) for every row that is one."""
    out = []
    for k, row in d.items():
        board, _, ent = str(k).partition(":")
        try:
            board_id, entity = int(board), int(ent, 16)
        except ValueError:
            continue
        if not isinstance(row, list) or not row:
            continue
        try:
            score = int(row[0])
        except (TypeError, ValueError):
            continue
        name = row[2] if len(row) > 2 and isinstance(row[2], str) else ""
        tail = row[3] if len(row) > 3 and isinstance(row[3], list) else None
        out.append((str(k), board_id, entity_hex(entity), score, name, tail))
    return out


def import_friends(conn, d: dict, data_dir: Path, log=print) -> dict[str, int]:
    out = {"names": 0, "friends": 0, "friend_invites": 0, "blocks": 0, "messages": 0}
    for e, name in (d.get("names") or {}).items():
        if isinstance(name, str) and name:
            conn.execute("INSERT OR REPLACE INTO names (entity, name) VALUES (?, ?)",
                         (str(e), name))
            out["names"] += 1
    for pair in d.get("friends") or []:
        if not (isinstance(pair, list) and len(pair) == 2):
            continue
        a, b = sorted(str(x) for x in pair)
        cur = conn.execute("INSERT OR IGNORE INTO friends (a, b) VALUES (?, ?)", (a, b))
        out["friends"] += cur.rowcount
    for i in d.get("invites") or []:
        cur = conn.execute("INSERT OR IGNORE INTO friend_invites (from_e, from_name, to_e, "
                           "to_name, at) VALUES (?, ?, ?, ?, ?)",
                           (i.get("from"), i.get("from_name"), i.get("to"),
                            i.get("to_name"), i.get("at")))
        out["friend_invites"] += cur.rowcount
    for b in d.get("blocked") or []:
        cur = conn.execute("INSERT OR IGNORE INTO blocks (by_e, who_e, who_name, at) "
                           "VALUES (?, ?, ?, ?)",
                           (b.get("by"), b.get("who"), b.get("who_name"), b.get("at")))
        out["blocks"] += cur.rowcount
    rows, next_msg = _message_ids(d.get("messages") or [], int(d.get("next_msg") or 1))
    for mid, m in rows:
        if mid != m.get("id"):
            log(f"  (!! friends-db.json: message id {m.get('id')!r} is taken or "
                f"invalid; filed as {mid})")
        conn.execute("INSERT INTO messages (id, to_e, type, from_e, from_name, session, "
                     "clan, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (mid, m.get("to"), int(m.get("type") or 0), m.get("from"),
                      m.get("from_name"), m.get("session") or "", m.get("clan") or "",
                      m.get("at")))
        out["messages"] += 1
    meta_set(conn, "next_msg", str(next_msg))
    return out


def import_teams(conn, d: dict, data_dir: Path, log=print) -> dict[str, int]:
    out = {"teams": 0, "team_members": 0, "team_proposals": 0}
    if d.get("invite_push_type") is not None:
        meta_set(conn, "invite_push_type", str(int(d["invite_push_type"])))
    nxt = int(d.get("next") or 1)
    for tid, rec in (d.get("teams") or {}).items():
        if not isinstance(rec, dict):
            continue
        try:
            offset = int(tid, 16) - TEAM_ID_BASE
        except ValueError:
            log(f"  (!! teams-db.json: {tid!r} is not a clan id -- skipped)")
            continue
        if 0 < offset < 2 ** 32:
            nxt = max(nxt, offset + 1)
        conn.execute("INSERT INTO teams (id, name, owner, created) VALUES (?, ?, ?, ?)",
                     (tid, rec.get("name") or "", rec.get("owner"), rec.get("created")))
        out["teams"] += 1
        ranks = rec.get("ranks") or {}
        members = [str(m) for m in rec.get("members") or []]
        for m in members:
            rank = ranks.get(m)
            cur = conn.execute("INSERT OR IGNORE INTO team_members (team, entity, rank) "
                               "VALUES (?, ?, ?)",
                               (tid, m, int(rank) if rank is not None else None))
            out["team_members"] += cur.rowcount
        for m in ranks:
            if m not in members:
                log(f"  (!! teams-db.json: {rec.get('name')!r} ranks {m}, who is "
                    f"not a member -- dropped)")
        for p in rec.get("proposals") or []:
            cur = conn.execute("INSERT OR IGNORE INTO team_proposals (team, to_e, from_e, "
                               "from_name, at) VALUES (?, ?, ?, ?, ?)",
                               (tid, p.get("to"), p.get("from"), p.get("from_name"),
                                p.get("at")))
            out["team_proposals"] += cur.rowcount
    meta_set(conn, "teams_next", str(nxt))
    return out


def import_profiles(conn, d: dict, data_dir: Path, log=print) -> dict[str, int]:
    n = 0
    for kind, recs in d.items():
        if kind not in ("public", "private") or not isinstance(recs, dict):
            log(f"  (!! profile-db.json: unexpected key {kind!r} -- skipped)")
            continue
        for e, rec in recs.items():
            if not isinstance(rec, dict):
                continue
            conn.execute("INSERT OR REPLACE INTO profiles (entity, kind, name, at, fields) "
                         "VALUES (?, ?, ?, ?, ?)",
                         (str(e), kind, rec.get("name"), rec.get("at"),
                          json.dumps(rec.get("fields") or [])))
            n += 1
    return {"profiles": n}


def import_storage(conn, d: dict, data_dir: Path, log=print) -> dict[str, int]:
    """Rows only; the bytes are files. A row with inline `data` is written out to
    storage/<id:x>-<name> so every row is a file."""
    n = 0
    blobs = Path(data_dir) / "storage"
    for f in d.get("files") or []:
        if not isinstance(f, dict):
            continue
        try:
            fid = int(f.get("id") or 0)
        except (TypeError, ValueError):
            fid = 0
        if fid <= 0:
            log(f"  (!! storage-db.json: row {f.get('name')!r} has no usable id -- "
                f"skipped; 0 is the client's 'no id' sentinel)")
            continue
        if conn.execute("SELECT 1 FROM storage WHERE id = ?", (fid,)).fetchone():
            raise StoreError(f"storage-db.json has two rows with file id 0x{fid:x} "
                             f"(D7). Op 5 could only ever reach the first; decide "
                             f"which one to keep and renumber the other before "
                             f"importing.")
        name = str(f.get("name") or "")
        file = f.get("file")
        size = f.get("size")
        if f.get("data") is not None:
            data = str(f["data"]).encode("latin1", "replace")
            file = f"{fid:x}-{name}"
            blobs.mkdir(parents=True, exist_ok=True)
            target = blobs / file
            if target.exists() and target.read_bytes() != data:
                raise StoreError(f"storage-db.json row 0x{fid:x} {name!r} carries "
                                 f"inline data, and {target} already exists with "
                                 f"different bytes -- not overwriting it")
            if not target.exists():
                tmp = target.with_name(target.name + f".tmp-{os.getpid()}")
                tmp.write_bytes(data)
                os.replace(tmp, target)
            size = len(data)
        conn.execute("INSERT INTO storage (id, name, owner, file, private, size, created, "
                     "modified) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (fid, name, _hex_owner(f.get("owner")), file,
                      1 if f.get("private") else 0,
                      int(size) if size is not None else None,
                      int(f["created"]) if f.get("created") is not None else None,
                      int(f["modified"]) if f.get("modified") is not None else None))
        n += 1
    return {"storage": n}


def import_stats(conn, d: dict, data_dir: Path, log=print) -> dict[str, int]:
    rows = _stats_rows(d)
    kept = {k for k, *_ in rows}
    for k in d:
        if k not in kept:
            log(f"  (!! stats-db.json: {k!r} is not a board:entity row with a score "
                f"-- skipped)")
    for _k, board_id, entity, score, name, tail in rows:
        conn.execute("INSERT OR REPLACE INTO stats (board, entity, score, name, tail) "
                     "VALUES (?, ?, ?, ?, ?)",
                     (board_id, entity, score, name,
                      json.dumps(tail) if tail is not None else None))
    return {"stats": len(rows)}


def import_pots(conn, d: dict, data_dir: Path, log=print) -> dict[str, int]:
    n = 0
    if isinstance(d.get("policy"), dict):
        meta_set(conn, "pot_policy", json.dumps(d["policy"]))
    for state in ("open", "pending"):
        for k, rec in (d.get(state) or {}).items():
            conn.execute("INSERT INTO pots (session, state, doc) VALUES (?, ?, ?)",
                         (str(k), state, json.dumps(rec)))
            n += 1
    for rec in d.get("settled") or []:
        conn.execute("INSERT INTO pots (session, state, doc) VALUES (?, ?, ?)",
                     (str(rec.get("session") or "?"), "settled", json.dumps(rec)))
        n += 1
    return {"pots": n}


IMPORTERS = {
    "accounts": import_accounts,
    "friends": import_friends,
    "teams": import_teams,
    "profiles": import_profiles,
    "storage": import_storage,
    "stats": import_stats,
    "pots": import_pots,
}


def import_dir(conn: sqlite3.Connection, src: Path, data_dir: Path,
               stores: tuple[str, ...] | None = None, log=print,
               rename: bool = False) -> dict[str, dict[str, int]]:
    """`wow2-db import DIR`: every JSON store found in DIR, in one transaction."""
    src = Path(src)
    done: dict[str, dict[str, int]] = {}
    with tx(conn):
        for s in stores or tuple(STORES):
            jpath = src / STORES[s]
            if not jpath.exists():
                continue
            held = sum(table_count(conn, t) for t in TABLES[s])
            if held:
                raise StoreError(f"the {s} tables already hold {held} row(s); import "
                                 f"into a fresh database (--db) instead")
            done[s] = IMPORTERS[s](conn, load_json(jpath), data_dir, log)
            meta_set(conn, f"imported:{s}", now_iso())
    if rename:
        for s in done:
            jpath = src / STORES[s]
            try:
                os.replace(jpath, jpath.with_name(f"{jpath.name}.imported-{_stamp()}"))
            except OSError as e:
                log(f"  (!! {jpath.name} imported but could not be renamed: {e})")
    return done


# ------------------------------------------------------------------ exporters

def _dict(row: sqlite3.Row, *keys: str) -> dict:
    """The named columns of a row, minus the NULLs."""
    return {k: row[k] for k in keys if row[k] is not None}


def export_accounts(conn) -> dict:
    out = {}
    for r in conn.execute("SELECT * FROM accounts ORDER BY name"):
        out[r["name"]] = _dict(r, "pwhash", "handle", "user_id", "first_seen",
                               "last_seen", "last_ip")
    return out


def export_friends(conn) -> dict:
    return {
        "names": {r["entity"]: r["name"] for r in
                  conn.execute("SELECT * FROM names ORDER BY entity")},
        "friends": [[r["a"], r["b"]] for r in
                    conn.execute("SELECT * FROM friends ORDER BY seq")],
        "invites": [{"from": r["from_e"], "from_name": r["from_name"] or "",
                     "to": r["to_e"], "to_name": r["to_name"] or "", "at": r["at"] or ""}
                    for r in conn.execute("SELECT * FROM friend_invites ORDER BY seq")],
        "blocked": [{"by": r["by_e"], "who": r["who_e"], "who_name": r["who_name"] or "",
                     "at": r["at"] or ""}
                    for r in conn.execute("SELECT * FROM blocks ORDER BY seq")],
        "messages": [{"id": r["id"], "to": r["to_e"], "type": r["type"],
                      "from": r["from_e"], "from_name": r["from_name"] or "",
                      "session": r["session"] or "", "clan": r["clan"] or "",
                      "at": r["at"] or ""}
                     for r in conn.execute("SELECT * FROM messages ORDER BY id")],
        "next_msg": int(meta_get(conn, "next_msg", "1")),
    }


def export_teams(conn) -> dict:
    teams = {}
    for t in conn.execute("SELECT * FROM teams ORDER BY id"):
        members = conn.execute("SELECT entity, rank FROM team_members WHERE team = ? "
                               "ORDER BY seq", (t["id"],)).fetchall()
        rec = {"name": t["name"], "owner": t["owner"],
               "members": [m["entity"] for m in members],
               "proposals": [{"to": p["to_e"], "from": p["from_e"],
                              "from_name": p["from_name"] or "", "at": p["at"] or ""}
                             for p in conn.execute(
                                 "SELECT * FROM team_proposals WHERE team = ? "
                                 "ORDER BY seq", (t["id"],))],
               "created": t["created"] or ""}
        ranks = {m["entity"]: m["rank"] for m in members if m["rank"] is not None}
        if ranks:
            rec["ranks"] = ranks
        teams[t["id"]] = rec
    out = {"next": int(meta_get(conn, "teams_next", "1")), "teams": teams}
    ptype = meta_get(conn, "invite_push_type")
    if ptype is not None:
        out["invite_push_type"] = int(ptype)
    return out


def export_profiles(conn) -> dict:
    out: dict = {"public": {}}
    for r in conn.execute("SELECT * FROM profiles ORDER BY kind, entity"):
        out.setdefault(r["kind"], {})[r["entity"]] = {
            "name": r["name"] or "", "at": r["at"] or "", "fields": json.loads(r["fields"])}
    return out


def export_storage(conn) -> dict:
    files = []
    for r in conn.execute("SELECT * FROM storage ORDER BY id"):
        rec = {"id": r["id"], "name": r["name"], "private": bool(r["private"])}
        rec.update(_dict(r, "owner", "file", "size", "created", "modified"))
        files.append(rec)
    return {"files": files}


def export_stats(conn) -> dict:
    out = {}
    for r in conn.execute("SELECT * FROM stats ORDER BY board, score DESC, entity"):
        rank = 1 + conn.execute("SELECT COUNT(*) FROM stats WHERE board = ? AND score > ?",
                                (r["board"], r["score"])).fetchone()[0]
        row: list = [r["score"], rank, r["name"] or ""]
        if r["tail"]:
            row.append(json.loads(r["tail"]))
        out[f"{r['board']}:{r['entity']}"] = row
    return out


def export_pots(conn) -> dict:
    out: dict = {"open": {}, "pending": {}, "settled": []}
    policy = meta_get(conn, "pot_policy")
    if policy:
        out["policy"] = json.loads(policy)
    for r in conn.execute("SELECT * FROM pots ORDER BY seq"):
        doc = json.loads(r["doc"])
        if r["state"] == "settled":
            out["settled"].append(doc)
        else:
            out[r["state"]][r["session"]] = doc
    return out


EXPORTERS = {
    "accounts": export_accounts,
    "friends": export_friends,
    "teams": export_teams,
    "profiles": export_profiles,
    "storage": export_storage,
    "stats": export_stats,
    "pots": export_pots,
}


def export_dir(conn: sqlite3.Connection, dst: Path,
               stores: tuple[str, ...] | None = None) -> dict[str, Path]:
    """`wow2-db export DIR`: the seven JSON files, written atomically."""
    dst = Path(dst)
    dst.mkdir(parents=True, exist_ok=True)
    written = {}
    for s in stores or tuple(STORES):
        p = dst / STORES[s]
        tmp = p.with_name(p.name + f".tmp-{os.getpid()}")
        tmp.write_text(json.dumps(EXPORTERS[s](conn), indent=1, sort_keys=True) + "\n")
        os.replace(tmp, p)
        written[s] = p
    return written


# ------------------------------------------------------------------- checking

def check(conn: sqlite3.Connection, data_dir: Path) -> tuple[list[str], list[str]]:
    """(findings, notes). A finding is something an operator should act on."""
    bad, notes = [], []
    verdict = quick_check(conn)
    if verdict != "ok":
        bad.append(f"PRAGMA quick_check: {verdict}")
    notes.append(f"schema version {meta_get(conn, 'schema_version', '?')}")
    for s in STORES:
        when = meta_get(conn, f"imported:{s}")
        counts = ", ".join(f"{t} {table_count(conn, t)}" for t in TABLES[s])
        notes.append(f"{s:9s} {counts}" + (f"   (imported {when})" if when else
                                            "   (not imported: this build still "
                                            "reads its JSON file)"))
    blobs = Path(data_dir) / "storage"
    for r in conn.execute("SELECT id, name, file FROM storage ORDER BY id"):
        if not r["file"] or not (blobs / r["file"]).is_file():
            bad.append(f"storage row 0x{r['id']:x} {r['name']!r}: no bytes at "
                       f"storage/{r['file'] or '?'} (served as an empty file)")
    for t in conn.execute("SELECT id, name, owner FROM teams"):
        if not conn.execute("SELECT 1 FROM team_members WHERE team = ? AND entity = ?",
                            (t["id"], t["owner"])).fetchone():
            bad.append(f"clan {t['name']!r} {t['id']}: the owner is not a member")
    ptype = int(meta_get(conn, "invite_push_type", "13"))
    for p in conn.execute("SELECT p.team, p.to_e, t.name FROM team_proposals p "
                          "JOIN teams t ON t.id = p.team"):
        blob = int(p["team"], 16).to_bytes(8, "little").hex()
        if not conn.execute("SELECT 1 FROM messages WHERE to_e = ? AND type = ? "
                            "AND session = ?", (p["to_e"], ptype, blob)).fetchone():
            bad.append(f"clan {p['name']!r} invite to {p['to_e']} has no mailbox row "
                       f"(an invite is TWO pieces of state; only one is here)")
    named = {r[0] for r in conn.execute("SELECT entity FROM names")}
    referenced = set()
    for sql in ("SELECT a FROM friends", "SELECT b FROM friends",
                "SELECT by_e FROM blocks", "SELECT who_e FROM blocks",
                "SELECT from_e FROM friend_invites", "SELECT to_e FROM friend_invites",
                "SELECT entity FROM team_members"):
        referenced |= {r[0] for r in conn.execute(sql)}
    nameless = sorted(referenced - named)
    if nameless:
        notes.append(f"{len(nameless)} entity(ies) in a list with no name on file "
                     f"(listed as 'unknown account'): {', '.join(nameless[:6])}"
                     + (" ..." if len(nameless) > 6 else ""))
    return bad, notes


# ---------------------------------------------------------------- round trip

def _canon(store: str, d: dict, log=print) -> object:
    """A JSON store reduced to what the import keeps, so that the JSON as
    found and the JSON as exported can be compared field by field.
    """
    if store == "accounts":
        out = {}
        for name, row in d.items():
            if not isinstance(row, dict):
                continue
            row = dict(row)
            aid = row.pop("account_id", None)
            if aid is not None and entity_hex(aid) != _derived_id(name):
                log(f"  note: accounts.json {name!r} account_id {aid:#x} != "
                    f"derivation {_derived_id(name)} (dropped either way; §65)")
            row.setdefault("handle", account_handle(name))
            if not row.get("user_id"):
                row.pop("user_id", None)
            if not row.get("pwhash"):
                row.pop("pwhash", None)
            out[name] = row
        return out
    if store == "friends":
        rows, next_msg = _message_ids(d.get("messages") or [], int(d.get("next_msg") or 1))
        msgs = [{"id": mid, "to": m.get("to"), "type": m.get("type"),
                 "from": m.get("from"), "from_name": m.get("from_name") or "",
                 "session": m.get("session") or "", "clan": m.get("clan") or "",
                 "at": m.get("at") or ""} for mid, m in rows]
        pairs = {tuple(sorted(map(str, p))) for p in d.get("friends") or []
                 if isinstance(p, list) and len(p) == 2}
        return {"names": d.get("names") or {},
                "friends": sorted(list(p) for p in pairs),
                "invites": [{"from": i.get("from"), "from_name": i.get("from_name") or "",
                             "to": i.get("to"), "to_name": i.get("to_name") or "",
                             "at": i.get("at") or ""} for i in d.get("invites") or []],
                "blocked": [{"by": b.get("by"), "who": b.get("who"),
                             "who_name": b.get("who_name") or "", "at": b.get("at") or ""}
                            for b in d.get("blocked") or []],
                "messages": msgs, "next_msg": next_msg}
    if store == "teams":
        teams, nxt = {}, int(d.get("next") or 1)
        for tid, rec in (d.get("teams") or {}).items():
            try:
                offset = int(tid, 16) - TEAM_ID_BASE
            except ValueError:
                continue
            if 0 < offset < 2 ** 32:
                nxt = max(nxt, offset + 1)
            teams[tid] = {
                "name": rec.get("name") or "", "owner": rec.get("owner"),
                "members": [str(m) for m in rec.get("members") or []],
                "proposals": [{"to": p.get("to"), "from": p.get("from"),
                               "from_name": p.get("from_name") or "", "at": p.get("at") or ""}
                              for p in rec.get("proposals") or []],
                "created": rec.get("created") or ""}
            ranks = {m: r for m, r in (rec.get("ranks") or {}).items()
                     if m in teams[tid]["members"] and r is not None}
            if ranks:
                teams[tid]["ranks"] = ranks
        out = {"next": nxt, "teams": teams}
        if d.get("invite_push_type") is not None:
            out["invite_push_type"] = int(d["invite_push_type"])
        return out
    if store == "profiles":
        out = {"public": {}}
        for kind in ("public", "private"):
            for e, rec in (d.get(kind) or {}).items():
                if isinstance(rec, dict):
                    out.setdefault(kind, {})[e] = {"name": rec.get("name") or "",
                                                   "at": rec.get("at") or "",
                                                   "fields": rec.get("fields") or []}
        return out
    if store == "storage":
        out = {}
        for f in d.get("files") or []:
            try:
                fid = int(f.get("id") or 0)
            except (TypeError, ValueError):
                fid = 0
            if fid <= 0:
                continue
            rec = {k: v for k, v in f.items()
                   if not k.startswith("_") and k not in ("data", "owner", "id")}
            rec["private"] = bool(f.get("private"))
            owner = _hex_owner(f.get("owner"))
            if owner:
                rec["owner"] = owner
            if f.get("data") is not None:
                rec["file"] = f"{fid:x}-{f.get('name')}"
                rec["size"] = len(str(f["data"]).encode("latin1", "replace"))
            out[fid] = rec
        return out
    if store == "stats":
        return {f"{board}:{entity}": [score, name] + ([tail] if tail is not None else [])
                for _k, board, entity, score, name, tail in _stats_rows(d)}
    if store == "pots":
        out = {"open": d.get("open") or {}, "pending": d.get("pending") or {},
               "settled": d.get("settled") or []}
        if isinstance(d.get("policy"), dict):
            out["policy"] = d["policy"]
        return out
    raise KeyError(store)


def _derived_id(name: str) -> str:
    return entity_hex(int.from_bytes(tiger192(name.encode())[:8], "little"))


def _diff(a, b, at="") -> list[str]:
    """The paths at which two JSON values differ, first few."""
    if type(a) is not type(b) and not (isinstance(a, (int, float)) and
                                       isinstance(b, (int, float))):
        return [f"{at or '/'}: {a!r} != {b!r}"]
    if isinstance(a, dict):
        out = []
        for k in sorted(set(a) | set(b), key=str):
            if k not in a:
                out.append(f"{at}/{k}: only in the export: {b[k]!r}")
            elif k not in b:
                out.append(f"{at}/{k}: only in the original: {a[k]!r}")
            else:
                out += _diff(a[k], b[k], f"{at}/{k}")
        return out
    if isinstance(a, list):
        if len(a) != len(b):
            return [f"{at or '/'}: {len(a)} item(s) in the original, {len(b)} exported"]
        out = []
        for i, (x, y) in enumerate(zip(a, b)):
            out += _diff(x, y, f"{at}[{i}]")
        return out
    return [] if a == b else [f"{at or '/'}: {a!r} != {b!r}"]


def roundtrip(src: Path, work: Path, log=print) -> tuple[list[str], list[str]]:
    """Import the JSON stores in `src` into a scratch database under `work`,
    export them again, and compare. Returns (failures, report lines).
    """
    src, work = Path(src), Path(work)
    conn = connect(work / DB_NAME)
    try:
        done = import_dir(conn, src, work, log=log)
        out = work / "export"
        export_dir(conn, out)
        fails, report = [], []
        for s in STORES:
            if s not in done:
                report.append(f"  {s:9s} no {STORES[s]} in {src}")
                continue
            before = _canon(s, load_json(src / STORES[s]), log)
            after = _canon(s, load_json(out / STORES[s]), log)
            diffs = _diff(before, after)
            if s == "storage":
                for f in load_json(src / STORES[s]).get("files") or []:
                    if isinstance(f, dict) and f.get("data") is not None and f.get("id"):
                        p = work / "storage" / f"{int(f['id']):x}-{f.get('name')}"
                        want = str(f["data"]).encode("latin1", "replace")
                        if not p.is_file() or p.read_bytes() != want:
                            diffs.append(f"/{f['id']}: inline data not written to {p.name}")
            if s == "stats":
                a = load_json(src / STORES[s])
                b = load_json(out / STORES[s])
                stale = [k for k in a if k in b and isinstance(a[k], list)
                         and len(a[k]) > 1 and a[k][1] != b[k][1]]
                if stale:
                    report.append(f"  {s:9s} note: {len(stale)} row(s) carried a rank "
                                  f"the board no longer supports (recomputed)")
            n = ", ".join(f"{t} {c}" for t, c in done[s].items())
            if diffs:
                fails.append(s)
                report.append(f"  {s:9s} FAIL  ({n}) -- {len(diffs)} difference(s):")
                report += [f"      {x}" for x in diffs[:12]]
            else:
                report.append(f"  {s:9s} ok    ({n})")
        return fails, report
    finally:
        conn.close()
