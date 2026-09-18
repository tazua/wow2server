#!/usr/bin/env python3
"""Does the SQLite store keep what the JSON stores held, and refuse what it
must? No emulator, no server process: the module is exercised directly on a
scratch directory (§66 step 1).

    storetest.py            # every check
    storetest.py --keep     # leave the scratch directory behind
"""
from __future__ import annotations

import argparse
import json
import shutil
import sqlite3
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import store                                                    # noqa: E402

RESULTS: list[tuple[bool, str]] = []


def check(cond: bool, what: str) -> bool:
    RESULTS.append((bool(cond), what))
    print(f"  {'ok  ' if cond else 'FAIL'} {what}")
    return bool(cond)


def quiet(_msg: str) -> None:
    pass


A, B, C, D = "975367efa4bbebed", "bb4dc191b75e31fc", "5ed7f893cb52b73e", "1826615a58bc65cd"


def fixture(d: Path) -> None:
    """The seven stores as the server wrote them, plus the corners."""
    d.mkdir(parents=True, exist_ok=True)
    (d / "accounts.json").write_text(json.dumps({
        "player1": {"account_id": 0x975367efa4bbebed, "first_seen": "2026-09-11T20:41:18"},
        "testuser": {"account_id": 0xbb4dc191b75e31fc, "first_seen": "2026-09-11T20:33:28",
                     "handle": "fc315eb791c14dbb", "last_ip": "10.42.0.2",
                     "last_seen": "2026-09-11T20:39:16", "pwhash": "ab" * 24, "user_id": 2},
        "stranger1": {"first_seen": "2026-09-15T01:00:00", "pwhash": "cd" * 24,
                      "user_id": 100, "handle": store.account_handle("stranger1")},
    }))
    (d / "friends-db.json").write_text(json.dumps({
        "names": {A: "player1", B: "testuser", C: "player3", D: "player5"},
        "friends": [[A, B], [B, A], [C, D]],
        "invites": [{"from": C, "from_name": "player3", "to": A, "to_name": "player1",
                     "at": "10:00:00.000"}],
        "blocked": [{"by": D, "who": C, "who_name": "player3", "at": "10:01:00.000"}],
        "messages": [{"id": 7, "to": A, "type": 1, "from": C, "from_name": "player3",
                      "session": "", "clan": "", "at": "10:00:00.001"},
                     {"id": 7, "to": B, "type": 5, "from": A, "from_name": "player1",
                      "session": "0157000000000000", "clan": "", "at": "10:02:00.000"},
                     {"id": 9, "to": D, "type": 13, "from": A, "from_name": "player1",
                      "session": "1400000000a0c100", "clan": "wormstest",
                      "at": "10:03:00.000"}],
        "next_msg": 5,
    }))
    (d / "teams-db.json").write_text(json.dumps({
        "invite_push_type": 13, "next": 3,
        "teams": {
            "0000c1a000000014": {"name": "wormstest", "owner": A, "members": [A, B],
                                 "proposals": [{"to": D, "from": A, "from_name": "player1",
                                                "at": "10:03:00.000"}],
                                 "created": "15:37:11.449",
                                 "ranks": {B: 1, C: 1}},
            "c1a0c1a0c1a0c1a1": {"name": "faraway", "owner": C, "members": [C],
                                 "created": "16:00:00.000"},
        },
    }))
    (d / "profile-db.json").write_text(json.dumps({"public": {
        A: {"at": "16:56:31.505", "name": "player1",
            "fields": [[9, 0], [9, 0], [9, 0], [9, 0], [14, -15.0], [14, 62.0], [9, 0],
                       [16, "hi"], [7, 0]]},
        "0000000000000003": {"at": "16:56:31.505", "name": "player3",
                             "fields": [[9, 1], [19, "0011"]]},
    }}))
    (d / "storage-db.json").write_text(json.dumps({
        "_comment": "documentation the import drops",
        "files": [
            {"id": 1, "name": "readme.txt", "file": "readme.txt", "private": False,
             "created": 1189000000, "modified": 1189000000},
            {"id": 20, "name": "dayc50w.sl0", "data": "MOIKlandscape-slot0", "owner": D,
             "private": False, "created": 1189000000, "modified": 1189000000},
            {"id": 20481, "name": "xyzzy.ufd", "file": "5001-xyzzy.ufd", "owner": B,
             "private": False, "size": 1340},
            {"_comment": "a decimal owner, as an old upload wrote it",
             "id": 20482, "name": "scoreboard0.dat", "file": "5002-scoreboard0.dat",
             "owner": str(int(A, 16)), "private": False, "size": 235,
             "created": 1789284604, "modified": 1789286210},
            {"name": "no-id.sl0", "data": "dropped", "owner": A},
        ],
    }))
    (d / "stats-db.json").write_text(json.dumps({
        f"5:{A}": [4649, 1, "player1"], f"5:{B}": [2771, 2, "testuser"],
        f"5:{C}": [2771, 0, "player3"],
        f"1:{A}": [28, 1, "player1", [["i32", 0], ["i64", 201326592], ["i64", 0]]],
        f"2:{D}": [1000, 1, "player5"],
        "garbage": [1, 1, "x"],
    }))
    (d / "pot.json").write_text(json.dumps({
        "open": {"5701": {"session": "5701", "opened": "17:10:39.599", "host": "player1",
                          "stakes": {A: {"name": "player1", "before": 4342, "after": 3908,
                                         "stake": 434, "at": "17:16:00.784"}}}},
        "pending": {"5702": {"session": "5702", "opened": "18:00:00.000", "host": "player1",
                             "stakes": {}, "ended": "18:10:00.000", "deadline": 1789000000.5}},
        "policy": {"payout": "winner-takes-all", "unresolved": "refund",
                   "placing": [0.6, 0.25, 0.15]},
        "settled": [{"session": "5701", "pot": 741, "settled": "client", "stakes": {},
                     "winner": {"entity": A, "name": "player1", "gain": 741}},
                    {"session": "5701", "pot": 200, "settled": "award", "stakes": {}}],
    }))


def run(keep: bool) -> int:
    root = Path(tempfile.mkdtemp(prefix="wow2-storetest-"))
    try:
        # ------------------------------------------------------- round trip
        print("round trip")
        src = root / "json"
        fixture(src)
        fails, report = store.roundtrip(src, root / "rt", log=quiet)
        for line in report:
            print("   " + line.strip())
        check(not fails, "every store round-trips field by field")
        conn = store.connect(root / "rt" / store.DB_NAME)
        check(conn.execute("SELECT COUNT(*) FROM friends").fetchone()[0] == 2,
              "the reversed duplicate buddy pair is one row")
        ids = [r[0] for r in conn.execute("SELECT id FROM messages ORDER BY id")]
        check(ids == [7, 8, 9] and store.meta_get(conn, "next_msg") == "10",
              f"colliding message id re-filed and next_msg moved past every row ({ids})")
        check(store.meta_get(conn, "teams_next") == "21",
              "teams_next follows the highest id in the window, not the far-away one")
        check(conn.execute("SELECT rank FROM team_members WHERE entity = ?",
                           (B,)).fetchone()[0] == 1
              and conn.execute("SELECT COUNT(*) FROM team_members WHERE entity = ?",
                               (C,)).fetchone()[0] == 1,
              "a rank override lands on the member; the non-member's is dropped")
        check(conn.execute("SELECT owner FROM storage WHERE id = 20482").fetchone()[0] == A,
              "a decimal owner is stored as the 16-hex-digit entity")
        blob = root / "rt" / "storage" / "14-dayc50w.sl0"
        check(blob.is_file() and blob.read_bytes() == b"MOIKlandscape-slot0"
              and conn.execute("SELECT file, size FROM storage WHERE id = 20").fetchone()[:]
              == ("14-dayc50w.sl0", 19),
              "inline data is written to storage/<id:x>-<name> and the row points at it")
        check(conn.execute("SELECT COUNT(*) FROM storage").fetchone()[0] == 4,
              "a row with no id is not imported")
        check(conn.execute("SELECT COUNT(*) FROM stats").fetchone()[0] == 5,
              "a stats key that is not board:entity is not imported")
        exp = json.loads((root / "rt" / "export" / "stats-db.json").read_text())
        check(exp[f"5:{B}"][1] == 2 and exp[f"5:{C}"][1] == 2 and exp[f"5:{A}"][1] == 1,
              "the exported rank is recomputed, ties sharing one")
        states = [tuple(r) for r in conn.execute(
            "SELECT session, state FROM pots ORDER BY seq")]
        check(states == [("5701", "open"), ("5702", "pending"), ("5701", "settled"),
                         ("5701", "settled")],
              "pots keep their state, and a session may settle more than once")
        bad, notes = store.check(conn, root / "rt")
        check(any("readme.txt" in b for b in bad) and any("wormstest" in b for b in bad),
              "check reports a row with no bytes and a proposal with no mailbox row")
        conn.close()

        # ---------------------------------------------------------- startup
        print("startup")
        store.close()
        data = root / "data"
        fixture(data)
        logs: list[str] = []
        store.startup(log=logs.append, stores=("stats", "pots"), data_dir=data)
        check(not (data / "stats-db.json").exists() and not (data / "pot.json").exists()
              and len(list(data.glob("stats-db.json.imported-*"))) == 1,
              "a migrated store's file is imported and renamed aside")
        check((data / "friends-db.json").exists() and (data / "accounts.json").exists(),
              "a store this build does not read from SQLite is left alone")
        conn = store.db()
        check(conn.execute("SELECT COUNT(*) FROM stats").fetchone()[0] == 5
              and conn.execute("SELECT COUNT(*) FROM names").fetchone()[0] == 0,
              "only the migrated stores' tables were filled")
        check(any("imported stats-db.json" in m for m in logs),
              "the import is logged with its row counts")
        (data / "pot.json").write_text("{}")
        logs.clear()
        store.startup(log=logs.append, stores=("stats", "pots"), data_dir=data)
        check((data / "pot.json").exists() and any("IGNORED" in m for m in logs)
              and conn.execute("SELECT COUNT(*) FROM pots").fetchone()[0] == 4,
              "a JSON file that reappears after its import is ignored, loudly")
        (data / "profile-db.json").unlink()
        logs.clear()
        store.startup(log=logs.append, stores=("profiles",), data_dir=data)
        check(store.meta_get(conn, "imported:profiles") is not None
              and any("starts empty" in m for m in logs),
              "a missing file marks the store imported and starts it empty")
        (data / "friends-db.json").write_text("{not json")
        try:
            store.startup(log=quiet, stores=("friends",), data_dir=data)
            refused = False
        except store.StoreError:
            refused = True
        check(refused and (data / "friends-db.json").read_text() == "{not json"
              and store.meta_get(conn, "imported:friends") is None,
              "an unreadable JSON store refuses to start and is left where it is")
        store.close()
        (data / "storage-db.json").write_text(json.dumps({"files": []}))
        try:
            store.startup(log=quiet, stores=("storage",), data_dir=data, import_files=False)
            refused = False
        except store.StoreError as e:
            refused = "wow2-db import" in str(e)
        check(refused and (data / "storage-db.json").exists()
              and store.meta_get(store.db(), "imported:storage") is None,
              "a CLI that finds a store's file still un-imported refuses rather than "
              "importing it out from under a running server")
        conn = store.db()
        with store.tx(conn):
            conn.execute("INSERT INTO teams (id, name) VALUES ('0000c1a000000001', 'x')")
        try:
            store.startup(log=quiet, stores=("teams",), data_dir=data)
            refused = False
        except store.StoreError:
            refused = True
        check(refused and (data / "teams-db.json").exists(),
              "tables that hold rows with no import recorded refuse to import over them")

        # ------------------------------------------------------ transactions
        print("transactions")
        with store.tx(conn):
            conn.execute("INSERT INTO names (entity, name) VALUES ('01', 'outer')")
            with store.tx(conn):
                conn.execute("INSERT INTO names (entity, name) VALUES ('02', 'inner')")
            check(conn.in_transaction, "a nested tx() does not commit the outer one")
        check(conn.execute("SELECT COUNT(*) FROM names").fetchone()[0] == 2
              and not conn.in_transaction, "the outermost tx() commits both writes")
        try:
            with store.tx(conn):
                conn.execute("INSERT INTO names (entity, name) VALUES ('03', 'lost')")
                with store.tx(conn):
                    raise RuntimeError("halfway")
        except RuntimeError:
            pass
        check(conn.execute("SELECT COUNT(*) FROM names").fetchone()[0] == 2
              and not conn.in_transaction,
              "an exception inside a nested tx() rolls the whole transaction back")
        try:
            with store.tx(conn):
                conn.execute("INSERT INTO storage (id, name) VALUES (7, 'a.flg')")
                conn.execute("INSERT INTO storage (id, name) VALUES (7, 'b.flg')")
            dup = False
        except sqlite3.IntegrityError:
            dup = True
        check(dup and conn.execute("SELECT COUNT(*) FROM storage WHERE id = 7")
              .fetchone()[0] == 0, "two rows cannot share a file id (D7), and the "
              "refused transaction leaves nothing behind")
        try:
            store.import_dir(conn, src, data, stores=("storage",), log=quiet)
            store.import_dir(conn, src, data, stores=("storage",), log=quiet)
            twice = False
        except store.StoreError:
            twice = True
        check(twice, "wow2-db import refuses a store whose tables already hold rows")
        d2 = root / "dup"
        fixture(d2)
        rows = json.loads((d2 / "storage-db.json").read_text())
        rows["files"].append({"id": 20481, "name": "again.ufd", "file": "x"})
        (d2 / "storage-db.json").write_text(json.dumps(rows))
        try:
            store.import_dir(store.connect(root / "dup.sqlite3"), d2, root, log=quiet)
            refused = False
        except store.StoreError as e:
            refused = "0x5001" in str(e)
        check(refused, "an import that meets two rows with one file id refuses, naming it")

        # ------------------------------------------------------------ backup
        print("backup and check")
        copy = sqlite3.connect(str(root / "backup.sqlite3"))
        with copy:
            conn.backup(copy)
        check(store.quick_check(copy) == "ok"
              and copy.execute("SELECT COUNT(*) FROM stats").fetchone()[0] == 5,
              "a backup copy passes quick_check and holds the rows")
        copy.close()
        store.close()
        p = data / store.DB_NAME
        raw = bytearray(p.read_bytes())
        raw[4096 * 2:4096 * 6] = b"\x00" * 4096 * 4
        p.write_bytes(raw)
        for w in p.parent.glob(store.DB_NAME + "-*"):
            w.unlink()
        try:
            store.startup(log=quiet, stores=(), data_dir=data)
            refused = False
        except store.StoreError:
            refused = True
        store.close()
        check(refused, "a damaged database refuses to start, with a StoreError")

        # ------------------------------------------------ schema 1 -> 2 (§71d)
        print("schema 1 -> 2: handles of the lowercased name")
        v1 = root / "v1" / store.DB_NAME
        conn = store.connect(v1)
        from tiger import tiger192
        typed = lambda n: tiger192(n.encode())[:8].hex()    # what schema 1 stored
        with store.tx(conn):
            for i, name in enumerate(("Hiragamer98", "lukas1", "Lukas1", "player1")):
                conn.execute("INSERT INTO accounts (name, pwhash, handle, user_id) VALUES (?, ?, ?, ?)",
                             (name, "aa" * 24, typed(name), 100 + i))
            store.meta_set(conn, "schema_version", "1")
        conn.close()
        printed = []
        import builtins
        real_print = builtins.print
        builtins.print = lambda *a, **k: printed.append(" ".join(str(x) for x in a))
        try:
            conn = store.connect(v1)
        finally:
            builtins.print = real_print
        rows = {r["name"]: r["handle"] for r in conn.execute("SELECT name, handle FROM accounts")}
        check(rows.get("Hiragamer98") == store.account_handle("hiragamer98") == typed("hiragamer98"),
              "an account registered with a capital letter gets the handle the client "
              "actually sends, Tiger192 of the lowercased name")
        check(rows.get("player1") == typed("player1") and rows.get("lukas1") == typed("lukas1"),
              "...a lowercase name's handle does not change")
        check("Lukas1" not in rows and "lukas1" in rows,
              "...and of two rows that differ only by case, the one that could never "
              "sign in is dropped and the one that worked is kept")
        check(store.meta_get(conn, "schema_version") == "2"
              and any("Hiragamer98" in ln for ln in printed) and any("Lukas1" in ln for ln in printed),
              "...the version is 2 and both changes were said out loud")
        conn.close()

        # ------------------------------------------- the previous digest (§73f)
        old2 = root / "v2" / store.DB_NAME
        old2.parent.mkdir(parents=True)
        raw = sqlite3.connect(str(old2))
        raw.executescript("""
            CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            INSERT INTO meta VALUES ('schema_version', '2');
            CREATE TABLE accounts (name TEXT PRIMARY KEY, pwhash TEXT, handle TEXT UNIQUE,
                user_id INTEGER UNIQUE, first_seen TEXT, last_seen TEXT, last_ip TEXT);
            INSERT INTO accounts (name, pwhash, handle, user_id) VALUES ('kept1', 'ab', 'cd', 7);
        """)
        raw.close()
        conn = store.connect(old2)
        cols = {r["name"] for r in conn.execute("PRAGMA table_info(accounts)")}
        row = conn.execute("SELECT * FROM accounts").fetchone()
        check({"prev_pwhash", "prev_at"} <= cols and row["name"] == "kept1" and row["user_id"] == 7
              and row["prev_pwhash"] is None and store.meta_get(conn, "schema_version") == "2",
              "a store from before the previous-digest columns gets them on connect, rows kept, "
              "still schema 2")
        conn.close()
    finally:
        store.close()
        if keep:
            print(f"(scratch kept at {root})")
        else:
            shutil.rmtree(root, ignore_errors=True)
    passed = sum(1 for ok, _ in RESULTS if ok)
    print(f"\n{passed} of {len(RESULTS)} passed")
    for ok, what in RESULTS:
        if not ok:
            print(f"  FAILED: {what}")
    return 0 if passed == len(RESULTS) else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--keep", action="store_true")
    return run(ap.parse_args().keep)


if __name__ == "__main__":
    raise SystemExit(main())
