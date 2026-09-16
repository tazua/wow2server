"""The leaderboard store, shared by the server and the CLI: the `stats` table
of wow2.sqlite3, rank derived on read, every read against the database so a
row can be edited with the server running.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import serverconfig
import store

CAP = serverconfig.DATA_DIR
STATS_UPLOADS = CAP / "stats-uploads.jsonl"

BOARD_NAMES = {
    1: "games started",
    2: "All players / Weekly",
    3: "Monthly",
    4: "(read at sign-in)",
    5: "RANKED RATING -- the one the lobby wagers 10% of",
    6: "(read in a ranked lobby)",
    7: "(read in a ranked lobby)",
    8: "(read in a ranked lobby)",
    29: "clan (games started)",
    30: "clan",
    31: "clan",
    32: "clan",
}
RATING_BOARD = 5
RATING_FLOOR = 10     # the floor the UPLOAD clamps to
DISPLAY_FLOOR = 1     # the floor the LOBBY DISPLAY clamps to; not the same
STARTING_RATING = int(serverconfig.get("stats", "starting_rating") or 0)


def upload_after_stake(served: int) -> int:
    """What the client uploads to board 5 when it stakes, given what we served."""
    return max(RATING_FLOOR, served - served // 10)


def displayed_stake(rating: int) -> int:
    """What the LOBBY shows this player is staking."""
    return max(DISPLAY_FLOOR, rating // 10)


def stake_paid(served: int) -> int:
    """What the player actually loses -- which can be NEGATIVE below the floor."""
    return served - upload_after_stake(served)
CLAN_BOARDS = (29, 30, 31, 32)


def disabled() -> bool:
    return os.environ.get("WOW2_NO_STATS_STORE") == "1"


def key(board_id: int, entity_id: int) -> str:
    """The `board:entity` spelling the JSON store used; still the log's spelling."""
    return f"{board_id}:{entity_id:016x}"


def _e(entity_id: int) -> str:
    return f"{int(entity_id):016x}"


def count(board_id: int) -> int:
    """How many rows the board has -- the `totalEntries` a leaderboard reply carries."""
    if disabled():
        return 0
    return int(store.db().execute("SELECT COUNT(*) FROM stats WHERE board = ?",
                                  (board_id,)).fetchone()[0])


def raw(board_id: int, entity_id: int) -> tuple[int, str, list | None] | None:
    """The stored (score, name, tail) for one board/entity, or None if no row."""
    if disabled():
        return None
    r = store.db().execute("SELECT score, name, tail FROM stats WHERE board = ? "
                           "AND entity = ?", (board_id, _e(entity_id))).fetchone()
    if r is None:
        return None
    return int(r["score"]), r["name"] or "", (json.loads(r["tail"]) if r["tail"] else None)


def tail(board_id: int, entity_id: int) -> list | None:
    """Board 1's `[i32][i64 A][i64 B]` as the upload's typed list, or None."""
    row = raw(board_id, entity_id)
    return row[2] if row else None


def _rank(conn, board_id: int, score: int) -> int:
    return 1 + int(conn.execute("SELECT COUNT(*) FROM stats WHERE board = ? AND score > ?",
                                (board_id, score)).fetchone()[0])


def get(board_id: int, entity_id: int, default_name: str = "") -> tuple[int, int, str]:
    """(score, rank, name) for one board/entity."""
    row = raw(board_id, entity_id)
    if row is not None:
        score, name, _tail = row
        return score, _rank(store.db(), board_id, score), name or default_name
    if board_id == RATING_BOARD:
        return STARTING_RATING, 0, default_name
    return 0, 0, default_name


_PAGE_SQL = ("SELECT entity, score, name, RANK() OVER (ORDER BY score DESC) AS rank "
             "FROM stats WHERE board = ? ORDER BY score DESC, entity")


def _rows(cur, default_name: str) -> list[tuple[int, int, int, str]]:
    return [(int(r["entity"], 16), int(r["score"]), int(r["rank"]), r["name"] or default_name)
            for r in cur]


def board(board_id: int, default_name: str = "") -> list:
    """Every stored row of one board as (entityID, score, rank, name), best first."""
    if disabled():
        return []
    return _rows(store.db().execute(_PAGE_SQL, (board_id,)), default_name)


def top(board_id: int, want: int, default_name: str = "") -> list:
    """The first `want` rows of a board, best first."""
    if disabled():
        return []
    return _rows(store.db().execute(_PAGE_SQL + " LIMIT ?", (board_id, want)), default_name)


def page_by_rank(board_id: int, start_rank: int, want: int, default_name: str = "") -> list:
    """`want` rows from the first row whose rank is >= start_rank -- the
    leaderboard's "start at rank N" view. Ties share a rank (RANK(), not
    ROW_NUMBER()), exactly as the JSON board() computed it.
    """
    if disabled():
        return []
    sql = f"SELECT * FROM ({_PAGE_SQL}) WHERE rank >= ? ORDER BY score DESC, entity LIMIT ?"
    return _rows(store.db().execute(sql, (board_id, start_rank, want)), default_name)


def page_around(board_id: int, pivot: int, want: int, default_name: str = "") -> list:
    """`want` rows with `pivot` as near the middle as the board's ends allow --
    the "Own rank" view. A pivot with no row centres on the top of the board.
    """
    if disabled():
        return []
    conn = store.db()
    n = count(board_id)
    row = raw(board_id, pivot)
    at = 0
    if row is not None:
        at = int(conn.execute(
            "SELECT COUNT(*) FROM stats WHERE board = ? AND (score > ? OR "
            "(score = ? AND entity < ?))",
            (board_id, row[0], row[0], _e(pivot))).fetchone()[0])
    lo = max(0, min(at - want // 2, max(0, n - want)))
    return _rows(conn.execute(_PAGE_SQL + " LIMIT ? OFFSET ?", (board_id, want, lo)),
                 default_name)


def put(board_id: int, entity_id: int, score: int, name: str = "",
        extra: list | None = None) -> tuple[bool, int]:
    """Record one score. Returns (written, rank)."""
    if disabled():
        return False, 0
    conn = store.db()
    with store.tx(conn):
        conn.execute(
            "INSERT INTO stats (board, entity, score, name, tail) VALUES (?, ?, ?, ?, ?) "
            "ON CONFLICT (board, entity) DO UPDATE SET score = excluded.score, "
            "name = excluded.name, tail = excluded.tail",
            (board_id, _e(entity_id), int(score), name or "",
             json.dumps(extra) if extra else None))
        return True, _rank(conn, board_id, int(score))


def find_entity(who: str) -> list:
    """Every (entityID, name) whose name matches `who`, or the id if `who` is one."""
    text = who.strip()
    try:
        ident = int(text, 16) if len(text.strip("0x")) >= 8 else 0
    except ValueError:
        ident = 0
    if disabled():
        return []
    seen: dict[int, str] = {}
    for r in store.db().execute(
            "SELECT DISTINCT entity, name FROM stats WHERE entity = ? OR lower(name) = ?",
            (_e(ident), text.lower())):
        eid = int(r["entity"], 16)
        seen[eid] = r["name"] or seen.get(eid, "")
    return sorted(seen.items())
