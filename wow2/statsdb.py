"""The leaderboard store, shared by the server and the CLI: the `stats` table
of wow2.sqlite3, rank derived on read, every read against the database so a
row can be edited with the server running.
"""
from __future__ import annotations

import datetime
import json
import os
import sys
import time
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
    4: "Yearly",
    5: "RANKED RATING -- the one the lobby wagers 10% of (Permanent)",
    6: "(read in a ranked lobby)",
    7: "(read in a ranked lobby)",
    8: "(read in a ranked lobby)",
    29: "clan (games started)",
    30: "clan",
    31: "clan",
    32: "clan",
}
RATING_BOARD = 5
GAMES_BOARD = 1       # games started: +1 from every player at a match start (§21, §48)
RATING_FLOOR = 10     # the floor the UPLOAD clamps to
DISPLAY_FLOOR = 1     # the floor the LOBBY DISPLAY clamps to; not the same
STARTING_RATING = int(serverconfig.get("stats", "starting_rating") or 0)
# The game's own Board types: 2 Weekly, 3 Monthly, 4 Yearly, 5 Permanent (§74).
PERIOD_BOARDS = {2: "week", 3: "month", 4: "year"}
PERIOD_BOARDS_ON = bool(serverconfig.get("stats", "period_boards"))
CLOCK = time.time


def period_key(board_id: int, now: float | None = None) -> str | None:
    """Which period a Weekly/Monthly/Yearly row belongs to right now (ISO week,
    month or year, UTC); None for a board that is not windowed."""
    if not PERIOD_BOARDS_ON or board_id not in PERIOD_BOARDS:
        return None
    t = datetime.datetime.fromtimestamp(CLOCK() if now is None else now, datetime.timezone.utc)
    kind = PERIOD_BOARDS[board_id]
    if kind == "week":
        y, w, _d = t.isocalendar()
        return f"{y}-W{w:02d}"
    return t.strftime("%Y-%m" if kind == "month" else "%Y")


def served_start(board_id: int) -> bool:
    """Is a missing row on this board served the starting rating?"""
    return board_id == RATING_BOARD or period_key(board_id) is not None


def _where(board_id: int) -> tuple[str, tuple]:
    """The rows that count as this board's, now: a windowed board's are only
    those written in the current period."""
    period = period_key(board_id)
    if period is None:
        return "board = ?", (board_id,)
    return "board = ? AND period = ?", (board_id, period)


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


def count(board_id: int, conn=None) -> int:
    """How many rows the board has -- the `totalEntries` a leaderboard reply carries."""
    if disabled():
        return 0
    where, args = _where(board_id)
    return int((conn or store.db()).execute(f"SELECT COUNT(*) FROM stats WHERE {where}",
                                            args).fetchone()[0])


def raw(board_id: int, entity_id: int) -> tuple[int, str, list | None] | None:
    """The stored (score, name, tail) for one board/entity, or None if no row
    (a windowed board's row from an earlier period is no row)."""
    if disabled():
        return None
    where, args = _where(board_id)
    r = store.db().execute(f"SELECT score, name, tail FROM stats WHERE {where} "
                           "AND entity = ?", (*args, _e(entity_id))).fetchone()
    if r is None:
        return None
    return int(r["score"]), r["name"] or "", (json.loads(r["tail"]) if r["tail"] else None)


def tail(board_id: int, entity_id: int) -> list | None:
    """Board 1's `[i32][i64 A][i64 B]` as the upload's typed list, or None."""
    row = raw(board_id, entity_id)
    return row[2] if row else None


def _rank(conn, board_id: int, score: int) -> int:
    where, args = _where(board_id)
    return 1 + int(conn.execute(f"SELECT COUNT(*) FROM stats WHERE {where} AND score > ?",
                                (*args, score)).fetchone()[0])


def get(board_id: int, entity_id: int, default_name: str = "") -> tuple[int, int, str]:
    """(score, rank, name) for one board/entity."""
    row = raw(board_id, entity_id)
    if row is not None:
        score, name, _tail = row
        return score, _rank(store.db(), board_id, score), name or default_name
    if served_start(board_id):
        return STARTING_RATING, 0, default_name
    return 0, 0, default_name


def _page_sql(board_id: int) -> tuple[str, tuple]:
    where, args = _where(board_id)
    return (f"SELECT entity, score, name, RANK() OVER (ORDER BY score DESC) AS rank "
            f"FROM stats WHERE {where} ORDER BY score DESC, entity"), args


def _rows(cur, default_name: str) -> list[tuple[int, int, int, str]]:
    return [(int(r["entity"], 16), int(r["score"]), int(r["rank"]), r["name"] or default_name)
            for r in cur]


def board(board_id: int, default_name: str = "") -> list:
    """Every stored row of one board as (entityID, score, rank, name), best first."""
    if disabled():
        return []
    sql, args = _page_sql(board_id)
    return _rows(store.db().execute(sql, args), default_name)


def top(board_id: int, want: int, default_name: str = "", conn=None) -> list:
    """The first `want` rows of a board, best first. `conn` is for a reader on
    another thread (the Discord leaderboards), which cannot use the process's."""
    if disabled():
        return []
    sql, args = _page_sql(board_id)
    return _rows((conn or store.db()).execute(sql + " LIMIT ?", (*args, want)), default_name)


def page_by_rank(board_id: int, start_rank: int, want: int, default_name: str = "") -> list:
    """`want` rows from the first row whose rank is >= start_rank -- the
    leaderboard's "start at rank N" view. Ties share a rank (RANK(), not
    ROW_NUMBER()), exactly as the JSON board() computed it.
    """
    if disabled():
        return []
    page, args = _page_sql(board_id)
    sql = f"SELECT * FROM ({page}) WHERE rank >= ? ORDER BY score DESC, entity LIMIT ?"
    return _rows(store.db().execute(sql, (*args, start_rank, want)), default_name)


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
    where, args = _where(board_id)
    if row is not None:
        at = int(conn.execute(
            f"SELECT COUNT(*) FROM stats WHERE {where} AND (score > ? OR "
            "(score = ? AND entity < ?))",
            (*args, row[0], row[0], _e(pivot))).fetchone()[0])
    lo = max(0, min(at - want // 2, max(0, n - want)))
    sql, args = _page_sql(board_id)
    return _rows(conn.execute(sql + " LIMIT ? OFFSET ?", (*args, want, lo)), default_name)


def put(board_id: int, entity_id: int, score: int, name: str = "",
        extra: list | None = None) -> tuple[bool, int]:
    """Record one score. Returns (written, rank)."""
    if disabled():
        return False, 0
    conn = store.db()
    with store.tx(conn):
        conn.execute(
            "INSERT INTO stats (board, entity, score, name, tail, period) VALUES (?, ?, ?, ?, ?, ?) "
            "ON CONFLICT (board, entity) DO UPDATE SET score = excluded.score, "
            "name = excluded.name, tail = excluded.tail, period = excluded.period",
            (board_id, _e(entity_id), int(score), name or "",
             json.dumps(extra) if extra else None, period_key(board_id)))
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
