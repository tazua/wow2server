"""The leaderboard store, shared by the server and the CLI.

Rows live in the `stats` table of `wow2.sqlite3` (tools/store.py, §66), one
per (board, entity): the score, the display name, and on board 1 the
completion-history tail the upload carried. **Rank is derived on read** --
`1 + COUNT(*) WHERE board = ? AND score > ?`, ties sharing a rank -- and is
never stored; nothing the client sends ever carries a rank.

Every read goes to the database, so rows can be edited (or awarded a pot)
with the server running, no restart and no re-login: `tools/potbank.py` and
`tools/wow2 rating` write the same table while `authserver.py` serves out of
it, and `sqlite3 capture/wow2.sqlite3` is the editor. Before §66 this was
`capture/stats-db.json`, re-parsed per call, which is what put the capacity
ceiling at the lifetime population (loadtest.py: 0.24 s sign-ins at 200
accounts, timeouts at 10,000); a build that finds that file imports it once
at startup and renames it aside.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import serverconfig
import store

# THE CONFIGURED DATA DIRECTORY, not one derived from where this file happens to
# live. It used to be `Path(__file__).parent.parent / "capture"`, which is the
# right answer in the source tree and silently wrong once installed: it resolves
# to `site-packages/capture`, which does not exist and is not writable, so every
# leaderboard write, every rating and the whole ranked pot failed with one line
# of log each and nothing persisted. Found on a live deployment after a real
# match between two real NATs uploaded ten boards and kept none of them.
CAP = serverconfig.DATA_DIR
STATS_UPLOADS = CAP / "stats-uploads.jsonl"     # append-only forensic trail

# The board map, as far as it is known (netrecon Phase 21/22):
BOARD_NAMES = {
    1: "games started",
    2: "All players / Weekly",
    3: "Monthly",
    4: "(read at sign-in)",
    5: "RANKED RATING -- the one the lobby wagers 10% of",
    6: "(read in a ranked lobby)",
    7: "(read in a ranked lobby)",
    8: "(read in a ranked lobby)",
    # 9..24 are the sixteen Daily awards -- see capture/award-boards.json
    29: "clan (games started)",
    30: "clan",
    31: "clan",
    32: "clan",
}
RATING_BOARD = 5           # the board the lobby stakes and the pot pays into
RATING_FLOOR = 10          # the floor the UPLOAD clamps to; see upload_after_stake
DISPLAY_FLOOR = 1          # the floor the LOBBY DISPLAY clamps to -- not the same
STARTING_RATING = int(serverconfig.get("stats", "starting_rating") or 0)


def upload_after_stake(served: int) -> int:
    """What the client uploads to board 5 when it stakes, given what we served.

    MEASURED, and it is not what this project believed for thirty phases.
    CLAUDE.md, potbank.py, rpcnotes.py and `wow2 rating` all said
    `max(10, round(0.9 * served))`. Seven discriminating values measured in
    Phase 51 -- 1009, 1006, 305, 45, 777, 188, 106 -- all fit

        max(10, served - floor(0.1 * served))

    and all contradict the rounding form. 1009 uploads 909, not 908; 1006
    uploads 906, not 905. The difference only shows when `0.1 * served` has a
    fractional part big enough to round up, which is why two decades of
    round-number test values never caught it.
    """
    return max(RATING_FLOOR, served - served // 10)


def displayed_stake(rating: int) -> int:
    """What the LOBBY shows this player is staking.

    A DIFFERENT floor from the upload, and that is a real defect rather than a
    rounding quibble: the display clamps to 1 and the upload clamps to 10, so a
    player rated below 10 is shown a stake of 1 that it does not pay -- and its
    "stake" upload RAISES board 5 (served 0 -> uploaded 10, served 5 -> 10).
    The server reads any board-5 rise during the start burst as a client payout
    and closes the pot early. In one measured match that created a point of
    rating from nothing: 1000 + 10 became 900 + 111 against a banked pot of 100.
    """
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
    """(score, rank, name) for one board/entity.

    Unknown -> an unranked row worth nothing, EXCEPT on the ranked board, where
    it is worth `stats.starting_rating` (T12, §53). A new player has no row, and
    what we answer here IS their opening rating -- the number lives on the
    server and the client never had a say in it. Zero is the one answer that
    cannot be right: the lobby shows `max(1, r//10)` and the client uploads
    `max(10, r - r//10)`, so a player served 0 is shown a stake of 1, pays -10,
    and starts the game already pinned under the floor. See serverconfig for the
    table and why the number is 400.

    Only the MISS is affected. A stored row is served as stored, including a
    stored 0, and `board()` is untouched -- an entity with no row must not
    appear in a leaderboard listing at the starting value, because it is not on
    the board. That asymmetry is the whole point: this is what you are worth
    before your first ranked match, not a row.
    """
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
    """Every stored row of one board as (entityID, score, rank, name), best first.

    The whole board: `top()`, `page_by_rank()` and `page_around()` are what the
    handlers use, because the client never asks for more than 50 rows."""
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
    ROW_NUMBER()), exactly as the JSON board() computed it."""
    if disabled():
        return []
    sql = f"SELECT * FROM ({_PAGE_SQL}) WHERE rank >= ? ORDER BY score DESC, entity LIMIT ?"
    return _rows(store.db().execute(sql, (board_id, start_rank, want)), default_name)


def page_around(board_id: int, pivot: int, want: int, default_name: str = "") -> list:
    """`want` rows with `pivot` as near the middle as the board's ends allow --
    the "Own rank" view. A pivot with no row centres on the top of the board."""
    if disabled():
        return []
    conn = store.db()
    n = count(board_id)
    row = raw(board_id, pivot)
    at = 0
    if row is not None:
        # The pivot's POSITION (not rank): rows ordered before it.
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
    """Every (entityID, name) whose name matches `who`, or the id if `who` is one.

    `who` may be a player name (case-insensitive), a 16-hex-digit account id, or
    `0x...`. Names are looked up across every board, so a player who only ever
    appears on the awards boards still resolves.
    """
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
