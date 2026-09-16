"""The leaderboard store, shared by the server and the CLI.

`capture/stats-db.json` is a flat dict keyed `"board:entityid"`:

    {"5:975367efa4bbebed": [4444, 1, "player1"]}      # score, rank, name[, blob]

The middle number is written back only so the file reads well -- **rank is
derived on read**, as the row's position with the board ordered by score, best
first, ties sharing a rank. Nothing the client sends ever carries a rank.

The file is re-read PER CALL, on purpose: rows can be edited (or awarded a pot)
with the server running, no restart and no re-login. That is also why this lives
in its own module -- `tools/potbank.py` and `tools/wow2` bank a pot straight into
the same file while `authserver.py` is serving out of it.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import serverconfig

# THE CONFIGURED DATA DIRECTORY, not one derived from where this file happens to
# live. It used to be `Path(__file__).parent.parent / "capture"`, which is the
# right answer in the source tree and silently wrong once installed: it resolves
# to `site-packages/capture`, which does not exist and is not writable, so every
# leaderboard write, every rating and the whole ranked pot failed with one line
# of log each and nothing persisted. Found on a live deployment after a real
# match between two real NATs uploaded ten boards and kept none of them.
#
# `authserver.py` had this right (`CAP = serverconfig.DATA_DIR`); the store
# modules did not, and potbank derives its own path from this one, so the same
# bug reached the pot ledger.
CAP = serverconfig.DATA_DIR
STATS_DB = CAP / "stats-db.json"
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
    return f"{board_id}:{entity_id:016x}"


def load() -> dict:
    if disabled():
        return {}
    try:
        return json.loads(STATS_DB.read_text())
    except (OSError, ValueError):
        return {}


def save(db: dict) -> bool:
    """Write the leaderboards, atomically, creating the data directory if needed.

    Two things this used to get wrong, both found on a live deployment:

    * **It assumed the directory existed.** The server creates it at startup, so
      the server was fine; the CLIs (`wow2 rating`, `wow2 award`) were not, and a
      fresh install had nothing to say about why the write failed.
    * **It was not atomic.** `write_text` truncates first, so a kill at the wrong
      moment left a half-written leaderboard -- which `load()` then reads as `{}`
      and the next write makes permanent. `authserver._jsave` has been atomic for
      exactly this reason; this one was missed because the rig never gets killed
      mid-match.
    """
    try:
        CAP.mkdir(parents=True, exist_ok=True)
        tmp = STATS_DB.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(db, indent=1, sort_keys=True))
        os.replace(tmp, STATS_DB)          # atomic within one filesystem
        return True
    except OSError:
        return False


def board(board_id: int, default_name: str = "") -> list:
    """Every stored row of one board as (entityID, score, rank, name), best first."""
    rows = []
    prefix = f"{board_id}:"
    for k, row in load().items():
        if not k.startswith(prefix) or not isinstance(row, list) or not row:
            continue
        try:
            entity_id = int(k[len(prefix):], 16)
        except ValueError:
            continue
        name = row[2] if len(row) > 2 and isinstance(row[2], str) else default_name
        rows.append((entity_id, int(row[0]), name))
    rows.sort(key=lambda r: -r[1])
    out = []
    for i, (entity_id, score, name) in enumerate(rows):
        rank = i + 1
        if i and score == rows[i - 1][1]:
            out.append((entity_id, score, out[-1][2], name))     # tie -> same rank
        else:
            out.append((entity_id, score, rank, name))
    return out


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
    for eid, score, rank, name in board(board_id, default_name):
        if eid == entity_id:
            return score, rank, name
    if board_id == RATING_BOARD:
        return STARTING_RATING, 0, default_name
    return 0, 0, default_name


def _reranked(db: dict, board_id: int) -> dict:
    ranked = {}
    tmp = sorted(((k, v) for k, v in db.items() if k.startswith(f"{board_id}:")),
                 key=lambda kv: -int(kv[1][0]))
    for i, (k, v) in enumerate(tmp):
        ranked[k] = i + 1
        if i and int(v[0]) == int(tmp[i - 1][1][0]):
            ranked[k] = ranked[tmp[i - 1][0]]
    return ranked


def put(board_id: int, entity_id: int, score: int, name: str = "",
        extra: list | None = None) -> tuple[bool, int]:
    """Record one score. Returns (written, rank). Rank is only cosmetic in the file."""
    if disabled():
        return False, 0
    db = load()
    k = key(board_id, entity_id)
    row = [int(score), 0, name]
    if extra:
        row.append(extra)
    db[k] = row
    ranked = _reranked(db, board_id)
    for kk, r in ranked.items():
        if len(db[kk]) > 1:
            db[kk][1] = r
    return save(db), ranked.get(k, 0)


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
    seen = {}
    for k, row in load().items():
        try:
            eid = int(k.split(":", 1)[1], 16)
        except (IndexError, ValueError):
            continue
        name = row[2] if isinstance(row, list) and len(row) > 2 else ""
        if eid == ident or (name and name.lower() == text.lower()):
            seen[eid] = name or seen.get(eid, "")
    return sorted(seen.items())
