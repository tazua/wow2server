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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAP = ROOT / "capture"
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
RATING_FLOOR = 10          # max(10, round(0.9*x)) -- the client's own floor
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
    try:
        STATS_DB.write_text(json.dumps(db, indent=1, sort_keys=True))
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
    """(score, rank, name) for one board/entity. Unknown -> an unranked zero row."""
    for eid, score, rank, name in board(board_id, default_name):
        if eid == entity_id:
            return score, rank, name
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
