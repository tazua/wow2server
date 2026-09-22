#!/usr/bin/env python3
"""The WOW2 server: the Demonware auth, lobby (LSG), bdNAT and NAT-type
services the game reaches, in one process on one port.

    tools/wow2 server start          # the rig; reads the committed wow2-server.toml
    wow2-server                      # an install; WOW2_CONFIG names the file

What each handler answers, and why, is in netrecon.md (by phase) and
tools/README.md §4; the deployment settings are in wow2-server.example.toml.
"""
from __future__ import annotations

import asyncio
import atexit
import datetime
import json
import secrets
import signal
import socket
import struct
import time
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bdproto as bd
import bddump
import statsdb
import potbank
import store

import natrelay
import lobbyboard
import serverconfig

ROOT = Path(__file__).resolve().parent.parent
CAP = serverconfig.DATA_DIR


class _SessionLog:
    """The session log, opened on the first line written to it."""
    _f = None

    @property
    def name(self) -> str:
        return self._open().name

    def write(self, text: str) -> None:
        self._open().write(text)

    def _open(self):
        if self._f is None:
            CAP.mkdir(parents=True, exist_ok=True)
            self._f = open(CAP / f"session-{datetime.datetime.now():%Y%m%d-%H%M%S}.log",
                           "a", buffering=1)
        return self._f


SESSION_LOG = _SessionLog()


def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def ts_file() -> str:
    """A timestamp safe in a filename (ts() has colons)."""
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def log(msg: str):
    line = f"[{ts()}] {msg}"
    print(line, flush=True)
    SESSION_LOG.write(line + "\n")


def debug(msg: str):
    """Per-PACKET detail: every read, every message body, every reply."""
    if _DEBUG[0]:
        log(msg)


_HEXDUMPS = [True]
_DEBUG = [True]


def hexdump(data: bytes, pfx="    ") -> str:
    """A hexdump of a message body, or a one-line summary with `logging.hexdumps` off."""
    if not _HEXDUMPS[0]:
        return f"{pfx}({len(data)}B; hexdumps off -- set logging.hexdumps = true)"
    return _hexdump_full(data, pfx)


def _hexdump_full(data: bytes, pfx="    ") -> str:
    out = []
    for i in range(0, len(data), 16):
        c = data[i:i + 16]
        h = " ".join(f"{b:02x}" for b in c).ljust(47)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        out.append(f"{pfx}{i:04x}  {h}  {a}")
    return "\n".join(out)


# ------------------------------------------------------------------ auth reply
AUTH_CREATE_ACCOUNT_REQ = 0x00
AUTH_CREATE_ACCOUNT_REPLY = 0x01
AUTH_CHANGE_PASSWORD_REQ = 0x02
AUTH_CHANGE_PASSWORD_REPLY = 0x03

BD_AUTH_NO_ERROR = 700
BD_AUTH_BAD_REQUEST = 701
BD_AUTH_SERVER_CONFIG_ERROR = 702
BD_AUTH_BAD_TITLE_ID = 703
BD_AUTH_BAD_ACCOUNT = 704
BD_AUTH_ILLEGAL_OPERATION = 705
BD_AUTH_INCORRECT_LICENSE_CODE = 706
BD_AUTH_CREATE_USERNAME_EXISTS = 707
BD_AUTH_CREATE_USERNAME_ILLEGAL = 708
BD_AUTH_CREATE_USERNAME_VULGAR = 709
BD_AUTH_CREATE_MAX_ACC_EXCEEDED = 710
BD_AUTH_MIGRATE_NOT_SUPPORTED = 711
BD_AUTH_TITLE_DISABLED = 712
BD_AUTH_ACCOUNT_EXPIRED = 713
BD_AUTH_ACCOUNT_LOCKED = 714
BD_AUTH_UNKNOWN_ERROR = 715
BD_AUTH_INCORRECT_PASSWORD = 716

BD_TITLE_ID = 0x131D

BD_AUTH_MAGIC = 0xEFBDADDE

BD_BOOTSTRAP_KEY = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeef"
                                 "0000000000000000")

import os
import rigconfig
_HEXDUMPS[0] = serverconfig.HEXDUMPS
_DEBUG[0] = serverconfig.DEBUG
CREATE_MODE = serverconfig.CREATE_MODE
if CREATE_MODE not in ("refuse_duplicates", "success", "name_exists"):
    raise SystemExit(
        f"!! accounts.create_mode = {CREATE_MODE!r} is not a mode. "
        f"Use 'refuse_duplicates' (default), 'success' or 'name_exists'.")
ACCOUNT_PASSWORD = rigconfig.ACCOUNT_PASSWORD


import tiger
from Crypto.Cipher import DES, DES3

TICKET_MAGIC = 0xEFBDADDE
OPAQUE_PROOF_MAGIC = 0xC0FFEEFFEEAA1337


def tiger192(data: bytes) -> bytes:
    """The 24-byte Tiger192 digest (tools/tiger.py)."""
    return tiger.tiger192(data)


def tiger_iv(seed: int) -> bytes:
    """IV = Tiger192(seed_le)[:8]."""
    return tiger192(seed.to_bytes(4, "little"))[:8]


def account_key(password: str) -> bytes:
    """Tiger192(password): the per-account key the login proof is encrypted with."""
    return tiger192(password.encode())


def cbc_3des_encrypt(plaintext: bytes, key24: bytes, iv: bytes) -> bytes:
    """3DES-EDE-CBC with a 24-byte key."""
    return DES3.new(key24, DES3.MODE_CBC, iv).encrypt(plaintext)


def build_client_opaque_proof(session_key: bytes, username: str = rigconfig.USERNAME,
                              user_id: int = rigconfig.USER_ID,
                              license_id: int = rigconfig.LICENSE_ID,
                              title: int = rigconfig.TITLE_ID) -> bytes:
    """The 128-byte ClientOpaqueAuthProof: sent in clear beside the ticket, relayed
    verbatim by the client at the LSG connect (netrecon §9, §33, §60)."""
    import struct as _s
    p = bytearray()
    p += _s.pack("<Q", OPAQUE_PROOF_MAGIC)
    p += _s.pack("<I", title)
    p += _s.pack("<q", 0x7FFFFFFF)
    p += _s.pack("<Q", license_id)
    p += _s.pack("<Q", user_id)
    p += session_key
    ub = username.encode()[:63]
    p += ub + b"\x00" * (64 - len(ub))
    p += _s.pack("<I", 0)
    assert len(p) == 128, len(p)
    return bytes(p)


def build_login_reply(session_key: bytes, key24: bytes, seed: int = 0,
                      username: str = rigconfig.USERNAME,
                      user_id: int = rigconfig.USER_ID,
                      license_id: int = rigconfig.LICENSE_ID,
                      proof_key: bytes | None = None) -> bytes:
    """Valid AccountForMmpReply (0x0b): [seed][3DES-CBC proof]."""
    import struct as _s
    p = bytearray(128)
    p[0:4]   = _s.pack("<I", TICKET_MAGIC)
    p[4]     = 0                              # ticket type
    p[5:9]   = _s.pack("<I", 0x131D)          # title id
    p[9:13]  = _s.pack("<I", 0)               # issued
    p[13:17] = _s.pack("<I", 0x7FFFFFFF)      # expires
    p[17:25] = _s.pack("<Q", license_id)
    p[25:33] = _s.pack("<Q", user_id)
    ub = username.encode()[:63]
    p[33:33 + len(ub)] = ub
    p[97:121] = session_key
    iv = tiger_iv(0)                              # the client decrypts with seed 0, not ours
    enc = cbc_3des_encrypt(bytes(p), key24, iv)

    opaque = build_client_opaque_proof(proof_key or session_key, username, user_id,
                                       license_id)

    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(0x0B)
    w.type_checked = True
    w.write_bits(b"\x01", 1)
    w.u32(BD_AUTH_NO_ERROR)
    w.type_checked = False
    w.write_bits(b"\x00", 5)
    w.write_bits(enc, len(enc) * 8)
    w.write_bits(opaque, len(opaque) * 8)
    return bd.frame_unencrypted(w.getvalue())


# ------------------------------------------------------------------ LSG reply
LSG_SERVICE_NAMES = {3: "Teams", 4: "Stats", 5: "Sessions", 6: "Messaging",
                     7: "LobbyService", 8: "Profile", 9: "Friends", 10: "Storage",
                     12: "TitleUtilities", 21: "Matchmaking", 23: "Counter"}

LSG_TYPE_CHECKED_BIT = 1

LSG_SERVICE_LOBBY = 7
LSG_SERVICE_STORAGE = 10
LSG_SERVICE_STATS = 4
LSG_SERVICE_SESSIONS = 5
LSG_SERVICE_TEAMS = 3
LSG_SERVICE_FRIENDS = 9
LSG_SERVICE_MESSAGING = 6
LSG_SERVICE_PROFILE = 8

LEFTOVER_HEXDUMP_MAX = 96

LSG_MSG_TASK_REPLY = 1
LSG_MSG_PUSH_MESSAGE = 2
LSG_MSG_ERROR = 3
LSG_MSG_CONNECTION_ID = 4
LSG_ENC_FLAG = int(os.environ.get("WOW2_LSG_ENC", "0"), 0)


def build_lsg_connid_reply(connection_id: int = 1, enc_flag: int = LSG_ENC_FLAG) -> bytes:
    """LsgServiceConnectionId (type 4): byte-mode [u8 4][typed u64 conn_id].
    Framed [u32 len][enc_flag][body]. enc_flag defaults 0 (unencrypted).
    """
    w = bd.BdWriter()
    w.type_checked = False
    w.u8(LSG_MSG_CONNECTION_ID)
    w.type_checked = True
    w.u64(connection_id)
    body = w.getvalue()
    return len((bytes([enc_flag]) + body)).to_bytes(4, "little") + bytes([enc_flag]) + body


RESPONSE_SIGNATURE = 0xDEADBEEF


def session_cbc_encrypt(plaintext: bytes, session_key: bytes, iv: bytes) -> bytes:
    """3DES-EDE-CBC under the session key; a key whose halves repeat is single DES,
    which pycryptodome refuses, so fall back to DES for that case."""
    if session_key[0:8] == session_key[8:16] == session_key[16:24]:
        return DES.new(session_key[:8], DES.MODE_CBC, iv).encrypt(plaintext)
    return DES3.new(session_key, DES3.MODE_CBC, iv).encrypt(plaintext)


def session_cbc_decrypt(ciphertext: bytes, session_key: bytes, iv: bytes) -> bytes:
    """Inverse of session_cbc_encrypt (same degenerate-key caveat)."""
    if session_key[0:8] == session_key[8:16] == session_key[16:24]:
        return DES.new(session_key[:8], DES.MODE_CBC, iv).decrypt(ciphertext)
    return DES3.new(session_key, DES3.MODE_CBC, iv).decrypt(ciphertext)


def decode_lsg_client_message(payload: bytes, session_key: bytes) -> dict:
    """Decode one client->server LSG message body (everything after [u32 len])."""
    out = {"enc": payload[0], "seed": None, "hmac": None,
           "service": None, "op": None, "plain": b""}
    if payload[0] == 1:
        out["seed"] = int.from_bytes(payload[1:5], "little")
        pt = session_cbc_decrypt(payload[5:], session_key, tiger_iv(out["seed"]))
        out["hmac"] = int.from_bytes(pt[0:4], "little")
        out["plain"] = pt
        body = pt[4:]
    else:
        out["plain"] = payload[1:]
        body = payload[1:]
    if body:
        out["service"] = body[0]
        try:
            r = bd.BdReader(body[1:])
            r.bitmode = True
            r.read_type_checked_bit()
            out["op"] = r.u8()
        except Exception:
            pass
    return out


def build_lsg_connid_reply_encrypted(connection_id: int, session_key: bytes,
                                     seed: int = 0x11223344) -> bytes:
    """The encrypted LsgServiceConnectionId reply: [u32 len][u8 1][u32 seed] then
    3DES-CBC under the session key of [u32 0xDEADBEEF][u8 4][typed u64 conn_id],
    the u64 bit-packed (netrecon §9)."""
    r = bd.BdWriter()
    r.bitmode = True
    r.type_checked = False
    r.write_bits(b"\x01", 1)
    r.type_checked = True
    r.u64(connection_id)
    plaintext = (RESPONSE_SIGNATURE.to_bytes(4, "little")
                 + bytes([LSG_MSG_CONNECTION_ID])
                 + r.getvalue())
    if len(plaintext) % 8:
        plaintext += b"\x00" * (8 - len(plaintext) % 8)
    ct = session_cbc_encrypt(plaintext, session_key, tiger_iv(seed))
    body = bytes([1]) + seed.to_bytes(4, "little") + ct
    return len(body).to_bytes(4, "little") + body


def build_lsg_taskreply_encrypted(session_key: bytes, transaction_id: int = 0,
                                  error_code: int = 0, operation_id: int = 0,
                                  num_results: int = 0, results=None,
                                  seed: int = 0x22446688) -> bytes:
    """A type-1 LobbyServiceTaskReply, matched to its request by txn_id:
    [u32 0xDEADBEEF][u8 1] then bit-mode [u64 txn][u32 err][u8 op][u32 numResults]
    [u32 total] and the rows (netrecon §9b)."""
    r = bd.BdWriter()
    r.bitmode = True
    r.type_checked = False
    r.write_bits(b"\x01", 1)
    r.type_checked = True
    r.u64(transaction_id)
    r.u32(error_code)
    r.u8(operation_id)
    if num_results is not None:
        r.u32(num_results)
    if results is not None:
        results(r)
    plaintext = (RESPONSE_SIGNATURE.to_bytes(4, "little")
                 + bytes([LSG_MSG_TASK_REPLY])
                 + r.getvalue())
    if len(plaintext) % 8:
        plaintext += b"\x00" * (8 - len(plaintext) % 8)
    ct = session_cbc_encrypt(plaintext, session_key, tiger_iv(seed))
    body = bytes([1]) + seed.to_bytes(4, "little") + ct
    return len(body).to_bytes(4, "little") + body


# ------------------------------------------------------ LSG service result rows
LEADERBOARD_NAME_MAX = 64


def write_leaderboard_row(w, entity_id: int, score: int, rank: int, name: str):
    """One bdLeaderBoardRow, appended to an in-progress type-checked bit writer."""
    w.u64(entity_id)
    w.i64(score)
    w.u64(rank)
    w.str_(name, LEADERBOARD_NAME_MAX)


def _request_reader(dec: dict):
    body = dec["plain"][4:] if dec["enc"] == 1 else dec["plain"]
    r = bd.BdReader(body[1:])
    r.bitmode = True
    r.read_type_checked_bit()
    r.type_checked = True
    r.u8()
    return r


def lsg_request_params(dec: dict):
    """A BdReader on a decoded client RPC, positioned just past the typed op id."""
    r = _request_reader(dec)
    _LAST_READER.append(r)
    return r


def lsg_request_noargs(dec: dict, what: str) -> None:
    """Consume the request of an RPC that takes NO parameters."""
    try:
        r = lsg_request_params(dec)
        lead = r.u8()
        extra = bd.read_fields(r)
    except Exception as e:
        log(f"  ({what}: request decode failed: {e})")
        return
    if lead or extra:
        shown = ", ".join(f"{bd.TYPE_NAMES.get(t, t)} {v!r}" for t, v in extra)
        log(f"  *** {what} TOOK ARGUMENTS (lead={lead}): {shown}")


# ---------------------------------------------------------- the request census
REQ_CENSUS_PATH = CAP / "request-census.json"
REQ_CENSUS: dict[str, dict] = {}
_LAST_READER: list = []
_CENSUS_LOGGED: set[str] = set()
_CENSUS_WRITES = 0
_CENSUS_LOADED = False
_CENSUS_SAVED_AT = 0.0
CENSUS_MAX_VALUES = 12
CENSUS_SAVE_S = 30.0


def _census_val(v) -> str:
    if isinstance(v, bytes):
        return v[:24].hex() + ("..." if len(v) > 24 else "")
    if isinstance(v, int) and not isinstance(v, bool) and abs(v) > 0xFFFF:
        return f"0x{v:x}"
    s = str(v)
    return s[:48] + ("..." if len(s) > 48 else "")


def census_load() -> None:
    """Carry the census across restarts: it accumulates what the client has ever sent."""
    global _CENSUS_LOADED
    _CENSUS_LOADED = True
    try:
        prev = json.loads(REQ_CENSUS_PATH.read_text())
    except (OSError, ValueError):
        return
    if isinstance(prev, dict):
        REQ_CENSUS.update(prev)


def census_note(svc: int, op: int, dec: dict) -> None:
    """Record one request's typed fields, and shout once if we ignored any."""
    global _CENSUS_WRITES
    reader = _LAST_READER[-1] if _LAST_READER else None
    del _LAST_READER[:]
    if os.environ.get("WOW2_NO_CENSUS") == "1":
        return
    if not _CENSUS_LOADED:
        census_load()
    try:
        fields = bd.read_fields(_request_reader(dec))
        tail = bd.read_fields(reader) if reader is not None else list(fields)
    except Exception:
        return
    key = f"{svc}:{op}"
    fresh = key not in REQ_CENSUS
    rec = REQ_CENSUS.setdefault(key, {"count": 0, "read": 0, "unread": 0,
                                      "fields": []})
    rec["count"] += 1
    nread, nun = len(fields) - len(tail), len(tail)
    if (rec["read"], rec["unread"]) != (nread, nun):
        fresh = True
    rec["read"], rec["unread"] = nread, nun    # the latest reading, not the max: a closed blind spot must clear
    for i, (t, v) in enumerate(fields):
        while len(rec["fields"]) <= i:
            rec["fields"].append({"type": "", "values": [], "more": False})
        f = rec["fields"][i]
        f["type"] = bd.TYPE_NAMES.get(t, f"type{t}")
        s = _census_val(v)
        if s not in f["values"]:
            fresh = True
            if len(f["values"]) < CENSUS_MAX_VALUES:
                f["values"].append(s)
            else:
                f["more"] = True
    if tail and key not in _CENSUS_LOGGED:
        _CENSUS_LOGGED.add(key)
        shown = ", ".join(f"{bd.TYPE_NAMES.get(t, f'type{t}')} {_census_val(v)}"
                          for t, v in tail[:6])
        log(f"  *** UNREAD REQUEST FIELD service={svc} op={op}: handler read "
            f"{len(fields) - len(tail)} of {len(fields)} fields, ignored "
            f"{len(tail)}: {shown}")
    global _CENSUS_SAVED_AT
    _CENSUS_WRITES += 1
    if fresh or time.time() - _CENSUS_SAVED_AT > CENSUS_SAVE_S:
        _CENSUS_SAVED_AT = time.time()
        _jsave(REQ_CENSUS_PATH, REQ_CENSUS)


def census_flush() -> None:
    if REQ_CENSUS and os.environ.get("WOW2_NO_CENSUS") != "1":
        _jsave(REQ_CENSUS_PATH, REQ_CENSUS)


atexit.register(census_flush)


# --------------------------------------------------------------- identities
IDENTITIES: dict[str, tuple[str, int]] = {
    "127.0.0.1": (rigconfig.USERNAME, rigconfig.USER_ID),
    "10.42.0.2": (os.environ.get("WOW2_USERNAME2", "testuser"), 2),
}
for _n in range(3, 9):
    IDENTITIES.setdefault(f"10.42.0.{_n}",
                          (os.environ.get(f"WOW2_USERNAME{_n}", f"player{_n}"), _n))
del _n

_AUTO_IDS: dict[str, tuple[str, int]] = {}


def identity_for(ip: str) -> tuple[str, int]:
    """(username, user_id) for a console, keyed by where it connects from."""
    if ip in IDENTITIES:
        return IDENTITIES[ip]
    if ip not in _AUTO_IDS:
        octet = 0
        if ip.startswith("10.42.0."):
            try:
                octet = int(ip.rsplit(".", 1)[1])
            except ValueError:
                octet = 0
        n = octet or (1 + len(IDENTITIES) + len(_AUTO_IDS))
        _AUTO_IDS[ip] = (f"player{n}", n)
        log(f"  new console at {ip} -> identity {_AUTO_IDS[ip]}")
    return _AUTO_IDS[ip]


# --------------------------------------------------------------- stats store
STATS_UPLOADS = CAP / "stats-uploads.jsonl"
NO_STATS_STORE = os.environ.get("WOW2_NO_STATS_STORE") == "1"
LEADERBOARD_CAPACITY = 50

KNOWN_ACCOUNTS: dict[str, int] = {
    "player1": 0x975367efa4bbebed,
    "testuser": 0xbb4dc191b75e31fc,
    "127.0.0.1": 0x975367efa4bbebed,
    "10.42.0.2": 0xbb4dc191b75e31fc,
}
_SEEN_ACCOUNTS: dict[str, int] = {}
LEARN_ACCOUNT_ID = os.environ.get("WOW2_LEARN_ACCOUNT_ID") == "1"


def account_seen(ident_key: str, entity_id: int, name: str) -> None:
    """Note the first 64-bit account a connection asks about, as a DIAGNOSTIC."""
    if not entity_id or ident_key in _SEEN_ACCOUNTS:
        return
    _SEEN_ACCOUNTS[ident_key] = entity_id
    if not ident_key.replace(".", "").isdigit():
        derived = account_id_for(ident_key)
        if derived != entity_id:
            log(f"  (!!!! {ident_key} asked about account 0x{entity_id:016x} "
                f"first, but Tiger192(name)[:8] derives 0x{derived:016x} -- "
                f"a console reads ITSELF first, so this connection is not "
                f"behaving like one; it stays filed under its own account"
                + (", except that WOW2_LEARN_ACCOUNT_ID=1 is set, so the "
                   "reported id is ADOPTED)" if LEARN_ACCOUNT_ID else ")"))
            return
        log(f"  account: {ident_key} ({name}) = 0x{entity_id:016x} "
            f"(the console's first read agrees with the derivation)")
        return
    if KNOWN_ACCOUNTS.get(ident_key) not in (None, entity_id):
        log(f"  (!! {ident_key} reads 0x{entity_id:016x} first, but KNOWN_ACCOUNTS "
            f"says 0x{KNOWN_ACCOUNTS[ident_key]:016x} -- using the live one)")
    log(f"  account: {ident_key} ({name}) = 0x{entity_id:016x} [by address]")


def account_id_for(username: str) -> int:
    """The client's 64-bit account id, DERIVED from the lowercased name (§71d)."""
    return int.from_bytes(account_handle(username), "little")


def account_for(ident_key: str) -> int:
    """The 64-bit account id behind an ident key (account name, or an address)."""
    if ident_key and not ident_key.replace(".", "").isdigit() and not LEARN_ACCOUNT_ID:
        return account_id_for(ident_key)
    if ident_key in _SEEN_ACCOUNTS:
        return _SEEN_ACCOUNTS[ident_key]
    if ident_key and not ident_key.replace(".", "").isdigit():
        return account_id_for(ident_key)
    return KNOWN_ACCOUNTS.get(ident_key, 0)


def stats_key(board_id: int, entity_id: int) -> str:
    return statsdb.key(board_id, entity_id)


def stats_get(board_id: int, entity_id: int, default_name: str = "") -> tuple[int, int, str]:
    """(score, rank, name) for one board/entity. Unknown -> an unranked zero row."""
    return statsdb.get(board_id, entity_id, default_name)


def stats_put(board_id: int, entity_id: int, score: int,
              name: str = "", extra: list | None = None) -> None:
    """Record one uploaded score; rank is derived on read (statsdb.put)."""
    if NO_STATS_STORE:
        log("  (stats store disabled by WOW2_NO_STATS_STORE)")
        return
    before = statsdb.raw(board_id, entity_id)
    try:
        ok, rank = statsdb.put(board_id, entity_id, score, name, extra)
    except store.sqlite3.Error as e:
        log(f"  (!! could not write the stats table: {e})")
        return
    if not ok:
        return
    log(f"  stats STORED {statsdb.key(board_id, entity_id)} = score {score} "
        f"(rank {rank or '?'}, was {before[0] if before else None})")
    lobbyboard.BOARD.scored(board_id)


def pot_gone(sid: int) -> None:
    """The session behind a pot went away: potbank holds or settles it, and a
    refund it sweeps moves board 5, so the leaderboards repaint."""
    settled = potbank.settle_unresolved(sid)
    if settled:
        log(f"  POT: {settled}")
        if "REFUNDED" in settled:
            lobbyboard.BOARD.scored(statsdb.RATING_BOARD)


def read_typed_tail(r) -> list:
    """Every remaining typed field of a request, walked blind. Used for the game's
    own RankData blob after the score: it is mask-gated, so its length varies with
    what the match produced, and no fixed parse would survive.
    """
    out = []
    while True:
        try:
            t, v = bddump.read_field(r)
        except Exception:
            return out
        out.append([bddump.TYPE_NAMES.get(t, str(t)), v])


def stats_write_upload(dec: dict, who: tuple[str, int] | None = None,
                       peer_ip: str = ""):
    """bdStats op 1 -- writeStats. Returns (0, None) on purpose."""
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        r.u8()
        board_id = r.i32()
        entity = r.u64()
        score = r.i64()
        extra = read_typed_tail(r)
    except Exception as e:
        log(f"  (stats op1 decode failed: {e})")
        return 0, None

    if board_id in statsdb.CLAN_BOARDS and not entity:
        tid, trec = team_of(account_for(peer_ip))
        if tid:
            entity = tid
            name = trec.get("name", name)
            log(f"  (board {board_id} is a clan board -- attributed to clan "
                f"{name!r} 0x{tid:016x}, not to the player)")
        else:
            log(f"  (board {board_id} is a clan board and this console has no "
                "clan yet -- upload dropped rather than filed under the player)")
            return 0, None
    entity = entity or account_for(peer_ip)
    blob = " ".join(f"{t}={v}" for t, v in extra)
    log(f"  stats op1 (WRITE): boardID={board_id} score={score} "
        f"entity=0x{entity:016x} ({name}) blob[{len(extra)}]: {blob or '-'}")
    try:
        with open(STATS_UPLOADS, "a") as f:
            f.write(json.dumps({"t": ts(), "peer": peer_ip, "name": name,
                                "entity": f"{entity:016x}", "board": board_id,
                                "score": score, "blob": extra}) + "\n")
    except OSError:
        pass
    if not entity:
        log("  (!! no account id for this console -- upload not stored)")
        return 0, None
    if board_id == statsdb.RATING_BOARD:
        sid = ranked_session_id()
        if sid:
            before, _rank, _n = stats_get(board_id, entity, name)
            if score > before and not os.environ.get("WOW2_NO_CLIENT_PAYOUT"):
                log("  POT: " + potbank.note_payout(sid, entity, name, before, score))
            else:
                stake, pot = potbank.note_stake(sid, entity, name, before, score)
                log(f"  POT: {name} staked {stake} ({before} -> {score}); "
                    f"session 0x{sid:x} pot is now {pot}")
    elif board_id in potbank.SIDE_BOARDS:
        sid = ranked_session_id()
        if sid:
            before, _rank, _n = stats_get(board_id, entity, name)
            stake = potbank.note_side_stake(sid, board_id, entity, name, before, score)
            if stake:
                log(f"  POT: {name} staked {stake} on {potbank.SIDE_BOARDS[board_id]} "
                    f"({before} -> {score}) for session 0x{sid:x}")
    elif board_id == statsdb.GAMES_BOARD:
        before, _rank, _n = stats_get(board_id, entity, name)
        host_reported_game(peer_ip, before, score)
    stats_put(board_id, entity, score, name, extra)
    return 0, None


def emit_rows(rows: list, total: int, board_id: int = 0):
    """Writer callback for a bdLeaderBoardResult: [u32 totalEntries] then the rows."""
    tail = board_id == 1 and os.environ.get("WOW2_NO_STATS_ROW_TAIL") != "1"
    sentinel = os.environ.get("WOW2_STATS_ROW_TAIL_A")

    def emit(w):
        w.u32(total)
        for eid, score, rank, name in rows:
            write_leaderboard_row(w, eid, score, rank, name)
            if tail:
                a, b = _board1_tail(eid)
                if sentinel:
                    a = int(sentinel, 0)
                log(f"  (board 1 tail for 0x{eid:016x}: A=0x{a:x} B=0x{b:x}"
                    f"{' SENTINEL' if sentinel else ''}, "
                    f"{bin(a).count('1') + bin(b).count('1')} game(s) unfinished)")
                w.i32(0)
                w.i64(a)
                w.i64(b)
    return emit


def _board1_tail(entity: int) -> tuple[int, int]:
    """The two i64s this account last uploaded on board 1: its completion history
    (netrecon §48)."""
    tail = statsdb.tail(1, entity)
    if isinstance(tail, list):
        vals = [v for _t, v in tail]
        if len(vals) >= 3:
            try:
                return int(vals[1]), int(vals[2])
            except (TypeError, ValueError):
                pass
    return 0, 0


def stats_read_results(dec: dict, who: tuple[str, int] | None = None,
                       peer_ip: str = ""):
    """bdStats op 4 -- readStatsByEntityIDs. One row per requested entity."""
    entities = []
    board_id = 0
    try:
        r = lsg_request_params(dec)
        r.u8()
        board_id = r.i32()
        for _ in range(r.u32()):
            entities.append(r.u64())
    except Exception as e:
        log(f"  (stats op4 decode failed: {e})")
    default = (who or (rigconfig.USERNAME, rigconfig.USER_ID))[0]
    if entities:
        account_seen(peer_ip, entities[0], default)
    entities = entities[:LEADERBOARD_CAPACITY]
    total = statsdb.count(board_id)
    rows = []
    for eid in entities:
        score, rank, name = stats_get(board_id, eid, default)
        rows.append((eid, score, rank, name))

    log(f"  stats op4 (read-by-entity): boardID={board_id} entities="
        + ",".join(f"0x{e:016x}" for e in entities)
        + " -> serving " + (", ".join(f"{r[2]}. {r[3]} {r[1]}" for r in rows) or "(nothing)")
        + f" of {total}")
    return len(rows), emit_rows(rows, total, board_id)


def stats_pivot_results(dec: dict, who: tuple[str, int] | None = None,
                        peer_ip: str = ""):
    """bdStats op 5 -- readStatsByPivot. A page of a board, anchored two ways."""
    board_id = pivot = start_rank = 0
    count = 1
    try:
        r = lsg_request_params(dec)
        r.u8()
        board_id = r.i32()
        pivot = r.u64()
        start_rank = r.u64()
        count = r.i64()
    except Exception as e:
        log(f"  (stats op5 decode failed: {e})")

    default = (who or (rigconfig.USERNAME, 0))[0]
    total = statsdb.count(board_id)
    want = max(1, min(int(count), LEADERBOARD_CAPACITY))
    if start_rank:
        rows = statsdb.page_by_rank(board_id, start_rank, want, default)
    elif pivot:
        rows = statsdb.page_around(board_id, pivot, want, default)
    else:
        rows = statsdb.top(board_id, want, default)
    if not rows and pivot:
        score, rank, name = stats_get(board_id, pivot, default)
        rows = [(pivot, score, rank, name)]

    log(f"  stats op5 (read-by-pivot): boardID={board_id} "
        f"pivot=0x{pivot:016x} startRank={start_rank} count={count} -> serving "
        + (" | ".join(f"{r[2]}. {r[3]} {r[1]}" for r in rows) or "(nothing)")
        + f" of {total}")
    return len(rows), emit_rows(rows, total, board_id)


# --------------------------------------------------------------- sessions (svc 5)
SESSION_ID_BYTES = 8
BD_COMMON_ADDR_SIZE = 25
SESSION_SECRET_BYTES = 16

NO_KEY_REWRITE = os.environ.get("WOW2_NO_KEY_REWRITE") == "1"

SESSIONS: dict[int, dict] = {}
_next_session_id = [0x5701]
SEARCH_PAGE_MAX = 50    # the browser asks for 25


def online_count() -> int:
    """Consoles signed in: the LSG connections bound to an account (§60)."""
    return sum(1 for c in LSG_CONNS.values() if c.is_lsg and c.account and c.authenticated)


def board_refresh() -> None:
    """The session table, or who is signed in, changed: repaint the lobby board."""
    lobbyboard.BOARD.refresh(SESSIONS, online_count())


def host_reported_game(host_key: str, before: int, score: int) -> None:
    """Board 1 from a session's host: one more game started puts the session in
    progress with the players it had before the start's own re-publish (which
    says maxPlayers, §63d); the same score again is the match's end (§48)."""
    for sid, rec in SESSIONS.items():
        if rec.get("host") != host_key:
            continue
        if score > before and not rec.get("started"):
            n = rec.get("players") or 0
            if rec.get("max_players") and n >= rec["max_players"] and rec.get("players_before"):
                n = rec["players_before"]
            rec["started"] = int(time.time())
            rec["playing"] = int(n)
            log(f"  session STARTED: id=0x{sid:x} {rec.get('name')!r} -- its host "
                f"reports a game started; {n} playing")
            board_refresh()
        elif score == before and rec.get("started"):
            log(f"  session FINISHED: id=0x{sid:x} {rec.get('name')!r} -- its host "
                f"reports the game over; the session goes when the host deletes it")


def sessions_create_result(dec: dict, peer_ip: str = "", host_key: str = ""):
    """Result block for Sessions op 1. Returns (num_results, writer-callback)."""
    rec: dict = {"info": [], "name": "", "max_players": 0, "addr": b"",
                 "host_ip": peer_ip, "host": host_key or peer_ip}
    try:
        r = lsg_request_params(dec)
        fields = bd.read_fields(r)
        rec["info"] = fields[1:]
        vals = [v for _t, v in fields]
        rec["addr"] = next((v for v in vals if isinstance(v, bytes)
                             and len(v) == BD_COMMON_ADDR_SIZE), b"")
        names = [v for v in vals if isinstance(v, str)]
        rec["name"] = names[0] if names else ""
        ints = [v for t, v in fields if t == bd.BD_SINT32]
        rec["max_players"] = ints[10] if len(ints) > 10 else 0
        rec["players"] = ints[1] if len(ints) > 1 else 0
        rec["points"] = ints[6] if len(ints) > 6 else 0
    except Exception as e:
        log(f"  (session create decode failed: {e})")
    for old_sid, old_rec in [(k, v) for k, v in SESSIONS.items()
                             if v.get("host") == rec["host"]]:
        SESSIONS.pop(old_sid, None)
        log(f"  session create: {rec['host']!r} already hosted 0x{old_sid:x} "
            f"{old_rec.get('name')!r} -- replaced")
        pot_gone(old_sid)
        lobbyboard.BOARD.closed(old_sid)
    sid = _next_session_id[0]
    _next_session_id[0] += 1
    rec["id"] = sid
    rec["created"] = int(time.time())
    SESSIONS[sid] = rec
    secret = (b"WOW2SESS" + sid.to_bytes(SESSION_ID_BYTES, "little"))[:SESSION_SECRET_BYTES]
    rec["secret"] = secret

    def emit(w):
        w.blob(sid.to_bytes(SESSION_ID_BYTES, "little"))
        w.blob(secret)

    addr = rec["addr"]
    where = (f"{'.'.join(str(b) for b in addr[0:4])}:"
             f"{int.from_bytes(addr[4:6], 'little')}" if len(addr) >= 6 else "?")
    if len(addr) >= 24:
        where += (f" / {'.'.join(str(b) for b in addr[18:22])}:"
                  f"{int.from_bytes(addr[22:24], 'little')}")
    log(f"  session create: id=0x{sid:x} host={rec['name']!r} at {where} "
        f"players={rec.get('players', 0)}/{rec['max_players']} "
        f"mode={'POINTS' if rec.get('points') else 'fun'} "
        f"info={len(rec['info'])} fields ({len(SESSIONS)} live)")
    if rec.get("points"):
        potbank.open_pot(sid, rec["name"])
        log(f"  POT opened for ranked session 0x{sid:x} -- each console will pay "
            f"10% of board {statsdb.RATING_BOARD} when the match starts")
    lobbyboard.BOARD.opened(rec)
    board_refresh()
    return 1, emit


def ranked_session_id() -> int:
    """The live ranked session a stake belongs to -- the newest `mode=POINTS` one."""
    ranked = [sid for sid, rec in SESSIONS.items() if rec.get("points")]
    return max(ranked) if ranked else 0


def host_addr_for(host_ip: str, joiner_ip: str) -> str:
    """The host console's address *as the joiner can actually reach it*."""
    if not host_ip or not joiner_ip:
        return host_ip
    if host_ip.startswith("127.") and not joiner_ip.startswith("127."):
        return rigconfig.NETNS_BRIDGE_IP
    return host_ip


def addr_with_host_ip(addr: bytes, ip: str) -> bytes:
    """bdCommonAddr with both endpoints repointed at `ip`."""
    if len(addr) < 24:
        return addr
    try:
        raw = socket.inet_aton(ip)
    except OSError:
        return addr
    b = bytearray(addr)
    b[0:4] = raw
    b[18:22] = raw
    return bytes(b)


def addr_with_endpoint(addr: bytes, ip: str, port: int) -> bytes:
    """bdCommonAddr with BOTH endpoints set to one ip:port -- the relay form."""
    if len(addr) < 25:
        return addr
    try:
        raw = socket.inet_aton(ip)
    except OSError:
        return addr
    b = bytearray(addr)
    b[0:4] = raw
    b[4:6] = port.to_bytes(2, "little")
    b[18:22] = raw
    b[22:24] = port.to_bytes(2, "little")
    return bytes(b)


def relay_endpoint_for_host(rec: dict, joiner_ip: str = ""):
    """Where to tell a joiner the host is, when the relay is carrying the match."""
    if not natrelay.RELAY.enabled:
        return None
    advertised = public = None
    for t, v in rec.get("info", []):
        if t == bd.BD_BLOB and isinstance(v, bytes) and len(v) == BD_COMMON_ADDR_SIZE:
            advertised = (socket.inet_ntoa(v[0:4]),
                          int.from_bytes(v[4:6], "little"))
            public = (socket.inet_ntoa(v[18:22]),
                      int.from_bytes(v[22:24], "little"))
            break
    host_ip = rec.get("host_ip", "")
    c = None
    if public and public[0] == server_address_for(host_ip):    # what our discovery reply told the host it is
        c = natrelay.RELAY.owner_of_advertised(public)
        if c is not None and c.key[0] != host_ip:
            c = None
    if c is None:
        c = natrelay.RELAY.owner_of_advertised(advertised)
    if c is None:
        hits = [x for x in natrelay.RELAY.consoles.values()
                if x.key[0] == host_ip and x.mailbox]
        if len(hits) == 1:
            c = hits[0]
            log(f"  (relay: host advertised {advertised} / {public}, which is not a "
                f"mailbox -- matched it to {c} by address instead)")
    if c is None or c.mailbox is None:
        log(f"  !! relay is ON but session 0x{rec.get('id', 0):x}'s host has no "
            f"mailbox (it advertised {advertised} / {public}); the joiner will be "
            f"given an address the relay does not serve")
        return None
    return server_address_for(joiner_ip or rec.get("host_ip", "")), c.mailbox.port


def info_with_session_id(rec: dict, joiner_ip: str = ""):
    """The host's bdMatchMakingInfo with OUR session id and a reachable address."""
    want_ip = ""
    if os.environ.get("WOW2_NO_ADDR_REWRITE") != "1":
        want_ip = host_addr_for(rec.get("host_ip", ""), joiner_ip)
    relay_to = relay_endpoint_for_host(rec, joiner_ip)
    if relay_to:
        want_ip = ""

    out, patched, keyed, moved = [], False, False, ""
    for t, v in rec.get("info", []):
        if t == bd.BD_BLOB and isinstance(v, bytes):
            if not patched and len(v) == SESSION_ID_BYTES:
                v = rec["id"].to_bytes(SESSION_ID_BYTES, "little")
                patched = True
            elif (not keyed and len(v) == SESSION_SECRET_BYTES
                  and rec.get("secret") and not NO_KEY_REWRITE):
                v = rec["secret"]
                keyed = True
            elif relay_to and len(v) == BD_COMMON_ADDR_SIZE:
                was = f"{'.'.join(str(x) for x in v[0:4])}:" \
                      f"{int.from_bytes(v[4:6], 'little')}"
                v = addr_with_endpoint(v, relay_to[0], relay_to[1])
                moved = f"{was} -> {relay_to[0]}:{relay_to[1]} [relay]"
            elif want_ip and len(v) == BD_COMMON_ADDR_SIZE:
                was = ".".join(str(x) for x in v[0:4])
                if was != want_ip:
                    v = addr_with_host_ip(v, want_ip)
                    moved = f"{was} -> {want_ip}"
        out.append((t, v))
    if not patched:
        log(f"  (!! no {SESSION_ID_BYTES}-byte id blob in session 0x{rec['id']:x}'s "
            "info -- advertising it with the host's original bytes)")
    if keyed:
        log(f"    security key for joiner {joiner_ip}: {rec['secret'].hex()}")
    elif not NO_KEY_REWRITE:
        log(f"  (!! no {SESSION_SECRET_BYTES}-byte key blob in session "
            f"0x{rec['id']:x}'s info -- the joiner will key its MAC differently "
            "from the host)")
    if moved:
        log(f"    host address for joiner {joiner_ip}: {moved}")
    return out


def sessions_search_results(dec: dict, joiner_ip: str = ""):
    """Sessions op 5 -- the game browser's search. One result per live session."""
    try:
        r = lsg_request_params(dec)
        filters = [v for t, v in bd.read_fields(r) if t == bd.BD_SINT32]
    except Exception as e:
        log(f"  (session search decode failed: {e})")
        filters = []
    want = filters[1] if len(filters) > 1 and 0 < filters[1] <= SEARCH_PAGE_MAX \
        else SEARCH_PAGE_MAX
    start = filters[2] if len(filters) > 2 and filters[2] > 0 else 0
    live = sorted(SESSIONS.values(),
                  key=lambda rec: (bool(rec.get("max_players")) and
                                   rec.get("players", 0) >= rec.get("max_players", 0),
                                   -rec.get("id", 0)))
    rows = live[start:start + want]

    def emit(w):
        for rec in rows:
            bd.write_fields(w, info_with_session_id(rec, joiner_ip))

    log(f"  session search: {len(rows)} of {len(live)} session(s) -> "
        + (", ".join(f"0x{r['id']:x} {r['name']!r}" for r in rows) or "none")
        + (f"  page {start}+{want}; filters={filters[:4]}..." if filters else ""))
    return len(rows), emit


def sessions_get_result(dec: dict, peer_ip: str = ""):
    """Sessions op 4: fetch one session by id (a match invite opened in View messages)."""
    try:
        r = lsg_request_params(dec)
        r.u8()
        blob = r.blob()
    except Exception as e:
        log(f"  (session get decode failed: {e})")
        return 0, None
    sid = int.from_bytes(blob[:SESSION_ID_BYTES], "little")
    rec = SESSIONS.get(sid)
    if rec is None:
        log(f"  session get: 0x{sid:x} -- NOT LIVE ({len(SESSIONS)} session(s) "
            "held); replying 0 results, which the client shows as "
            "\"Couldn't fetch match details.\"")
        return 0, None
    log(f"  session get: 0x{sid:x} {rec['name']!r} "
        f"mode={'POINTS' if rec.get('points') else 'fun'} -> 1 result")

    def emit(w):
        bd.write_fields(w, info_with_session_id(rec, peer_ip))
    return 1, emit


def sessions_host_gone(host_key: str) -> None:
    """The LSG connection bound to `host_key` dropped. Drop what it was hosting."""
    if not host_key or os.environ.get("WOW2_NO_HOST_EXPIRY") == "1":
        return
    if os.environ.get("WOW2_KEEP_SESSIONS") == "1":
        return
    doomed = [sid for sid, rec in SESSIONS.items() if rec.get("host") == host_key]
    for sid in doomed:
        rec = SESSIONS.pop(sid)
        log(f"  session EXPIRED: id=0x{sid:x} {rec.get('name')!r} -- its host's LSG "
            f"connection went away without a Sessions op 3 "
            f"({len(SESSIONS)} live)")
        pot_gone(sid)
        lobbyboard.BOARD.closed(sid)
    if doomed:
        board_refresh()


def sessions_update(dec: dict, peer_ip: str = "", host_key: str = ""):
    """Sessions op 2: the host re-publishes its bdMatchMakingInfo. No results."""
    if os.environ.get("WOW2_NO_SESSION_UPDATE") == "1":
        return 0, None
    try:
        r = lsg_request_params(dec)
        fields = bd.read_fields(r)
    except Exception as e:
        log(f"  (session update decode failed: {e})")
        return 0, None
    vals = [v for _t, v in fields]
    blobs = [v for v in vals if isinstance(v, bytes)]
    sid_blob = next((b for b in blobs if len(b) == SESSION_ID_BYTES), b"")
    sid = int.from_bytes(sid_blob, "little") if sid_blob else 0
    rec = SESSIONS.get(sid)
    if rec is None:
        log(f"  session update: id=0x{sid:x} is not one of ours -- ignored "
            f"({len(SESSIONS)} live)")
        return 0, None
    if not session_owned_by(rec, host_key or peer_ip):
        log(f"  session update: id=0x{sid:x} is hosted by {rec.get('host')!r}, "
            f"and this connection is {host_key or peer_ip!r} -- REFUSED "
            f"(if a promoted host ever re-advertises after a migration, this "
            f"is where it would show; netrecon §23)")
        return 0, None

    addr = next((b for b in blobs if len(b) == BD_COMMON_ADDR_SIZE), b"")
    names = [v for v in vals if isinstance(v, str)]
    ints = [v for t, v in fields if t == bd.BD_SINT32]
    was_addr, was_ip, was_name = rec.get("addr"), rec.get("host_ip"), rec.get("name")

    rec["info"] = fields[1:]
    if addr:
        rec["addr"] = addr
    if names:
        rec["name"] = names[0]
    if len(ints) > 10:
        rec["max_players"] = ints[10]
    if len(ints) > 1:
        rec["players_before"] = int(rec.get("players") or 0)
        rec["players"] = ints[1]
    if len(ints) > 6:
        rec["points"] = ints[6]
    if peer_ip:
        rec["host_ip"] = peer_ip

    where = (f"{'.'.join(str(b) for b in rec['addr'][0:4])}:"
             f"{int.from_bytes(rec['addr'][4:6], 'little')}"
             if len(rec.get("addr") or b"") >= 6 else "?")
    moved = (addr and was_addr and addr != was_addr) or \
            (peer_ip and was_ip and peer_ip != was_ip) or \
            (names and was_name and names[0] != was_name)
    log(f"  session update: id=0x{sid:x} host={rec['name']!r} at {where} "
        f"from {peer_ip or '?'} players={rec.get('players', 0)}/{rec['max_players']} "
        f"mode={'POINTS' if rec.get('points') else 'fun'}")
    if moved:
        log(f"  *** SESSION HOST CHANGED: {was_name!r}@{was_ip} -> "
            f"{rec['name']!r}@{rec['host_ip']} -- this is what a HOST MIGRATION "
            f"would look like from here. Write it down (netrecon Phase 23).")
    board_refresh()
    return 0, None


def session_owned_by(rec: dict, key: str) -> bool:
    """Is `key` (an ident key) the host of this session record?"""
    if os.environ.get("WOW2_NO_SESSION_OWNER") == "1":
        return True
    return key == (rec.get("host") or rec.get("host_ip"))


def sessions_delete(dec: dict, host_key: str = ""):
    """Sessions op 3: drop the session the client names. No results expected."""
    try:
        r = lsg_request_params(dec)
        r.u8()
        sid = int.from_bytes(r.blob(), "little")
    except Exception as e:
        log(f"  (session delete decode failed: {e})")
        return 0, None
    rec = SESSIONS.get(sid)
    if rec is not None and not session_owned_by(rec, host_key):
        log(f"  session delete: id=0x{sid:x} is hosted by {rec.get('host')!r}, "
            f"and this connection is {host_key!r} -- REFUSED")
        return 0, None
    if os.environ.get("WOW2_KEEP_SESSIONS") == "1" and sid in SESSIONS:
        log(f"  session delete: id=0x{sid:x} -- WOW2_KEEP_SESSIONS, left listed")
        return 0, None
    gone = SESSIONS.pop(sid, None)
    log(f"  session delete: id=0x{sid:x} "
        + (f"({gone['name']!r} removed, {len(SESSIONS)} live)" if gone
           else "-- not one of ours; the client had no session id"))
    pot_gone(sid)
    if gone:
        lobbyboard.BOARD.closed(sid)
        board_refresh()
    return 0, None


# ----------------------------------------------------- server -> client PUSH
FRIEND_LIST_BUDGET = 40
FRIEND_BLOCK_LIMIT = 40

PUSH_BUDDY_INVITE = 1
PUSH_BUDDY_ACCEPTED = 2
PUSH_BUDDY_REJECTED = 3
PUSH_BUDDY_REVOKED = 4
PUSH_MATCH_INVITE = 5
PUSH_CLAN_INVITE = 13
CLAN_PUSH_TYPES = tuple(range(13, 29)) + (37, 39)
CLAN_TAIL_TYPES = (17, 18, 28, 39)
CLAN_BLOB_TYPES = (13, 22, 23)
CLAN_INVITE_PUSH_DEFAULT = PUSH_CLAN_INVITE
PUSH_MATCH_ACCEPTED = 6
PUSH_MATCH_REJECTED = 7
PUSH_NOW_ONLINE = 9
PUSH_NOW_OFFLINE = 10
PUSH_PROPOSAL_CANCELLED = 34
PUSH_SIGNED_IN_ELSEWHERE = 29

LSG_CONNS: dict[str, "AuthConnection"] = {}
_push_ids = [1]


def write_push_body(w, type_id: int, msg_id: int, sender: int, sender_name: str,
                    session_id: bytes = b"", clan_name: str = "",
                    target: int = 0, target_name: str = ""):
    """The class-selected body of one lobby message."""
    w.u32(type_id)

    # --- the super-base 0x08c299cc: EVERY message class begins with these ---
    w.u64(msg_id)                 # message id
    w.u64(msg_id)                 # dedup key: the client drops a repeat, unless 0
    w.u32(0)
    w.bool_(False)
    # --- base A's own two fields 0x08c23acc, shared by base B at the same
    w.u64(sender)
    w.str_(sender_name, 63)

    if type_id in CLAN_PUSH_TYPES:
        w.u64(int.from_bytes(bytes(session_id[:8]).ljust(8, b"\x00"), "little"))
        w.str_(os.environ.get("WOW2_PUSH_MIDNAME") or clan_name, 63)
        if type_id in CLAN_BLOB_TYPES:
            w.u16(0)
        elif type_id in CLAN_TAIL_TYPES:
            w.u64(target)
            w.str_(os.environ.get("WOW2_PUSH_TAILNAME") or target_name
                   or clan_name, 63)
        return

    if type_id == PUSH_BUDDY_INVITE:
        w.u16(0)
    elif type_id == PUSH_MATCH_INVITE:
        w.blob(bytes(session_id[:8]).ljust(8, b"\x00"))
        w.u16(0)


def build_lsg_push_encrypted(type_id: int, sender: int, sender_name: str,
                             session_key: bytes, msg_id: int = 0,
                             seed: int = 0x22446688,
                             session_id: bytes = b"", clan_name: str = "",
                             target: int = 0, target_name: str = "") -> bytes:
    """One LsgServicePushMessage. Same envelope as a TaskReply, type byte 2."""
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    write_push_body(w, type_id, msg_id, sender, sender_name, session_id,
                    clan_name, target, target_name)
    plaintext = (RESPONSE_SIGNATURE.to_bytes(4, "little")
                 + bytes([LSG_MSG_PUSH_MESSAGE])
                 + w.getvalue())
    if len(plaintext) % 8:
        plaintext += b"\x00" * (8 - len(plaintext) % 8)
    ct = session_cbc_encrypt(plaintext, session_key, tiger_iv(seed))
    body = bytes([1]) + seed.to_bytes(4, "little") + ct
    return len(body).to_bytes(4, "little") + body


def push_to_account(entity: int, type_id: int, sender: int, sender_name: str,
                    msg_id: int = 0, session_id: bytes = b"",
                    clan_name: str = "", target: int = 0,
                    target_name: str = "") -> bool:
    """Send one push to whichever live connection is signed in as `entity`."""
    if os.environ.get("WOW2_NO_PUSH") == "1":
        log("  (push suppressed by WOW2_NO_PUSH)")
        return False
    for ident_key, conn in list(LSG_CONNS.items()):
        if account_for(ident_key) != entity or conn.t is None:
            continue
        try:
            conn.t.write(build_lsg_push_encrypted(type_id, sender, sender_name,
                                                  conn.session_key
                                                  or rigconfig.SESSION_KEY, msg_id,
                                                  session_id=session_id,
                                                  clan_name=clan_name,
                                                  target=target,
                                                  target_name=target_name))
        except Exception as e:
            log(f"  (!! push to {ident_key} failed: {e})")
            return False
        log(f"  -> PUSH type {type_id} to {ident_key} (0x{entity:016x}): "
            f"from {sender_name!r} 0x{sender:016x}")
        return True
    log(f"  (no live LSG connection for 0x{entity:016x} -- push not sent; "
        "the target sees it at its next sign-in instead)")
    return False


NO_EVICT = os.environ.get("WOW2_NO_EVICT") == "1"


def evict_other_lsg(account: str, keep) -> int:
    """Sign `account` out of every LSG connection except `keep`. How many went."""
    if NO_EVICT:
        return 0
    gone = 0
    for key, conn in list(LSG_CONNS.items()):
        if conn is keep or conn.account != account or conn.t is None:
            continue
        try:
            conn.t.write(build_lsg_push_encrypted(
                PUSH_SIGNED_IN_ELSEWHERE, account_for(account), account,
                conn.session_key or rigconfig.SESSION_KEY, notify_id()))
        except Exception as e:
            log(f"  (!! could not tell {key} it had been signed out: {e})")
        if LSG_CONNS.get(key) is conn:
            del LSG_CONNS[key]
        conn.t.close()
        gone += 1
        log(f"  A7: {account!r} has signed in again -- pushed type "
            f"{PUSH_SIGNED_IN_ELSEWHERE} to the older connection ({conn.peer}) "
            f"and closed it")
    if gone:
        sessions_host_gone(account)
    return gone


# ------------------------------------------------------- buddies and clans
TEAM_ID_BASE = 0x00C1A0_0000_0000
FRIEND_NAME_MAX = 64
FRIEND_ROW_DEFAULT = "5=bool,7=u8,19=none"
FRIEND_ROWS = {}
for _part in os.environ.get("WOW2_FRIEND_ROWS", FRIEND_ROW_DEFAULT).split(","):
    if "=" in _part:
        _o, _k = _part.split("=", 1)
        FRIEND_ROWS[int(_o)] = _k.strip()


_UNREADABLE: dict[str, str] = {}


def _jload(path: Path, default: dict) -> dict:
    """Read a JSON store. Missing means empty; CORRUPT is loud and sticky."""
    try:
        raw = path.read_text()
    except FileNotFoundError:
        return dict(default)
    except OSError as e:
        log(f"  (!! could not read {path.name}: {e})")
        return dict(default)
    try:
        d = json.loads(raw)
    except ValueError as e:
        if str(path) not in _UNREADABLE:
            keep = path.with_suffix(path.suffix + f".corrupt-{ts_file()}")
            try:
                path.replace(keep)
                where = keep.name
            except OSError:
                where = "(could not be preserved)"
            _UNREADABLE[str(path)] = str(e)
            log(f"  (!!!! {path.name} IS CORRUPT and will NOT be overwritten: {e}"
                f"\n        the damaged file is kept as {where}; writes to this"
                f" store are refused until the server restarts)")
        return dict(default)
    if not isinstance(d, dict):
        if str(path) not in _UNREADABLE:
            _UNREADABLE[str(path)] = f"top level is {type(d).__name__}, not an object"
            log(f"  (!!!! {path.name} is not a JSON object -- writes refused)")
        return dict(default)
    return d


def _jsave(path: Path, data: dict) -> None:
    """Write a JSON store ATOMICALLY, or not at all."""
    if str(path) in _UNREADABLE:
        log(f"  (!! refusing to write {path.name}: it failed to load this run "
            f"({_UNREADABLE[str(path)]}) and overwriting it would destroy data)")
        return
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True))
        os.replace(tmp, path)
    except OSError as e:
        log(f"  (!! could not write {path}: {e})")
        try:
            tmp.unlink()
        except OSError:
            pass


# --------------------------------------------------------- account credentials


def stored_credential(username: str) -> bytes | None:
    """The digest we hold for `username` (in any letter case), or None."""
    row = store.db().execute("SELECT pwhash FROM accounts WHERE handle = ?",
                             (account_handle(username).hex(),)).fetchone()
    if row and row["pwhash"]:
        try:
            return bytes.fromhex(row["pwhash"])
        except ValueError:
            log(f"  (!! {username!r} has an unreadable pwhash in the store)")
    return None


CREATES_PER_IP: dict[str, list[float]] = {}
CREATES_WINDOW = 3600.0
CREATES_ADDRESSES_MAX = 65536


def create_allowed(peer_ip: str, now: float | None = None) -> bool:
    """May this address create one more account? Counted only when it does."""
    limit = serverconfig.MAX_CREATES_PER_IP_PER_HOUR
    if limit <= 0:
        return True
    now = time.time() if now is None else now
    recent = [t for t in CREATES_PER_IP.get(peer_ip, ()) if now - t < CREATES_WINDOW]
    if len(recent) >= limit:
        CREATES_PER_IP[peer_ip] = recent
        return False
    recent.append(now)
    CREATES_PER_IP.pop(peer_ip, None)    # re-insert: the dict's order is last-create order
    CREATES_PER_IP[peer_ip] = recent
    if len(CREATES_PER_IP) > CREATES_ADDRESSES_MAX:
        for ip in [ip for ip, ts in CREATES_PER_IP.items() if now - ts[-1] >= CREATES_WINDOW]:
            del CREATES_PER_IP[ip]
        while len(CREATES_PER_IP) > CREATES_ADDRESSES_MAX:
            del CREATES_PER_IP[next(iter(CREATES_PER_IP))]
    return True


def note_account(username: str, password_hash: bytes, peer_ip: str) -> None:
    """Record an account the client just created."""
    if os.environ.get("WOW2_NO_ACCOUNT_STORE") == "1":
        return
    with store.tx() as conn:
        old = conn.execute("SELECT pwhash FROM accounts WHERE handle = ?",
                           (account_handle(username).hex(),)).fetchone()
        old = old["pwhash"] if old else None
        if old and old != password_hash.hex():
            log(f"    (!!!! account {username!r}: password digest REPLACED by a "
                f"create-account from {peer_ip} -- the previous owner can no longer "
                f"sign in. Only create_mode = 'success' allows this.)")
        _write_credential(conn, username, password_hash, peer_ip)


def _write_credential(conn, username: str, password_hash: bytes, peer_ip: str) -> None:
    """Upsert one account's credential row; the caller holds the transaction."""
    now = store.now_iso()
    handle = account_handle(username).hex()
    have = conn.execute("SELECT name FROM accounts WHERE handle = ?", (handle,)).fetchone()
    name = have["name"] if have else username    # the case it was first registered in is what others see
    conn.execute(
        "INSERT INTO accounts (name, pwhash, handle, user_id, first_seen, last_seen, last_ip) "
        "VALUES (?, ?, ?, ?, ?, ?, ?) "
        "ON CONFLICT (name) DO UPDATE SET pwhash = excluded.pwhash, "
        "handle = excluded.handle, last_seen = excluded.last_seen, "
        "last_ip = COALESCE(excluded.last_ip, accounts.last_ip), "
        "user_id = COALESCE(accounts.user_id, excluded.user_id)",
        (name, password_hash.hex(), handle,
         allocate_user_id(conn, name), now, now, peer_ip or None))


def allocate_user_id(conn, username: str) -> int:
    """A stable small id per account. The rig's own consoles keep the ids
    IDENTITIES gives them (1..8) so nothing about the eight-console rig changes;
    anyone else is numbered from 100 up, which cannot collide.
    """
    have = conn.execute("SELECT user_id FROM accounts WHERE name = ?", (username,)).fetchone()
    if have and have["user_id"]:
        return int(have["user_id"])
    cfg = next((uid for _ip, (n, uid) in IDENTITIES.items() if n == username), 0)
    if cfg:
        return cfg
    top = conn.execute("SELECT MAX(user_id) FROM accounts WHERE user_id >= 100").fetchone()[0]
    return max(100, int(top or 0)) + 1


def set_account_password(username: str, password_hash: bytes, peer_ip: str = "") -> None:
    """Commit a new credential for an account. The digest IS the credential."""
    with store.tx() as conn:
        _write_credential(conn, username, password_hash, peer_ip)


def account_handle(username: str) -> bytes:
    """The 8 bytes a client puts in its login request to say who it is:
    Tiger192 of the name LOWERCASED (§71d); store.account_handle is the one copy."""
    return bytes.fromhex(store.account_handle(username))


_CONFIG_HANDLES: dict[bytes, dict] = {
    account_handle(name): {"name": name, "user_id": uid, "pwhash": None, "src": "config"}
    for _ip, (name, uid) in IDENTITIES.items()}


def account_by_handle(handle: bytes) -> dict | None:
    """{name, user_id, pwhash, src} for a login handle, or None."""
    row = store.db().execute(
        "SELECT name, user_id, pwhash FROM accounts WHERE handle = ?",
        (handle.hex(),)).fetchone()
    cfg = _CONFIG_HANDLES.get(handle)
    if row is None:
        return dict(cfg) if cfg else None
    pwhash = None
    if row["pwhash"]:
        try:
            pwhash = bytes.fromhex(row["pwhash"])
        except ValueError:
            log(f"  (!! {row['name']!r} has an unreadable pwhash in the store)")
    return {"name": row["name"],
            "user_id": row["user_id"] or (cfg["user_id"] if cfg else 0) or 0,
            "pwhash": pwhash or (cfg["pwhash"] if cfg else None),
            "src": "store" if not cfg else "config+store"}


ISSUED_SESSION_KEYS: dict[tuple[bytes, str], float] = {}
PROOF_HANDLES: dict[bytes, tuple[str, bytes, float]] = {}
PROOF_TTL = float(os.environ.get("WOW2_PROOF_TTL", "120"))
PROOFS_MAX = int(os.environ.get("WOW2_PROOFS_MAX", "65536"))
_proofs_swept = 0.0


def proofs_sweep(now: float | None = None, force: bool = False) -> None:
    """Drop the keys and handles no console will present any more: older
    than PROOF_TTL, and the oldest past PROOFS_MAX. At most once a second.
    """
    global _proofs_swept
    now = time.time() if now is None else now
    for table in (ISSUED_SESSION_KEYS, PROOF_HANDLES):
        while len(table) > PROOFS_MAX:
            del table[next(iter(table))]    # a dict keeps issue order
    if now - _proofs_swept < 1.0 and not force:
        return
    _proofs_swept = now
    for k in [k for k, t in ISSUED_SESSION_KEYS.items() if now - t > PROOF_TTL]:
        del ISSUED_SESSION_KEYS[k]
    for k in [k for k, v in PROOF_HANDLES.items() if now - v[2] > PROOF_TTL]:
        del PROOF_HANDLES[k]


def new_session_key(username: str, register: bool = True) -> bytes:
    """A fresh random 24-byte LSG session key for this sign-in."""
    if os.environ.get("WOW2_FIXED_SESSION_KEY") == "1":
        key = rigconfig.SESSION_KEY
    else:
        while True:
            key = secrets.token_bytes(24)
            if key[0:8] != key[8:16] and key[8:16] != key[16:24]:
                break
    if register:
        ISSUED_SESSION_KEYS[key, username] = time.time()
        proofs_sweep()
    return key


def session_key_is_ours(username: str, key: bytes) -> bool:
    issued = ISSUED_SESSION_KEYS.get((key, username))
    return issued is not None and time.time() - issued <= PROOF_TTL


LSG_NO_KEY_CHECK = os.environ.get("WOW2_LSG_NO_KEY_CHECK") == "1"

PROOF_HANDLE = os.environ.get("WOW2_NO_PROOF_HANDLE") != "1"


def lsg_message_readable(dec: dict, strict: bool = False) -> bool:
    """Did the decrypt produce a message that parses -- i.e. was the key right?"""
    if dec["service"] not in LSG_SERVICE_NAMES or dec["op"] is None or dec["op"] > 63:
        return False
    plain = dec["plain"]
    pad = dec["seed"] & 0xFF
    if not plain or plain[-1] not in (pad, 0):
        return False
    if not strict:
        return True
    body = plain[4:]
    try:
        r = bd.BdReader(body[1:])
        r.bitmode = True
        r.read_type_checked_bit()
        r.u8()
        bd.read_fields(r)
        tail = body[1:][r.pos:]
    except Exception:
        return False
    return all(b in (pad, 0) for b in tail)


NO_PROFILES = os.environ.get("WOW2_NO_PROFILES") == "1"
BD_PROFILE_ALREADY_EXISTS = 800
BD_EXCEPTION_IN_DB = 102
BD_NOT_AN_ADMIN_OR_OWNER = 311
BD_MEMBER_NO_PROPOSAL = 300
BD_NO_FILE = 1000
BD_PERMISSION_DENIED = 1001
BD_FILESIZE_LIMIT_EXCEEDED = 1002

# ------------------------------------------------------------- profiles (svc 8)

NO_PROFILE_EXISTS = os.environ.get("WOW2_NO_PROFILE_EXISTS") == "1"


def profile_get(entity_hex: str, kind: str = "public") -> dict | None:
    """One stored profile, {name, at, fields}, from the `profiles` table."""
    r = store.db().execute("SELECT name, at, fields FROM profiles WHERE entity = ? "
                           "AND kind = ?", (entity_hex, kind)).fetchone()
    if r is None:
        return None
    return {"name": r["name"] or "", "at": r["at"] or "", "fields": json.loads(r["fields"])}


def profile_put(entity_hex: str, rec: dict, kind: str = "public") -> None:
    with store.tx() as conn:
        conn.execute("INSERT INTO profiles (entity, kind, name, at, fields) VALUES "
                     "(?, ?, ?, ?, ?) ON CONFLICT (entity, kind) DO UPDATE SET "
                     "name = excluded.name, at = excluded.at, fields = excluded.fields",
                     (entity_hex, kind, rec.get("name"), rec.get("at"),
                      json.dumps(rec.get("fields") or [])))


def _field_to_json(t: int, v):
    return [t, v.hex() if isinstance(v, bytes) else v]


def _write_field(w, t: int, v) -> bool:
    """Write one typed bd field back out. Returns False for a type we cannot."""
    if t == bd.BD_SINT64:
        w.i64(int(v))
    elif t == bd.BD_UINT64:
        w.u64(int(v))
    elif t == bd.BD_SINT32:
        w.i32(int(v))
    elif t == bd.BD_UINT32:
        w.u32(int(v))
    elif t == bd.BD_UINT8:
        w.u8(int(v))
    elif t == bd.BD_BOOL:
        w.bool_(bool(v))
    elif t == bd.BD_F64:
        w.f64(float(v))
    elif t == bd.BD_STR:
        w.str_(str(v), maxlen=FRIEND_NAME_MAX)
    elif t == bd.BD_BLOB:
        w.blob(bytes.fromhex(v) if isinstance(v, str) else bytes(v))
    else:
        return False
    return True


PROFILE_EMPTY = [[bd.BD_SINT64, 0], [bd.BD_SINT64, 0], [bd.BD_SINT64, 0],
                 [bd.BD_SINT64, 0], [bd.BD_F64, 0.0], [bd.BD_F64, 0.0],
                 [bd.BD_SINT64, 0], [bd.BD_STR, ""], [bd.BD_SINT32, 0]]


def profile_upload(dec: dict, who=None, peer_ip: str = "", create: bool = False):
    """Profile op 4 (upload) and op 1 (create) -- both write the PUBLIC profile."""
    entity = account_for(peer_ip) or (who[1] if who else 0)
    if NO_PROFILES or not entity:
        return 0, None
    try:
        r = lsg_request_params(dec)
        r.u8()
        fields = bd.read_fields(r)
    except Exception as e:
        log(f"  (profile upload decode failed: {e})")
        return 0, None
    key = f"{entity:016x}"
    name = (who[0] if who else "") or name_of(entity)
    old = profile_get(key)
    if create and old is not None:
        if NO_PROFILE_EXISTS:
            log(f"  profile op1 (create): {name or key} already has a profile -- "
                f"keeping it (WOW2_NO_PROFILE_EXISTS: answering err=0)")
            return 0, None
        log(f"  profile op1 (create): {name or key} already has a profile -- "
            f"answering BD_PROFILE_ALREADY_EXISTS (800), so the client DOWNLOADS "
            f"it instead of uploading over it")
        return 0, None, BD_PROFILE_ALREADY_EXISTS
    if (old and any(v for _t, v in
                    [(f[0], f[1]) for f in old.get("fields", [])])
            and not any(v for _t, v in fields)):
        log(f"  *** PROFILE ABOUT TO BE BLANKED: {name or key} uploaded "
            f"{len(fields)} empty fields over a populated record")
    profile_put(key, {"name": name, "at": store.now_iso(),
                      "fields": [_field_to_json(t, v) for t, v in fields]})
    shown = ", ".join(str(v) for _t, v in fields[:4])
    log(f"  profile {'op1 (create)' if create else 'op4 (upload)'}: "
        f"{name or key} <- {len(fields)} fields ({shown}...)")
    return 0, None


def profile_op5(dec: dict, who=None, peer_ip: str = ""):
    """Profile op 5 -- upload the PRIVATE profile, and there is nothing in it."""
    try:
        r = lsg_request_params(dec)
        r.u8()
        fields = bd.read_fields(r)
    except Exception as e:
        log(f"  (profile op5 decode failed: {e})")
        return 0, None
    shown = ", ".join(f"{bd.TYPE_NAMES.get(t, t)} {v!r}" for t, v in fields)
    log(f"  profile op5 (private upload): {shown or '(empty)'}"
        + ("" if fields == [(bd.BD_SINT32, 99)] else
           "   <- NOT the hard-coded i32 99"))
    return 0, None


def profile_read_private(dec: dict, who=None, peer_ip: str = ""):
    """Profile op 3 -- download MY private profile. It takes NO parameters."""
    lsg_request_noargs(dec, "profile op3")
    entity = account_for(peer_ip) or (who[1] if who else 0)
    log(f"  profile op3 (read private) for 0x{entity:016x} -- the client"
        f" discards both fields, so this is a formality")

    def emit(w):
        w.u64(entity)
        w.i32(99)
    return None, emit


def profile_read_public(dec: dict, who=None, peer_ip: str = ""):
    """Profile op 2: read one public profile. ONE row, and NO result count."""
    if NO_PROFILES:
        return 0, None
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
    except Exception as e:
        log(f"  (profile read decode failed: {e})")
        return 0, None
    rec = profile_get(f"{target:016x}")
    fields = rec["fields"] if rec else [list(f) for f in PROFILE_EMPTY]
    name = (rec or {}).get("name") or name_of(target)
    if not rec:
        for f in fields:
            if f[0] == bd.BD_STR:
                f[1] = name
                break

    def emit(w):
        w.u64(target)
        for t, v in fields:
            if not _write_field(w, int(t), v):
                log(f"  (!! profile field type {t} has no writer -- skipped)")

    log(f"  profile op2 (read public): entity 0x{target:016x} "
        f"({name or 'unknown'}) -- {'stored' if rec else 'EMPTY placeholder'}, "
        f"{len(fields)} fields")
    return None, emit


def _hx(entity) -> str:
    return entity if isinstance(entity, str) else f"{int(entity):016x}"


def name_of(entity) -> str:
    """The display name on file for an account, or "" if none."""
    r = store.db().execute("SELECT name FROM names WHERE entity = ?",
                           (_hx(entity),)).fetchone()
    return (r["name"] if r else "") or ""


def blocked_by(entity: int) -> set:
    """The accounts `entity` has blocked (Friends op 6 flag=1)."""
    return {r["who_e"] for r in store.db().execute(
        "SELECT who_e FROM blocks WHERE by_e = ?", (_hx(entity),))}


def are_buddies(a, b) -> bool:
    x, y = sorted((_hx(a), _hx(b)))
    return store.db().execute("SELECT 1 FROM friends WHERE a = ? AND b = ?",
                              (x, y)).fetchone() is not None


def invite_pending(from_e, to_e) -> bool:
    return store.db().execute("SELECT 1 FROM friend_invites WHERE from_e = ? AND to_e = ?",
                              (_hx(from_e), _hx(to_e))).fetchone() is not None


def _count(table: str) -> int:
    return int(store.db().execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0])


def invite_blocked(target: int, sender: int, what: str) -> bool:
    """Has `target` blocked `sender`? Then drop the invite and say nothing -- F19."""
    if os.environ.get("WOW2_NO_BLOCK_GUARD") == "1":
        return False
    if f"{sender:016x}" not in blocked_by(target):
        return False
    log(f"  {what}: 0x{sender:016x} is BLOCKED by 0x{target:016x} -- "
        f"filed nothing, pushed nothing, and told the sender nothing")
    return True


def friends_note_name(entity: int, name: str) -> None:
    """Remember entity -> name so a buddy row can be labelled from either side."""
    if not entity or not name:
        return
    with store.tx() as conn:
        conn.execute("INSERT INTO names (entity, name) VALUES (?, ?) "
                     "ON CONFLICT (entity) DO UPDATE SET name = excluded.name "
                     "WHERE names.name != excluded.name", (_hx(entity), name))


def friends_of(entity: int) -> list:
    """(other account, its name) for every buddy pair `entity` is in, oldest first."""
    mine = _hx(entity)
    return [(int(r["other"], 16), r["name"] or "") for r in store.db().execute(
        "SELECT CASE WHEN f.a = ? THEN f.b ELSE f.a END AS other, n.name "
        "FROM friends f LEFT JOIN names n "
        "ON n.entity = CASE WHEN f.a = ? THEN f.b ELSE f.a END "
        "WHERE f.a = ? OR f.b = ? ORDER BY f.seq", (mine, mine, mine, mine))]


def friends_write_row(w, entity: int, name: str, kind: str) -> None:
    """One Friends result row. `kind` picks the shape (see FRIEND_ROWS)."""
    w.u64(entity)
    w.str_(name or f"{entity:x}"[:8], FRIEND_NAME_MAX)
    if kind == "u8":
        w.u8(1)
    elif kind == "bool":
        w.bool_(True)


def friends_list_result(op: int, dec: dict, who=None, peer_ip: str = ""):
    """Friends ops 5 / 7 / 19 -- the three lists the client downloads at sign-in."""
    lsg_request_noargs(dec, f"friends op{op}")
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    friends_note_name(me, name)
    kind = FRIEND_ROWS.get(op, "none")
    mine = f"{me:016x}"
    conn = store.db()
    if op == 5:
        what = "friends"
        rows = friends_of(me)
    elif op == 19:
        what = "friend proposals"
        rows = [(int(r["from_e"], 16), r["name"] or r["from_name"] or "")
                for r in conn.execute(
                    "SELECT i.from_e, i.from_name, n.name FROM friend_invites i "
                    "LEFT JOIN names n ON n.entity = i.from_e WHERE i.to_e = ? "
                    "ORDER BY i.seq", (mine,))]
    else:
        what = "block list"
        rows = [(int(r["who_e"], 16), r["name"] or "")
                for r in conn.execute(
                    "SELECT b.who_e, n.name FROM blocks b LEFT JOIN names n "
                    "ON n.entity = b.who_e WHERE b.by_e = ? ORDER BY b.seq", (mine,))]
    env = os.environ.get("WOW2_FRIEND_LIMIT")
    budget = int(env) if env is not None else FRIEND_LIST_BUDGET
    dropped = 0
    if budget:
        if op == 7:
            limit = FRIEND_BLOCK_LIMIT if env is None else budget
        elif op == 5:
            limit = budget
        else:
            limit = max(0, budget - len(friends_of(me)))
        if len(rows) > limit:
            dropped = len(rows) - limit
            rows = rows[:limit]
    log(f"  friends op{op} ({what}) for {name} 0x{me:016x}: {len(rows)} row(s)"
        + (f" [row={kind}]" if rows else "")
        + (" -> " + ", ".join(f"{n or '?'} 0x{e:016x}" for e, n in rows) if rows else ""))
    if dropped:
        log(f"  !!!! capped {what} at {limit}: {dropped} row(s) NOT served. The "
            f"client holds 49 rows across op5+op19 TOGETHER and dies on the "
            f"50th -- and 50-56 rows draw perfectly and crash on the circle that "
            f"LEAVES the panel, so rendering is not survival. There is no window "
            f"field to ask for less. WOW2_FRIEND_LIMIT=0 disables the cap.")

    def emit(w):
        if os.environ.get("WOW2_FRIEND_TOTAL") == "1":
            w.u32(len(rows))
        if os.environ.get("WOW2_FRIEND_COUNT_ONLY") == "1":
            return
        for entity, rname in rows:
            friends_write_row(w, entity, rname, kind)
    return len(rows), emit


def friends_add(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 1 -- send a buddy invite. Reads no results (arm 0x08c18e8c)."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
    except Exception as e:
        log(f"  (friends op1 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    mine, theirs = f"{me:016x}", f"{target:016x}"
    if target == me:
        log(f"  friends op1 (INVITE): {name} 0x{mine} invited ITSELF -- REFUSED "
            f"(a self-buddy has no verb that can undo it)")
        return 0, None
    if are_buddies(mine, theirs):
        log(f"  friends op1 (INVITE): {name} -> 0x{target:016x} (already buddies)")
        return 0, None
    if invite_pending(mine, theirs):
        log(f"  friends op1 (INVITE): {name} -> 0x{target:016x} (already pending)")
        return 0, None
    if (os.environ.get("WOW2_NO_FRIENDS_FIX") != "1"
            and invite_blocked(target, me, "friends op1 (INVITE)")):
        return 0, None
    with store.tx() as conn:
        conn.execute("INSERT OR IGNORE INTO friend_invites (from_e, from_name, to_e, "
                     "to_name, at) VALUES (?, ?, ?, ?, ?)",
                     (mine, name, theirs, name_of(theirs), store.now_iso()))
    log(f"  friends op1 (INVITE): {name} 0x{me:016x} -> 0x{target:016x}"
        f" ({name_of(theirs) or 'unknown account'}) -- "
        f"{_count('friend_invites')} proposal(s) pending")
    mid = message_add(target, PUSH_BUDDY_INVITE, me, name)
    push_to_account(target, PUSH_BUDDY_INVITE, me, name, mid)
    return 0, None


def friends_match_invite(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 8 -- invite a buddy INTO THE LOBBY YOU ARE HOSTING."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
        session_id = r.blob()
    except Exception as e:
        log(f"  (friends op8 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    if invite_blocked(target, me, "friends op8 (MATCH INVITE)"):
        return 0, None
    sid = int.from_bytes(session_id[:SESSION_ID_BYTES], "little")
    rec = SESSIONS.get(sid)
    theirs = f"{target:016x}"
    log(f"  friends op8 (MATCH INVITE): {name} 0x{me:016x} -> 0x{target:016x}"
        f" ({name_of(theirs) or 'unknown account'}) for session 0x{sid:x}"
        + (f" ({rec['name']!r}, mode={'POINTS' if rec.get('points') else 'fun'})"
           if rec else " -- NO SUCH LIVE SESSION, relaying the id anyway"))
    mid = message_add(target, PUSH_MATCH_INVITE, me, name, session_id)
    push_to_account(target, PUSH_MATCH_INVITE, me, name, mid, session_id)
    return 0, None


def friends_match_decline(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 10 -- `[u8 0][u64 inviter]`. DECLINE a match invite."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        inviter = r.u64()
    except Exception as e:
        log(f"  (friends op10 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    theirs = f"{inviter:016x}"
    log(f"  friends op10 (MATCH DECLINE): {name} 0x{me:016x} declined the match "
        f"invite from 0x{inviter:016x} "
        f"({name_of(theirs) or 'unknown account'})")
    push_to_account(inviter, PUSH_MATCH_REJECTED, me, name, notify_id())
    return 0, None


def friends_match_accept(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 9 -- `[u8 0][u64 inviter]`. ACCEPT a match invite."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        inviter = r.u64()
    except Exception as e:
        log(f"  (friends op9 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    theirs = f"{inviter:016x}"
    log(f"  friends op9 (MATCH ACCEPT): {name} 0x{me:016x} accepted the match "
        f"invite from 0x{inviter:016x} "
        f"({name_of(theirs) or 'unknown account'})")
    push_to_account(inviter, PUSH_MATCH_ACCEPTED, me, name, notify_id())
    return 0, None


def friends_block(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 6 -- `[u8 0][u64 entity][u8 flag]`. BLOCK (1) / UNBLOCK (0)."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
        flag = r.u8()
    except Exception as e:
        log(f"  (friends op6 decode failed: {e})")
        return 0, None
    if os.environ.get("WOW2_NO_FRIENDS_FIX") == "1":
        return friends_respond_legacy(dec, me, name, target, flag)
    friends_note_name(me, name)
    mine, theirs = f"{me:016x}", f"{target:016x}"
    with store.tx() as conn:
        conn.execute("DELETE FROM blocks WHERE by_e = ? AND who_e = ?", (mine, theirs))
        if flag:
            conn.execute("INSERT INTO blocks (by_e, who_e, who_name, at) VALUES (?, ?, ?, ?)",
                         (mine, theirs, name_of(theirs), store.now_iso()))
        blocked = conn.execute("SELECT COUNT(*) FROM blocks WHERE by_e = ?",
                               (mine,)).fetchone()[0]
    log(f"  friends op6 ({'BLOCK' if flag else 'UNBLOCK'}): {name} "
        f"0x{me:016x} -> 0x{target:016x} "
        f"({name_of(theirs) or 'unknown account'}) -- {blocked} blocked")
    return 0, None


def friends_respond_legacy(dec: dict, me: int, name: str, target: int, flag: int):
    """The pre-Phase-28 op 6 reading, kept for `WOW2_NO_FRIENDS_FIX=1` bisects."""
    mine, theirs = f"{me:016x}", f"{target:016x}"
    with store.tx() as conn:
        pending = _drop_invites_between(conn, mine, theirs)
        if not pending:
            log(f"  friends op6: {name} -> 0x{target:016x} flag={flag} "
                "(no matching proposal -- recorded nothing)")
            return 0, None
        if flag:
            _add_pair(conn, mine, theirs)
    if flag:
        log(f"  friends op6: {name} ACCEPTED 0x{target:016x} -- now buddies "
            f"({_count('friends')} pair(s))")
        push_to_account(target, PUSH_BUDDY_ACCEPTED, me, name, notify_id())
    else:
        log(f"  friends op6: {name} REJECTED 0x{target:016x}")
        push_to_account(target, PUSH_BUDDY_REJECTED, me, name, notify_id())
    return 0, None


def _drop_invites_between(conn, a: str, b: str) -> int:
    """Delete every proposal between two accounts, either direction. How many."""
    return conn.execute("DELETE FROM friend_invites WHERE (from_e = ? AND to_e = ?) "
                        "OR (from_e = ? AND to_e = ?)", (a, b, b, a)).rowcount


def _add_pair(conn, a: str, b: str) -> None:
    x, y = sorted((a, b))
    conn.execute("INSERT OR IGNORE INTO friends (a, b) VALUES (?, ?)", (x, y))


def _drop_pair(conn, a: str, b: str) -> int:
    x, y = sorted((a, b))
    return conn.execute("DELETE FROM friends WHERE a = ? AND b = ?", (x, y)).rowcount


def friends_revoke(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 4 -- `[u8 0][u64 entity]`. REVOKE: the relationship, from my side."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
    except Exception as e:
        log(f"  (friends op4 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    mine, theirs = f"{me:016x}", f"{target:016x}"
    with store.tx() as conn:
        incoming = invite_pending(theirs, mine)
        was_buddy = _drop_pair(conn, mine, theirs) > 0
        _drop_invites_between(conn, mine, theirs)
        conn.execute("DELETE FROM messages WHERE to_e = ? AND from_e = ? AND type = ?",
                     (mine, theirs, PUSH_BUDDY_INVITE))
    what = "DECLINED the invite from" if incoming else (
        "REMOVED the buddy" if was_buddy else "revoked nothing with")
    log(f"  friends op4 (REVOKE): {name} {what} 0x{target:016x} "
        f"({name_of(theirs) or 'unknown account'}) -- "
        f"{_count('friends')} buddy pair(s), {_count('friend_invites')} proposal(s)")
    if incoming:
        push_to_account(target, PUSH_BUDDY_REJECTED, me, name, notify_id())
    elif was_buddy:
        push_to_account(target, PUSH_BUDDY_REVOKED, me, name, notify_id())
    return 0, None


def friends_remove(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 13 -- `[u8 0][u64 entity]`. CANCEL MY OUTGOING PROPOSAL."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
    except Exception as e:
        log(f"  (friends op13 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    mine, theirs = f"{me:016x}", f"{target:016x}"
    before = (_count("friends"), _count("friend_invites"))
    with store.tx() as conn:
        if os.environ.get("WOW2_NO_FRIENDS_FIX") == "1":
            _drop_pair(conn, mine, theirs)
            outgoing = _drop_invites_between(conn, mine, theirs)
        else:
            outgoing = conn.execute("DELETE FROM friend_invites WHERE from_e = ? AND to_e = ?",
                                    (mine, theirs)).rowcount
            conn.execute("DELETE FROM messages WHERE to_e = ? AND from_e = ? AND type = ?",
                         (theirs, mine, PUSH_BUDDY_INVITE))
    log(f"  friends op13 (CANCEL INVITE): {name} 0x{me:016x} -> 0x{target:016x} "
        f"({name_of(theirs) or 'unknown account'}, "
        f"{outgoing} proposal(s) withdrawn; "
        f"friends {before[0]}->{_count('friends')}, "
        f"proposals {before[1]}->{_count('friend_invites')})")
    if outgoing and os.environ.get("WOW2_NO_FRIENDS_FIX") != "1":
        push_to_account(target, PUSH_PROPOSAL_CANCELLED, me, name, notify_id())
    return 0, None


def _next_msg(conn) -> int:
    """Take the next message id. Inside the caller's transaction, so two
    handlers cannot draw the same number; `meta.next_msg` is the counter the
    JSON store kept, and it serves notifications too (see notify_id).
    """
    mid = int(store.meta_get(conn, "next_msg", "1"))
    store.meta_set(conn, "next_msg", str(mid + 1))
    return mid


MAILBOX_TYPES = (1, 5, 13)    # the only types the client files; a filed notification is re-applied at every sign-in


def message_add(to_entity: int, type_id: int, sender: int, sender_name: str,
                session_id: bytes = b"", clan_name: str = "") -> int:
    """Store one lobby message for an account. Returns its id."""
    if type_id not in MAILBOX_TYPES:
        log(f"  !!!! refusing to FILE a type-{type_id} message to "
            f"0x{to_entity:016x}: only {MAILBOX_TYPES} are mailbox items, and a "
            f"filed notification is re-delivered AND APPLIED at every sign-in "
            f"(§49.16). Push it with notify_id() instead.")
        return notify_id()
    with store.tx() as conn:
        mid = _next_msg(conn)
        conn.execute("INSERT INTO messages (id, to_e, type, from_e, from_name, session, "
                     "clan, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                     (mid, f"{to_entity:016x}", type_id, f"{sender:016x}", sender_name,
                      bytes(session_id).hex(), clan_name, store.now_iso()))
    return mid


def notify_id() -> int:
    """An id for a push that is NOT filed. Unique, non-zero, nothing stored."""
    with store.tx() as conn:
        return _next_msg(conn)


CLAN_MSG_CACCEPT = 14
CLAN_MSG_CREJECT = 15
CLAN_MSG_CLEFT = 16
CLAN_MSG_CADMIN = 17
CLAN_MSG_CKICKED = 18
CLAN_MSG_CDISBAND = 26
CLAN_MSG_COWNER = 28
CLAN_MSG_CORDINARY = 39


def account_name(entity: int) -> str:
    """The display name we have on file for an account, or "" if none."""
    try:
        return name_of(entity)
    except Exception:
        return ""


def clan_notify(to_entity: int, type_id: int, tid: int, clan_name: str,
                actor: int, actor_name: str,
                target: int = 0, target_name: str = "") -> None:
    """Tell one account that something happened to its clan. Push only."""
    if os.environ.get("WOW2_NO_CLAN_NOTIFY") == "1":
        log(f"  (clan notify type {type_id} suppressed by WOW2_NO_CLAN_NOTIFY)")
        return
    with store.tx() as conn:
        mid = _next_msg(conn)
    ok = push_to_account(to_entity, type_id, actor, actor_name, msg_id=mid,
                         session_id=tid.to_bytes(8, "little"),
                         clan_name=clan_name,
                         target=target, target_name=target_name)
    log(f"  clan notify type {type_id} -> 0x{to_entity:016x} "
        f"({clan_name!r} 0x{tid:016x}, msg {mid}): "
        + ("pushed" if ok else "not online, and a notification is never filed"))


def messages_for(entity: int, start: int = 0, count: int | None = None) -> list:
    """This account's mailbox rows, oldest first, in the shape the JSON kept:
    {id, to, type, from, from_name, session, clan, at}.
    """
    sql = "SELECT * FROM messages WHERE to_e = ? ORDER BY id"
    args: list = [f"{entity:016x}"]
    if count is not None:
        sql += " LIMIT ? OFFSET ?"
        args += [count, start]
    return [{"id": r["id"], "to": r["to_e"], "type": r["type"], "from": r["from_e"],
             "from_name": r["from_name"] or "", "session": r["session"] or "",
             "clan": r["clan"] or "", "at": r["at"] or ""}
            for r in store.db().execute(sql, args)]


def messages_result(dec: dict, who=None, peer_ip: str = ""):
    """bdMessaging op 1 -- download the inbox."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    start, count = 0, 25
    try:
        r = lsg_request_params(dec)
        r.u8()
        start = r.u32()
        count = r.u32()
        flags = [v for t, v in bd.read_fields(r) if t == bd.BD_BOOL]
        if any(flags):
            log(f"  *** messaging op1 flags are not both false: {flags}")
    except Exception as e:
        log(f"  (messaging op1 decode failed: {e})")
    rows = messages_for(me, start, max(1, count))
    log(f"  messaging op1 (inbox) for {name} 0x{me:016x}: {len(rows)} message(s)"
        + (" -> " + ", ".join(f"type {m['type']} from {m['from_name']}" for m in rows)
           if rows else ""))

    def emit(w):
        for m in rows:
            to_hex = m.get("to", "0")
            write_push_body(w, int(m["type"]), int(m["id"]),
                            int(m["from"], 16), m.get("from_name", ""),
                            bytes.fromhex(m.get("session", "")),
                            m.get("clan", ""),
                            int(to_hex, 16),
                            name_of(to_hex))
    return len(rows), emit


def messages_delete(dec: dict, who=None, peer_ip: str = ""):
    """bdMessaging op 4 -- delete one message by id. Reads no results."""
    me = account_for(peer_ip)
    try:
        r = lsg_request_params(dec)
        r.u8()
        mid = r.u64()
    except Exception as e:
        log(f"  (messaging op4 decode failed: {e})")
        return 0, None
    before = _count("messages")
    with store.tx() as conn:
        conn.execute("DELETE FROM messages WHERE id = ? AND to_e = ?", (mid, f"{me:016x}"))
    log(f"  messaging op4: 0x{me:016x} deleted message {mid} "
        f"({before} -> {_count('messages')} stored)")
    return 0, None


def friends_answer(dec: dict, accept: bool, who=None, peer_ip: str = ""):
    """Friends op 2 (accept) / op 3 (decline) -- both take the SENDER's id."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        sender = r.u64()
    except Exception as e:
        log(f"  (friends op{2 if accept else 3} decode failed: {e})")
        return 0, None
    mine, theirs = f"{me:016x}", f"{sender:016x}"
    with store.tx() as conn:
        _drop_invites_between(conn, mine, theirs)
        if accept:
            _add_pair(conn, mine, theirs)
    verb = "ACCEPTED" if accept else "DECLINED"
    log(f"  friends op{2 if accept else 3}: {name} {verb} the invite from "
        f"0x{sender:016x} ({_count('friends')} buddy pair(s))")
    kind = PUSH_BUDDY_ACCEPTED if accept else PUSH_BUDDY_REJECTED
    push_to_account(sender, kind, me, name, notify_id())
    return 0, None


TEAM_RANK_MEMBER = 0
TEAM_RANK_ADMIN = 1
TEAM_RANK_OWNER = 2


def team_get(key: str) -> dict | None:
    """One clan's record by id (16 hex digits), or None."""
    conn = store.db()
    t = conn.execute("SELECT * FROM teams WHERE id = ?", (key,)).fetchone()
    if t is None:
        return None
    members = conn.execute("SELECT entity, rank FROM team_members WHERE team = ? "
                           "ORDER BY seq", (key,)).fetchall()
    rec = {"name": t["name"] or "", "owner": t["owner"], "created": t["created"] or "",
           "members": [m["entity"] for m in members],
           "proposals": [{"to": p["to_e"], "from": p["from_e"],
                          "from_name": p["from_name"] or "", "at": p["at"] or ""}
                         for p in conn.execute(
                             "SELECT * FROM team_proposals WHERE team = ? ORDER BY seq",
                             (key,))]}
    ranks = {m["entity"]: int(m["rank"]) for m in members if m["rank"] is not None}
    if ranks:
        rec["ranks"] = ranks
    return rec


def team_put(key: str, rec: dict) -> None:
    """Write one clan's record back, members and proposals included."""
    with store.tx() as conn:
        conn.execute("INSERT INTO teams (id, name, owner, created) VALUES (?, ?, ?, ?) "
                     "ON CONFLICT (id) DO UPDATE SET name = excluded.name, "
                     "owner = excluded.owner, created = excluded.created",
                     (key, rec.get("name") or "", rec.get("owner"), rec.get("created")))
        conn.execute("DELETE FROM team_members WHERE team = ?", (key,))
        ranks = rec.get("ranks") or {}
        for m in rec.get("members", []):
            conn.execute("INSERT OR IGNORE INTO team_members (team, entity, rank) "
                         "VALUES (?, ?, ?)", (key, m, ranks.get(m)))
        conn.execute("DELETE FROM team_proposals WHERE team = ?", (key,))
        for pr in rec.get("proposals", []):
            conn.execute("INSERT OR IGNORE INTO team_proposals (team, to_e, from_e, "
                         "from_name, at) VALUES (?, ?, ?, ?, ?)",
                         (key, pr.get("to"), pr.get("from"), pr.get("from_name"),
                          pr.get("at")))


def team_delete(key: str) -> None:
    with store.tx() as conn:
        conn.execute("DELETE FROM team_proposals WHERE team = ?", (key,))
        conn.execute("DELETE FROM team_members WHERE team = ?", (key,))
        conn.execute("DELETE FROM teams WHERE id = ?", (key,))


def clan_invite_push_type() -> int:
    """The lobby-message type a clan invite is delivered as; `meta.invite_push_type`
    overrides the default."""
    v = store.meta_get(store.db(), "invite_push_type")
    return int(v) if v is not None else CLAN_INVITE_PUSH_DEFAULT


def team_of(entity: int) -> tuple[int, dict] | tuple[int, None]:
    r = store.db().execute("SELECT team FROM team_members WHERE entity = ? ORDER BY seq "
                           "LIMIT 1", (f"{entity:016x}",)).fetchone()
    if r is None:
        return 0, None
    rec = team_get(r["team"])
    return (int(r["team"], 16), rec) if rec else (0, None)


def proposals_to(entity: int) -> list[tuple[str, str, str, str]]:
    """(team id, clan name, inviter, inviter's name) for every clan invite
    addressed to `entity`, oldest first.
    """
    return [(r["team"], r["cname"] or "", r["from_e"],
             r["from_name"] or name_of(r["from_e"]))
            for r in store.db().execute(
                "SELECT p.team, p.from_e, p.from_name, t.name AS cname FROM team_proposals p "
                "JOIN teams t ON t.id = p.team WHERE p.to_e = ? ORDER BY p.seq",
                (f"{entity:016x}",))]


def clan_invite_backfill(me: int, name: str) -> None:
    """Put a mailbox row behind any clan invite that has none, at sign-in."""
    if os.environ.get("WOW2_NO_CLAN_BACKFILL") == "1":
        return
    mine = f"{me:016x}"
    have = {(m.get("from"), m.get("clan")) for m in messages_for(me)
            if int(m.get("type", 0)) == PUSH_CLAN_INVITE}
    for tid, cname, frm, iname in proposals_to(me):
        if (frm, cname) in have or store.db().execute(
                "SELECT 1 FROM team_members WHERE team = ? AND entity = ?",
                (tid, mine)).fetchone():
            continue
        log(f"  (clan invite waiting for {name}: {cname!r} from {iname!r} "
            f"-- no mailbox row, filing one now so this sign-in's inbox "
            f"read delivers it)")
        message_add(me, PUSH_CLAN_INVITE, int(frm, 16), iname,
                    int(tid, 16).to_bytes(8, "little"), cname)


def teams_memberships_result(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 20 -- "the teams I belong to". Fires at EVERY sign-in."""
    lsg_request_noargs(dec, "teams op20")
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    rows = [(int(r["id"], 16), r["name"] or "", 1 if r["owner"] == f"{me:016x}" else 0)
            for r in store.db().execute(
                "SELECT t.id, t.name, t.owner FROM team_members m JOIN teams t "
                "ON t.id = m.team WHERE m.entity = ? ORDER BY m.seq", (f"{me:016x}",))]
    log(f"  teams op20 (memberships) for {name} 0x{me:016x}: {len(rows)} clan(s)"
        + (" -> " + ", ".join(f"{n!r} 0x{t:016x}{' owner' if o else ''}"
                              for t, n, o in rows) if rows else ""))
    clan_invite_backfill(me, name)

    def emit(w):
        for tid, tname, owner in rows:
            w.u64(tid)
            w.str_(tname, 63)
            w.u8(owner)
    return len(rows), emit


def team_rank(rec: dict, member: str) -> int:
    """The `u8` that trails a `Teams op 21` member row -- the member's ROLE."""
    ranks = rec.get("ranks") or {}
    if member in ranks:
        return int(ranks[member]) & 0xFF
    return TEAM_RANK_OWNER if member == rec.get("owner") else TEAM_RANK_MEMBER


def clan_admin_or_owner(rec: dict, actor: int) -> bool:
    """May `actor` administer this clan -- invite, cancel an invite, remove?"""
    if os.environ.get("WOW2_NO_CLAN_ADMIN_CHECK") == "1":
        return True
    mine = f"{actor:016x}"
    return mine in rec.get("members", []) and team_rank(rec, mine) >= TEAM_RANK_ADMIN


def teams_members_result(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 21 -- the members of one team. Row [u64][str][bool][u8] (0x08c2804c)."""
    try:
        r = lsg_request_params(dec)
        r.u8()
        tid = r.u64()
    except Exception as e:
        log(f"  (teams op21 decode failed: {e})")
        return 0, None
    rec = team_get(f"{tid:016x}")
    rows = []
    if rec:
        for m in rec.get("members", []):
            rows.append((int(m, 16), name_of(m),
                         m == rec.get("owner"), team_rank(rec, m)))
    log(f"  teams op21 (members of 0x{tid:016x} {rec.get('name') if rec else '?'!r}): "
        f"{len(rows)} member(s)")

    def emit(w):
        for eid, mname, owner, rank in rows:
            w.u64(eid)
            w.str_(mname, 63)
            w.bool_(owner)
            w.u8(rank)
    return len(rows), emit


def teams_invite(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 6: send a clan invite (administrator or owner)."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        tid = r.u64()
        target = r.u64()
    except Exception as e:
        log(f"  (teams op6 decode failed: {e})")
        return 0, None
    key = f"{tid:016x}"
    rec = team_get(key)
    theirs = f"{target:016x}"
    if rec is None:
        log(f"  teams op6 (CLAN INVITE): no such clan 0x{key} -- ignored")
        return 0, None
    if not clan_admin_or_owner(rec, me):
        log(f"  teams op6 (CLAN INVITE): {name} 0x{me:016x} is not an "
            f"administrator of {rec.get('name')!r} -- REFUSED")
        return 0, None
    if theirs in rec.get("members", []):
        log(f"  teams op6 (CLAN INVITE): 0x{theirs} is already in "
            f"{rec.get('name')!r}")
        return 0, None
    if invite_blocked(target, me, "teams op6 (CLAN INVITE)"):
        return 0, None
    props = rec.setdefault("proposals", [])
    if not any(p.get("to") == theirs for p in props):
        props.append({"to": theirs, "from": f"{me:016x}", "from_name": name,
                      "at": store.now_iso()})
        team_put(key, rec)
    log(f"  teams op6 (CLAN INVITE): {name} invites 0x{theirs} "
        f"({name_of(theirs) or 'unknown account'}) to "
        f"{rec.get('name')!r} 0x{key} -- {len(props)} proposal(s) outstanding")
    ptype = clan_invite_push_type()
    if not ptype:
        log("  (clan invite filed but NOT delivered: the lobby-message layout "
            "for a clan type is unsolved -- see netrecon.md Phase 25. Set "
            "meta.invite_push_type in the store to try an id.)")
        return 0, None
    blob = tid.to_bytes(8, "little")
    cname = rec.get("name", "")
    tname = name_of(theirs)
    mid = message_add(target, ptype, me, name, blob, cname)
    push_to_account(target, ptype, me, name, mid, blob, cname,
                    target=target, target_name=tname)
    return 0, None


def clan_invite_mail_drop(tid: int, ptype: int, recipients=None) -> int:
    """Withdraw the mailbox rows `teams_invite` filed for clan `tid`."""
    blob = tid.to_bytes(8, "little").hex()
    want = None if recipients is None else sorted({r for r in recipients})
    with store.tx() as conn:
        if want is None:
            return conn.execute("DELETE FROM messages WHERE type = ? AND session = ?",
                                (ptype, blob)).rowcount
        if not want:
            return 0
        marks = ",".join("?" * len(want))
        return conn.execute(f"DELETE FROM messages WHERE type = ? AND session = ? "
                            f"AND to_e IN ({marks})", (ptype, blob, *want)).rowcount


def teams_cancel_invite(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 25: cancel a clan invite you sent. The pair is (gamerId, teamId),
    the reverse of every other clan verb."""
    me, name = _teams_actor(peer_ip, who)
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
        tid = r.u64()
    except Exception as e:
        log(f"  (teams op25 decode failed: {e})")
        return 0, None
    key, theirs, mine = f"{tid:016x}", f"{target:016x}", f"{me:016x}"
    rec = team_get(key)
    if rec is None:
        log(f"  teams op25 (CANCEL CLAN INVITE): no such clan 0x{key} -- ignored")
        return 0, None
    if not clan_admin_or_owner(rec, me):
        log(f"  teams op25 (CANCEL CLAN INVITE): {name} 0x{mine} is not an "
            f"administrator of {rec.get('name')!r} -- REFUSED")
        return 0, None
    props = rec.get("proposals", [])
    had = any(p.get("to") == theirs for p in props)
    rec["proposals"] = [p for p in props if p.get("to") != theirs]
    team_put(key, rec)
    ptype = clan_invite_push_type()
    pulled = clan_invite_mail_drop(tid, ptype, [theirs])
    log(f"  teams op25 (CANCEL CLAN INVITE): {name} 0x{mine} withdraws the "
        f"invite to 0x{theirs} "
        f"({name_of(theirs) or 'unknown account'}) for "
        f"{rec.get('name')!r} 0x{key}"
        + ("" if had else " -- but no proposal was on file")
        + f" ({len(rec['proposals'])} proposal(s) left, "
        f"{pulled} mailbox row(s) withdrawn)")
    return 0, None


def teams_answer_invite(accept: bool, dec: dict, who=None, peer_ip: str = ""):
    """Teams op 8 (accept) / op 7 (decline) -- answer a clan invitation."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    verb = "ACCEPT" if accept else "DECLINE"
    try:
        r = lsg_request_params(dec)
        r.u8()
        tid = r.u64()
        inviter = r.u64()
    except Exception as e:
        log(f"  (teams op{8 if accept else 7} decode failed: {e})")
        return 0, None
    key = f"{tid:016x}"
    rec = team_get(key)
    mine = f"{me:016x}"
    if rec is None:
        log(f"  teams op{8 if accept else 7} ({verb} CLAN INVITE): no such clan "
            f"0x{key} -- ignored")
        return 0, None
    props = rec.get("proposals", [])
    prop = next((p for p in props if p.get("to") == mine), None)
    had = prop is not None
    if accept and not had:
        log(f"  teams op8 (ACCEPT CLAN INVITE): {name} 0x{mine} has NO proposal "
            f"on file for {rec.get('name')!r} 0x{key} -- REFUSED "
            f"(cancelled, already answered, or never sent)")
        return 0, None
    rec["proposals"] = [p for p in props if p.get("to") != mine]
    if accept and mine not in rec.setdefault("members", []):
        rec["members"].append(mine)
    team_put(key, rec)
    pulled = clan_invite_mail_drop(tid, clan_invite_push_type(), [mine])
    log(f"  teams op{8 if accept else 7} ({verb} CLAN INVITE): {name} "
        f"0x{mine} {'joins' if accept else 'declines'} {rec.get('name')!r} "
        f"0x{key} (invited by 0x{inviter:016x}"
        + ("" if had else ", but no proposal was on file")
        + f") -- {len(rec['members'])} member(s), "
        f"{len(rec['proposals'])} proposal(s) left"
        + (f", {pulled} mailbox row(s) withdrawn" if pulled else ""))
    try:
        by = int(prop.get("from") or "0", 16) if prop else 0
    except ValueError:
        by = 0
    by = by or (inviter if had else 0)
    if by and by != me:
        clan_notify(by, CLAN_MSG_CACCEPT if accept else CLAN_MSG_CREJECT,
                    tid, rec.get("name") or "", me, name,
                    target=me, target_name=name)
    return 0, None


def _teams_req_pair(dec: dict, op: int):
    """The shape every clan-administration request shares: `[u8 0][u64][u64]`."""
    r = lsg_request_params(dec)
    r.u8()
    return r.u64(), r.u64()


def _teams_actor(peer_ip: str, who):
    return account_for(peer_ip), (who or (rigconfig.USERNAME, 0))[0]


def teams_set_rank(promote: bool, dec: dict, who=None, peer_ip: str = ""):
    """Teams op 3 (promote to administrator) / op 26 (demote to member)."""
    op = 3 if promote else 26
    verb = "PROMOTE" if promote else "DEMOTE"
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, op)
    except Exception as e:
        log(f"  (teams op{op} decode failed: {e})")
        return 0, None
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = team_get(key)
    if rec is None:
        log(f"  teams op{op} ({verb}): no such clan 0x{key} -- ignored")
        return 0, None
    if rec.get("owner") != mine:
        log(f"  teams op{op} ({verb}): {name} 0x{mine} does not own "
            f"{rec.get('name')!r} -- REFUSED")
        return 0, None
    if them not in rec.get("members", []):
        log(f"  teams op{op} ({verb}): 0x{them} is not in {rec.get('name')!r} "
            f"-- ignored")
        return 0, None
    ranks = rec.setdefault("ranks", {})
    ranks[them] = TEAM_RANK_ADMIN if promote else TEAM_RANK_MEMBER
    team_put(key, rec)
    log(f"  teams op{op} ({verb} CLAN MEMBER): {name} 0x{mine} sets 0x{them} "
        f"to {'administrator' if promote else 'member'} (rank "
        f"{ranks[them]}) in {rec.get('name')!r} 0x{key}")
    clan_notify(target, CLAN_MSG_CADMIN if promote else CLAN_MSG_CORDINARY,
                tid, rec.get("name") or "", me, name,
                target=target, target_name=account_name(target))
    return 0, None


def teams_remove_member(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 4 -- remove a member from the clan ("Remove from clan")."""
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, 4)
    except Exception as e:
        log(f"  (teams op4 decode failed: {e})")
        return 0, None
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = team_get(key)
    if rec is None:
        log(f"  teams op4 (REMOVE): no such clan 0x{key} -- ignored")
        return 0, None
    if team_rank(rec, mine) < TEAM_RANK_ADMIN:
        log(f"  teams op4 (REMOVE): {name} 0x{mine} is an ordinary member of "
            f"{rec.get('name')!r} -- REFUSED")
        return 0, None
    if not _team_drop(rec, them):
        log(f"  teams op4 (REMOVE): 0x{them} is not in {rec.get('name')!r} "
            f"-- ignored")
        return 0, None
    team_put(key, rec)
    log(f"  teams op4 (REMOVE FROM CLAN): {name} 0x{mine} removes 0x{them} "
        f"from {rec.get('name')!r} 0x{key} -- {len(rec['members'])} member(s) left")
    clan_notify(target, CLAN_MSG_CKICKED, tid, rec.get("name") or "", me, name,
                target=target, target_name=account_name(target))
    return 0, None


def _team_drop(rec: dict, member: str) -> bool:
    """Take a member off a clan, rank override and all. True if they were on it."""
    if member not in rec.get("members", []):
        return False
    rec["members"] = [m for m in rec["members"] if m != member]
    (rec.get("ranks") or {}).pop(member, None)
    return True


def teams_leave(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 5 -- leave the clan, DISBAND it, or remove a member. All three."""
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, 5)
    except Exception as e:
        log(f"  (teams op5 decode failed: {e})")
        return 0, None
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = team_get(key)
    if rec is None:
        log(f"  teams op5 (LEAVE/DISBAND): no such clan 0x{key} -- ignored")
        return 0, None
    cname = rec.get("name")
    if target and them != mine:
        if team_rank(rec, mine) < TEAM_RANK_ADMIN:
            log(f"  teams op5 (REMOVE): {name} 0x{mine} is an ordinary member "
                f"of {cname!r} -- REFUSED")
            return 0, None
        if not _team_drop(rec, them):
            log(f"  teams op5 (REMOVE): 0x{them} is not in {cname!r} -- ignored")
            return 0, None
        team_put(key, rec)
        log(f"  teams op5 (REMOVE FROM CLAN): {name} 0x{mine} removes 0x{them} "
            f"from {cname!r} 0x{key} -- {len(rec['members'])} member(s) left")
        clan_notify(target, CLAN_MSG_CKICKED, tid, cname or "", me, name,
                    target=target, target_name=account_name(target))
        return 0, None
    if rec.get("owner") == mine:
        members = [m for m in rec.get("members", []) if m != mine]
        invited = [p.get("to") for p in rec.get("proposals", []) if p.get("to")]
        team_delete(key)
        pulled = clan_invite_mail_drop(tid, clan_invite_push_type(), invited)
        log(f"  teams op5 (DISBAND CLAN): {name} 0x{mine} disbands {cname!r} "
            f"0x{key} -- {len(members)} other member(s) lose it, "
            f"{len(invited)} outstanding invite(s) withdrawn "
            f"({pulled} mailbox row(s))")
        for m in members:
            clan_notify(int(m, 16), CLAN_MSG_CDISBAND, tid, cname or "", me, name,
                        target=me, target_name=name)
        return 0, None
    _team_drop(rec, mine)
    team_put(key, rec)
    log(f"  teams op5 (LEAVE CLAN): {name} 0x{mine} leaves {cname!r} 0x{key} "
        f"-- {len(rec['members'])} member(s) left")
    for m in rec.get("members", []):
        clan_notify(int(m, 16), CLAN_MSG_CLEFT, tid, cname or "", me, name,
                    target=me, target_name=name)
    return 0, None


def teams_transfer_owner(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 27 -- hand the clan to another member ("Transfer ownership")."""
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, 27)
    except Exception as e:
        log(f"  (teams op27 decode failed: {e})")
        return 0, None
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = team_get(key)
    if rec is None:
        log(f"  teams op27 (TRANSFER): no such clan 0x{key} -- ignored")
        return 0, None
    if rec.get("owner") != mine:
        log(f"  teams op27 (TRANSFER): {name} 0x{mine} does not own "
            f"{rec.get('name')!r} -- REFUSED")
        return 0, None
    if them not in rec.get("members", []):
        log(f"  teams op27 (TRANSFER): 0x{them} is not in {rec.get('name')!r} "
            f"-- ignored")
        return 0, None
    rec["owner"] = them
    ranks = rec.setdefault("ranks", {})
    ranks.pop(them, None)
    ranks[mine] = TEAM_RANK_MEMBER
    team_put(key, rec)
    log(f"  teams op27 (TRANSFER OWNERSHIP): {name} 0x{mine} hands "
        f"{rec.get('name')!r} 0x{key} to 0x{them}; the old owner is now an "
        f"ordinary member")
    clan_notify(target, CLAN_MSG_COWNER, tid, rec.get("name") or "", me, name,
                target=target, target_name=account_name(target))
    return 0, None


def teams_op10(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 10 -- `[u8 0][u64 gamerId]`, and NOT one of the ten clan verbs."""
    me, name = _teams_actor(peer_ip, who)
    try:
        r = lsg_request_params(dec)
        r.u8()
        target = r.u64()
    except Exception as e:
        log(f"  (teams op10 decode failed: {e})")
        return 0, None
    tid, rec = team_of(me)
    log(f"  teams op10 (UNIDENTIFIED, from the block-gamer chain): {name} "
        f"0x{me:016x} -> gamer 0x{target:016x}"
        + (f"; caller is in {rec.get('name')!r} 0x{tid:016x}" if rec else
           "; caller is in no clan")
        + " -- recorded, not acted on")
    return 0, None


def teams_proposals_result(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 24 -- clan invitations addressed to me. Row [u64][u64][str][str]
    (0x08c284b0), and it must carry the [u32 numResults] the arm at 0x08c29794
    reads.
    """
    lsg_request_noargs(dec, "teams op24")
    me = account_for(peer_ip)
    mine = f"{me:016x}"
    rows = [(int(tid, 16), int(frm, 16), cname, iname)
            for tid, cname, frm, iname in proposals_to(me)]
    log(f"  teams op24 (clan proposals) for 0x{mine}: {len(rows)}"
        + ("".join(f" -> {n!r} from {who_!r}" for _t, _f, n, who_ in rows)
           if rows else ""))
    if not rows:
        return 0, None

    def emit(w):
        for tid, inviter, tname, iname in rows:
            w.u64(tid)
            w.u64(inviter)
            w.str_(tname, 63)
            w.str_(iname, 63)
    return len(rows), emit


# ------------------------------------------------------------- downloads
STORAGE_DIR = CAP / "storage"
STORAGE_FIRST_ID = 0x5001


def _storage_row(r) -> dict:
    """One `storage` row as the dict the handlers always used, NULLs omitted so
    `f.get("created", 0)` and friends read as they did from the JSON.
    """
    out = {"id": r["id"], "name": r["name"] or "", "private": bool(r["private"])}
    for k in ("owner", "file", "size", "created", "modified"):
        if r[k] is not None:
            out[k] = r[k]
    return out


def storage_row(fid: int) -> dict | None:
    r = store.db().execute("SELECT * FROM storage WHERE id = ?", (fid,)).fetchone()
    return _storage_row(r) if r else None


def storage_rows(owner: int | None, everyone: bool = False) -> list:
    """The rows one list op serves: op 8 the GLOBAL rows (no owner), op 7 the
    global rows plus `owner`'s. In id order, which is upload order for
    anything the server allocated.
    """
    conn = store.db()
    if everyone:
        cur = conn.execute("SELECT * FROM storage WHERE owner IS NULL OR owner = ? "
                           "ORDER BY id", (f"{owner:016x}",))
    else:
        cur = conn.execute("SELECT * FROM storage WHERE owner IS NULL ORDER BY id")
    return [_storage_row(r) for r in cur]


def storage_list_result(op: int, dec: dict, who=None, peer_ip: str = ""):
    """Storage op 7 (by owner) / op 8 (global). Both reply [u32 n] + n rows."""
    me = account_for(peer_ip)
    owner = me
    start, count, filt = 0, 0, ""
    try:
        r = lsg_request_params(dec)
        r.u8()
        if op == 7:
            asked = r.u64()
            if os.environ.get("WOW2_NO_STORAGE_OWNER") != "1":
                owner = asked or me
        start = r.u32()
        count = r.u16()
        filt = next((v for t, v in bd.read_fields(r) if t == bd.BD_STR and v), "")
    except Exception as e:
        log(f"  (storage op{op} request decode failed: {e}; serving unwindowed)")
    files = storage_rows(owner, everyone=(op == 7))
    total = len(files)
    if count > 0:
        files = files[start:start + count]
    log(f"  storage op{op} ({'by owner' if op == 7 else 'global'}) for "
        f"0x{owner:016x}"
        + (f" (asked by 0x{me:016x})" if owner != me else "")
        + f": {len(files)} file(s)"
        + (f" of {total} (window {start}..{start + count})"
           if len(files) != total else "")
        + (f" [filter {filt!r} IGNORED]" if filt else "")
        + (" -> " + ", ".join(f.get("name", "?") for f in files) if files else ""))

    def emit(w):
        for i, f in enumerate(files, start=1):
            body = storage_bytes(f)
            w.u32(len(body))
            w.u64(_storage_id(f, i))
            w.u32(int(f.get("created", 0)))
            w.u32(int(f.get("modified", 0)))
            w.bool_(bool(f.get("private")))
            w.bool_(False)
            w.u64(_storage_owner(f))
            w.str_(f.get("name", ""), 127)
    return len(files), emit


def storage_bytes(f: dict) -> bytes:
    """The file's bytes from storage/."""
    try:
        return (STORAGE_DIR / f.get("file", "")).read_bytes()
    except OSError:
        return b""


def storage_get_result(dec: dict, who=None, peer_ip: str = ""):
    """Storage op 5 -- fetch one file's bytes. ONE row, and the arm at
    0x08c275bc calls the container with a hard-coded count of 1, so this reply
    must NOT carry a numResults field (same trap as Teams op 1).
    """
    try:
        r = lsg_request_params(dec)
        r.u8()
        fid = r.u64()
    except Exception as e:
        log(f"  (storage op5 decode failed: {e})")
        return 0, None
    f = storage_row(fid)
    body = storage_bytes(f) if f else b""
    blob_only = os.environ.get("WOW2_STORAGE_BLOB_ONLY") == "1"
    log(f"  storage op5 (get file 0x{fid:x}): "
        + (f"{f.get('name')!r} {len(body)} bytes" if f else "no such file")
        + (" [BLOB ONLY]" if blob_only else ""))

    def emit(w):
        if not blob_only:
            w.u32(len(body))
            w.u64(fid)
            w.u32(int(f.get("created", 0)) if f else 0)
            w.u32(int(f.get("modified", 0)) if f else 0)
            w.bool_(bool(f.get("private")) if f else False)
            w.bool_(False)
            w.u64(_storage_owner(f) if f else 0)
            w.str_(f.get("name", "") if f else "", 127)
        w.blob(body)
    return None, emit


def _storage_owner(rec: dict) -> int:
    """The account that owns one storage row, however the row spells it."""
    v = rec.get("owner")
    if v in (None, ""):
        return 0
    if isinstance(v, int):
        return v
    s = str(v).strip()
    try:
        return int(s, 16) if len(s) == 16 else int(s)
    except ValueError:
        return 0


def _storage_id(rec: dict, default: int = 0) -> int:
    """One storage row's file id, int or string."""
    try:
        return int(rec.get("id", default) or default)
    except (TypeError, ValueError):
        return default


def storage_upload_result(dec: dict, who=None, peer_ip: str = ""):
    """Storage op 1 -- store a file and hand back its id."""
    me = account_for(peer_ip)
    try:
        r = lsg_request_params(dec)
        r.u8()
        published = r.bool_()
        name = r.str_(128)
        private = r.bool_()
        data = r.blob()
    except Exception as e:
        log(f"  (storage op1 decode failed: {e})")
        return 0, None
    conn = store.db()
    mine = f"{me:016x}"
    r = conn.execute("SELECT id FROM storage WHERE name = ? AND owner = ? ORDER BY id "
                     "LIMIT 1", (name, mine)).fetchone()
    fid = int(r["id"]) if r else 0
    if not fid:
        used = {int(x[0]) for x in conn.execute("SELECT id FROM storage WHERE id >= ?",
                                                 (STORAGE_FIRST_ID,))}
        fid = next(i for i in range(STORAGE_FIRST_ID, STORAGE_FIRST_ID + 65536)
                   if i not in used)
    blob_name = f"{fid:x}-{name}"
    try:
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        blob_tmp = STORAGE_DIR / f"{blob_name}.tmp-{os.getpid()}"
        blob_tmp.write_bytes(data)
        os.replace(blob_tmp, STORAGE_DIR / blob_name)
    except OSError as e:
        log(f"  (!! storage op1 could not write {blob_name}: {e} -- the "
            f"upload FAILS and no row is filed)")
        return 0, None, BD_EXCEPTION_IN_DB
    now = int(time.time())
    with store.tx():
        conn.execute("INSERT INTO storage (id, name, owner, file, private, size, created, "
                     "modified) VALUES (?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT (id) DO UPDATE SET "
                     "name = excluded.name, owner = excluded.owner, file = excluded.file, "
                     "private = excluded.private, size = excluded.size, "
                     "created = excluded.created, modified = excluded.modified",
                     (fid, name, mine, blob_name, 1 if private else 0, len(data), now, now))
    log(f"  storage op1 (UPLOAD): {name!r} {len(data)} bytes from "
        f"0x{me:016x} -> file id 0x{fid:x} "
        f"(published={published} private={private})")

    def emit(w):
        w.u64(fid)
    return None, emit


def storage_overwrite_result(dec: dict, who=None, peer_ip: str = ""):
    """Storage op 2 -- replace a file's contents, by id."""
    me = account_for(peer_ip)
    try:
        r = lsg_request_params(dec)
        r.u8()
        fid = r.u64()
        data = r.blob()
    except Exception as e:
        log(f"  (storage op2 decode failed: {e})")
        return 0, None
    rec = storage_row(fid)
    if rec is None:
        log(f"  storage op2 (OVERWRITE): no file 0x{fid:x} -- ignored")
        return 0, None
    owner = _storage_owner(rec)
    if owner and owner != me:
        log(f"  storage op2 (OVERWRITE): file 0x{fid:x} {rec.get('name')!r} "
            f"belongs to 0x{owner:016x}, not 0x{me:016x} -- REFUSED")
        return 0, None
    blob_name = rec.get("file") or f"{fid:x}-{rec.get('name', 'file')}"
    try:
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        tmp = STORAGE_DIR / f"{blob_name}.tmp-{os.getpid()}"
        tmp.write_bytes(data)
        os.replace(tmp, STORAGE_DIR / blob_name)
    except OSError as e:
        log(f"  (storage op2 could not write {blob_name}: {e})")
        return 0, None
    was = int(rec.get("size", 0) or 0)
    now = int(time.time())
    with store.tx() as conn:
        conn.execute("UPDATE storage SET size = ?, modified = ?, file = ?, "
                     "created = COALESCE(created, ?) WHERE id = ?",
                     (len(data), now, blob_name, now, fid))
    log(f"  storage op2 (OVERWRITE): file 0x{fid:x} {rec.get('name')!r} "
        f"{was} -> {len(data)} bytes, from 0x{me:016x}")
    return 0, None


def storage_delete_result(dec: dict, who=None, peer_ip: str = ""):
    """Storage op 4 -- delete a file by id. `[u8 0][u64 fileId]`
    (builder `0x08c26f48`). Reads nothing, same as op 2.
    """
    me = account_for(peer_ip)
    try:
        r = lsg_request_params(dec)
        r.u8()
        fid = r.u64()
    except Exception as e:
        log(f"  (storage op4 decode failed: {e})")
        return 0, None
    rec = storage_row(fid)
    if rec is None:
        log(f"  storage op4 (DELETE): no file 0x{fid:x} -- ignored")
        return 0, None
    owner = _storage_owner(rec)
    if owner and owner != me:
        log(f"  storage op4 (DELETE): file 0x{fid:x} {rec.get('name')!r} "
            f"belongs to 0x{owner:016x}, not 0x{me:016x} -- REFUSED")
        return 0, None
    with store.tx() as conn:
        conn.execute("DELETE FROM storage WHERE id = ?", (fid,))
        left = conn.execute("SELECT COUNT(*) FROM storage").fetchone()[0]
    log(f"  storage op4 (DELETE): file 0x{fid:x} {rec.get('name')!r} removed by "
        f"0x{me:016x} ({left} file(s) left; the blob is kept on disk)")
    return 0, None


def teams_create_result(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 1 -- create a clan. Returns exactly ONE result: [u64 teamID]."""
    me = account_for(peer_ip)
    who_name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        clan = r.str_(64)
    except Exception as e:
        log(f"  (teams op1 decode failed: {e})")
        return 0, None
    mine = f"{me:016x}"
    existing = ""
    conn = store.db()
    if os.environ.get("WOW2_CLAN_NAME_IS_KEY") == "1":
        r = conn.execute("SELECT id FROM teams WHERE lower(name) = ? ORDER BY id LIMIT 1",
                         (clan.lower(),)).fetchone()
        existing = r["id"] if r else ""
    if existing:
        rec = team_get(existing)
        if mine not in rec["members"]:
            rec["members"].append(mine)
        team_put(existing, rec)
        tid = int(existing, 16)
        log(f"  teams op1 (CREATE): {who_name} joined existing clan {clan!r} "
            f"id=0x{tid:016x} ({len(rec['members'])} member(s)) "
            f"[WOW2_CLAN_NAME_IS_KEY]")
    else:
        with store.tx():
            dupes = conn.execute("SELECT COUNT(*) FROM teams WHERE lower(name) = ?",
                                 (clan.lower(),)).fetchone()[0]
            nxt = int(store.meta_get(conn, "teams_next", "1"))
            store.meta_set(conn, "teams_next", str(nxt + 1))
            tid = TEAM_ID_BASE + nxt
            team_put(f"{tid:016x}", {"name": clan, "owner": mine, "members": [mine],
                                     "created": store.now_iso()})
            total = conn.execute("SELECT COUNT(*) FROM teams").fetchone()[0]
        log(f"  teams op1 (CREATE): {who_name} created clan {clan!r} "
            f"id=0x{tid:016x} ({total} clan(s))"
            + (f" -- {dupes} other clan(s) already share that name, which is "
               f"allowed: the name is not a key" if dupes else ""))
    friends_note_name(me, who_name)

    def emit(w):
        w.u64(tid)
    return None, emit


def lsg_result_block(svc: int, op: int, dec: dict,
                     who: tuple[str, int] | None = None,
                     peer_ip: str = "", ident_key: str = ""):
    """(num_results, writer-callback|None) for one service RPC. Services not listed
    here still take a bare error=0 / numResults=0 reply, which they accept.
    """
    if os.environ.get("WOW2_LSG_NORESULTS") == "1":
        return 0, None
    if svc == LSG_SERVICE_STATS and op == 1:
        return stats_write_upload(dec, who, ident_key)
    if svc == LSG_SERVICE_STATS and op == 4:
        return stats_read_results(dec, who, ident_key)
    if svc == LSG_SERVICE_STATS and op == 5:
        return stats_pivot_results(dec, who, ident_key)
    if svc == LSG_SERVICE_SESSIONS and op == 1:
        return sessions_create_result(dec, peer_ip, ident_key)
    if svc == LSG_SERVICE_SESSIONS and op == 2:
        return sessions_update(dec, peer_ip, ident_key)
    if svc == LSG_SERVICE_SESSIONS and op == 3:
        return sessions_delete(dec, ident_key)
    if svc == LSG_SERVICE_SESSIONS and op == 4:
        return sessions_get_result(dec, peer_ip)
    if svc == LSG_SERVICE_SESSIONS and op == 5:
        return sessions_search_results(dec, peer_ip)
    if svc == LSG_SERVICE_FRIENDS and op in (5, 7, 19):
        return friends_list_result(op, dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 1:
        return friends_add(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 2:
        return friends_answer(dec, True, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 3:
        return friends_answer(dec, False, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 4:
        return friends_revoke(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 6:
        return friends_block(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 8:
        return friends_match_invite(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 10:
        return friends_match_decline(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 9:
        return friends_match_accept(dec, who, ident_key)
    if svc == LSG_SERVICE_PROFILE and op == 2:
        return profile_read_public(dec, who, ident_key)
    if svc == LSG_SERVICE_PROFILE and op == 4:
        return profile_upload(dec, who, ident_key)
    if svc == LSG_SERVICE_PROFILE and op == 1:
        return profile_upload(dec, who, ident_key, create=True)
    if svc == LSG_SERVICE_PROFILE and op == 3:
        return profile_read_private(dec, who, ident_key)
    if svc == LSG_SERVICE_PROFILE and op == 5:
        return profile_op5(dec, who, ident_key)
    if svc == LSG_SERVICE_MESSAGING and op == 1:
        return messages_result(dec, who, ident_key)
    if svc == LSG_SERVICE_MESSAGING and op == 4:
        return messages_delete(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 13:
        return friends_remove(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 1:
        return teams_create_result(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 20:
        return teams_memberships_result(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 21:
        return teams_members_result(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 6:
        return teams_invite(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op in (7, 8):
        return teams_answer_invite(op == 8, dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 25:
        return teams_cancel_invite(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 24:
        return teams_proposals_result(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op in (3, 26):
        return teams_set_rank(op == 3, dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 4:
        return teams_remove_member(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 5:
        return teams_leave(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 27:
        return teams_transfer_owner(dec, who, ident_key)
    if svc == LSG_SERVICE_TEAMS and op == 10:
        return teams_op10(dec, who, ident_key)
    if svc == LSG_SERVICE_STORAGE and op in (7, 8):
        return storage_list_result(op, dec, who, ident_key)
    if svc == LSG_SERVICE_STORAGE and op == 5:
        return storage_get_result(dec, who, ident_key)
    if svc == LSG_SERVICE_STORAGE and op == 1:
        return storage_upload_result(dec, who, ident_key)
    if svc == LSG_SERVICE_STORAGE and op == 2:
        return storage_overwrite_result(dec, who, ident_key)
    if svc == LSG_SERVICE_STORAGE and op == 4:
        return storage_delete_result(dec, who, ident_key)
    return 0, None


def parse_auth_header(body: bytes):
    """The two typed fields every auth request opens with: (iv_seed, titleId)."""
    r = bd.BdReader(body)
    msg_type = r.u8()
    r.bitmode = True
    r.read_type_checked_bit()
    r.type_checked = True
    return msg_type, r.u32(), r.u32(), r


def auth_cbc_decrypt(ct: bytes, key24: bytes, iv: bytes) -> bytes:
    """3DES-EDE-CBC as the CLIENT does it, degenerate keys and all."""
    k1, k2, k3 = key24[0:8], key24[8:16], key24[16:24]
    if k1 == k2:
        return DES.new(k3, DES.MODE_CBC, iv).decrypt(ct)
    if k1 == k3:
        return DES3.new(key24, DES3.MODE_CBC, iv).decrypt(ct)
    return DES3.new(key24, DES3.MODE_CBC, iv).decrypt(ct)


def auth_payload_decrypt(ct: bytes, key24: bytes, iv_seed: int) -> bytes | None:
    """Decrypt an auth payload and check its magic. None means the key was wrong."""
    pt = auth_cbc_decrypt(ct, key24, tiger_iv(iv_seed))
    if int.from_bytes(pt[:4], "little") != BD_AUTH_MAGIC:
        return None
    return pt


def parse_login(body: bytes) -> dict:
    """Decode a 0x0a login request: [u8 0x0a][tc bit][u32 iv_seed][u32 titleId][64 bits
    handle], the handle being Tiger192(username)[:8]. It carries no password."""
    msg_type, seed, title, r = parse_auth_header(body)
    r.type_checked = False
    return {"type": msg_type, "iv_seed": seed, "title_id": title,
            "handle": bytes(r.read_bits(64)[:8])}


def parse_lsg_connect(payload: bytes) -> dict | None:
    """Pull the ClientOpaqueAuthProof out of an LSG connect message (service 7)."""
    if len(payload) < 4 or payload[0] == 1:
        return None
    magic = struct.pack("<Q", OPAQUE_PROOF_MAGIC)
    r = bd.BdReader(payload)
    r.bitmode = True
    try:
        r.read_bits(16 + 1 + 37 + 37)
        proof = bytes(r.read_bits(128 * 8))
    except Exception:
        return None
    if proof[:8] != magic:
        return None
    _m, title, _exp, license_id, user_id = struct.unpack_from("<QIqQQ", proof, 0)
    return {"title_id": title, "license_id": license_id, "user_id": user_id,
            "session_key": proof[36:60],
            "username": proof[60:124].split(b"\x00")[0].decode("ascii", "replace")}


def parse_create_account(body: bytes) -> dict:
    """Decode a 0x00 (create account) request -- username and password, in clear."""
    msg_type, seed, title, r = parse_auth_header(body)
    r.type_checked = False
    account = bytes(r.read_bits(64)[:8])
    ct = bytes(r.read_bits(96 * 8)[:96])
    out = {"type": msg_type, "iv_seed": seed, "title_id": title,
           "account": account, "ciphertext": ct,
           "username": None, "password_hash": None}
    pt = auth_payload_decrypt(ct, BD_BOOTSTRAP_KEY, seed)
    if pt is not None:
        out["username"] = pt[4:68].split(b"\x00")[0].decode("ascii", "replace")
        out["password_hash"] = pt[68:92]
    return out


def parse_change_password(body: bytes, candidate_keys=()) -> dict:
    """Decode a 0x02 (change password) request."""
    msg_type, seed, title, r = parse_auth_header(body)
    r.type_checked = False
    user_hash = bytes(r.read_bits(64)[:8])
    ciphertext = bytes(r.read_bits(256)[:32])
    out = {"type": msg_type, "iv_seed": seed, "title_id": title,
           "user_hash": user_hash, "ciphertext": ciphertext,
           "matched_key": None, "new_password_hash": None}
    for label, key in (candidate_keys or ()):
        pt = auth_payload_decrypt(ciphertext, key, seed)
        if pt is not None:
            out["matched_key"] = label
            out["new_password_hash"] = pt[4:28]
            break
    return out


def build_auth_reply(reply_type: int, error_code: int, auth_data: bytes = b"") -> bytes:
    """An auth reply: [u8 type][tc bit][typed u32 error] then the raw auth data,
    framed unencrypted as [u32 len][0x00][payload]."""
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(reply_type)
    w.type_checked = True
    w.write_bits(b"\x01", 1)
    w.u32(error_code)
    payload = w.getvalue()
    if auth_data:
        payload += auth_data
    return bd.frame_unencrypted(payload)


CONNS_PER_IP: dict[str, int] = {}


class AuthConnection(asyncio.Protocol):
    def connection_made(self, transport):
        self.t = transport
        self.peer_ip, self.peer_port = transport.get_extra_info("peername")[:2]
        self.peer = f"{self.peer_ip}:{self.peer_port}"
        self.ident = identity_for(self.peer_ip)
        self.buf = b""
        self.rx_bytes = 0
        self.msg_window = [0.0, 0]
        self.counted = False
        self.next_txn = 0
        self.is_lsg = False
        self.account = None
        self.session_key = None
        self.authenticated = True
        self.proof_handle = None
        self.pending_ident = None
        live = CONNS_PER_IP.get(self.peer_ip, 0)
        if live >= serverconfig.MAX_CONNS_PER_IP:
            log(f"TCP connect from {self.peer} REFUSED: {live} connections already "
                f"open from that address (limits.max_conns_per_ip)")
            transport.close()
            return
        CONNS_PER_IP[self.peer_ip] = live + 1
        self.counted = True
        log(f"TCP connect from {self.peer} (console identity {self.ident[0]!r} id={self.ident[1]})")

    def over_limit(self, data: bytes) -> bool:
        """Per-connection caps. A peer that misbehaves loses its OWN connection."""
        self.rx_bytes += len(data)
        if self.rx_bytes > serverconfig.MAX_STREAM_BYTES:
            log(f"  (!! {self.peer} sent {self.rx_bytes}B this connection, over "
                f"limits.max_stream_bytes -- closing)")
            return True
        return False

    def over_msg_rate(self, n: int) -> bool:
        """Count MESSAGES, not reads."""
        now = time.monotonic()
        if now - self.msg_window[0] >= 1.0:
            self.msg_window = [now, n]
        else:
            self.msg_window[1] += n
        if self.msg_window[1] > serverconfig.MAX_MSGS_PER_SEC:
            log(f"  (!! {self.peer} sent {self.msg_window[1]} messages in a "
                f"second, over limits.max_msgs_per_sec -- closing)")
            return True
        return False

    def resolve_login(self, body: bytes) -> tuple[str, int, bytes, str, bool]:
        """(username, user_id, proof key, how, refused) for a 0x0a request."""
        try:
            req = parse_login(body)
        except Exception as e:
            log(f"  (couldn't decode the login request: {e})")
            req = None
        if req is not None and os.environ.get("WOW2_RIG_IDENTITY") != "1":
            acct = account_by_handle(req["handle"])
            if acct:
                name, uid = acct["name"], acct["user_id"] or self.ident[1]
                self.ident = (name, uid)
                self.account = name
                if acct["pwhash"]:
                    return name, uid, acct["pwhash"], \
                        f"handle {req['handle'].hex()}, stored credential", False
                if serverconfig.SHARED_PASSWORD_FALLBACK:
                    return name, uid, account_key(ACCOUNT_PASSWORD), \
                        f"handle {req['handle'].hex()}, shared password", False
                log(f"  (!! {name!r} has no stored credential and the shared "
                    f"password fallback is off -> refusing by answering with a "
                    f"key it cannot have)")
                return name, uid, secrets.token_bytes(24), \
                    f"handle {req['handle'].hex()}, NO CREDENTIAL", True
            if not serverconfig.SHARED_PASSWORD_FALLBACK:
                uname, uid = self.ident
                self.account = uname
                log(f"  (!! login handle {req['handle'].hex()} is not an account "
                    f"we know and the shared password fallback is off -> "
                    f"refusing by answering with a key it cannot have)")
                return uname, uid, secrets.token_bytes(24), \
                    f"handle {req['handle'].hex()}, UNKNOWN ACCOUNT", True
            log(f"  (!! login handle {req['handle'].hex()} is not an account we "
                f"know -- falling back to the source address, which is a GUESS)")
        uname, uid = self.ident
        self.account = uname
        if not serverconfig.SHARED_PASSWORD_FALLBACK:
            log(f"  (!! the login request could not be decoded and the shared "
                f"password fallback is off -> refusing by answering with a "
                f"key it cannot have)")
            return uname, uid, secrets.token_bytes(24), \
                "undecodable request, NO FALLBACK", True
        return uname, uid, account_key(ACCOUNT_PASSWORD), "by source address", False

    def bind_lsg(self, payload: bytes) -> bool:
        """Bind this LSG connection to an account, from its own first message."""
        proof = parse_lsg_connect(payload)
        self.proof_handle = None
        if proof is not None and PROOF_HANDLE and proof["session_key"] in PROOF_HANDLES:
            acct, key, issued = PROOF_HANDLES[proof["session_key"]]
            if time.time() - issued > PROOF_TTL:
                log(f"  (!! LSG connect for {proof['username']!r} presents a handle "
                    f"issued {time.time() - issued:.0f} s ago, past PROOF_TTL "
                    f"({PROOF_TTL:.0f} s) -- "
                    + ("keeping it on the source address, because "
                       "WOW2_LSG_NO_KEY_CHECK=1)" if LSG_NO_KEY_CHECK
                       else "closing the connection)"))
                return LSG_NO_KEY_CHECK
            if acct == proof["username"]:
                self.proof_handle = proof["session_key"]
                proof["session_key"] = key
        if proof is None:
            log("  (!! LSG connect carried no readable proof -- "
                + ("keeping it on the source address, because "
                   "WOW2_LSG_NO_KEY_CHECK=1)" if LSG_NO_KEY_CHECK
                   else "closing; there is no identity to fall back to)"))
            return LSG_NO_KEY_CHECK
        name = proof["username"]
        if session_key_is_ours(name, proof["session_key"]):
            self.pending_ident = (name, proof["user_id"] or self.ident[1])
            self.session_key = proof["session_key"]
            if self.proof_handle:
                self.authenticated = False
                log(f"  LSG connect: account {name!r} id={proof['user_id']} "
                    f"presents the handle we issued -> provisional; the first "
                    f"RPC that decrypts under the ticket key completes it")
                return True
            self.complete_bind("session key verified as one we issued")
            return True
        log(f"  (!! LSG connect for {name!r} presents a session key we did "
            f"not issue: {proof['session_key'].hex()[:16]}.. -- "
            + ("using the fixed key and the source address, because "
               "WOW2_LSG_NO_KEY_CHECK=1)" if LSG_NO_KEY_CHECK
               else "closing the connection)"))
        return LSG_NO_KEY_CHECK

    def complete_bind(self, why: str) -> None:
        """The second half of a bind: the single-session rule and the push route."""
        was = self.ident_key
        name, uid = self.pending_ident
        self.account = name
        self.ident = (name, uid)
        evict_other_lsg(name, keep=self)
        if LSG_CONNS.get(was) is self and was != self.ident_key:
            del LSG_CONNS[was]
        if self.is_lsg:
            LSG_CONNS[self.ident_key] = self
        self.authenticated = True
        log(f"  LSG connect: account {name!r} id={uid} ({why})")
        if self.is_lsg:
            board_refresh()

    @property
    def ident_key(self) -> str:
        """What identity-keyed state hangs off: the ACCOUNT when we know it."""
        return self.account or self.peer_ip

    def data_received(self, data):
        if self.over_limit(data):
            self.t.close()
            return
        self.buf += data
        debug(f"TCP {self.peer} +{len(data)}B (buf={len(self.buf)}, "
              f"stream={self.rx_bytes})")
        frames, self.buf, skipped = bd.parse_frame(self.buf)
        if skipped:
            path = CAP / f"unframed-{self.peer_ip.replace('.', '_')}.bin"
            with open(path, "ab") as f:
                f.write(skipped)
            log(f"  (!! {len(skipped)}B could not be framed; resynchronised past it "
                f"-> {path.name}: {skipped[:32].hex()}...)")
        if self.buf:
            head = self.buf[:LEFTOVER_HEXDUMP_MAX]
            debug(f"  (leftover {len(self.buf)}B in parse buffer: {head.hex()}"
                  f"{'...' if len(self.buf) > LEFTOVER_HEXDUMP_MAX else ''})")
        if frames and self.over_msg_rate(len(frames)):
            self.t.close()
            return
        for kind, payload in frames:
            try:
                self.handle(kind, payload)
            except Exception as e:
                log(f"  (!! handler raised on a {kind} frame from {self.peer}: "
                    f"{type(e).__name__}: {e} -- message dropped, connection kept)")

    def handle(self, kind: str, payload: bytes):
        if kind == "ping":
            log("  <- recv PING; replying 00000000 (keepalive)")
            self.t.write((0).to_bytes(4, "little"))
            return
        if kind == "bufsize":
            self.is_lsg = True
            LSG_CONNS[self.ident_key] = self
            n = int.from_bytes(payload, "little")
            log(f"  <- recv BUFSIZE announce: {n} bytes available (no reply); "
                f"this connection is the LSG")
            return
        enc, body = bd.unwrap_message(payload)
        debug(f"  <- recv MSG {len(payload)}B enc={enc}\n{hexdump(payload)}")
        if self.is_lsg or enc == 1:
            if enc == 0 and len(payload) > 1 and payload[1] == LSG_SERVICE_LOBBY:
                if not self.bind_lsg(payload):
                    self.t.close()
                    return
            session_key = self.session_key or rigconfig.SESSION_KEY
            try:
                dec = decode_lsg_client_message(payload, session_key)
            except Exception as e:
                log(f"  (LSG decode failed: {e})")
                return
            svc, op = dec["service"], dec["op"]
            log(f"  LSG msg: enc={dec['enc']} seed={dec['seed']} "
                f"hmac={dec['hmac'] and hex(dec['hmac'])} "
                f"service={svc} ({LSG_SERVICE_NAMES.get(svc, '?')}) op={op}")
            if dec["enc"] == 1:
                debug("  decrypted plaintext:\n" + hexdump(dec["plain"]))

            if svc == LSG_SERVICE_LOBBY:
                mode = os.environ.get("WOW2_LSG_MODE", "enc_connid")
                if mode == "enc_connid":
                    reply = build_lsg_connid_reply_encrypted(1, session_key)
                    desc = "encrypted LsgServiceConnectionId (enc=1, DES-CBC session key)"
                elif mode == "proof":
                    reply = build_login_reply(session_key, account_key(ACCOUNT_PASSWORD))
                    desc = "0x0b auth proof"
                else:
                    reply = build_lsg_connid_reply(1)
                    desc = "unencrypted LsgServiceConnectionId (type 4)"
                log(f"  -> send LSG connect reply [{desc}] {len(reply)}B")
                debug(hexdump(reply))
                self.t.write(reply)
                return

            if self.session_key is None and not LSG_NO_KEY_CHECK:
                log(f"  (!! service={svc} op={op} on an LSG connection that "
                    f"never presented a session key we issued -- closing)")
                self.t.close()
                return
            if PROOF_HANDLE and not LSG_NO_KEY_CHECK:
                first = not getattr(self, "authenticated", True)
                if dec["enc"] != 1:
                    log(f"  (!! service={svc} op={op} arrived UNENCRYPTED on a "
                        f"bound LSG connection -- a console never does that; "
                        f"closing)")
                    self.t.close()
                    return
                if not lsg_message_readable(dec, strict=first):
                    log(f"  (!! an encrypted message that does not decrypt under "
                        f"the ticket key (seed={dec['seed']}) -- this connection "
                        f"presented the clear proof without ever opening the "
                        f"ticket; closing)")
                    self.t.close()
                    return
                if first:
                    self.complete_bind("first RPC decrypts under the ticket key")

            if f"{svc}:{op}" in os.environ.get("WOW2_LSG_HOLD", "").split(","):
                log(f"  (WOW2_LSG_HOLD: not answering service={svc} op={op})")
                return
            err = int(os.environ.get("WOW2_LSG_ERR", "0"), 0)
            txn = self.next_txn
            self.next_txn += 1
            block = lsg_result_block(svc, op, dec, self.ident, self.peer_ip,
                                     self.ident_key)
            if len(block) == 3:
                nres, results, err = block
            else:
                nres, results = block
            census_note(svc, op, dec)
            reply = build_lsg_taskreply_encrypted(session_key, transaction_id=txn,
                                                  error_code=err, operation_id=op or 0,
                                                  num_results=nres, results=results)
            desc = (f"TaskReply (type 1, txn={txn}, service={svc}, op={op}, "
                    f"err={err}, "
                    f"{'1 result, no count field' if nres is None else f'{nres} results'})"
                    f" {len(reply)}B")
            delay = float(os.environ.get("WOW2_LSG_DELAY", "0"))
            if delay > 0:
                log(f"  -> [deferred {delay}s] {desc}")
                asyncio.get_event_loop().call_later(
                    delay, lambda: (log(f"  -> send (deferred) {desc}"),
                                    self.t.write(reply)))
            else:
                log(f"  -> send {desc}")
                debug(hexdump(reply))
                self.t.write(reply)
            return
        if not body:
            return
        auth_type = body[0]
        log(f"  auth message type = 0x{auth_type:02x}")
        if auth_type == AUTH_CREATE_ACCOUNT_REQ:
            try:
                req = parse_create_account(body)
                if req["username"] is None:
                    log(f"  create-account request: iv_seed=0x{req['iv_seed']:08x} "
                        f"-- payload did NOT decrypt (magic missing)")
                else:
                    log(f"  create-account request: iv_seed=0x{req['iv_seed']:08x} "
                        f"titleId=0x{req['title_id']:04x} "
                        f"username={req['username']!r} "
                        f"pwhash={req['password_hash'].hex()}")
            except Exception as e:
                log(f"  (couldn't decode the create-account request: {e})")
                req = None
            name = (req or {}).get("username")
            taken = bool(name) and stored_credential(name) is not None
            if CREATE_MODE == "name_exists" or (
                    CREATE_MODE == "refuse_duplicates" and taken):
                reply = build_auth_reply(AUTH_CREATE_ACCOUNT_REPLY,
                                         BD_AUTH_CREATE_USERNAME_EXISTS)
                log(f"  -> send CreateAccountReply (0x01, error 707 name-exists"
                    + (f"; {name!r} already has a credential and this request "
                       f"does not get to replace it" if taken else "")
                    + f") {len(reply)}B")
                if taken:
                    log(f"     ({name!r} will now be retried as a sign-in; it "
                        f"succeeds only for whoever set that password)")
            elif name and not create_allowed(self.peer_ip):
                reply = build_auth_reply(AUTH_CREATE_ACCOUNT_REPLY,
                                         BD_AUTH_CREATE_MAX_ACC_EXCEEDED)
                log(f"  -> send CreateAccountReply (0x01, error 710 max-accounts; "
                    f"{self.peer_ip} has already created "
                    f"{serverconfig.MAX_CREATES_PER_IP_PER_HOUR} online profiles "
                    f"this hour, limits.max_creates_per_ip_per_hour) {len(reply)}B")
            else:
                if name:
                    note_account(name, req["password_hash"], self.peer_ip)
                reply = build_auth_reply(AUTH_CREATE_ACCOUNT_REPLY, BD_AUTH_NO_ERROR)
                log(f"  -> send CreateAccountReply (0x01, SUCCESS 700, no body) {len(reply)}B")
            self.t.write(reply)
        elif auth_type == 0x0A:
            uname, uid, kc, how, refused = self.resolve_login(body)
            session_key = new_session_key(
                uname, register=not refused or LSG_NO_KEY_CHECK)
            handle = None
            if PROOF_HANDLE and not refused:
                handle = secrets.token_bytes(24)
                PROOF_HANDLES[handle] = (uname, session_key, time.time())
            reply = build_login_reply(session_key, kc, username=uname,
                                      user_id=uid, license_id=uid,
                                      proof_key=handle)
            if refused:
                log(f"  -> send LoginReply (0x0b REFUSED for {self.peer_ip}: {how}; a "
                    f"random key nobody holds, nothing registered. {uname!r} is this "
                    f"address's placeholder, not a name anyone typed. A login with no "
                    f"create before it is a profile that has been online before -- an "
                    f"account from before a wipe, or from another server: "
                    f"`wow2-account set <their profile name>` lets them in)"
                    f" {len(reply)}B")
                self.t.write(reply)
                return
            log(f"  -> send LoginReply (0x0b proof for {uname!r} id={uid} [{how}], "
                f"proof key={kc.hex()[:16]}.., "
                f"session key={session_key.hex()[:16]}..) {len(reply)}B")
            if handle:
                log(f"     (the clear proof carries handle {handle.hex()[:16]}.. "
                    f"for that key; the key itself is only in the ticket)")
            self.t.write(reply)
        elif auth_type == AUTH_CHANGE_PASSWORD_REQ:
            err = BD_AUTH_UNKNOWN_ERROR
            try:
                req = parse_change_password(body)
                acct = account_by_handle(req["user_hash"])
                name = acct["name"] if acct else None
                current = (acct and acct["pwhash"]) or account_key(ACCOUNT_PASSWORD)
                log(f"  change-password request: iv_seed=0x{req['iv_seed']:08x} "
                    f"titleId=0x{req['title_id']:04x} "
                    f"userHash={req['user_hash'].hex()} "
                    f"account={name!r}")
                pt = auth_payload_decrypt(req["ciphertext"], current, req["iv_seed"])
                if name is None:
                    err = BD_AUTH_BAD_ACCOUNT
                    log("    no account with that handle -> 704 "
                        "BD_AUTH_BAD_ACCOUNT")
                    log("    (the name is not recoverable from a handle. If you "
                        "know it: wow2-account set <name>, then have the console "
                        "sign in with that password)")
                elif pt is None:
                    err = BD_AUTH_INCORRECT_PASSWORD
                    log("    current password does NOT match -> 716 "
                        "BD_AUTH_INCORRECT_PASSWORD")
                else:
                    new_hash = pt[4:28]
                    set_account_password(name, new_hash, self.peer_ip)
                    err = BD_AUTH_NO_ERROR
                    log(f"    current password verified; {name!r} password hash "
                        f"-> {new_hash.hex()} (stored)")
            except Exception as e:
                log(f"  (couldn't decode the change-password request: {e})")
            err = int(os.environ.get("WOW2_CHANGE_PW_ERR", err))
            reply = build_auth_reply(AUTH_CHANGE_PASSWORD_REPLY, err)
            log(f"  -> send ChangePasswordReply (0x03, error {err}"
                f"{' SUCCESS' if err == BD_AUTH_NO_ERROR else ''}) {len(reply)}B")
            self.t.write(reply)
        else:
            log(f"  (no handler yet for auth type 0x{auth_type:02x} — logging only)")

    def connection_lost(self, exc):
        if self.counted:
            CONNS_PER_IP[self.peer_ip] = max(0, CONNS_PER_IP.get(self.peer_ip, 1) - 1)
            if not CONNS_PER_IP[self.peer_ip]:
                del CONNS_PER_IP[self.peer_ip]
            self.counted = False
        was_lsg = LSG_CONNS.get(self.ident_key) is self
        if was_lsg:
            del LSG_CONNS[self.ident_key]
        log(f"TCP {self.peer} closed ({exc})")
        if was_lsg:
            sessions_host_gone(self.ident_key)
            if self.account:
                board_refresh()


# ------------------------------------------------------------- UDP discovery
def bd_addr(ip: str, port: int) -> bytes:
    return socket.inet_aton(ip) + port.to_bytes(2, "little")


def _bridge_is_up() -> bool:
    """Is the rig's bridge address assigned to this host?"""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((rigconfig.NETNS_BRIDGE_IP, 0))
        s.close()
        return True
    except OSError:
        return False


BRIDGE_UP = _bridge_is_up()
NO_SELF_REWRITE = os.environ.get("WOW2_NO_SELF_REWRITE") == "1"


def discovered_self(ip: str) -> str:
    """What to tell a console its OWN address is, in the 0x1f/0x15 reply."""
    if NO_SELF_REWRITE or not BRIDGE_UP or not ip.startswith("127."):
        return ip
    return rigconfig.NETNS_BRIDGE_IP


def server_address_for(client_ip: str) -> str:
    """OUR address, as the console at `client_ip` reaches us."""
    ip = natrelay.server_addr_for(client_ip)
    if (ip.startswith("127.") and BRIDGE_UP and not NO_SELF_REWRITE
            and not natrelay.PUBLIC_ADDRESS):
        ip = rigconfig.NETNS_BRIDGE_IP
    return ip


def discovered_endpoint(addr: tuple[str, int]) -> tuple[str, int]:
    """The (ip, port) to tell a console its own public address is."""
    mb = natrelay.RELAY.mailbox_for(addr)
    if mb is None:
        return discovered_self(addr[0]), addr[1]
    return server_address_for(addr[0]), mb.port


# ---------------------------------------------------------------- NAT TYPE
NAT_TYPE_REQ = 0x14
NAT_TYPE_REPLY = 0x15
NAT_CHANGE_NONE, NAT_CHANGE_PORT, NAT_CHANGE_BOTH = 0, 2, 3


class NatTypeSocket(asyncio.DatagramProtocol):
    """A send-only socket that exists purely for the address it sends FROM."""

    def __init__(self, name: str):
        self.name = name
        self.t = None

    def connection_made(self, transport):
        self.t = transport

    def datagram_received(self, data, addr):
        log(f"UDP {addr[0]}:{addr[1]} -> {self.name} socket, {len(data)}B "
            f"(unexpected): {data[:32].hex()}")


NAT_TYPE_PORT_SOCK: NatTypeSocket | None = None
NAT_TYPE_ADDR_SOCK: NatTypeSocket | None = None


def nat_type_changed_addr(addr: tuple[str, int]) -> tuple[str, int]:
    """What to advertise as CHANGED."""
    alt = serverconfig.NAT_TYPE_ALT_ADDRESS
    return (alt or server_address_for(addr[0])), serverconfig.PORT


import collections
_UNKNOWN_UDP: collections.deque = collections.deque(maxlen=64)
UNKNOWN_UDP_LOG_PER_MIN = 20
UNKNOWN_UDP_FILES_MAX = 16
UNKNOWN_UDP_FILE_BYTES = 65536
_unknown_udp_minute = [0.0, 0, 0, set()]
_unknown_udp_files: set[str] = set()


def unknown_udp_note(peer: str, data: bytes, addr: tuple[str, int]) -> None:
    """Log and sample an unrecognised datagram, within the caps above."""
    now = time.time()
    win = _unknown_udp_minute
    if now - win[0] >= 60:
        if win[2]:
            log(f"UDP {win[2]} more unrecognised datagram(s) from {len(win[3])} "
                f"source(s) in the last minute were not printed")
        win[0], win[1], win[2] = now, 0, 0
        win[3].clear()
    _UNKNOWN_UDP.append((peer, data))
    win[3].add(addr[0])
    if win[1] >= UNKNOWN_UDP_LOG_PER_MIN:
        win[2] += 1
        return
    win[1] += 1
    log(f"UDP {peer} UNRECOGNISED {len(data)}B (no reply sent)")
    for off in range(0, min(len(data), 64), 16):
        chunk = data[off:off + 16]
        log("    " + f"{off:04x}  " + " ".join(f"{b:02x}" for b in chunk).ljust(47)
            + " " + "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
    if not _HEXDUMPS[0]:
        return
    name = f"udp-unknown-{addr[0].replace('.', '_')}-{addr[1]}.bin"
    if name not in _unknown_udp_files and len(_unknown_udp_files) >= UNKNOWN_UDP_FILES_MAX:
        return
    try:
        path = CAP / name
        if path.exists() and path.stat().st_size >= UNKNOWN_UDP_FILE_BYTES:
            return
        with open(path, "ab") as fh:
            fh.write(data)
        _unknown_udp_files.add(name)
    except OSError:
        pass

# ------------------------------------------------- bdNAT traversal brokering
NAT_INTRO_REQ = 0x0A
NAT_INTRO_RELAY = 0x0B
NAT_INTRO_REPLY = 0x0C
NAT_KEEPALIVE = 0x0E
NAT_MSG_SIZE = 29
NAT_ADDR_SIZE = 6
NAT_ADDR_UNSET = bytes.fromhex("00ff00ff0000")

NAT_BROKER = os.environ.get("WOW2_NAT_BROKER", "relay").lower()

NAT_MODE_FILE = CAP / "nat-broker.mode"


def nat_broker_mode() -> str:
    try:
        line = NAT_MODE_FILE.read_text().split("#")[0].strip().lower()
        return line.partition("=")[2].strip() if "=" in line else (line or NAT_BROKER)
    except OSError:
        return NAT_BROKER


NAT_PEERS: dict[tuple[str, int], float] = {}
NAT_PEER_TTL = 90.0
NAT_PEERS_MAX = 16384


def nat_peers_sweep(now: float | None = None) -> None:
    now = time.time() if now is None else now
    for addr in [a for a, t in NAT_PEERS.items() if now - t > NAT_PEER_TTL]:
        del NAT_PEERS[addr]
    while len(NAT_PEERS) > NAT_PEERS_MAX:
        del NAT_PEERS[min(NAT_PEERS, key=NAT_PEERS.get)]


def unbd_addr(raw: bytes) -> tuple[str, int]:
    """Inverse of bd_addr(): 4 in_addr bytes + u16 LE port."""
    return socket.inet_ntoa(raw[:4]), int.from_bytes(raw[4:6], "little")


def nat_parse(data: bytes):
    """(type, hmac, identifier, addrA, addrB), or None if not a bdNAT packet."""
    if len(data) != NAT_MSG_SIZE or data[1:3] != b"\x02\x00":
        return None
    return (data[0], data[3:13], int.from_bytes(data[13:17], "little"),
            unbd_addr(data[17:23]), unbd_addr(data[23:29]))


def nat_endpoint_for(target: tuple[str, int], sender: tuple[str, int]):
    """Translate an advertised peer address to where that console really is."""
    nat_peers_sweep()
    if target in NAT_PEERS:
        return target
    same_port = [p for p in NAT_PEERS if p[1] == target[1] and p != sender]
    return same_port[0] if len(same_port) == 1 else None


class Discovery(asyncio.DatagramProtocol):
    def connection_made(self, transport):
        self.t = transport

    def datagram_received(self, data, addr):
        peer = f"{addr[0]}:{addr[1]}"
        reply = None
        if len(data) >= 3 and data[1:3] == b"\x02\x00":
            if data[0] == 0x1E:
                reply = b"\x1f\x02\x00" + bd_addr(*discovered_endpoint(addr))
            elif data[0] == NAT_TYPE_REQ:
                self.nat_type(data, addr)
                return
        if reply:
            self.t.sendto(reply, addr)
            log(f"UDP {peer} disc 0x{data[0]:02x} -> reply {reply.hex()}")
            return

        msg = nat_parse(data)
        if msg and msg[0] == NAT_KEEPALIVE:
            nat_peers_sweep()
            if addr not in NAT_PEERS:
                log(f"UDP {peer} bdNAT keepalive -- console registered "
                    f"(now {len(NAT_PEERS) + 1} known)")
            NAT_PEERS[addr] = time.time()
            natrelay.RELAY.mailbox_for(addr)
            return
        if msg and msg[0] == NAT_INTRO_REQ and nat_broker_mode() != "off":
            self.introduce(data, msg, addr)
            return

        unknown_udp_note(peer, data, addr)

    def nat_type(self, data: bytes, addr: tuple[str, int]) -> None:
        """Answer one test of the console's NAT type probe."""
        peer = f"{addr[0]}:{addr[1]}"
        flags = data[3] if len(data) > 3 else NAT_CHANGE_NONE
        name = {NAT_CHANGE_NONE: "test 1", NAT_CHANGE_PORT: "test 3 (change port)",
                NAT_CHANGE_BOTH: "test 2 (change ip+port)"}.get(flags, f"flags {flags}")
        if not serverconfig.NAT_TYPE:
            log(f"UDP {peer} NAT type {name} -- ignored (type discovery off)")
            return
        mine = discovered_self(addr[0])
        body = (bytes([NAT_TYPE_REPLY, 0x02, 0x00])
                + bd_addr(mine, addr[1])
                + bd_addr(*nat_type_changed_addr(addr)))
        if flags == NAT_CHANGE_NONE:
            sock, via = self.t, f"UDP {serverconfig.PORT}"
        elif flags == NAT_CHANGE_PORT:
            sock = NAT_TYPE_PORT_SOCK.t if NAT_TYPE_PORT_SOCK else None
            via = f"UDP {serverconfig.NAT_TYPE_ALT_PORT}"
        elif flags == NAT_CHANGE_BOTH:
            sock = NAT_TYPE_ADDR_SOCK.t if NAT_TYPE_ADDR_SOCK else None
            via = (f"{serverconfig.NAT_TYPE_ALT_ADDRESS} (ephemeral port)"
                   if serverconfig.NAT_TYPE_ALT_ADDRESS
                   else "second-public-address")
            ours = {server_address_for(addr[0]), natrelay.server_addr_for(addr[0])}
            if sock is not None and serverconfig.NAT_TYPE_ALT_ADDRESS in ours:
                log(f"UDP {peer} NAT type {name} -- NOT answered: "
                    f"nat_type_alt_address is {serverconfig.NAT_TYPE_ALT_ADDRESS}, "
                    f"which is an address this console already reaches us on "
                    f"({'/'.join(sorted(ours))}). Test 2 needs a DIFFERENT public "
                    f"IP; answering from ours would report OPEN for an "
                    f"address-restricted NAT")
                return
        else:
            log(f"UDP {peer} NAT type {name} -- unknown change flags, ignored")
            return
        if sock is None:
            log(f"UDP {peer} NAT type {name} -- NOT answered "
                f"(no {via} socket; the console will retry, time out and "
                f"fall through to the next test)")
            return
        sock.sendto(body, addr)
        log(f"UDP {peer} NAT type {name} -> reply via {via}: {body.hex()}")

    def introduce(self, data, msg, addr):
        """Relay a NAT-traversal introduction to the peer the joiner asked for."""
        _, hmac, ident, a_addr, b_addr = msg
        mode = nat_broker_mode()
        log(f"UDP {addr[0]}:{addr[1]} bdNAT INTRO REQ id=0x{ident:08x} "
            f"A={a_addr[0]}:{a_addr[1]} B={b_addr[0]}:{b_addr[1]} "
            f"hmac={hmac.hex()} [{mode}]")

        if mode == "reply":
            out = bytes([NAT_INTRO_REPLY]) + data[1:]
            self.t.sendto(out, addr)
            log(f"    0x0c -> {addr[0]}:{addr[1]} (we look like the peer)")
            return

        target = None
        if natrelay.RELAY.enabled:
            owner = natrelay.RELAY.owner_of_advertised(b_addr)
            if owner is not None:
                natrelay.RELAY.pair(natrelay.RELAY.console_at(addr), owner)
                target = owner.key
                log(f"    [relay] B names mailbox :{b_addr[1]} -> {owner}")
            else:
                log(f"    [relay] B={b_addr[0]}:{b_addr[1]} is not one of our "
                    f"mailboxes; falling back to the port match")
        if target is None:
            target = nat_endpoint_for(b_addr, addr)
        if target is None:
            log(f"    no bdNAT socket known for {b_addr[0]}:{b_addr[1]} "
                f"-- seen: {sorted(NAT_PEERS)}")
            return
        out = bytes([NAT_INTRO_RELAY]) + data[1:]
        self.t.sendto(out, target)
        log(f"    0x0b -> {target[0]}:{target[1]}  {out.hex()}")


TIGER_EMPTY = tiger.TIGER_EMPTY


def check_tiger() -> None:
    """Refuse to start if Tiger192 is wrong."""
    got = tiger192(b"").hex()
    if got != TIGER_EMPTY:
        raise SystemExit(
            f"!! Tiger192 produced the wrong digest for the empty string.\n"
            f"   got      {got}\n   expected {TIGER_EMPTY}\n"
            f"   Every login proof built with it would be wrong.")
    if tiger192(b"abc").hex() != "2aab1484e8c158f2bfb8c5ff41b57a525129131c957b5f93":
        raise SystemExit("!! Tiger192 produced the wrong digest for 'abc'.")


async def start_nat_type_sockets(loop, bind: str) -> None:
    """Bind the extra source addresses the NAT type probe needs."""
    global NAT_TYPE_PORT_SOCK, NAT_TYPE_ADDR_SOCK
    if not serverconfig.NAT_TYPE:
        return
    alt_port = serverconfig.NAT_TYPE_ALT_PORT
    alt_addr = serverconfig.NAT_TYPE_ALT_ADDRESS
    try:
        _tr, NAT_TYPE_PORT_SOCK = await loop.create_datagram_endpoint(
            lambda: NatTypeSocket("nat-type change-port"),
            local_addr=(bind, alt_port))
    except OSError as e:
        log(f"!! NAT type: could not bind UDP {bind}:{alt_port} ({e}) -- test 3 "
            f"will go unanswered, so every console reports STRICT")
    if alt_addr:
        try:
            _tr, NAT_TYPE_ADDR_SOCK = await loop.create_datagram_endpoint(
                lambda: NatTypeSocket("nat-type change-addr"),
                local_addr=(alt_addr, 0))
        except OSError as e:
            log(f"!! NAT type: could not bind UDP {alt_addr}:0 ({e}) -- "
                f"test 2 will go unanswered, so no console can report OPEN")


async def main():
    check_tiger()
    store.set_logger(log)
    try:
        store.startup()
    except store.StoreError as e:
        log(f"!!!! {e}")
        print(f"!! {e}", file=sys.stderr, flush=True)
        raise SystemExit(2)
    loop = asyncio.get_running_loop()
    bind, port = serverconfig.BIND, serverconfig.PORT
    server = await loop.create_server(AuthConnection, bind, port)
    await loop.create_datagram_endpoint(lambda: Discovery(), local_addr=(bind, port))
    natrelay.set_logger(log)
    await natrelay.RELAY.start(bind)
    await start_nat_type_sockets(loop, bind)
    lobbyboard.set_logger(log)
    for problem in lobbyboard.BOARD.configure(serverconfig.DISCORD_LOBBY_WEBHOOK,
                                              serverconfig.DISCORD_ANNOUNCE_WEBHOOK,
                                              serverconfig.DISCORD_MENTION,
                                              serverconfig.DISCORD_TITLE,
                                              serverconfig.DISCORD_TEXT,
                                              serverconfig.DISCORD_COOLDOWN,
                                              serverconfig.DISCORD_ALSO,
                                              serverconfig.DISCORD_LEADERBOARD_WEBHOOK,
                                              serverconfig.DISCORD_LEADERBOARD_TITLE,
                                              serverconfig.DISCORD_LEADERBOARD_ROWS,
                                              serverconfig.STARTING_RATING):
        log(f"!! {problem} -- ignored")
    lobbyboard.BOARD.start(store.path())
    log(f"WOW2 server up: TCP+UDP {bind}:{port}")
    for line in serverconfig.describe().split("\n"):
        log(line)
    log(f"logging to {SESSION_LOG.name}")
    stop = asyncio.Event()
    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, stop.set)
    await stop.wait()
    log("WOW2 server stopping")
    server.close()      # not wait_closed(): on 3.12+ that waits for every console to hang up


def cli() -> None:
    """Console entry point (`wow2-server`). Same as running this file."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
    finally:
        lobbyboard.BOARD.stop(timeout=3.0)


if __name__ == "__main__":
    cli()
