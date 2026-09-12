#!/usr/bin/env python3
"""WOW2 PSP revival server — iteration build.

One process serving the whole Demonware surface the game reaches so far:
  * UDP 3074 : bdNAT discovery (IP-discovery 0x1e/0x1f, NAT-test 0x14/0x15)  [WORKING]
  * TCP 3074 : bd connection framing + ping + auth service                   [WIP]

Everything in/out is hex-logged to capture/ so each live launch is maximally
informative. The auth reply is intentionally easy to tweak between launches —
this is the iteration surface. Run:  ../.venv/bin/python tools/authserver.py
"""
from __future__ import annotations

import asyncio
import datetime
import json
import secrets
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

import natrelay
import serverconfig

ROOT = Path(__file__).resolve().parent.parent
# Where the rig WRITES. Derived from the source tree by default, which is right
# for the rig and wrong for an installed server -- site-packages is not a data
# directory. `storage.data_dir` / WOW2_DATA_DIR moves it.
CAP = serverconfig.DATA_DIR
CAP.mkdir(parents=True, exist_ok=True)
SESSION_LOG = open(CAP / f"session-{datetime.datetime.now():%Y%m%d-%H%M%S}.log", "a", buffering=1)


def ts() -> str:
    return datetime.datetime.now().strftime("%H:%M:%S.%f")[:-3]


def ts_file() -> str:
    """A timestamp safe in a filename (ts() has colons)."""
    return datetime.datetime.now().strftime("%Y%m%d-%H%M%S")


def log(msg: str):
    line = f"[{ts()}] {msg}"
    # flush=True because Python block-buffers stdout when it is not a tty. On the
    # rig that is invisible (everything reads the session log), but under systemd
    # or in a container the journal is stdout, and an unflushed server looks hung
    # for as long as it takes to fill 8 KB.
    print(line, flush=True)
    SESSION_LOG.write(line + "\n")


def debug(msg: str):
    """Per-PACKET detail: every read, every message body, every reply.

    This is ~90% of the log volume and all of the reason a session log grows
    without bound -- and it is also exactly what the recon needs, which is why it
    is on by default. `logging.level = "info"` (or WOW2_LOG_LEVEL=info) leaves one
    line per RPC.

    Only the highest-volume call sites go through here. Classifying all ~400 of
    them would be churn for no gain: the rest fire once per sign-in or once per
    lobby, and an operator wants to see those.
    """
    if _DEBUG[0]:
        log(msg)


# Set from serverconfig once it is imported (below -- this file sets sys.path
# first, so the config import cannot come before the helpers that use it). A list
# so the flag is mutable without a `global`.
_HEXDUMPS = [True]
_DEBUG = [True]


def hexdump(data: bytes, pfx="    ") -> str:
    """A full hexdump of every message is how this protocol got reversed, and it
    is also how a session log reaches hundreds of megabytes. `logging.hexdumps`
    (or WOW2_HEXDUMPS=0) replaces the body with a one-line summary."""
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
# Reference message-type numbering (bd auth_handler mod.rs). WOW2 is the 2007
# SDK; create/login reply numbers confirmed against BOOT.BIN where possible.
AUTH_CREATE_ACCOUNT_REQ = 0x00
AUTH_CREATE_ACCOUNT_REPLY = 0x01
AUTH_CHANGE_PASSWORD_REQ = 0x02
AUTH_CHANGE_PASSWORD_REPLY = 0x03   # by the 0x00 -> 0x01 convention; see below

# The FULL bdAuth error enum, read out of the client's own code->string mapper
# (`0x0898a168`): it binary-searches to `0x0898a2a4`, checks `code >= 700`, and
# indexes a 17-entry jump table at `0x08d38260` with `code - 700`. Each entry
# loads the name below. So these are the client's numbers, not a guess -- and 707
# (already known from the create-account path) lands exactly where it should.
BD_AUTH_NO_ERROR = 700  # == 0x2bc, the success code the client checks for
BD_AUTH_BAD_REQUEST = 701
BD_AUTH_SERVER_CONFIG_ERROR = 702
BD_AUTH_BAD_TITLE_ID = 703
BD_AUTH_BAD_ACCOUNT = 704
BD_AUTH_ILLEGAL_OPERATION = 705
BD_AUTH_INCORRECT_LICENSE_CODE = 706
BD_AUTH_CREATE_USERNAME_EXISTS = 707  # returning-user: name taken -> client logs in instead
BD_AUTH_CREATE_USERNAME_ILLEGAL = 708
BD_AUTH_CREATE_USERNAME_VULGAR = 709
BD_AUTH_CREATE_MAX_ACC_EXCEEDED = 710
BD_AUTH_MIGRATE_NOT_SUPPORTED = 711
BD_AUTH_TITLE_DISABLED = 712
BD_AUTH_ACCOUNT_EXPIRED = 713
BD_AUTH_ACCOUNT_LOCKED = 714
BD_AUTH_UNKNOWN_ERROR = 715
BD_AUTH_INCORRECT_PASSWORD = 716

# The title id the client stamps into every auth request as field [1]. One
# `ori $a1, $zero, 0x131d` in the whole image (0x0896fd84) feeds
# bdAuthService's constructor, and all 64 captured auth bodies carry it.
BD_TITLE_ID = 0x131D

# The magic the client puts at the head of an encrypted auth payload
# (global 0x08d6a2a8). Same constant the login proof is checked against.
BD_AUTH_MAGIC = 0xEFBDADDE

# The 24-byte key the client uses when it has NO account yet -- i.e. for
# create-account. `0x08c19d60` is a hash wrapper whose very first test is
# `bnez $a0` on the input pointer: a NULL input does not hash anything, it
# memcpy's 24 bytes from the constant at `0x08d6a290`. This is that constant.
#
# It is not really 3DES. K1 == K2 (`deadbeefdeadbeef` twice), so EDE collapses:
# D_K2(E_K1(P)) == P, leaving C = E_K3(P) with K3 = eight ZERO bytes -- single
# DES under a key that is one of DES's four WEAK keys, and a weak key is an
# involution (E(E(x)) == x). That is not a footnote, it is the thing that made
# these bodies look encrypted-but-odd for months: in CBC a run of zero plaintext
# becomes C[i+2] == C[i], so the unused tail of the 64-byte username buffer comes
# out as a 16-byte pattern repeating to the end of the buffer. Every capture shows
# it, and it stops exactly where the password hash begins.
BD_BOOTSTRAP_KEY = bytes.fromhex("deadbeefdeadbeefdeadbeefdeadbeef"
                                 "0000000000000000")

# How to answer the create-account request (0x00). Flip via env WOW2_CREATE_MODE:
#   "success"     -> reply 700 (account created); client should then login (0x0a) -> LSG
#   "name_exists" -> reply 707; renders "profile name already in use" + disconnect (old default)
import os
import rigconfig
_HEXDUMPS[0] = serverconfig.HEXDUMPS
_DEBUG[0] = serverconfig.DEBUG
CREATE_MODE = serverconfig.CREATE_MODE
# The account password the client uses. K_client = Tiger192(password) is the key the
# client decrypts the login proof with, so the server must key the proof with the SAME
# password the game typed at the on-screen keyboard. Both sides read it from
# tools/rigconfig.py so they cannot drift apart (they did once: the input sequence
# typed "111111" while the server assumed "123456", which fails as a bogus proof and
# shows up as a misleading "couldn't sign in" dialog).
# TODO(persist): learn this per-account from the create-account request / an account
# store. Blocked: that request's identity blob does not decrypt with the deadbeef
# bootstrap key (retested 2026-09-10, tools/decode_create.py) -- its key is unknown.
ACCOUNT_PASSWORD = rigconfig.ACCOUNT_PASSWORD


import subprocess
from Crypto.Cipher import DES, DES3

# SOLVED (Phase 8, 2026-09-09): the login proof is decrypted by the client with
#   K_client = Tiger192(password)
# a per-ACCOUNT key derived from the player's password. Proven live: the client's
# captured decrypt key == Tiger192(exact password typed) (24-byte full match, stable
# across cycles). Phase 7's "authobj+0xB8 = Tiger192(bdSecurityID)" was a red herring
# (authobj+0xB8 simply HOLDS Tiger192(password)). Encrypting the proof with deadbeef
# made the client's magic check (expects 0xEFBDADDE) fail -> "profile name already in
# use". Encrypting with Tiger192(password) makes it pass -> "Signing in..." -> LSG.
# The create-account request (0x00) is encrypted with the universal deadbeef default
# key (first-contact bootstrap) and carries the account material the server records.
TICKET_MAGIC = 0xEFBDADDE
# The opaque-proof magic (reference auth_proof.rs ClientOpaqueAuthProof::MAGIC). This
# blob is opaque TO THE CLIENT: it stores it verbatim (authobj+0x20) and relays it to
# the LSG on connect. Our server is both auth and LSG, so we can format it freely; we
# keep the reference layout unencrypted so the LSG side can read it back directly.
OPAQUE_PROOF_MAGIC = 0xC0FFEEFFEEAA1337


def tiger192(data: bytes) -> bytes:
    """Full 24-byte Tiger192 digest via rhash (validated against the ref vector)."""
    h = subprocess.check_output(["rhash", "--tiger", "-"], input=data)
    return bytes.fromhex(h.split()[0].decode())


def tiger_iv(seed: int) -> bytes:
    """IV = Tiger192(seed_le)[:8]."""
    return tiger192(seed.to_bytes(4, "little"))[:8]


def account_key(password: str) -> bytes:
    """K_client = Tiger192(password) -- the 24-byte per-account key the client derives
    and uses to decrypt the login proof. This is what the original server keyed on."""
    return tiger192(password.encode())


def cbc_3des_encrypt(plaintext: bytes, key24: bytes, iv: bytes) -> bytes:
    """Real 3DES-EDE-CBC with a 24-byte key. For the login proof key24 is the
    account key Tiger192(password); the client 3DES-decrypts the proof with the
    identical key it derived from its own password."""
    return DES3.new(key24, DES3.MODE_CBC, iv).encrypt(plaintext)


def build_client_opaque_proof(session_key: bytes, username: str = rigconfig.USERNAME,
                              user_id: int = rigconfig.USER_ID,
                              license_id: int = rigconfig.LICENSE_ID,
                              title: int = rigconfig.TITLE_ID) -> bytes:
    """The 128-byte ClientOpaqueAuthProof the client reads into authobj+0x20 (login-reply
    handler +0x410964, read_bits 0x400) right after the encrypted proof, then relays to
    the LSG in bdRemoteTaskManager::onConnected (the 180B RPC, from conn+0x54). Layout is
    the reference's ClientOpaqueAuthProof::serialize (auth_proof.rs), LE, exactly 128 B:
      u64 magic, u32 title, i64 time_expires, u64 license, u64 user_id,
      24B session_key, 64B username(zero-pad), u32 pad.
    Left UNENCRYPTED — it is opaque to the client (stored/relayed verbatim), and our own
    LSG can parse it directly. NOTE(before this fix the client read 128 B PAST the end of
    our reply -> uninitialised memory -> it relayed garbage to the LSG, stalling sign-in)."""
    import struct as _s
    p = bytearray()
    p += _s.pack("<Q", OPAQUE_PROOF_MAGIC)   # 8
    p += _s.pack("<I", title)                # 4
    p += _s.pack("<q", 0x7FFFFFFF)           # 8  time_expires (far future)
    p += _s.pack("<Q", license_id)           # 8
    p += _s.pack("<Q", user_id)              # 8
    p += session_key                         # 24
    ub = username.encode()[:63]
    p += ub + b"\x00" * (64 - len(ub))       # 64
    p += _s.pack("<I", 0)                    # 4  pad
    assert len(p) == 128, len(p)
    return bytes(p)


def build_login_reply(session_key: bytes, key24: bytes, seed: int = 0,
                      username: str = rigconfig.USERNAME,
                      user_id: int = rigconfig.USER_ID,
                      license_id: int = rigconfig.LICENSE_ID) -> bytes:
    """Valid AccountForMmpReply (0x0b): [seed][3DES-CBC proof]. The client's proof
    deserializer (0x410ec4) reads fields SEQUENTIALLY, so byte layout matters:
      [0:4] magic  [4:5] type  [5:9] title  [9:13] t_issued  [13:17] t_expires
      [17:25] license_id(u64)  [25:33] user_id(u64)  [33:97] username(64)
      [97:121] session_key(24)  [121:128] pad
    """
    import struct as _s
    p = bytearray(128)
    p[0:4]   = _s.pack("<I", TICKET_MAGIC)
    p[4]     = 0                              # ticket type (UserToService)
    p[5:9]   = _s.pack("<I", 0x131D)          # title id
    p[9:13]  = _s.pack("<I", 0)               # time issued
    p[13:17] = _s.pack("<I", 0x7FFFFFFF)      # time expires (far future)
    p[17:25] = _s.pack("<Q", license_id)      # license id (non-zero!)
    p[25:33] = _s.pack("<Q", user_id)         # user id (non-zero -> not anonymous)
    ub = username.encode()[:63]
    p[33:33 + len(ub)] = ub                   # username, matches the client's name
    p[97:121] = session_key                   # LSG session key we assign
    # The client 3DES-CBC-decrypts the proof with a FIXED seed of 0 (IV=Tiger192(0)),
    # NOT a seed from our reply. Verified live 2026-09-09.
    iv = tiger_iv(0)
    enc = cbc_3des_encrypt(bytes(p), key24, iv)   # key24 = Tiger192(password)

    # The client reads the reply as ONE continuous bitstream and reads the 1024-bit
    # (128-byte) proof at a FIXED bit position: right after the 46-bit header
    # [type u8 + type_checked bit + typed-u32 error] plus 5 bits, i.e. payload bit 51.
    # So bit-pack the proof continuously (NO byte padding, NO seed field) -- byte-
    # appending it (the old build_auth_reply path) lands it 29 bits too late and the
    # client decrypts stale stack bytes -> "profile name already in use". Verified live.
    # The 128-byte opaque proof the client reads (bit-continuous, right after the encrypted
    # proof) into authobj+0x20 and later relays to the LSG. Same session_key/identity as the
    # encrypted ticket above so both halves of the reply describe one account.
    opaque = build_client_opaque_proof(session_key, username, user_id, license_id)

    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(0x0B)                       # reply type (8 bits, untyped)
    w.type_checked = True
    w.write_bits(b"\x01", 1)         # type_checked bit
    w.u32(BD_AUTH_NO_ERROR)          # typed u32 error 700 (5-bit tag + 32 bits) -> bit 46
    w.type_checked = False
    w.write_bits(b"\x00", 5)         # 5 filler bits: read as the seed's type tag; != u32(8)
                                     # so the client's seed read is skipped (seed=0 ->
                                     # IV=Tiger(0)) and the proof begins at payload bit 51.
    w.write_bits(enc, len(enc) * 8)          # 1024-bit encrypted proof (-> decrypt+magic)
    w.write_bits(opaque, len(opaque) * 8)    # 1024-bit opaque proof (-> authobj+0x20 -> LSG)
    return bd.frame_unencrypted(w.getvalue())


# ------------------------------------------------------------------ LSG reply
# After auth, the client opens a 2nd TCP connection to the LSG (Lobby Service
# Gateway = bdLobbyConnection) and presents its (relayed) auth to it, then waits
# for a reply. Reversed from the live client (pspram-live.bin, RAM=fileoff+0x7dfc000):
#   * reply dispatcher z_un_08c17c88 reads a 1-byte message TYPE, switch:
#       1 BD_LOBBY_SERVICE_TASK_REPLY   2 BD_LOBBY_SERVICE_PUSH_MESSAGE
#       3 LsgServiceError               4 LsgServiceConnectionId   (else unknown)
#   * type-4 handler @0x08c180ac: readType(expect 0x0A=BD_UINT64) then read 64 bits
#     = the connection id (u64), stores it in the task manager (obj+0x18/+0x1C),
#     logs "Received LSG connection ID:%llu". This is the "you're connected" reply.
# Matches reference ConnectionIdResponse: byte-mode [u8 4][typed u64]. The client's
# LSG connect carries enc flag 0xff; whether the reply must be unencrypted (enc=0,
# like the auth replies) or echo/enc is being pinned live -> WOW2_LSG_ENC.
# Lobby service ids (reference lobby/mod.rs LobbyServiceId). The ones this title
# actually uses so far: 7 = the LSG connect RPC, 10 = Storage (the "global storage"
# step the game blocks on right after "connected to bit demon lobby").
LSG_SERVICE_NAMES = {3: "Teams", 4: "Stats", 5: "Sessions", 6: "Messaging",
                     7: "LobbyService", 8: "Profile", 9: "Friends", 10: "Storage",
                     12: "TitleUtilities", 21: "Matchmaking", 23: "Counter"}

# EVERY LSG reply body must start with a 1-bit type_checked flag, before the first
# typed field. The client's receive buffer constructor (bdBitBuffer @0x08be5d88)
# ends by doing `read_bits(&this->type_checked, 1)` -- it eats the first bit of the
# body as the flag, exactly like the client's own outgoing messages write it
# (bdRemoteTaskManager::startTask @0x08c2486c writes the bit, then typed fields).
# Omit it and the flag reads as the LSB of your first 5-bit type tag: with tag 0x0A
# that is 0, so the reader turns type-checking OFF, stops consuming tags, and reads
# every field one bit late with the tag bits folded into the value. That silently
# turned a ConnectionId of 1 into 0x15 (harmless -- nothing validates it) and a
# TaskReply error code of 0 into 128, which the storage result reader (0x08c273cc)
# treats as a failed task -> "Couldn't sign in". The auth-service replies always had
# this bit (see build_login_reply); the LSG ones did not.
LSG_TYPE_CHECKED_BIT = 1

LSG_SERVICE_LOBBY = 7      # the LSG connect/auth presentation
LSG_SERVICE_STORAGE = 10   # "global storage" -- the step sign-in blocks on
LSG_SERVICE_STATS = 4      # leaderboards; the last RPC of the sign-in chain
LSG_SERVICE_SESSIONS = 5   # bdMatchMaking: the game lobby itself (create/delete)
LSG_SERVICE_TEAMS = 3      # clans; op 1 = create, and it MUST return the new id
LSG_SERVICE_FRIENDS = 9    # buddies; ops 5/7/19 are the three lists (Phase 22)
LSG_SERVICE_MESSAGING = 6  # the lobby mailbox -- where a buddy invite is ANSWERED
LSG_SERVICE_PROFILE = 8    # player profiles

LSG_MSG_TASK_REPLY = 1
LSG_MSG_PUSH_MESSAGE = 2
LSG_MSG_ERROR = 3
LSG_MSG_CONNECTION_ID = 4
LSG_ENC_FLAG = int(os.environ.get("WOW2_LSG_ENC", "0"), 0)  # 0 = unencrypted reply


def build_lsg_connid_reply(connection_id: int = 1, enc_flag: int = LSG_ENC_FLAG) -> bytes:
    """LsgServiceConnectionId (type 4): byte-mode [u8 4][typed u64 conn_id].
    Framed [u32 len][enc_flag][body]. enc_flag defaults 0 (unencrypted)."""
    w = bd.BdWriter()                 # byte mode
    w.type_checked = False
    w.u8(LSG_MSG_CONNECTION_ID)       # message type (untyped u8)
    w.type_checked = True
    w.u64(connection_id)              # typed u64 -> [tag 0x0A][8 bytes LE]
    body = w.getvalue()
    return len((bytes([enc_flag]) + body)).to_bytes(4, "little") + bytes([enc_flag]) + body


RESPONSE_SIGNATURE = 0xDEADBEEF  # bd_response.rs prepends this before the payload (the
                                 # client reads it as the 4-byte hmac slot; not validated)


def session_cbc_encrypt(plaintext: bytes, session_key: bytes, iv: bytes) -> bytes:
    """3DES-EDE-CBC with the 24-byte session key. Our assigned key is \\x42*24 whose
    K1==K2==K3, which pycryptodome DES3 rejects and which is cryptographically identical
    to single DES-E(K1) under EDE -- so fall back to DES for that degenerate case."""
    if session_key[0:8] == session_key[8:16] == session_key[16:24]:
        return DES.new(session_key[:8], DES.MODE_CBC, iv).encrypt(plaintext)
    return DES3.new(session_key, DES3.MODE_CBC, iv).encrypt(plaintext)


def session_cbc_decrypt(ciphertext: bytes, session_key: bytes, iv: bytes) -> bytes:
    """Inverse of session_cbc_encrypt (same degenerate-key caveat)."""
    if session_key[0:8] == session_key[8:16] == session_key[16:24]:
        return DES.new(session_key[:8], DES.MODE_CBC, iv).decrypt(ciphertext)
    return DES3.new(session_key, DES3.MODE_CBC, iv).decrypt(ciphertext)


def decode_lsg_client_message(payload: bytes, session_key: bytes) -> dict:
    """Decode one client->server LSG message body (everything after [u32 len]).

    Layout mirrors bd_message.rs, and the client's own sender
    (bdRemoteTaskManager::startTask @0x08c2486c, verified by disassembly):
      plain      [u8 enc!=1][u8 service_id][bit-mode: tc-bit, typed u8 op_id, params]
      encrypted  [u8 enc==1][u32 seed][ 3DES-CBC( [u32 hmac][u8 service_id][bits] ) ]
    Only enc==1 means encrypted -- the client reads that flag with a *signed* load
    and compares == 1, so its own 0xff connect frame is plaintext (Phase 9).
    """
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
    """Encrypted LsgServiceConnectionId, per bd_response.rs `encrypted_if_available`:
      frame  = [u32 len][u8 enc=1][u32 seed][ciphertext]
      cipher = 3DES-CBC(session_key, IV=Tiger192(seed)[:8]) of
               [u32 sig 0xDEADBEEF][u8 type=4][typed u64 conn_id]  (zero-padded to 8)
    The client (enc==1 path) reads seed, decrypts with the session key it took from the
    login proof (verified = \\x42*24), reads the 4-byte sig slot (byte), the 1-byte type
    (byte), then hands the REST to a BIT-mode reader. So the typed-u64 must be BIT-packed
    ([5-bit tag 0x0A][64-bit value]) -- byte-mode packing is misread (conn-id came out
    0x85 instead of 1). Verified: the auth proof reader is bit-mode too."""
    r = bd.BdWriter()                 # bit-mode reader payload (after the byte type)
    r.bitmode = True
    r.type_checked = False
    r.write_bits(b"\x01", 1)          # <- the type_checked BIT (see LSG_TYPE_CHECKED_BIT)
    r.type_checked = True
    r.u64(connection_id)              # [5-bit tag 0x0A][64 bits], flushed to 9 bytes
    plaintext = (RESPONSE_SIGNATURE.to_bytes(4, "little")
                 + bytes([LSG_MSG_CONNECTION_ID])   # type 4 (byte-aligned, read by framing)
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
    """Type-1 LobbyServiceTaskReply (Phase 9b): completes the pending auth bdRemoteTask the
    client registered in bdRemoteTaskManager::onConnected. Same envelope as the conn-id reply
    (enc=1, DES-CBC session key, 0xDEADBEEF sig, then a BIT-mode reader). Wire (per
    reference task_reply.rs, bit-packed for this client's reader):
      [sig u32=0xDEADBEEF][u8 type=1] then bit-mode:
      [typed u64 txn_id][typed u32 err][typed u8 op_id][typed u32 numResults][typed u32 total]
    The dispatcher routes type 1 -> task manager (z_un_08c24bec) which matches by txn_id."""
    r = bd.BdWriter()
    r.bitmode = True
    r.type_checked = False
    r.write_bits(b"\x01", 1)  # <- the type_checked BIT (see LSG_TYPE_CHECKED_BIT)
    r.type_checked = True
    r.u64(transaction_id)     # typed u64: [5-bit tag 0x0A][64 bits]  (read by 0x08c24bec)
    r.u32(error_code)         # typed u32: [5-bit tag 0x08][32 bits]  (read by 0x08c273cc)
    r.u8(operation_id)        # typed u8:  [5-bit tag 0x03][8 bits]
    # numResults -- rows follow IMMEDIATELY; this SDK has no totalNumResults
    # field (0x08c273cc goes straight from the count to the row loop), unlike
    # the newer reference.
    #
    # PHASE 22: the count is NOT universal. Whether it is in the stream is decided
    # per (service, op) by the arm the service's reply reader jumps to:
    #   bdStats  0x08c2529c        reads [u32 numResults] itself   -> send it
    #   Friends  arm 0x08c18dac    reads [u32 numResults]          -> send it
    #   Teams op 1 arm 0x08c29704  does NOT: it calls the result   -> DO NOT send it
    #                              deserializer with a hard-coded
    #                              count of 1 (`ori $a1,$zero,1`)
    # Sending it anyway put a typed u32 where bdCreateTeamResult::deserialize
    # expected its typed u64, the tag check failed, and the clan came back
    # "Unable to create clan <name>" with the id sitting unread in the packet.
    # num_results=None means "no count field".
    if num_results is not None:
        r.u32(num_results)
    # `results` is a callback that appends the service-specific result rows. It
    # writes into THIS writer rather than returning bytes: the block starts at a
    # non-byte-aligned bit position (a typed u32 is 37 bits), so splicing a
    # separately-packed byte string in here would shift every field.
    if results is not None:
        results(r)
    plaintext = (RESPONSE_SIGNATURE.to_bytes(4, "little")
                 + bytes([LSG_MSG_TASK_REPLY])          # type 1
                 + r.getvalue())
    if len(plaintext) % 8:
        plaintext += b"\x00" * (8 - len(plaintext) % 8)
    ct = session_cbc_encrypt(plaintext, session_key, tiger_iv(seed))
    body = bytes([1]) + seed.to_bytes(4, "little") + ct
    return len(body).to_bytes(4, "little") + body


# ------------------------------------------------------ LSG service result rows
#
# PHASE 12 -- bdStats op 4 ("read leaderboard rows for these entity IDs").
#
# Answering an RPC with error=0 and numResults=0 is enough for Storage, Friends,
# Teams, Profile and Messaging, but NOT for Stats: its reply reader has no
# zero-results early-out. The chain is
#
#   bdStats reply reader        0x08c2529c   reads [u32 err][u8 opID][u32 numResults]
#     ops 3,4,5,6 -> 0x08c25394 calls container->vtable[2](count, &buf)
#   bdLeaderBoardResult<1>      0x08ce5d98   reads [u32 totalEntries] -> this+0x70,
#                                            then `count` rows (capacity is ONE;
#                                            more logs "Received %u results but can
#                                            only store %u")
#   row deserialize (game)      0x089a9480   base row, then the Worms stat blob
#   row deserialize (SDK base)  0x08c25770   the four fields below
#
# 0x08ce5d98 returns the success flag of its FIRST read, so a reply with no
# [u32 totalEntries] at all returns false -> the reply reader returns false ->
# "Couldn't sign in". That single missing u32 is what ended the Phase 11 chain.
#
# Row layout (0x08c25770, field offsets are into the 0x68-byte row object):
#   +0x08  typed u64  entityID   echo the ID the client asked about
#   +0x10  typed i64  score      the number bdStats op 1 UPLOADS (0x08c25714
#                                serialises this field and no other)
#   +0x18  typed u64  rank       server-computed; nothing uploads a rank
#   +0x20  typed str  name       NUL-terminated, <= 64 chars, no length prefix
# After the base row the game parses its own stat blob (0x089ad31c). That is a
# table-driven loop over stat descriptors gated by a bitmask at fp+0x10, every
# read is individually fault-tolerant, and its return value is DISCARDED -- so
# leaving it out costs stats content, not sign-in.
LEADERBOARD_NAME_MAX = 64


def write_leaderboard_row(w, entity_id: int, score: int, rank: int, name: str):
    """One bdLeaderBoardRow, appended to an in-progress type-checked bit writer.

    FIELD ORDER CONFIRMED ON SCREEN (2026-09-10). Serving score=2111, rank=2
    rendered as "2,111. player1   2", and serving score=4242, rank=7 rendered as
    "7. player1   4,242" -- so the i64 is the SCORE shown on the right and the u64
    is the RANK shown as the "N." prefix. The previous parameter names had these
    two the wrong way round.
    """
    w.u64(entity_id)
    w.i64(score)
    w.u64(rank)
    w.str_(name, LEADERBOARD_NAME_MAX)


def lsg_request_params(dec: dict):
    """A BdReader on a decoded client RPC, positioned just past the typed op id."""
    body = dec["plain"][4:] if dec["enc"] == 1 else dec["plain"]
    r = bd.BdReader(body[1:])          # skip the service-id byte
    r.bitmode = True
    r.read_type_checked_bit()
    r.type_checked = True
    r.u8()                             # op id
    return r


# --------------------------------------------------------------- identities
# The server ISSUES the account identity: the client's login request (0x0a) is
# 19 bytes -- type, iv_seed, proof -- and carries no name at all, so there is
# nothing to echo back. With one console that did not matter and every account
# was rigconfig.USERNAME/USER_ID. With two it does: handing both consoles the
# same user_id makes them ONE player to the matchmaker, so the host would see
# its own entity join.
#
# One console is one address. Console 1 is the host namespace (127.0.0.1) and
# console 2..N live at 10.42.0.N inside their own network namespace
# (tools/netns.sh), so the source address of the connection is exactly what
# tells the two players apart.
IDENTITIES: dict[str, tuple[str, int]] = {
    "127.0.0.1": (rigconfig.USERNAME, rigconfig.USER_ID),
    "10.42.0.2": (os.environ.get("WOW2_USERNAME2", "testuser"), 2),
}
# Consoles 3..8 (tools/newemu.py) are named after their bridge octet, and the
# name here must be the one typed into that console's GAME PROFILE -- the
# profile is what the player sees, this is what the matchmaker sees, and two
# consoles showing different names for the same seat is the kind of confusion
# that costs an hour. All are >= 6 characters, which is the game's own rule.
for _n in range(3, 9):
    IDENTITIES.setdefault(f"10.42.0.{_n}",
                          (os.environ.get(f"WOW2_USERNAME{_n}", f"player{_n}"), _n))
del _n

_AUTO_IDS: dict[str, tuple[str, int]] = {}


def identity_for(ip: str) -> tuple[str, int]:
    """(username, user_id) for a console, keyed by where it connects from.

    An id must be STABLE per console and unique across consoles -- two consoles
    sharing a user_id are one player to the matchmaker, so the host watches its
    own entity join. The bridge makes that exact: console N is 10.42.0.N and
    nothing else, so the last octet IS the id. The old fallback numbered
    consoles by ARRIVAL ORDER, which meant the same console got a different id
    depending on who signed in first -- harmless with two, a trap with eight."""
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
#
# PHASE 20 -- bdStats is ONE WRITE and TWO READS, and op 1 is the WRITE.
#
#   op 1  writeStats            [u8 0][u8 f][i32 boardID][u64 0][i64 score]<RankData>
#   op 4  readStatsByEntityIDs  [u8 0][i32 boardID][u32 n][u64 entityID x n]
#   op 5  readStatsByPivot      [u8 0][i32 boardID][u64 pivot][u64 startRank][i64 numRows]
#
# This corrects TWO earlier readings, both of which had the write in the wrong
# place. op 5 was first documented as the upload -- it is a read: it fires as you
# merely BROWSE the boards, and its last field is a row count (10 while browsing,
# 1 at lobby creation). op 1 was then implemented as "readStatsByRank" -- it is
# the upload. The disassembly settles it: the bdStats reply dispatcher
# (0x08c2529c) jumps through a table at 0x08d6ae00 indexed opID-1, and op 1's arm
# (0x08c2538c) reads NOTHING after the opID -- no numResults, no rows; only ops
# 3/4/5/6 read a result container. The single caller that sends op 1,
# net::tStatsEditor, logs "uploading stats (board %u64)" the moment it queues the
# task (0x089a8aa4); net::tStatsViewer sends ops 4 and 5 and logs "downloading
# stats (board %u64)" -- its string pool has no upload strings at all.
#
# WHERE A SCORE COMES FROM -- the frontier question, answered: THE CLIENT
# COMPUTES IT AND UPLOADS IT. On the wire in session-20260910-204010.log every
# op 1 lands ~1 s after the `Sessions op 2` that starts a match, from BOTH
# consoles, and the numbers move between matches:
#
#   21:16:44  board 1        score 2   <blob i32 0, i64 4,  i64 0>
#   21:41:19  board 1        score 3   <blob i32 0, i64 12, i64 0>
#   21:41:20  boards 2,3,4,5 score 10  (no blob)
#
# So a finished match DOES reach this server -- at the START OF THE NEXT ONE, not
# at the end of the one that produced it. That is why every capture taken at
# "the match ended", on the results screen and on the awards screen showed
# nothing: the report was still a minute in the future. (Phase 19's negative
# result was correct about where it looked and wrong about the conclusion.)
#
# bdStatsInfo::serialize (0x08c25714) writes exactly ONE field -- the i64 at
# row+0x10 -- and does NOT send the entity id, so the server must attribute the
# write to the signed-in account. We learn that 64-bit account id from the op 4
# the same console sends at sign-in, which asks about ITSELF on boards 1..5.
# (In a ranked lobby each console reads the OPPONENT on boards 5..8, so only the
# first entity a console ever asks about may be treated as its own.)
#
# RANK IS OURS. Nothing uploads a rank; the client only ever reads one. The store
# therefore keeps a SCORE per (board, entity) and the rank we serve is the row's
# position with the board ordered by score, best first.
#
# The file is re-read PER REQUEST (like nat-broker.mode) so rows can be edited
# with the server running -- no restart, no re-login:
#
#   {"2:975367efa4bbebed": [4242, 7, "player1"]}   # board:entity -> score, rank, name
#
# The middle number is written back for readability and IGNORED on read. A row
# may carry a 4th element, the decoded RankData blob of the last upload.
STATS_DB = CAP / "stats-db.json"
STATS_UPLOADS = CAP / "stats-uploads.jsonl"     # append-only forensic trail
NO_STATS_STORE = os.environ.get("WOW2_NO_STATS_STORE") == "1"
LEADERBOARD_CAPACITY = 50      # bdLeaderBoardResultTemplate<50> (0x08ce6080); the
                               # editor's own container holds 1, but it only ever
                               # asks for 1, so one cap covers both.

# 64-bit account ids are client-side and stable per savedata. These are known
# from every capture; anything else is learned at run time by account_seen().
#
# Keyed by IDENT KEY, which is the account name once a connection has said who it
# is (login handle / LSG opaque proof) and the source address only as a fallback.
# Both spellings are listed so a connection that never identified itself still
# resolves on the rig -- the address entries are the LEGACY path and everything
# new should arrive by name.
KNOWN_ACCOUNTS: dict[str, int] = {
    "player1": 0x975367efa4bbebed,            # console 1
    "testuser": 0xbb4dc191b75e31fc,         # console 2
    "127.0.0.1": 0x975367efa4bbebed,        # legacy: by source address
    "10.42.0.2": 0xbb4dc191b75e31fc,
}
_SEEN_ACCOUNTS: dict[str, int] = {}         # ident key -> the id that console reads first


def account_seen(ident_key: str, entity_id: int, name: str) -> None:
    """Remember which 64-bit account a console signed in as (first read wins)."""
    if not entity_id or ident_key in _SEEN_ACCOUNTS:
        return
    _SEEN_ACCOUNTS[ident_key] = entity_id
    # The derivation should always agree. If it ever does not, the assumption
    # that the id is Tiger192(name)[:8] is wrong for that console and everything
    # keyed on it (leaderboards, buddies, the pot) would be filed under the
    # wrong account. Say so rather than silently preferring one.
    if not ident_key.replace(".", "").isdigit():
        derived = account_id_for(ident_key)
        if derived != entity_id:
            log(f"  (!!!! {ident_key} reports account 0x{entity_id:016x} but "
                f"Tiger192(name)[:8] derives 0x{derived:016x} -- the derivation "
                f"is WRONG for this console; using the reported one)")
    if KNOWN_ACCOUNTS.get(ident_key) not in (None, entity_id):
        log(f"  (!! {ident_key} reads 0x{entity_id:016x} first, but KNOWN_ACCOUNTS "
            f"says 0x{KNOWN_ACCOUNTS[ident_key]:016x} -- using the live one)")
    log(f"  account: {ident_key} ({name}) = 0x{entity_id:016x}")
    # Persist it. This map used to live only in process memory, so a restart
    # forgot every account but the two hard-coded in KNOWN_ACCOUNTS -- and the
    # 64-bit id is what the leaderboards, the buddy list and the pot bank all key
    # on. Only store it under an ACCOUNT NAME; an address is not an identity.
    if ident_key and not ident_key.replace(".", "").isdigit():
        db = _jload(ACCOUNTS_DB, {})
        row = db.get(ident_key) or {}
        if row.get("account_id") != entity_id:
            row["account_id"] = entity_id
            row.setdefault("first_seen",
                           datetime.datetime.now().isoformat(timespec="seconds"))
            db[ident_key] = row
            _jsave(ACCOUNTS_DB, db)
    # A brand-new account has no board-5 row, so the client reads 0, writes back
    # max(10, round(0.9*0)) = 10 and can never stake anything. Nothing in the
    # game decides a starting rating -- it reads its own from us -- so we issue
    # one (potbank.RATING_START).
    started = potbank.ensure_start(entity_id, name)
    if started is not None:
        log(f"  rating: new account -- {name} starts board "
            f"{statsdb.RATING_BOARD} on {started}")


def account_id_for(username: str) -> int:
    """The client's 64-bit account id, DERIVED from the name.

    It is `Tiger192(username)[:8]` read as a little-endian u64 -- the same eight
    bytes the login request carries as its handle. Confirmed on `player1`,
    `testuser` and on `player1b`, an account created from scratch on a real PSP.

    This was an opaque value for a long time. The id lives in the console's
    savedata, the server only ever saw it echoed back in a `Stats op 4`, and
    `account_seen()` was built to learn it from the first such read. That works
    on a rig where the two accounts are hard-coded, and it is visibly wrong on a
    fresh deployment: a new console's FIRST sign-in runs storage, friends, teams,
    messaging and profile RPCs before any Stats op ever arrives, so every one of
    them was answered for account `0x0000000000000000`.
    """
    return int.from_bytes(tiger192(username.encode())[:8], "little")


def account_for(ident_key: str) -> int:
    """The 64-bit account id behind an ident key (account name, or an address).

    Live reading first, then the store, then the derivation, then the legacy
    address-keyed table. The derivation makes the first three mostly redundant
    and is kept behind them so a console that somehow disagrees with it still
    wins -- `account_seen()` logs loudly if that ever happens.
    """
    if ident_key in _SEEN_ACCOUNTS:
        return _SEEN_ACCOUNTS[ident_key]
    row = _jload(ACCOUNTS_DB, {}).get(ident_key)
    if isinstance(row, dict) and row.get("account_id"):
        return row["account_id"]
    if ident_key and not ident_key.replace(".", "").isdigit():
        return account_id_for(ident_key)          # it is an account name
    return KNOWN_ACCOUNTS.get(ident_key, 0)


def stats_key(board_id: int, entity_id: int) -> str:
    return statsdb.key(board_id, entity_id)


def stats_all() -> dict:
    return statsdb.load()


def stats_board(board_id: int, default_name: str = "") -> list:
    """Every stored row of one board as (entityID, score, rank, name), best first.

    The rank is COMPUTED (statsdb.board) -- the row's position by score,
    descending, ties sharing a rank. Nothing the client sends carries a rank.
    """
    return statsdb.board(board_id, default_name)


def stats_get(board_id: int, entity_id: int, default_name: str = "") -> tuple[int, int, str]:
    """(score, rank, name) for one board/entity. Unknown -> an unranked zero row."""
    return statsdb.get(board_id, entity_id, default_name)


def stats_put(board_id: int, entity_id: int, score: int,
              name: str = "", extra: list | None = None) -> None:
    """Record one uploaded score. Rank is derived on read; the number written back
    into the file is only there to make it readable (statsdb.put)."""
    if NO_STATS_STORE:
        log("  (stats store disabled by WOW2_NO_STATS_STORE)")
        return
    before = stats_all().get(statsdb.key(board_id, entity_id))
    ok, rank = statsdb.put(board_id, entity_id, score, name, extra)
    if not ok:
        log(f"  (!! could not write {statsdb.STATS_DB})")
        return
    log(f"  stats STORED {statsdb.key(board_id, entity_id)} = score {score} "
        f"(rank {rank or '?'}, was {before})")


def read_typed_tail(r) -> list:
    """Every remaining typed field of a request, walked blind. Used for the game's
    own RankData blob after the score: it is mask-gated, so its length varies with
    what the match produced, and no fixed parse would survive."""
    out = []
    while True:
        try:
            t, v = bddump.read_field(r)
        except Exception:
            return out
        out.append([bddump.TYPE_NAMES.get(t, str(t)), v])


def stats_write_upload(dec: dict, who: tuple[str, int] | None = None,
                       peer_ip: str = ""):
    """bdStats op 1 -- writeStats. Returns (0, None) on purpose.

    The client reads NOTHING after the opID for this op (dispatch arm 0x08c2538c),
    so rows served here are dead bytes. Everything this handler does is store.
    """
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()                              # leaderboard type/flags, always 0
        r.u8()                              # tStatsEditor ctor flag, always 0
        board_id = r.i32()
        entity = r.u64()                    # always 0 = "the signed-in account"
        score = r.i64()
        extra = read_typed_tail(r)
    except Exception as e:
        log(f"  (stats op1 decode failed: {e})")
        return 0, None

    # Boards 29..32 are the CLAN boards: creating a clan fires four uploads, one
    # per second, exactly like a match start fires five. The client sends
    # entityID = 0 there too, but "the signed-in account" is the wrong owner --
    # the row belongs to the player's TEAM, and attributing it to the player puts
    # a clan score on a personal board. (The four uploads that follow a create
    # are sent BEFORE the create reply lands, so on the very first one the client
    # genuinely has no team yet and there is nothing to attribute it to.)
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
    # A write to the rating board during a ranked session is one of two things,
    # told apart by DIRECTION (Phase 24):
    #   score <  served   the client PAYING ITS STAKE at the start of the match.
    #                     `served - written` is the wager the lobby displayed.
    #   score >  served   the client PAYING THE POT OUT at the end of a finished
    #                     match. The winner re-uploads boards 2..5 each raised by
    #                     the whole pot, and the loser re-uploads nothing. So this
    #                     write identifies the WINNER and settles the pot; paying
    #                     it again here (or refunding on session delete) would
    #                     create rating out of nothing, which is exactly what
    #                     happened on 2026-09-11 before this branch existed.
    # WOW2_NO_CLIENT_PAYOUT=1 goes back to treating every write as a stake.
    if board_id == statsdb.RATING_BOARD:
        sid = ranked_session_id()
        if sid:
            before, _rank, _n = stats_get(board_id, entity, name)
            if score > before and not os.environ.get("WOW2_NO_CLIENT_PAYOUT"):
                log("  POT: " + potbank.note_payout(sid, entity, name, before,
                                                    score, ts()))
            else:
                stake, pot = potbank.note_stake(sid, entity, name, before, score,
                                                ts())
                log(f"  POT: {name} staked {stake} ({before} -> {score}); "
                    f"session 0x{sid:x} pot is now {pot}")
    stats_put(board_id, entity, score, name, extra)
    return 0, None


def emit_rows(rows: list, total: int):
    """Writer callback for a bdLeaderBoardResult: [u32 totalEntries] then the rows.

    0x08ce6080 returns the success flag of that FIRST read, so the u32 is
    mandatory even when no rows follow -- a reply without it fails the whole
    bdStats task, which is what ended the Phase 11 sign-in chain.
    """
    def emit(w):
        w.u32(total)
        for eid, score, rank, name in rows:
            write_leaderboard_row(w, eid, score, rank, name)
    return emit


def stats_read_results(dec: dict, who: tuple[str, int] | None = None,
                       peer_ip: str = ""):
    """bdStats op 4 -- readStatsByEntityIDs. One row per requested entity.

    Request (0x08c24fe4): [typed u8 0][typed i32 boardID][typed u32 count]
    [typed u64 entityID x count]. tStatsEditor always asks for 1; tStatsViewer
    can ask for up to 50 (its array runs obj+0x40..obj+0x1d0).
    """
    entities = []
    board_id = 0
    try:
        r = lsg_request_params(dec)
        r.u8()                              # leaderboard type/flags, always 0
        board_id = r.i32()
        for _ in range(r.u32()):
            entities.append(r.u64())
    except Exception as e:
        log(f"  (stats op4 decode failed: {e})")
    default = (who or (rigconfig.USERNAME, rigconfig.USER_ID))[0]
    if entities:
        account_seen(peer_ip, entities[0], default)
    entities = entities[:LEADERBOARD_CAPACITY]
    board = stats_board(board_id, default)
    rows = []
    for eid in entities:
        score, rank, name = stats_get(board_id, eid, default)
        rows.append((eid, score, rank, name))

    log(f"  stats op4 (read-by-entity): boardID={board_id} entities="
        + ",".join(f"0x{e:016x}" for e in entities)
        + " -> serving " + (", ".join(f"{r[2]}. {r[3]} {r[1]}" for r in rows) or "(nothing)")
        + f" of {len(board)}")
    return len(rows), emit_rows(rows, len(board))


def stats_pivot_results(dec: dict, who: tuple[str, int] | None = None,
                        peer_ip: str = ""):
    """bdStats op 5 -- readStatsByPivot. A page of a board, anchored two ways.

    Request (0x08c25138): [typed u8 0][typed i32 boardID][typed u64 pivotEntity]
    [typed u64 startRank][typed i64 numRows]. The two anchors are mutually
    exclusive by construction (0x089aac44 picks the call site on startRank != 0):
    factory 0x089aa2a4 is "by entity" (startRank 0, centre on the player) and
    0x089aa1c8 is "by rank" (pivot 0). The screen's View setting is exactly this:
    "Own rank" sends the account and startRank 0, the other mode sends pivot 0 and
    startRank 1.
    """
    board_id = pivot = start_rank = 0
    count = 1
    try:
        r = lsg_request_params(dec)
        r.u8()                              # leaderboard type/flags, always 0
        board_id = r.i32()
        pivot = r.u64()
        start_rank = r.u64()
        count = r.i64()
    except Exception as e:
        log(f"  (stats op5 decode failed: {e})")

    default = (who or (rigconfig.USERNAME, 0))[0]
    board = stats_board(board_id, default)
    want = max(1, min(int(count), LEADERBOARD_CAPACITY))
    if start_rank:                          # "start at rank N"
        rows = [r for r in board if r[2] >= start_rank][:want]
    elif pivot:                             # centre the page on that player
        at = next((i for i, r in enumerate(board) if r[0] == pivot), 0)
        lo = max(0, min(at - want // 2, max(0, len(board) - want)))
        rows = board[lo:lo + want]
    else:
        rows = board[:want]
    if not rows and pivot:                  # nothing stored: still answer with a row
        score, rank, name = stats_get(board_id, pivot, default)
        rows = [(pivot, score, rank, name)]

    log(f"  stats op5 (read-by-pivot): boardID={board_id} "
        f"pivot=0x{pivot:016x} startRank={start_rank} count={count} -> serving "
        + (" | ".join(f"{r[2]}. {r[3]} {r[1]}" for r in rows) or "(nothing)")
        + f" of {len(board)}")
    return len(rows), emit_rows(rows, len(board))


# --------------------------------------------------------------- sessions (svc 5)
# Hosting a game is service 5, the bdMatchMaking one. Confirmed live:
#   op 1  create session   <- "Start lobby" -> "Create a game lobby?" -> cross
#   op 3  delete session   <- "Leave lobby"
# The create request (200B) is, in order:
#   [u8 0][blob 25B bdCommonAddr][blob 8B][blob 16B][i32 x9][str hostName]
#   [i32 0][i32 maxPlayers][i32][i32][i32][i64 x3][i64 0x3ffffffff][str hostName]
#   [i32 100]
# The 25-byte addr is BD_COMMON_ADDR_SERIALIZED_SIZE (bdMatchMakingInfo.cpp
# complains by that name if it ever gets another length) and carries BOTH of the
# host's endpoints: [u32 ip][u16 port] for the public one at +0 and the private
# one at +18. Both were 192.168.178.72:3075 / 127.0.0.1:3075 -- port 3075 is the
# UDP socket PPSSPP has bound the whole time (`ss -uanp`), i.e. the peer-to-peer
# channel joiners are meant to use. The two opaque blobs hold game-side structs
# (they contain live 0x08d4xxxx pointers), so they are stored verbatim.
#
# The reply is a bdSessionCreateResult (deserializer 0x08c1bd9c):
#   [blob <= 8B session id -> result+0x08][blob <= 16B -> result+0x10]
# and numResults==0 is a legal, silent "no session" -- the deserializer returns
# its pre-set success flag without reading anything. That is why the lobby opened
# before this existed; the cost only showed up on the way out, where the delete
# (op 3) sent back an all-zero session id.
SESSION_ID_BYTES = 8
BD_COMMON_ADDR_SIZE = 25       # BD_COMMON_ADDR_SERIALIZED_SIZE
SESSION_SECRET_BYTES = 16      # bdSecurityKey; the id above is bdSecurityID

# Bisect switch: advertise the host's original (uninitialised) key bytes in the
# search reply, i.e. the behaviour that made the peer handshake stall on the
# joiner's first MAC'd message.
NO_KEY_REWRITE = os.environ.get("WOW2_NO_KEY_REWRITE") == "1"

SESSIONS: dict[int, dict] = {}
_next_session_id = [0x5701]        # arbitrary; just has to fit in 8 bytes


def sessions_create_result(dec: dict, peer_ip: str = ""):
    """Result block for Sessions op 1. Returns (num_results, writer-callback).

    The request's fields after the op id are [u8 flags] followed by the host's
    bdMatchMakingInfo. We walk them generically (bd.read_fields) and keep the
    whole list: the search reply hands that same list back verbatim, so the
    server never has to model fields it has not reversed -- and the two blobs
    that carry game-side structs survive untouched.
    """
    rec: dict = {"info": [], "name": "", "max_players": 0, "addr": b"",
                 "host_ip": peer_ip}
    try:
        r = lsg_request_params(dec)
        fields = bd.read_fields(r)
        rec["info"] = fields[1:]            # drop [u8 flags]; the info starts at the addr
        vals = [v for _t, v in fields]
        rec["addr"] = next((v for v in vals if isinstance(v, bytes)
                             and len(v) == BD_COMMON_ADDR_SIZE), b"")
        names = [v for v in vals if isinstance(v, str)]
        rec["name"] = names[0] if names else ""
        ints = [v for t, v in fields if t == bd.BD_SINT32]
        rec["max_players"] = ints[10] if len(ints) > 10 else 0
        # ints[6] is field [11] of the request and is the Host Setup "Play mode"
        # row: 1 = Play for points, 0 = Play for fun. Diffing a ranked create
        # against an unranked one, it is the ONLY settings field that moves --
        # and it decides whether the ranked boards get written at match start
        # (bdStats op 1 touches boards 2..5 only for a points match; board 1,
        # the games-played counter, is written either way).
        rec["points"] = ints[6] if len(ints) > 6 else 0
    except Exception as e:
        log(f"  (session create decode failed: {e})")
    sid = _next_session_id[0]
    _next_session_id[0] += 1
    rec["id"] = sid
    SESSIONS[sid] = rec
    secret = (b"WOW2SESS" + sid.to_bytes(SESSION_ID_BYTES, "little"))[:SESSION_SECRET_BYTES]
    rec["secret"] = secret

    def emit(w):
        w.blob(sid.to_bytes(SESSION_ID_BYTES, "little"))
        w.blob(secret)

    addr = rec["addr"]
    # Both endpoints, always, because which of the two the console fills with
    # OUR discovery answer and which with its own local interface is the single
    # fact the relay turns on -- and the log said only the first one for months.
    where = (f"{'.'.join(str(b) for b in addr[0:4])}:"
             f"{int.from_bytes(addr[4:6], 'little')}" if len(addr) >= 6 else "?")
    if len(addr) >= 24:
        where += (f" / {'.'.join(str(b) for b in addr[18:22])}:"
                  f"{int.from_bytes(addr[22:24], 'little')}")
    log(f"  session create: id=0x{sid:x} host={rec['name']!r} at {where} "
        f"maxPlayers={rec['max_players']} "
        f"mode={'POINTS' if rec.get('points') else 'fun'} "
        f"info={len(rec['info'])} fields ({len(SESSIONS)} live)")
    if rec.get("points"):
        potbank.open_pot(sid, rec["name"], ts())
        log(f"  POT opened for ranked session 0x{sid:x} -- each console will pay "
            f"10% of board {statsdb.RATING_BOARD} when the match starts")
    return 1, emit


def ranked_session_id() -> int:
    """The live ranked session a stake belongs to -- the newest `mode=POINTS` one.

    A stake arrives as a board-5 write ~1 s after `Sessions op 2`, and the write
    carries nothing that names a session, so it has to be attributed. On this rig
    that is unambiguous: matchmaking has one ranked lobby at a time. With more,
    the newest wins, which is the one that just started.
    """
    ranked = [sid for sid, rec in SESSIONS.items() if rec.get("points")]
    return max(ranked) if ranked else 0


def host_addr_for(host_ip: str, joiner_ip: str) -> str:
    """The host console's address *as the joiner can actually reach it*.

    The address in the create request is the one the host discovered for itself,
    and on this rig that is never the one a joiner can use. Console 1 announces
    192.168.178.72 (its LAN address) and 127.0.0.1 -- from inside a namespace the
    first routes to the host but comes BACK from 10.42.0.1, because the reply's
    source address is chosen by the route to 10.42.0.x, and the second is the
    joiner's own empty loopback. A peer that filters on the address it dialled
    sees the reply as coming from a stranger.

    So translate: if the host reached us over loopback but the joiner did not,
    the joiner must use the bridge address, which is the same host and picks
    itself as the reply source. Every other pairing (both on the bridge, both on
    loopback, host namespaced and joiner on the host) is already symmetric, so
    the host's own peer address stands.
    """
    if not host_ip or not joiner_ip:
        return host_ip
    if host_ip.startswith("127.") and not joiner_ip.startswith("127."):
        return rigconfig.NETNS_BRIDGE_IP
    return host_ip


def addr_with_host_ip(addr: bytes, ip: str) -> bytes:
    """bdCommonAddr with both endpoints repointed at `ip`.

    25 bytes, confirmed against a live create request:
        [0:4]   public IP, network order      c0 a8 b2 48 = 192.168.178.72
        [4:6]   public port, LITTLE endian    03 0c       = 3075
        [6:18]  opaque
        [18:22] private IP, network order     7f 00 00 01 = 127.0.0.1
        [22:24] private port, little endian   03 0c       = 3075
        [24]    address count/type            02
    Both endpoints get the same address: whichever one the peer picks is then
    reachable, so we never have to model how it chooses.
    """
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
    """bdCommonAddr with BOTH endpoints set to one ip:port -- the relay form.

    `addr_with_host_ip()` moves the addresses and leaves the ports, which is
    right when the console really is listening on 3075 somewhere reachable. A
    relay mailbox is a different port, so the port has to move too.

    Both endpoints get the same value for the reason Phase 17 gives: the joiner
    fires at BOTH announced endpoints, and leaving the private one alone would
    leave it firing at an address that is either unreachable or -- worse, on the
    rig -- its own loopback, which is how a console once completed a session
    handshake with itself.
    """
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
    """Where to tell a joiner the host is, when the relay is carrying the match.

    The answer is normally already in the host's own create request: the console
    publishes whatever the discovery reply said its address was, and with the
    relay on that is its mailbox. So this mostly CONFIRMS rather than decides --
    and when the confirmation fails it says so, because a host advertising an
    address that is not one of ours means the relay cannot carry this session and
    the join is about to fail for a reason that would otherwise be invisible.

    Falls back to matching the host's source address, which is exact on the rig
    (one console per address) and ambiguous only when two consoles share a public
    address, i.e. sit behind the same NAT -- where they can reach each other
    directly anyway.
    """
    if not natrelay.RELAY.enabled:
        return None
    advertised = None
    for t, v in rec.get("info", []):
        if t == bd.BD_BLOB and isinstance(v, bytes) and len(v) == BD_COMMON_ADDR_SIZE:
            advertised = (socket.inet_ntoa(v[0:4]),
                          int.from_bytes(v[4:6], "little"))
            break
    c = natrelay.RELAY.owner_of_advertised(advertised)
    if c is None:
        host_ip = rec.get("host_ip", "")
        hits = [x for x in natrelay.RELAY.consoles.values()
                if x.key[0] == host_ip and x.mailbox]
        if len(hits) == 1:
            c = hits[0]
            log(f"  (relay: host advertised {advertised}, which is not a "
                f"mailbox -- matched it to {c} by address instead)")
    if c is None or c.mailbox is None:
        log(f"  !! relay is ON but session 0x{rec.get('id', 0):x}'s host has no "
            f"mailbox (it advertised {advertised}); the joiner will be given an "
            f"address the relay does not serve")
        return None
    return natrelay.server_addr_for(joiner_ip or rec.get("host_ip", "")), c.mailbox.port


def info_with_session_id(rec: dict, joiner_ip: str = ""):
    """The host's bdMatchMakingInfo with OUR session id and a reachable address.

    Three fields cannot be replayed verbatim, and they are told apart by length:
    8 = bdSecurityID, 16 = bdSecurityKey, 25 = bdCommonAddr.

    The 8-byte blob is the session/security ID. The host cannot know it at create
    time and does not clear it either -- a live create carried
    `10 04 e9 08 34 14 d4 08`, i.e. uninitialised stack holding 0x08d4xxxx game
    pointers -- so whatever is there is meaningless. Advertising it unchanged
    made choosing the row die on "This session is no longer available." before
    the joiner sent a single packet, and that failure never reaches the server,
    because resolving the id happens client-side first. The id the create reply
    assigned goes here instead (the client hands the same id back on delete,
    which is how it was confirmed).

    **The 16-byte blob is the security KEY and has exactly the same problem.**
    A live create carried `02 00 00 00 0c 04 bd 08 28 14 d4 08 04 00 00 00` --
    more uninitialised stack. The create reply assigns the real one
    (`blob(id) + blob(secret)`), so the HOST has it; replaying the garbage here
    left the JOINER keyed differently, and that is a silent failure much later:
    the two complete a 8/30/169/106-byte handshake and then the joiner's 32-byte
    message -- which ends in a 16-byte MAC -- is received by the host and
    dropped without a word, four retries, until the join times out.

    The 25-byte blob is the bdCommonAddr -- see host_addr_for() for why the
    host's own idea of its address is unusable from a namespace.
    Set WOW2_NO_ADDR_REWRITE=1 to advertise the host's original bytes.
    """
    want_ip = ""
    if os.environ.get("WOW2_NO_ADDR_REWRITE") != "1":
        want_ip = host_addr_for(rec.get("host_ip", ""), joiner_ip)
    relay_to = relay_endpoint_for_host(rec, joiner_ip)
    if relay_to:
        want_ip = ""      # the mailbox rewrite below replaces it entirely

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
    """Sessions op 5 -- the game browser's search. One result per live session.

    Each result is the host's own bdMatchMakingInfo replayed field for field.
    The client's deserializer (0x08c1b3f0) opens with a blob of at most 25 bytes,
    which is exactly the bdCommonAddr the create request led with, so a
    round-tripped info is the right shape by construction.

    The request's filters are all 0x7fffffff ("Any") straight off the Define Game
    Search screen; nothing is filtered yet -- every live session is returned and
    the client applies its own view.
    """
    try:
        r = lsg_request_params(dec)
        filters = [v for t, v in bd.read_fields(r) if t == bd.BD_SINT32]
    except Exception as e:
        log(f"  (session search decode failed: {e})")
        filters = []
    rows = list(SESSIONS.values())

    def emit(w):
        for rec in rows:
            bd.write_fields(w, info_with_session_id(rec, joiner_ip))

    log(f"  session search: {len(rows)} session(s) -> "
        + (", ".join(f"0x{r['id']:x} {r['name']!r}" for r in rows) or "none")
        + (f"  filters={filters[:4]}..." if filters else ""))
    return len(rows), emit


def sessions_get_result(dec: dict, peer_ip: str = ""):
    """Sessions op 4 -- fetch ONE session by id. Cold until Phase 25.

    The UI that fires it was the missing piece: it is **opening a match invite**
    in `View messages`. The client takes the session id out of the invite
    message (push type 5 carries it) and asks the server for the session behind
    it; answering the old bare `err=0, 0 results` puts
    "Couldn't fetch match details." on screen, which is precisely what a
    0-result reply means here.

        request  [u8 0][blob 8B session id]     (wire-identical to op 3)
        reply    one bdMatchMakingInfo, the same row the op-5 search returns

    Phase 23 had already read the request shape off the builder offline and
    filed it as "wire-identical to op 3, unknown UI"; the shape was right and
    only the UI was missing.
    """
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


def sessions_host_gone(peer_ip: str) -> None:
    """A console's LSG connection dropped. Drop any session it was hosting.

    Phase 23. HOST MIGRATION IS REAL IN THIS GAME BUT IT IS ENTIRELY
    PEER-TO-PEER: the surviving consoles elect a new host between themselves and
    never tell us (the whole bdPeer/bdSession closure contains no call to
    bdRemoteTaskManager::startTask, and neither does WiFiGame's resync path).
    So the server cannot follow a migration -- but it CAN stop lying about one.

    Without this, a host that crashes, pulls the network, or is killed leaves its
    session advertised forever, pointing at an address and a security key that
    now belong to nobody. A joiner picking that row gets no answer from the host
    and lands on "This session is no longer available." after a timeout. An empty
    game browser is the honest answer, and it is also the recoverable one: if the
    match survived on 3+ consoles, the new host can advertise it again.

    A clean "Leave lobby" already sends `Sessions op 3`; this only catches the
    ungraceful exits. WOW2_KEEP_SESSIONS=1 (the one-console game-browser trick)
    and WOW2_NO_HOST_EXPIRY=1 both switch it off.
    """
    if not peer_ip or os.environ.get("WOW2_NO_HOST_EXPIRY") == "1":
        return
    if os.environ.get("WOW2_KEEP_SESSIONS") == "1":
        return
    doomed = [sid for sid, rec in SESSIONS.items() if rec.get("host_ip") == peer_ip]
    for sid in doomed:
        rec = SESSIONS.pop(sid)
        log(f"  session EXPIRED: id=0x{sid:x} {rec.get('name')!r} -- its host's LSG "
            f"connection went away without a Sessions op 3 "
            f"({len(SESSIONS)} live)")
        settled = potbank.settle_unresolved(sid, ts())
        if settled:
            log(f"  POT: {settled}")


def sessions_update(dec: dict, peer_ip: str = ""):
    """Sessions op 2: the host re-publishes its bdMatchMakingInfo. No results.

    Op 2 carries the SAME payload as the op 1 create -- the 25-byte
    bdCommonAddr, the session id we assigned, our 16-byte secret, the settings
    ints, the host name -- with the leading `[u8]` set to 2 instead of 0, and
    the session id filled in (op 1 has uninitialised stack garbage there,
    because the host cannot know one yet).

    Until now this fell through to the generic `err=0, 0 results` reply, which
    the client accepts -- op 2 fires at every match start and has never needed
    more. The reply is deliberately left exactly as it was; the only thing that
    changes here is that the SERVER now believes it. That matters for one
    reason: the address and the host name in this message are the ones that go
    out in the next search reply, so a session whose host details have moved is
    only advertised correctly if we take the update.

    A move is also the server's only possible view of HOST MIGRATION. The
    migration itself is peer-to-peer (bdSession promotes a peer with no help
    from us), so if a promoted host ever re-advertises, it can only be through
    this op -- and the log line below is what would prove it. Nothing has been
    observed doing so yet; see netrecon Phase 23.

    WOW2_NO_SESSION_UPDATE=1 goes back to ignoring it.
    """
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

    addr = next((b for b in blobs if len(b) == BD_COMMON_ADDR_SIZE), b"")
    names = [v for v in vals if isinstance(v, str)]
    ints = [v for t, v in fields if t == bd.BD_SINT32]
    was_addr, was_ip, was_name = rec.get("addr"), rec.get("host_ip"), rec.get("name")

    rec["info"] = fields[1:]                 # what the search reply hands back
    if addr:
        rec["addr"] = addr
    if names:
        rec["name"] = names[0]
    if len(ints) > 10:
        rec["max_players"] = ints[10]
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
        f"from {peer_ip or '?'} maxPlayers={rec['max_players']} "
        f"mode={'POINTS' if rec.get('points') else 'fun'}")
    if moved:
        log(f"  *** SESSION HOST CHANGED: {was_name!r}@{was_ip} -> "
            f"{rec['name']!r}@{rec['host_ip']} -- this is what a HOST MIGRATION "
            f"would look like from here. Write it down (netrecon Phase 23).")
    return 0, None


def sessions_delete(dec: dict):
    """Sessions op 3: drop the session the client names. No results expected."""
    try:
        r = lsg_request_params(dec)
        r.u8()                              # flags
        sid = int.from_bytes(r.blob(), "little")
    except Exception as e:
        log(f"  (session delete decode failed: {e})")
        return 0, None
    # WOW2_KEEP_SESSIONS keeps the record after the host leaves. With one console
    # on the rig that is the only way to exercise the game browser: host a lobby,
    # leave it, then Find Game and the session is still there to be listed.
    if os.environ.get("WOW2_KEEP_SESSIONS") == "1" and sid in SESSIONS:
        log(f"  session delete: id=0x{sid:x} -- WOW2_KEEP_SESSIONS, left listed")
        return 0, None
    gone = SESSIONS.pop(sid, None)
    log(f"  session delete: id=0x{sid:x} "
        + (f"({gone['name']!r} removed, {len(SESSIONS)} live)" if gone
           else "-- not one of ours; the client had no session id"))
    settled = potbank.settle_unresolved(sid, ts())
    if settled:
        log(f"  POT: {settled}")
    return 0, None


# ----------------------------------------------------- server -> client PUSH
#
# PHASE 22 -- LsgServicePushMessage (message type 2), the channel that delivers
# "buddy invite received" and every other unsolicited event.
#
# The dispatcher arm is 0x08c17f10 (it logs BD_LOBBY_SERVICE_PUSH_MESSAGE) and it
# parses NOTHING itself: it fetches the lobby service's message store and hands
# the whole reader to 0x08c1cec0. That function reads ONE typed u32 -- the
# message TYPE ID -- looks it up in a factory registered with 27 classes, news
# the class, and lets the class deserialize the rest of the same bit stream. So a
# push is:
#
#   [u32 0xDEADBEEF][u8 2]  then bit mode:  [tc bit][typed u32 typeID][class fields]
#
# There is no length, no blob wrapper and no service byte. The type id IS the
# game-level event: `msg->[8]` is set from it (0x08c29930 `sw $a1,8($a0)`) and
# net::tBuddy's 35-entry jump table (0x08d36be8) indexes `[8] - 1`:
#
#   1 buddy invite received      5 received match invite        9  now on-line
#   2 buddy invite accepted      6 ...match invite accept      10  now off-line
#   3 buddy invite rejected      7 ...match invite reject      34  proposal cancelled
#   4 buddy revoked
#
# Types 2,3,4,6,7,9,10,11,12 share one class (deserialize 0x08c23acc) whose
# fields are the first six below; type 1 adds a u16 length and a blob.
#
#   +0x10 u64    message id
#   +0x18 u64    DEDUP KEY -- the store (0x08c1d290) drops a message whose +0x18
#                matches one already held, unless it is 0. The UI passes this
#                back as the handle when the invite is answered, so make it
#                unique and non-zero.
#   +0x20 u32    timestamp (inferred)
#   +0x24 bool   read/ack flag (inferred)
#   +0x28 u64    SENDER's account id -- 0x0898f4d0 looks the buddy up by it
#   +0x30 str    SENDER's name, NUL-terminated, 64-byte buffer
#   +0x70 u16    payload length   (type 1 only; 0 short-circuits the blob)
#
# Every field is readTypeChecked(tag) + readBits chained on the previous
# success, so the ORDER IS MANDATORY and a wrong tag silently truncates the rest
# -- the store still appends the object, so a mis-encoded push shows up as an
# invite from account 0 with an empty name rather than as an error.
PUSH_BUDDY_INVITE = 1
PUSH_BUDDY_ACCEPTED = 2
PUSH_BUDDY_REJECTED = 3
PUSH_BUDDY_REVOKED = 4
PUSH_MATCH_INVITE = 5
# The four ids that share the 0x100-byte class whose team id sits at +0xb8. The
# clan message handlers read that offset, so the clan traffic is in here.
# THE MESSAGE TYPE IDS ARE READ OFF THE CLIENT'S OWN DISPATCHER (Phase 38), not
# guessed. `UserProfileMessageListScreen` turns a bd message into a UI row in
# two hops, and both are jump tables:
#
#   0x0898c368  a2 = msg->type ; switch (a2 - 1) over 39 entries  -> a family
#               handler:  1-10,34,35 buddy/match   13-28,37,39 CLAN
#   0x0898f578  the buddy/match family's own switch (table 0x08d386a0)
#   0x08990564  the CLAN family's own switch        (table 0x08d38728, type-13)
#
# and each arm constructs `UserProfileMessage(kind)` at 0x089808cc, whose kind
# is what the detail screen switches on to decide which options to draw.
#
# The table VALIDATES ITSELF: types 1-4 come out Binvite/Baccept/Breject/Brevoke
# and 5-7 come out Minvite/Maccept/Mreject, which are exactly the four buddy ids
# and the match-invite id this server has been using successfully for phases.
#
#   13 Cinvite   14 Caccept   15 Creject   16 Cleft     17 Cadmin
#   18 Ckicked   26 Cdisband  28 Cowner    39 Cordinary
#
# So the four ids Phases 25-33 spent months on -- 17, 18, 28, 39 -- are
# MEMBERSHIP NOTIFICATIONS ("you are now an admin of X"), which is precisely
# what Phase 33e deduced from their behaviour: resolve the clan, fetch its
# members, delete the message. The reading was right and the id was never in
# the set being guessed.
PUSH_CLAN_INVITE = 13
# The whole clan family, because the first switch routes all of these to the
# handler that reads the two name fields at +0x30 and +0x78 -- i.e. they all use
# base B's layout, not base A's.
CLAN_PUSH_TYPES = tuple(range(13, 29)) + (37, 39)
# ...of which these carry the 0x100-byte class's extra (u64, str64) tail. The
# rest stop after base B at 0xb8. Derived, not guessed: of the 27 clan arms
# exactly these four touch `+0xb8`, and they are precisely the four ids Phases
# 25-33 were trying -- which is why the ten-field layout kept the connection
# alive for them and dropped it for a ten-field type 13.
CLAN_TAIL_TYPES = (17, 18, 28, 39)
# ...and these carry a u16 payload length instead. Both lists are read off the
# CLASS REGISTRY, not guessed: `0x08c1fffc` registers 44 message types, each
# with a 4-byte factory whose vtable+0x14 allocates the real class, and the
# malloc size names the layout --
#
#   0x70  base A                              2,3,4,6,7,9,10,11,12,34,35,36
#   0x78  base A + u16 payload                1 (buddy invite), 8, 40
#   0x80  base A + blob8 + u16 payload        5 (match invite)
#   0xb8  base B  = A + [u64][str64]          14,15,16,20,21,24..27,37,38,41..44
#   0xc0  base B + u16 payload                13 (CLAN INVITE), 22, 23
#   0x100 base B + [u64][str64]               17,18,28,39
#
# Getting this wrong is not subtle and not visible: a row that over- or
# under-reads makes the client drop the LSG connection ~450 ms after the reply,
# with nothing on screen but "Connection Lost". A ten-field type 13 did it, and
# so did an eight-field one.
CLAN_BLOB_TYPES = (13, 22, 23)
# `write_push_body()`'s clan arm is TEN fields, because base B (0x08c23190) and
# base A (0x08c23acc) both open by calling the same super-base 0x08c299cc, which
# Phase 25 never noticed -- all three of Phase 25's attempts were short of that,
# which is consistent with all three dropping the LSG connection ~450 ms after
# the inbox reply.
#
# 0 = DO NOT PUSH. Override per deployment with `"invite_push_type"` in
# capture/teams-db.json. If a console cannot sign in after a change here, clear
# `messages` in capture/friends-db.json -- the message is re-sent from the
# mailbox at EVERY sign-in, so a bad one bricks that account until it is deleted.
CLAN_INVITE_PUSH_DEFAULT = PUSH_CLAN_INVITE
PUSH_MATCH_ACCEPTED = 6
PUSH_MATCH_REJECTED = 7
PUSH_NOW_ONLINE = 9
PUSH_NOW_OFFLINE = 10
PUSH_PROPOSAL_CANCELLED = 34

# peer ip -> the live LSG connection, so a push can be routed to an account.
LSG_CONNS: dict[str, "AuthConnection"] = {}
_push_ids = [1]


def write_push_body(w, type_id: int, msg_id: int, sender: int, sender_name: str,
                    session_id: bytes = b"", clan_name: str = "",
                    target: int = 0, target_name: str = ""):
    """The class-selected body of one lobby message.

    THE SAME BYTES serve two transports: an LsgServicePushMessage (type 2) and a
    row of a bdMessaging op-1 reply. Both land in 0x08c1cec0, which reads the
    leading u32, asks the message factory for that class and lets it deserialize
    the rest -- so the mailbox and the live push are one format, and that is why
    a pushed buddy invite shows up under `View messages`.

    PHASE 26 -- THERE ARE NOT TWO UNRELATED BASES; THERE IS ONE, AND BOTH
    "bases" DERIVE FROM IT. Phase 25 read `0x08c23190` starting at its first
    field read and concluded a clan message carries "no id, no dedup, no
    timestamp, no read flag". It does. Its FIRST instruction group is a call:

        0x08c231d8  jal 0x8c299cc            <- base B's super-base
        0x08c23b0c  jal 0x8c299cc            <- base A calls the SAME one

    and `0x08c299cc` is exactly those four fields:

        tag 0xA  64 bits -> +0x10   msgId          (0x08c299f8 / 0x08c29a10)
        tag 0xA  64 bits -> +0x18   dedup          (0x08c29a50 / 0x08c29a68)
        tag 8    32 bits -> +0x20   timestamp      (0x08c29ab0 / 0x08c29ac8)
        tag 1     1 bit  -> +0x24   read flag      (0x08c29b08 / 0x08c29b24)

    So the three layers stack, and the malloc sizes prove it -- base A's class
    is 0x70 bytes and ends at 0x70; type 5's is 0x80 and adds three fields from
    0x70; the clan class is 0x100 and its last field is a 64-byte string at
    0xc0. Nothing is left over anywhere:

        super   0x08c299cc  [u64 ->0x10][u64 ->0x18][u32 ->0x20][bool ->0x24]
        base A  0x08c23acc  + [u64 ->0x28 sender][str64 ->0x30 sender name]
        base B  0x08c23190  + [u64 ->0x70][str64 ->0x78]
        clan    0x08c23884  + [u64 ->0xb8 teamId][str64 ->0xc0]

    which makes a clan message TEN fields, not four and not six. Phase 25's
    three failures were attempt 1 = wrong class, attempt 2 = base B's six
    fields with the clan tail missing, attempt 3 = the clan's six tail fields
    with the super-base's four missing. Every one of them was short.

    A string on the wire is `tag 0x10` then raw bytes read EIGHT BITS AT A TIME
    until a NUL (0x08c239a8..0x08c239e4); there is no length prefix, the buffer
    is 64 bytes and byte 0x3f is forced to NUL, so 63 characters is the limit.

    THE FULL LAYOUT, all of it now proven (Phase 33c sentinels, then Phase 41
    from the class ctor 0x08c237d0 and deserializer 0x08c23884):

        +0x10 u64 msgId    +0x18 u64 dedup   +0x20 u32 ts   +0x24 bool read
        +0x28 u64 SENDER   +0x30 char[64] sender name
        +0x70 u64 teamId   +0x78 char[64] clan name
        +0xb8 u64 SUBJECT GAMER   +0xc0 char[64] subject name   (0x100 class only)

    +0xc0 IS NEVER READ by anything, but it must still be on the wire or the
    parse under-reads and the connection dies.

    THERE ARE THREE DISPATCHERS, and the one that changes membership is not the
    one you find first:

        0x08990564  the UI switch (type-13). Builds inbox items. Sends NO RPC
                    and never marks anything stale -- enumerated every jal.
        0x089be770  net::tClan::onMessage (vtable +0x2c), switch(type-17).
                    Picks the SUBJECT: types 17/18/28/39 use +0xb8, EVERY OTHER
                    TYPE USES +0x28, the sender. Null lookup -> silent drop.
        0x089b4b9c  net::tGamer::onMessage (type-13) -- the actual mutation:
                    14 -> rank 2 + flag 0x800   15/16/18/26 -> remove
                    17 -> rank 3   28 -> rank 4   39 -> rank 2

    So a notification without its subject has nothing to act on. `findMember`
    is 0x089ba930 (walks clan->0x24 comparing node->0x20, a GAMER id); finding a
    CLAN by id is the different function 0x089c0030. An earlier version of this
    comment called both of them findTeam, which is what made +0xb8 look like a
    team id.

    AND NOTHING HERE CAN FORCE A REFRESH. `0x089b9674` sets flag bit 0x4,
    "needs a server refresh", and the idle delegates poll that bit into
    `Teams op 20` (0x089c0238) / `op 21` (0x089bab38). None of its 28 callers is
    in a message handler -- only creating a clan node (0x089bfe78) or adding a
    member (0x089ba738) marks stale. That is the whole reason a push can refresh
    a clan the console does NOT hold (the preamble creates it) and can only
    mutate one it does.
    """
    w.u32(type_id)                    # read by 0x08c1cec0 -> factory -> msg[8]

    # --- the super-base 0x08c299cc: EVERY message class begins with these ---
    w.u64(msg_id)                     # +0x10  the id Messaging op 4 deletes by
    w.u64(msg_id)                     # +0x18  dedup key: unique and non-zero
    w.u32(0)                          # +0x20  timestamp
    w.bool_(False)                    # +0x24  read/ack flag
    # --- base A's own two fields 0x08c23acc, shared by base B at the same
    #     offsets (0x08c23234 / 0x08c23294) ---
    w.u64(sender)                     # +0x28  the sender's account
    w.str_(sender_name, 63)           # +0x30  64-byte buffer including the NUL

    if type_id in CLAN_PUSH_TYPES:
        # base B's extra pair (0x08c23314 -> +0x70, 0x08c23374 -> +0x78): the
        # CLAN this message is about, id then name. Proved with sentinels in
        # Phase 33c -- a push whose +0x78 read "MIDDLE1" made the console fire
        # `Teams op 1` for a clan called MIDDLE1, while +0xc0 was ignored.
        # WOW2_PUSH_MIDNAME still replaces it for that kind of experiment.
        w.u64(int.from_bytes(bytes(session_id[:8]).ljust(8, b"\x00"), "little"))
        w.str_(os.environ.get("WOW2_PUSH_MIDNAME") or clan_name, 63)
        if type_id in CLAN_BLOB_TYPES:
            # NINE fields. Base B plus a payload length, exactly the trailer
            # type 1 uses -- `readTypeChecked(6)` then 16 bits into +0xb8 at
            # 0x08c22f44, and `blez` at 0x08c22f98 means 0 ends the message.
            w.u16(0)
        elif type_id in CLAN_TAIL_TYPES:
            # TEN. The 0x100-byte class's own tail
            # (0x08c23920 -> +0xb8, 0x08c23980 -> +0xc0).
            w.u64(target)
            w.str_(os.environ.get("WOW2_PUSH_TAILNAME") or target_name
                   or clan_name, 63)
        # ...and everything else in the family stops at base B: EIGHT fields.
        return

    if type_id == PUSH_BUDDY_INVITE:
        w.u16(0)                      # +0x70  payload length; 0 = no blob
    elif type_id == PUSH_MATCH_INVITE:
        # Type 5 has its OWN class -- 0x80 bytes, ctor 0x08c223e8, vtable
        # 0x08dba520, deserialize 0x08c224b4 -- and it is the only one of the
        # first twelve that carries a session id, which is exactly what a match
        # invite needs:
        #
        #   <base A>
        #   blob  capped at 8 bytes  -> +0x70   the SESSION ID
        #   u16                      -> +0x78   payload length
        #   blob  (only if +0x78 > 0)-> +0x7c   payload
        #
        # The cap is a hard `ori $s2,$zero,8` + `sltu` at 0x08c22550: a longer
        # blob takes the error path and the field is left unset. The trailing
        # blob is skipped by `blez` at 0x08c22694, so u16 0 ends the message --
        # the same trick type 1 uses.
        w.blob(bytes(session_id[:8]).ljust(8, b"\x00"))
        w.u16(0)                      # +0x78  payload length; 0 = no blob


def build_lsg_push_encrypted(type_id: int, sender: int, sender_name: str,
                             session_key: bytes, msg_id: int = 0,
                             seed: int = 0x22446688,
                             session_id: bytes = b"", clan_name: str = "",
                             target: int = 0, target_name: str = "") -> bytes:
    """One LsgServicePushMessage. Same envelope as a TaskReply, type byte 2."""
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.write_bits(b"\x01", 1)          # the type_checked bit, as in every reply
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
            # The connection's OWN key -- session keys are per sign-in now, so a
            # push encrypted with the old global constant would be noise to it.
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


# ------------------------------------------------------- buddies and clans
#
# PHASE 22 -- service 9 (Friends) and service 3 (Teams), read off the client.
#
# Both were answered with the generic `err=0, 0 results` from Phase 11 onward,
# which every no-result op accepts and every LIST op does not. The user's report
# ("I can send buddy invites but there is no way to accept them", "making a clan
# does nothing") is exactly what that produces, and the binary says why.
#
# THE RPC MAP came out of `bdRemoteTaskManager::startTask` (0x08c2486c): all 45
# call sites pass the service in $a2 and the op in $a3 as immediates, so walking
# them lists every RPC this title can send. The FRIENDS REPLY READER is at
# 0x08c18cb8: it reads [u32 err][u8 opID], then indexes a 15-entry table at
# 0x08d6a208 with opID-5, and only FIVE arms read anything -- ops 5, 7, 16, 17
# and 19 land on 0x08c18dac, which reads [u32 numResults] and then that many
# rows; every other op lands on the bare exit at 0x08c18e8c. So op 1 (send an
# invite), op 6 and op 13 want nothing back, and the three no-argument ops the
# client fires at sign-in are the three lists.
#
# WHICH LIST IS WHICH comes from the game layer's own log lines, which sit in
# the same functions as the calls:
#
#   net::tBuddyList  "downloading friends"           0x0897a0fc -> op 5  @0x0897a3cc
#                    "downloading friend proposals"  0x0897a4ac -> op 19 @0x0897a77c
#   net::tEnemyList  "downloading block list"        0x0897f3b4 -> op 7  @0x0897f684
#
# ROW LAYOUTS: three container classes sit immediately after that reply reader,
# each a vtable whose slot 2 is a row deserializer (the same shape as the
# leaderboard row's 0x08c25770):
#
#   0x08c1904c   [u64 id][str name][u8  status]     vtable 0x08dba238
#   0x08c19494   [u64 id][str name][bool flag]      vtable 0x08dba258
#   0x08c198dc   [u64 id][str name]                 vtable 0x08dba278
#
# The mapping below (friends carry a status, a proposal carries a direction, a
# blocked player carries neither) is an inference from that shape, not something
# the binary states; WOW2_FRIEND_ROWS=a|b|c rotates it if a screen comes up
# empty. Everything else here is read straight off the wire or the disassembly.
#
# CLANS are simpler and completely pinned. `bdCreateTeamResult::deserialize`
# (0x08c27ddc) asserts "Only expecting 1 or 0 results." and, given one, reads a
# single typed u64 into the object -- the new team's id. Returning zero results
# leaves the client with no id at all, and the proof of that is on the wire: the
# three clan attempts in session-20260911-002831.log are each followed by FOUR
# `bdStats op 1` uploads, one per second, to boards 29..32 -- the clan boards --
# every one of them carrying `entityID = 0`, because the client had no team to
# name. Hand back an id and those uploads carry it.
TEAM_ID_BASE = 0x00C1A0_0000_0000        # "clan" ids, obviously ours in a capture
TEAMS_DB = CAP / "teams-db.json"
FRIENDS_DB = CAP / "friends-db.json"
FRIEND_NAME_MAX = 64
# Row shape per list op, overridable while bisecting:
#   WOW2_FRIEND_ROWS="5=u8,7=none,19=none"
# `none` = [u64 id][str name] (deserializer 0x08c198dc)
# `u8`   = ...[u8  status]    (0x08c1904c)
# `bool` = ...[bool flag]     (0x08c19494)
# Getting it wrong is LOUD: the client drops the whole LSG connection about
# 300 ms after the bad reply and the console shows "Connection Lost".
# CONFIRMED, not guessed: each list's row shape is fixed by which container the
# GAME-side reply handler constructs -- friends 0x08c19364 -> 0x08c19494
# [u64][str][bool], proposals 0x08c197ac -> 0x08c198dc [u64][str], block list
# 0x08c18f1c -> 0x08c1904c [u64][str][u8]. Get one wrong and the client drops the
# LSG connection ~330 ms after the reply ("Connection Lost").
FRIEND_ROW_DEFAULT = "5=bool,7=u8,19=none"
FRIEND_ROWS = {}
for _part in os.environ.get("WOW2_FRIEND_ROWS", FRIEND_ROW_DEFAULT).split(","):
    if "=" in _part:
        _o, _k = _part.split("=", 1)
        FRIEND_ROWS[int(_o)] = _k.strip()


# Stores that failed to PARSE. A missing file is fine and means "empty"; a file
# that exists and does not parse is a damaged database, and the old code could not
# tell the two apart -- it caught ValueError and returned {}. That is the quiet
# way to lose everything: read {} -> serve an empty board -> write {} back, and
# the data is gone with no error anywhere. Refusing to WRITE a store we could not
# READ is what makes that unrecoverable path impossible.
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
            # Keep the damaged bytes. Whatever is wrong, the file is the only
            # copy of that data and the next _jsave must not land on top of it.
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
    """Write a JSON store ATOMICALLY, or not at all.

    `path.write_text()` truncates first, so a crash mid-write leaves a short file
    that `_jload` then reads as corrupt. Write a temp file in the SAME directory
    (rename is only atomic within a filesystem) and `os.replace` it over the top,
    which is atomic on POSIX: a reader sees either the whole old file or the whole
    new one, never a partial.
    """
    if str(path) in _UNREADABLE:
        log(f"  (!! refusing to write {path.name}: it failed to load this run "
            f"({_UNREADABLE[str(path)]}) and overwriting it would destroy data)")
        return
    tmp = path.with_suffix(path.suffix + f".tmp-{os.getpid()}")
    try:
        tmp.write_text(json.dumps(data, indent=1, sort_keys=True))
        os.replace(tmp, path)
    except OSError as e:
        log(f"  (!! could not write {path}: {e})")
        try:
            tmp.unlink()
        except OSError:
            pass


# ------------------------------------------------------------- profiles (svc 8)
# `service 8` is the busiest thing the server did NOT answer until Phase 23: the
# logs have 275 hits across ops 4/1/5/2, and op 4 alone is the second-busiest RPC
# in every capture after `Stats op 4`. All five ops are `net::tProfile` task
# methods, and a "kind" flag at this+0x20 (net::tPrivateProfile=1,
# net::tPublicProfile=0, set from the ctor's $a3) picks which one is sent:
#
#   op 1  create profile            (0x0898639c, logs "creating profile")
#   op 2  READ a public profile     [u8 0][u64 entityId]
#   op 3  read MY private profile   [u8 0]                     -- never fired
#   op 4  WRITE a public profile    [u8 0][s64 x4][f64 x2][s64][str][s32]
#   op 5  write my private profile  [u8 0][s32 99]             -- a stub payload
#
# Sign-in fires 1 -> 4 -> 5 -> 4, which is why the counts are so lopsided.
#
# ONLY op 2 READS RESULTS. The service's reply reader (0x08c24194) takes
# [u32 err] then a [u8 opId] which it reads and DISCARDS, and hands the container
# a hard-coded count of 1 (`ori $a1,$zero,1` at 0x08c242a4) -- so, like Teams op 1
# and Storage op 5, there is NO [u32 numResults] in the stream and exactly one row
# follows. But the three call sites differ in whether a container exists at all:
# 0x08986bec (op 1) and 0x089889a0 (ops 4/5) pass a2 = $zero, so no row is ever
# read and the bare `err=0, 0 results` stub was already correct for them. Only
# 0x08987aa4 -- the download poll behind "Download profile for %GAMER%?" -- passes
# a real container. So the blank View-profile screen is op 2, alone.
#
# The op 2 row is what op 4 uploads with the entity id in front:
#   [u64 entityId][s64][s64][s64][s64][f64][f64][s64][str][s32]
# The nine payload fields have no recovered meaning -- every one was zero in the
# captures and only the str is obviously displayable -- so this does not model
# them. It stores what the console uploaded and hands the same typed fields back,
# which is the one answer guaranteed to be the shape the client expects.
# --------------------------------------------------------- account credentials
# What the create-account request told us, per account name. This is NOT yet the
# credential store the server AUTHENTICATES against (that is ROADMAP B2, and it
# has to come with account-keyed identity in B1 -- writing one without the other
# would just be a second source of truth). It is written now because the data is
# free the moment the request is decoded, and because having real captures of
# what accounts exist is what makes B1/B2 a mechanical change rather than a
# design exercise.
#
# The stored value is Tiger192(password), which is exactly `account_key()` -- the
# key the login proof is built with. So this file never holds a password, and a
# server built on it never learns one.
ACCOUNTS_DB = CAP / "accounts.json"


def note_account(username: str, password_hash: bytes, peer_ip: str) -> None:
    """Record an account the client just created (or re-created)."""
    if os.environ.get("WOW2_NO_ACCOUNT_STORE") == "1":
        return
    db = _jload(ACCOUNTS_DB, {})
    row = db.get(username) or {}
    now = datetime.datetime.now().isoformat(timespec="seconds")
    old = row.get("pwhash")
    row.update({"pwhash": password_hash.hex(), "last_ip": peer_ip, "last_seen": now,
                "handle": account_handle(username).hex()})
    row.setdefault("first_seen", now)
    if not row.get("user_id"):
        # A stable small id per account. The rig's own consoles keep the ids
        # IDENTITIES gives them (1..8) so nothing about the eight-console rig
        # changes; anyone else is numbered from 100 up, which cannot collide.
        cfg = next((uid for _ip, (n, uid) in IDENTITIES.items() if n == username), 0)
        row["user_id"] = cfg or max(
            [100] + [r.get("user_id", 0) for r in db.values()
                     if isinstance(r, dict) and r.get("user_id", 0) >= 100]) + 1
    if old and old != row["pwhash"]:
        log(f"    (account {username!r}: password hash CHANGED on re-create)")
    db[username] = row
    _jsave(ACCOUNTS_DB, db)


def set_account_password(username: str, password_hash: bytes, peer_ip: str = "") -> None:
    """Commit a new credential for an account. The digest IS the credential.

    The server never sees the password -- the client sends Tiger192(password),
    which is exactly the key `build_login_reply` needs. So this store holds
    digests and the operator learns nothing from reading it.
    """
    db = _jload(ACCOUNTS_DB, {})
    row = db.get(username) or {}
    now = datetime.datetime.now().isoformat(timespec="seconds")
    row.update({"pwhash": password_hash.hex(), "last_seen": now,
                "handle": account_handle(username).hex()})
    row.setdefault("first_seen", now)
    if peer_ip:
        row["last_ip"] = peer_ip
    if not row.get("user_id"):
        row["user_id"] = next((uid for _ip, (n, uid) in IDENTITIES.items()
                               if n == username), 0)
    db[username] = row
    _jsave(ACCOUNTS_DB, db)


def account_handle(username: str) -> bytes:
    """The 8 bytes a client puts in its login request to say who it is."""
    return tiger192(username.encode())[:8]


def handle_index() -> dict[bytes, dict]:
    """Tiger192(name)[:8] -> {name, user_id, pwhash} for every account we can name.

    Two sources, and the first one matters more than it looks: the rig's
    configured IDENTITIES give us the NAMES, and a name is all you need to
    compute its handle. So console 1..8 are resolvable by account from the very
    first login with no store at all -- the store only has to carry accounts we
    learned from a create-account request, plus their passwords.
    """
    idx: dict[bytes, dict] = {}
    for _ip, (name, uid) in IDENTITIES.items():
        idx[account_handle(name)] = {"name": name, "user_id": uid,
                                     "pwhash": None, "src": "config"}
    for name, row in _jload(ACCOUNTS_DB, {}).items():
        if not isinstance(row, dict):
            continue
        h = account_handle(name)
        prev = idx.get(h, {})
        idx[h] = {"name": name,
                  "user_id": row.get("user_id") or prev.get("user_id") or 0,
                  "pwhash": (bytes.fromhex(row["pwhash"]) if row.get("pwhash")
                             else prev.get("pwhash")),
                  "src": "store" if not prev else "config+store"}
    return idx


def account_by_handle(handle: bytes) -> dict | None:
    return handle_index().get(handle)


# Session keys we have issued, per account. The client relays the key back to the
# LSG inside its opaque proof, which is how the LSG connection learns it -- but a
# relayed value is client-supplied, so it is only honoured if it is one we
# actually issued to that account.
ISSUED_SESSION_KEYS: dict[str, set[bytes]] = {}


def new_session_key(username: str) -> bytes:
    """A fresh random 24-byte LSG session key for this sign-in.

    Was `rigconfig.SESSION_KEY` -- the SAME key for every client, forever. With
    one shared key any client that signs in can decrypt any other's lobby
    traffic, which is not a subtle weakness. `WOW2_FIXED_SESSION_KEY=1` restores
    the old behaviour for a bisect; several rig tools assume the constant.
    """
    if os.environ.get("WOW2_FIXED_SESSION_KEY") == "1":
        key = rigconfig.SESSION_KEY
    else:
        # Reject a key whose halves repeat: EDE degenerates to single DES, which
        # is exactly the weakness BD_BOOTSTRAP_KEY documents. 1 in 2^64, but it
        # costs nothing to exclude and the failure would be silent.
        while True:
            key = secrets.token_bytes(24)
            if key[0:8] != key[8:16] and key[8:16] != key[16:24]:
                break
    ISSUED_SESSION_KEYS.setdefault(username, set()).add(key)
    return key


def session_key_is_ours(username: str, key: bytes) -> bool:
    return key in ISSUED_SESSION_KEYS.get(username, ())


PROFILE_DB = CAP / "profile-db.json"
NO_PROFILES = os.environ.get("WOW2_NO_PROFILES") == "1"


def profile_db() -> dict:
    d = _jload(PROFILE_DB, {})
    d.setdefault("public", {})
    return d


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


# What to serve for an account that has never uploaded one: the right SHAPE with
# nothing in it, so the screen draws instead of staying blank. Nine fields, in
# the order tPublicProfile::serialize (0x089894c8) writes them.
PROFILE_EMPTY = [[bd.BD_SINT64, 0], [bd.BD_SINT64, 0], [bd.BD_SINT64, 0],
                 [bd.BD_SINT64, 0], [bd.BD_F64, 0.0], [bd.BD_F64, 0.0],
                 [bd.BD_SINT64, 0], [bd.BD_STR, ""], [bd.BD_SINT32, 0]]


def profile_upload(dec: dict, who=None, peer_ip: str = ""):
    """Profile op 4: the console uploads its own public profile. No results."""
    # account_for() FIRST: `who` is the identity the server ISSUES (1, 2, ...),
    # while every store on this rig is keyed by the CLIENT's 64-bit account id
    # (0x975367efa4bbebed and friends). Getting that precedence backwards files
    # the profile under an id the client will never ask for, and the download
    # silently serves the empty placeholder forever.
    entity = account_for(peer_ip) or (who[1] if who else 0)
    if NO_PROFILES or not entity:
        return 0, None
    try:
        r = lsg_request_params(dec)
        r.u8()                              # leading flags byte
        fields = bd.read_fields(r)
    except Exception as e:
        log(f"  (profile upload decode failed: {e})")
        return 0, None
    d = profile_db()
    key = f"{entity:016x}"
    name = (who[0] if who else "") or friend_name(friends_db(), entity)
    d["public"][key] = {"name": name, "at": ts(),
                        "fields": [_field_to_json(t, v) for t, v in fields]}
    _jsave(PROFILE_DB, d)
    shown = ", ".join(str(v) for _t, v in fields[:4])
    log(f"  profile upload: {name or key} <- {len(fields)} fields ({shown}...)")
    return 0, None


def profile_read_public(dec: dict, who=None, peer_ip: str = ""):
    """Profile op 2: read one public profile. ONE row, and NO result count."""
    if NO_PROFILES:
        return 0, None
    try:
        r = lsg_request_params(dec)
        r.u8()                              # leading flags byte
        target = r.u64()
    except Exception as e:
        log(f"  (profile read decode failed: {e})")
        return 0, None
    d = profile_db()
    rec = d["public"].get(f"{target:016x}")
    fields = rec["fields"] if rec else [list(f) for f in PROFILE_EMPTY]
    name = (rec or {}).get("name") or friend_name(friends_db(), target)
    if not rec:
        # Nothing stored: at least put the player's name in the one displayable
        # field, so the screen has something on it rather than nothing.
        for f in fields:
            if f[0] == bd.BD_STR:
                f[1] = name
                break

    def emit(w):
        # NO count here: service 8's reply arm hands the deserializer a hard-coded
        # 1 (0x08c242a4), so a [u32 numResults] would land where the row's first
        # field belongs -- the same trap as Teams op 1 and Storage op 5.
        w.u64(target)
        for t, v in fields:
            if not _write_field(w, int(t), v):
                log(f"  (!! profile field type {t} has no writer -- skipped)")

    log(f"  profile read: entity 0x{target:016x} ({name or 'unknown'}) -- "
        f"{'stored' if rec else 'EMPTY placeholder'}, {len(fields)} fields")
    return None, emit


def friends_db() -> dict:
    d = _jload(FRIENDS_DB, {})
    d.setdefault("names", {})
    d.setdefault("friends", [])
    d.setdefault("invites", [])
    d.setdefault("blocked", [])
    d.setdefault("messages", [])     # Phase 28: op 4 / op 13 withdraw messages
    return d


def blocked_by(entity: int) -> set:
    """The accounts `entity` has blocked (Friends op 6 flag=1) -- Phase 28.

    The CLIENT does not enforce a block: a blocked gamer's buddy invite still
    arrives, still renders under View messages (with a red no-entry icon beside
    it) and still offers Accept. So if a block is to mean anything it has to be
    enforced here, which is presumably what the real backend did.
    """
    mine = f"{entity:016x}"
    return {b.get("who") for b in friends_db()["blocked"] if b.get("by") == mine}


def friend_name(d: dict, entity: int) -> str:
    return d["names"].get(f"{entity:016x}", "")


def friends_note_name(entity: int, name: str) -> None:
    """Remember entity -> name so a buddy row can be labelled from either side."""
    if not entity or not name:
        return
    d = friends_db()
    if d["names"].get(f"{entity:016x}") == name:
        return
    d["names"][f"{entity:016x}"] = name
    _jsave(FRIENDS_DB, d)


def friends_of(entity: int) -> list:
    d = friends_db()
    out = []
    for a, b in d["friends"]:
        other = b if a == f"{entity:016x}" else (a if b == f"{entity:016x}" else None)
        if other:
            out.append((int(other, 16), d["names"].get(other, "")))
    return out


def friends_write_row(w, entity: int, name: str, kind: str) -> None:
    """One Friends result row. `kind` picks the shape (see FRIEND_ROWS)."""
    w.u64(entity)
    w.str_(name or f"{entity:x}"[:8], FRIEND_NAME_MAX)
    if kind == "u8":
        w.u8(1)                       # 1 = on-line (net::tBuddy's "now on-line")
    elif kind == "bool":
        w.bool_(True)                 # a 1-BIT field, tag + 1 bit


def friends_list_result(op: int, dec: dict, who=None, peer_ip: str = ""):
    """Friends ops 5 / 7 / 19 -- the three lists the client downloads at sign-in."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    friends_note_name(me, name)
    d = friends_db()
    kind = FRIEND_ROWS.get(op, "none")
    mine = f"{me:016x}"
    if op == 5:
        what = "friends"
        rows = friends_of(me)
    elif op == 19:
        what = "friend proposals"
        rows = [(int(i["from"], 16), d["names"].get(i["from"], i.get("from_name", "")))
                for i in d["invites"] if i.get("to") == mine]
    else:
        what = "block list"
        rows = [(int(b["who"], 16), d["names"].get(b["who"], ""))
                for b in d["blocked"] if b.get("by") == mine]
    log(f"  friends op{op} ({what}) for {name} 0x{me:016x}: {len(rows)} row(s)"
        + (f" [row={kind}]" if rows else "")
        + (" -> " + ", ".join(f"{n or '?'} 0x{e:016x}" for e, n in rows) if rows else ""))

    # Two counts, like bdStats: the reply reader's arm (0x08c18dac) reads
    # [u32 numResults] out of the TaskReply envelope, and then the result
    # CONTAINER reads its own [u32 totalEntries] before the rows -- the same
    # shape as bdLeaderBoardResult (0x08ce5d98), whose missing header was what
    # ended the Phase 11 sign-in chain. WOW2_FRIEND_NO_TOTAL=1 drops it.
    def emit(w):
        if os.environ.get("WOW2_FRIEND_TOTAL") == "1":
            w.u32(len(rows))          # a totalEntries header -- see the note above
        if os.environ.get("WOW2_FRIEND_COUNT_ONLY") == "1":
            return                    # bisect: announce N, send no rows at all
        for entity, rname in rows:
            friends_write_row(w, entity, rname, kind)
    return len(rows), emit


def friends_add(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 1 -- send a buddy invite. Reads no results (arm 0x08c18e8c)."""
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()                                       # always 0
        target = r.u64()
    except Exception as e:
        log(f"  (friends op1 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    d = friends_db()
    mine, theirs = f"{me:016x}", f"{target:016x}"
    if sorted((mine, theirs)) in [sorted(p) for p in d["friends"]]:
        log(f"  friends op1 (INVITE): {name} -> 0x{target:016x} (already buddies)")
        return 0, None
    if any(i["from"] == mine and i["to"] == theirs for i in d["invites"]):
        log(f"  friends op1 (INVITE): {name} -> 0x{target:016x} (already pending)")
        return 0, None
    # PHASE 28: honour the target's block list. The client does not -- a blocked
    # gamer's invite still arrives and still offers Accept, with only a red icon
    # to mark it -- so a block only means anything if the server drops it here.
    # The sender is told nothing, which is what a block is for. Unproven against
    # the real backend; WOW2_NO_FRIENDS_FIX=1 turns it off.
    if (os.environ.get("WOW2_NO_FRIENDS_FIX") != "1"
            and mine in blocked_by(target)):
        log(f"  friends op1 (INVITE): {name} -> 0x{target:016x} "
            "BLOCKED by the target -- filed nothing, pushed nothing")
        return 0, None
    d["invites"].append({"from": mine, "from_name": name, "to": theirs,
                         "to_name": d["names"].get(theirs, ""), "at": ts()})
    _jsave(FRIENDS_DB, d)
    log(f"  friends op1 (INVITE): {name} 0x{me:016x} -> 0x{target:016x}"
        f" ({d['names'].get(theirs) or 'unknown account'}) -- "
        f"{len(d['invites'])} proposal(s) pending")
    # Friends op 19 turned out to be the SENDER's own list ("Cancel buddy
    # invite"). The TARGET's copy is a lobby MESSAGE: it shows up under
    # `View messages` as "Buddy invite from <name>", and cross on it offers
    # Accept / Decline. File it, then deliver it live if they are signed in.
    mid = message_add(target, PUSH_BUDDY_INVITE, me, name)
    push_to_account(target, PUSH_BUDDY_INVITE, me, name, mid)
    return 0, None


def friends_match_invite(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 8 -- invite a buddy INTO THE LOBBY YOU ARE HOSTING.

    PHASE 25. This was a cold gap until the UI that fires it was found, and the
    UI is not where anyone looked: the row only exists **while you are hosting**.
    Host a game, press `start` in the lobby to open the online menu, pick a buddy
    off the Buddy list, and the gamer menu grows an invite row. From the
    Infrastructure menu, with no lobby open, that row is simply absent -- which
    is why five phases of walking the online menu never produced this opcode.

    Request, decoded off the wire with `bddump.py --log --svc 9 --op 8`:

        [u8 op=8][u8 0][u64 target][blob 8B session id]

    -- and note that `lsg_request_params()` has ALREADY eaten the op id, so the
    handler reads three fields, not four. Reading the op again costs you the
    whole message: the blob runs off the end and the decode fails with
    "want 1 at 35, have 0", which looks like a truncated request and is not.

    The blob is the id the server assigned in the `Sessions op 1` create reply,
    little-endian (`01 57 00 ..` for session 0x5701), so the client is handing
    back exactly what we gave the host -- it is not inventing one.

    Nothing reads results (bare `err=0, 0 results` is correct). The DELIVERY is
    the whole job, and it is the same two-transport channel as a buddy invite:
    file a message for the target and push it live. The push type is 5,
    "received match invite" (net::tBuddy's table at 0x08d36be8), whose class
    carries the session id -- see write_push_body().
    """
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()                                       # always 0
        target = r.u64()
        session_id = r.blob()
    except Exception as e:
        log(f"  (friends op8 decode failed: {e})")
        return 0, None
    friends_note_name(me, name)
    sid = int.from_bytes(session_id[:SESSION_ID_BYTES], "little")
    rec = SESSIONS.get(sid)
    d = friends_db()
    theirs = f"{target:016x}"
    log(f"  friends op8 (MATCH INVITE): {name} 0x{me:016x} -> 0x{target:016x}"
        f" ({d['names'].get(theirs) or 'unknown account'}) for session 0x{sid:x}"
        + (f" ({rec['name']!r}, mode={'POINTS' if rec.get('points') else 'fun'})"
           if rec else " -- NO SUCH LIVE SESSION, relaying the id anyway"))
    mid = message_add(target, PUSH_MATCH_INVITE, me, name, session_id)
    push_to_account(target, PUSH_MATCH_INVITE, me, name, mid, session_id)
    return 0, None


def friends_match_decline(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 10 -- `[u8 0][u64 inviter]`. DECLINE a match invite.

    PHASE 28, the last cold Friends opcode. Measured at 16:38:11 on console 8:
    View messages -> open "Match invite from player7" (which fires
    `Sessions op 4`) -> **Decline match invite** -> confirm. The id is the
    INVITER's, and `Messaging op 4` follows 33 ms later to delete the message --
    the same two-message shape as `op 9` (accept) in Phase 25.

    Nothing reads results; the bare `err=0, 0 results` was accepted live and the
    console printed "Declined match invite." The whole job is telling the
    inviter, and `net::tBuddy`'s table names the push: type 7, "received match
    invite reject", whose string is `%GAMER% has declined your match invite`.
    A rejection is transient -- it is not filed in the mailbox, because a match
    that has since ended must not raise it at the next sign-in.
    """
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
    d = friends_db()
    theirs = f"{inviter:016x}"
    log(f"  friends op10 (MATCH DECLINE): {name} 0x{me:016x} declined the match "
        f"invite from 0x{inviter:016x} "
        f"({d['names'].get(theirs) or 'unknown account'})")
    push_to_account(inviter, PUSH_MATCH_REJECTED, me, name)
    return 0, None


def friends_block(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 6 -- `[u8 0][u64 entity][u8 flag]`. BLOCK (1) / UNBLOCK (0).

    PHASE 28, measured on consoles 7 and 8. This op used to be served as
    "accept (1) / reject (0) a buddy proposal", which was a guess from Phase 22
    and is wrong. It is `net::tEnemy` Create/Revoke -- the gamer menu's
    **Block gamer** row and the blocked gamer menu's **Unblock player** row:

        16:10:31  op 6 flag=1  -> "player8 has been blocked."
        16:15:38  op 6 flag=0  -> "player8 has been unblocked."

    The old reading was not merely idle: on 2026-09-11 an *unblock* landed while
    an unrelated buddy proposal from that same gamer was pending, and the
    handler deleted the proposal and pushed type 3 to the other console, which
    duly displayed "player7 declined your buddy invite". A wrong op map is a
    live bug, not a documentation error.

    Blocking a gamer you have a relationship with is TWO messages, one second
    apart, and the second one depends on what the relationship was:

        buddy            op 6 flag=1  then  op 4   (revoke the buddy)
        outgoing invite  op 6 flag=1  then  op 13  (cancel the proposal)

    -- so op 6 itself only ever moves the block list. Nothing reads results
    (the reply reader's table at 0x08d6a208 is indexed by opID-5, so op 4 is
    below the table and ops 6/13 land on the bare exit at 0x08c18e8c); the
    generic `err=0, 0 results` is correct and was accepted live on both.
    """
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
    d = friends_db()
    mine, theirs = f"{me:016x}", f"{target:016x}"
    d["blocked"] = [b for b in d["blocked"]
                    if not (b.get("by") == mine and b.get("who") == theirs)]
    if flag:
        d["blocked"].append({"by": mine, "who": theirs,
                             "who_name": d["names"].get(theirs, ""), "at": ts()})
    _jsave(FRIENDS_DB, d)
    log(f"  friends op6 ({'BLOCK' if flag else 'UNBLOCK'}): {name} "
        f"0x{me:016x} -> 0x{target:016x} "
        f"({d['names'].get(theirs) or 'unknown account'}) -- "
        f"{sum(1 for b in d['blocked'] if b.get('by') == mine)} blocked")
    return 0, None


def friends_respond_legacy(dec: dict, me: int, name: str, target: int, flag: int):
    """The pre-Phase-28 op 6 reading, kept for `WOW2_NO_FRIENDS_FIX=1` bisects."""
    d = friends_db()
    mine, theirs = f"{me:016x}", f"{target:016x}"
    pending = [i for i in d["invites"]
               if (i["from"], i["to"]) in ((theirs, mine), (mine, theirs))]
    if not pending:
        log(f"  friends op6: {name} -> 0x{target:016x} flag={flag} "
            "(no matching proposal -- recorded nothing)")
        return 0, None
    d["invites"] = [i for i in d["invites"] if i not in pending]
    if flag:
        if sorted((mine, theirs)) not in [sorted(p) for p in d["friends"]]:
            d["friends"].append([mine, theirs])
        log(f"  friends op6: {name} ACCEPTED 0x{target:016x} -- now buddies "
            f"({len(d['friends'])} pair(s))")
        push_to_account(target, PUSH_BUDDY_ACCEPTED, me, name)
    else:
        log(f"  friends op6: {name} REJECTED 0x{target:016x}")
        push_to_account(target, PUSH_BUDDY_REJECTED, me, name)
    _jsave(FRIENDS_DB, d)
    return 0, None


def friends_revoke(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 4 -- `[u8 0][u64 entity]`. REVOKE: the relationship, from my side.

    PHASE 28. Cold since Phase 23 and filed in `gapmap.py` as "cancel outgoing
    proposal? (inferred)", which is wrong -- cancelling is op 13. Op 4 is the
    one verb behind THREE on-screen actions, all of which mean "there is
    nothing between us, and I am the one saying so":

        gamer menu -> Remove buddy                      16:26:10
        View messages -> Decline buddy invite           16:23:36  (+ Messaging op 4)
        gamer menu -> Block gamer, when they were a buddy  16:10:32

    The id is the OTHER account in every case (the buddy, or the inviter). It
    matches `net::tBuddy`'s message id 4, "buddy revoked". Reads no results.

    Note this is the only Friends verb the client fires with an id it MANGLES:
    the row served as 0x00000000cafe0009 came back as 0x906c63bc6158f5fc, the
    same corruption Phase 26 saw in `Teams op 6`. Real console ids round-trip
    exactly, so the id here is trustworthy for real accounts only.
    """
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
    d = friends_db()
    mine, theirs = f"{me:016x}", f"{target:016x}"
    was_buddy = sorted((mine, theirs)) in [sorted(p) for p in d["friends"]]
    incoming = [i for i in d["invites"] if (i["from"], i["to"]) == (theirs, mine)]
    d["friends"] = [p for p in d["friends"] if sorted(p) != sorted((mine, theirs))]
    d["invites"] = [i for i in d["invites"]
                    if (i["from"], i["to"]) not in ((mine, theirs), (theirs, mine))]
    # Declining leaves the invite MESSAGE behind unless we drop it too. The
    # client sends its own `Messaging op 4` for the copy it can see, so this
    # only matters for a target that was offline when the invite was filed.
    d["messages"] = [m for m in d["messages"]
                     if not (m.get("to") == mine and m.get("from") == theirs
                             and int(m.get("type", 0)) == PUSH_BUDDY_INVITE)]
    _jsave(FRIENDS_DB, d)
    what = "DECLINED the invite from" if incoming else (
        "REMOVED the buddy" if was_buddy else "revoked nothing with")
    log(f"  friends op4 (REVOKE): {name} {what} 0x{target:016x} "
        f"({d['names'].get(theirs) or 'unknown account'}) -- "
        f"{len(d['friends'])} buddy pair(s), {len(d['invites'])} proposal(s)")
    # Tell the other side. A decline is worth keeping in their mailbox (they may
    # be offline); a plain removal is a transient notice, like the real thing.
    if incoming:
        mid = message_add(target, PUSH_BUDDY_REJECTED, me, name)
        push_to_account(target, PUSH_BUDDY_REJECTED, me, name, mid)
    elif was_buddy:
        push_to_account(target, PUSH_BUDDY_REVOKED, me, name)
    return 0, None


def friends_remove(dec: dict, who=None, peer_ip: str = ""):
    """Friends op 13 -- `[u8 0][u64 entity]`. CANCEL MY OUTGOING PROPOSAL.

    PHASE 28 pins what this is. It is the gamer menu's **Cancel buddy invite**
    row -- the row that replaces "Send buddy invite" for as long as a proposal
    of yours is outstanding, and the row `Friends op 19` exists to restore
    across a sign-in. Measured at 16:20:13 (cancel from the menu) and again at
    16:28:45, one second after an `op 6` block of a gamer with a proposal
    pending. It is NOT the buddy-removal verb: that is op 4.

    Reads no results.
    """
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
    d = friends_db()
    mine, theirs = f"{me:016x}", f"{target:016x}"
    before = (len(d["friends"]), len(d["invites"]))
    outgoing = [i for i in d["invites"] if (i["from"], i["to"]) == (mine, theirs)]
    if os.environ.get("WOW2_NO_FRIENDS_FIX") == "1":
        d["friends"] = [p for p in d["friends"]
                        if sorted(p) != sorted((mine, theirs))]
        d["invites"] = [i for i in d["invites"]
                        if (i["from"], i["to"]) not in ((mine, theirs), (theirs, mine))]
    else:
        # Only the proposal I sent -- op 13 never means "drop a buddy" (op 4 does),
        # and dropping one here would silently delete a friendship on a console
        # that only cancelled an invite.
        d["invites"] = [i for i in d["invites"] if i not in outgoing]
        # Withdraw the copy sitting in their mailbox, so a cancelled invite does
        # not reappear at their next sign-in.
        d["messages"] = [m for m in d["messages"]
                         if not (m.get("to") == theirs and m.get("from") == mine
                                 and int(m.get("type", 0)) == PUSH_BUDDY_INVITE)]
    _jsave(FRIENDS_DB, d)
    log(f"  friends op13 (CANCEL INVITE): {name} 0x{me:016x} -> 0x{target:016x} "
        f"({d['names'].get(theirs) or 'unknown account'}, "
        f"{len(outgoing)} proposal(s) withdrawn; "
        f"friends {before[0]}->{len(d['friends'])}, "
        f"proposals {before[1]}->{len(d['invites'])})")
    if outgoing and os.environ.get("WOW2_NO_FRIENDS_FIX") != "1":
        push_to_account(target, PUSH_PROPOSAL_CANCELLED, me, name)
    return 0, None


def messages_db() -> dict:
    d = friends_db()
    d.setdefault("messages", [])
    d.setdefault("next_msg", 1)
    return d


def message_add(to_entity: int, type_id: int, sender: int, sender_name: str,
                session_id: bytes = b"", clan_name: str = "") -> int:
    """Store one lobby message for an account. Returns its id.

    The mailbox is what makes an invite survive: a live push is delivered once,
    but `bdMessaging op 1` is re-read at every sign-in, and both carry the same
    bytes (write_push_body). Without this an invite sent while the target is
    offline would vanish.
    """
    d = messages_db()
    mid = int(d["next_msg"])
    d["next_msg"] = mid + 1
    d["messages"].append({"id": mid, "to": f"{to_entity:016x}", "type": type_id,
                          "from": f"{sender:016x}", "from_name": sender_name,
                          "session": bytes(session_id).hex(),
                          "clan": clan_name, "at": ts()})
    _jsave(FRIENDS_DB, d)
    return mid


# The six clan NOTIFICATIONS, from the client's own message dispatcher
# (0x08990564, `type - 13`). These are not mailbox items and must never be
# filed: a notification DELETES ITSELF when it is handled (the console resolves
# the clan, re-reads the roster, then fires `Messaging op 4`), which is exactly
# the difference between the two kinds -- "a message that survives being read is
# a mailbox item; one that deletes itself is a notification". Filing one would
# re-deliver it at every sign-in forever, and a message the client cannot make
# sense of is how an account gets bricked.
CLAN_MSG_CACCEPT = 14          # the INVITER's copy: the invite was accepted
CLAN_MSG_CREJECT = 15          # the INVITER's copy: the invite was declined
CLAN_MSG_CLEFT = 16            # "%GAMER% has left the clan"
CLAN_MSG_CADMIN = 17           # "You are now a clan %CLAN% administrator"
CLAN_MSG_CKICKED = 18          # "You have been kicked from the clan %CLAN%"
CLAN_MSG_CDISBAND = 26         # "The clan %CLAN% has been disbanded"
CLAN_MSG_COWNER = 28           # "You are now the clan %CLAN% owner"
CLAN_MSG_CORDINARY = 39        # "You are no longer a clan %CLAN% administrator"


def account_name(entity: int) -> str:
    """The display name we have on file for an account, or "" if none."""
    try:
        return (friends_db().get("names") or {}).get(f"{entity:016x}", "") or ""
    except Exception:
        return ""


def clan_notify(to_entity: int, type_id: int, tid: int, clan_name: str,
                actor: int, actor_name: str,
                target: int = 0, target_name: str = "") -> None:
    """Tell one account that something happened to its clan. Push only.

    This is the half of every clan verb that the REQUEST does not do. Without
    it a promoted member keeps a stale roster and its own gamer menu goes on
    offering the verbs an ordinary member should not have, until it signs in
    again -- the client has no polling anywhere in the clan surface.

    **Name the gamer the notification is ABOUT in `target`.** Type 14 proved the
    mechanism: a clan push is not only a prompt to re-read, the client can apply
    it to its cached member list directly -- pushing 14 to the inviter made the
    new member appear in `View clan` with no `Teams op 21` and no re-sign-in.
    The corollary is that a notification whose subject is missing has nothing to
    apply, which is the most likely reason `Ckicked` did nothing: the tail was
    left empty, so it said "remove account 0".

    The id is taken from the mailbox counter but nothing is stored, so a
    `Messaging op 4` for it finds nothing and says so. That is the correct
    outcome, not a leak: the client deletes what it has consumed either way.

    `WOW2_NO_CLAN_NOTIFY=1` turns all of these off. Worth having because the
    tail layout is only proven for the 0x100-byte class (types 17/18/28/39,
    Phase 32); 16 and 26 fall to the plain eight-field base B on the strength of
    the registry's malloc sizes alone, and a wrong shape drops the receiver's
    LSG connection. Nothing is persisted, so a re-login is the whole recovery.
    """
    if os.environ.get("WOW2_NO_CLAN_NOTIFY") == "1":
        log(f"  (clan notify type {type_id} suppressed by WOW2_NO_CLAN_NOTIFY)")
        return
    d = messages_db()
    mid = int(d["next_msg"])
    d["next_msg"] = mid + 1
    _jsave(FRIENDS_DB, d)
    ok = push_to_account(to_entity, type_id, actor, actor_name, msg_id=mid,
                         session_id=tid.to_bytes(8, "little"),
                         clan_name=clan_name,
                         target=target, target_name=target_name)
    log(f"  clan notify type {type_id} -> 0x{to_entity:016x} "
        f"({clan_name!r} 0x{tid:016x}, msg {mid}): "
        + ("pushed" if ok else "not online, and a notification is never filed"))


def messages_for(entity: int) -> list:
    return [m for m in messages_db()["messages"] if m.get("to") == f"{entity:016x}"]


def messages_result(dec: dict, who=None, peer_ip: str = ""):
    """bdMessaging op 1 -- download the inbox.

    Request  [u8 0][u32 start][u32 count][bool][bool]   (the client sends 0, 25)
    Reply    [u32 numResults] then one write_push_body per message.
    The reply reader is 0x08c1ca90; ops 1/2/5 read a count, op 4 reads nothing.
    """
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    start, count = 0, 25
    try:
        r = lsg_request_params(dec)
        r.u8()
        start = r.u32()
        count = r.u32()
    except Exception as e:
        log(f"  (messaging op1 decode failed: {e})")
    rows = messages_for(me)[start:start + max(1, count)]
    log(f"  messaging op1 (inbox) for {name} 0x{me:016x}: {len(rows)} message(s)"
        + (" -> " + ", ".join(f"type {m['type']} from {m['from_name']}" for m in rows)
           if rows else ""))

    def emit(w):
        # NO count here: build_lsg_taskreply_encrypted already wrote the
        # [u32 numResults] this arm reads. Writing it again would put the rows
        # one field late -- the mistake that cost Phase 22 five sign-ins.
        fd = friends_db()
        for m in rows:
            to_hex = m.get("to", "0")
            write_push_body(w, int(m["type"]), int(m["id"]),
                            int(m["from"], 16), m.get("from_name", ""),
                            bytes.fromhex(m.get("session", "")),
                            m.get("clan", ""),
                            int(to_hex, 16),
                            fd["names"].get(to_hex, ""))
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
    d = messages_db()
    before = len(d["messages"])
    d["messages"] = [m for m in d["messages"]
                     if not (int(m["id"]) == mid and m.get("to") == f"{me:016x}")]
    _jsave(FRIENDS_DB, d)
    log(f"  messaging op4: 0x{me:016x} deleted message {mid} "
        f"({before} -> {len(d['messages'])} stored)")
    return 0, None


def friends_answer(dec: dict, accept: bool, who=None, peer_ip: str = ""):
    """Friends op 2 (accept) / op 3 (decline) -- both take the SENDER's id.

    Measured on the wire: pressing 'Accept buddy invite' in the message inbox
    sends `service 9 op 2` carrying the inviter's account id, immediately
    followed by `Messaging op 4` to delete the message. Neither reads results.
    (An earlier reading had op 6 as accept/reject; op 6 takes (u64, u8) and is
    something else -- it fires from the gamer menu, not from an invite.)
    """
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()
        sender = r.u64()
    except Exception as e:
        log(f"  (friends op{2 if accept else 3} decode failed: {e})")
        return 0, None
    d = friends_db()
    mine, theirs = f"{me:016x}", f"{sender:016x}"
    d["invites"] = [i for i in d["invites"]
                    if (i["from"], i["to"]) not in ((theirs, mine), (mine, theirs))]
    if accept and sorted((mine, theirs)) not in [sorted(p) for p in d["friends"]]:
        d["friends"].append([mine, theirs])
    _jsave(FRIENDS_DB, d)
    verb = "ACCEPTED" if accept else "DECLINED"
    log(f"  friends op{2 if accept else 3}: {name} {verb} the invite from "
        f"0x{sender:016x} ({len(d['friends'])} buddy pair(s))")
    kind = PUSH_BUDDY_ACCEPTED if accept else PUSH_BUDDY_REJECTED
    mid = message_add(sender, kind, me, name)
    push_to_account(sender, kind, me, name, mid)
    return 0, None


TEAM_RANK_MEMBER = 0
TEAM_RANK_ADMIN = 1
TEAM_RANK_OWNER = 2


def teams_db() -> dict:
    d = _jload(TEAMS_DB, {})
    d.setdefault("next", 1)
    d.setdefault("teams", {})
    return d


def team_of(entity: int) -> tuple[int, dict] | tuple[int, None]:
    for tid, rec in teams_db()["teams"].items():
        if f"{entity:016x}" in rec.get("members", []):
            return int(tid, 16), rec
    return 0, None


def clan_invite_backfill(me: int, name: str, d: dict) -> None:
    """Put a mailbox row behind any clan invite that has none, at sign-in.

    `Teams op 20` -- "which clans am I in" -- is the FIRST clan RPC of every
    sign-in and it arrives about two seconds before `bdMessaging op 1`, so a
    message filed here is delivered by this same sign-in's inbox read. Measured:
    op 20 at 04:19:38.2, op 1 at 04:19:40.5.

    THIS USED TO PUSH, AND IT SHOULD NOT. Before Phase 38 the clan invite had no
    working message type, so a proposal could only sit in `proposals` where the
    invited console never looked -- and the workaround was to fire a live push
    12 s after sign-in, timed to miss the RPC chain. Now that type 13 works,
    `teams_invite()` files a mailbox row when the invite is made and the inbox
    delivers it whether the target was online or not. All that is left for this
    to do is repair a store written before that, and pushing as WELL as filing
    puts the invite in the inbox TWICE -- which is exactly what the first live
    test showed on screen.
    """
    if os.environ.get("WOW2_NO_CLAN_BACKFILL") == "1":
        return
    mine = f"{me:016x}"
    fd = friends_db()
    have = {(m.get("from"), m.get("clan")) for m in messages_for(me)
            if int(m.get("type", 0)) == PUSH_CLAN_INVITE}
    for tid, rec in d["teams"].items():
        if mine in rec.get("members", []):
            continue
        for pr in rec.get("proposals", []):
            if pr.get("to") != mine:
                continue
            cname = rec.get("name", "")
            if (pr.get("from"), cname) in have:
                continue
            inviter = int(pr["from"], 16)
            iname = pr.get("from_name") or fd["names"].get(pr["from"], "")
            log(f"  (clan invite waiting for {name}: {cname!r} from {iname!r} "
                f"-- no mailbox row, filing one now so this sign-in's inbox "
                f"read delivers it)")
            message_add(me, PUSH_CLAN_INVITE, inviter, iname,
                        int(tid, 16).to_bytes(8, "little"), cname)


def teams_memberships_result(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 20 -- "the teams I belong to". Fires at EVERY sign-in.

    Answering it with nothing is why a clan did not survive a sign-in: the
    console created `wormstest`, the server stored it, and the next sign-in put
    the Clans screen back to `Create new clan` with `View clan` greyed out.
    net::tClanList logs "downloading memberships" / "memberships downloaded"
    around this call (0x089c032c / 0x089c10ec).

    Reply: [u32 numResults] then rows [u64 teamID][str name][u8] (0x08c279a4).
    """
    me = account_for(peer_ip)
    name = (who or (rigconfig.USERNAME, 0))[0]
    d = teams_db()
    rows = [(int(tid, 16), rec.get("name", ""),
             1 if rec.get("owner") == f"{me:016x}" else 0)
            for tid, rec in d["teams"].items()
            if f"{me:016x}" in rec.get("members", [])]
    log(f"  teams op20 (memberships) for {name} 0x{me:016x}: {len(rows)} clan(s)"
        + (" -> " + ", ".join(f"{n!r} 0x{t:016x}{' owner' if o else ''}"
                              for t, n, o in rows) if rows else ""))
    clan_invite_backfill(me, name, d)

    def emit(w):
        # NO count here: build_lsg_taskreply_encrypted already wrote the
        # [u32 numResults] this arm reads. Writing it again would put the rows
        # one field late -- the mistake that cost Phase 22 five sign-ins.
        for tid, tname, owner in rows:
            w.u64(tid)
            w.str_(tname, 63)         # 64-byte buffer, forced NUL at +0x3f
            w.u8(owner)
    return len(rows), emit


def team_rank(rec: dict, member: str) -> int:
    """The `u8` that trails a `Teams op 21` member row -- the member's ROLE.

    PHASE 25, UNRESOLVED. The game's own strings prove three roles exist
    ("Promote %GAMER% to administrator", "Demote %GAMER% to member", plus the
    owner, who is the only one who can "Transfer ownership"), so this byte is
    almost certainly 0 = member / 1 = administrator / 2 = owner. It had been
    hard-coded to 0 since Phase 22, which would make even the clan's owner look
    like a plain member to the client.

    That matters because **`Send clan invite` does not appear anywhere**, and the
    four contexts that could have hidden it are already ruled out: the row is
    absent from the gamer menu whether the console is in a lobby or at the
    Infrastructure menu, and whether the gamer was picked off the Buddy list or
    the Gamer list -- with `Teams op 20` and `op 21` both confirming, in the same
    sign-in, that this account owns `wormstest`. A role byte of 0 is the last
    server-controlled thing left that the client could be reading as "you are
    not an administrator, so you may not invite".

    It is read from the team record so the value can be changed without touching
    code -- `teams_db()` is `_jload`ed per request. The client caches the roster,
    though, so a change still needs a fresh sign-in to be seen:

        "ranks": { "<entity hex>": 2 }        in capture/teams-db.json
    """
    ranks = rec.get("ranks") or {}
    if member in ranks:
        return int(ranks[member]) & 0xFF
    return TEAM_RANK_OWNER if member == rec.get("owner") else TEAM_RANK_MEMBER


def teams_members_result(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 21 -- the members of one team. Row [u64][str][bool][u8] (0x08c2804c)."""
    try:
        r = lsg_request_params(dec)
        r.u8()
        tid = r.u64()
    except Exception as e:
        log(f"  (teams op21 decode failed: {e})")
        return 0, None
    rec = teams_db()["teams"].get(f"{tid:016x}")
    fd = friends_db()
    rows = []
    if rec:
        for m in rec.get("members", []):
            rows.append((int(m, 16), fd["names"].get(m, ""),
                         m == rec.get("owner"), team_rank(rec, m)))
    log(f"  teams op21 (members of 0x{tid:016x} {rec.get('name') if rec else '?'!r}): "
        f"{len(rows)} member(s)")

    def emit(w):
        # NO count here: build_lsg_taskreply_encrypted already wrote the
        # [u32 numResults] this arm reads. Writing it again would put the rows
        # one field late -- the mistake that cost Phase 22 five sign-ins.
        for eid, mname, owner, rank in rows:
            w.u64(eid)
            w.str_(mname, 63)
            w.bool_(owner)
            w.u8(rank)
    return len(rows), emit


def teams_invite(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 6 -- SEND A CLAN INVITE. Cold until Phase 25.

        request   [u8 0][u64 teamId][u64 target account]
        reply     err=0, 0 results

    Finding the UI took a server fix, not a menu walk: `Send clan invite` is a
    row of the **gamer menu**, and it is hidden unless the client believes you
    are a clan administrator. It reads that from the trailing `u8` of the
    `Teams op 21` member row -- the ROLE -- which this server hard-coded to 0
    from Phase 22 until Phase 25, so even the clan's owner looked like a plain
    member. See team_rank(). With the owner's role served as 2 the row appears
    immediately, from the Infrastructure menu, with no other change.
    """
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
    d = teams_db()
    key = f"{tid:016x}"
    rec = d["teams"].get(key)
    theirs = f"{target:016x}"
    if rec is None:
        log(f"  teams op6 (CLAN INVITE): no such clan 0x{key} -- ignored")
        return 0, None
    if theirs in rec.get("members", []):
        log(f"  teams op6 (CLAN INVITE): 0x{theirs} is already in "
            f"{rec.get('name')!r}")
        return 0, None
    props = rec.setdefault("proposals", [])
    if not any(p.get("to") == theirs for p in props):
        props.append({"to": theirs, "from": f"{me:016x}", "from_name": name,
                      "at": ts()})
        _jsave(TEAMS_DB, d)
    fd = friends_db()
    log(f"  teams op6 (CLAN INVITE): {name} invites 0x{theirs} "
        f"({fd['names'].get(theirs) or 'unknown account'}) to "
        f"{rec.get('name')!r} 0x{key} -- {len(props)} proposal(s) outstanding")
    # `Teams op 24` is NOT the delivery path: it only fires for a console that
    # already belongs to a clan (measured -- the invited, clanless console never
    # sent it), so it is "proposals concerning MY clan", not "invitations to me".
    # The invited console must therefore be told the same way a buddy or match
    # invite tells it: a lobby message. The game has the inbox string
    # `Clan %CLAN% invite from %GAMER%` to render it.
    ptype = int(d.get("invite_push_type", CLAN_INVITE_PUSH_DEFAULT))
    if not ptype:
        log("  (clan invite filed but NOT delivered: the lobby-message layout "
            "for a clan type is unsolved -- see netrecon.md Phase 25. Set "
            "\"invite_push_type\" in capture/teams-db.json to try an id.)")
        return 0, None
    blob = tid.to_bytes(8, "little")
    cname = rec.get("name", "")
    tname = fd["names"].get(theirs, "")
    mid = message_add(target, ptype, me, name, blob, cname)
    push_to_account(target, ptype, me, name, mid, blob, cname,
                    target=target, target_name=tname)
    return 0, None


def teams_answer_invite(accept: bool, dec: dict, who=None, peer_ip: str = ""):
    """Teams op 8 (accept) / op 7 (decline) -- answer a clan invitation.

    `[u8 0][u64 teamId][u64 inviter]`, the same shape as `op 6` and the same
    convention as `Friends op 2`: the request names the OTHER party, not itself.
    Measured on the wire the moment `Accept clan invite` was finally reachable
    (Phase 38) -- op 8 fires, then `Messaging op 4` deletes the invite, exactly
    as a buddy accept does.

    Neither reads results: Teams op 7 and 8 are both on the dispatcher's
    "reads nothing" arm (`0x08c29874`), so the bare `err=0, 0 results` is
    correct and the work here is purely the server's own bookkeeping.
    """
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
    d = teams_db()
    key = f"{tid:016x}"
    rec = d["teams"].get(key)
    mine = f"{me:016x}"
    if rec is None:
        log(f"  teams op{8 if accept else 7} ({verb} CLAN INVITE): no such clan "
            f"0x{key} -- ignored")
        return 0, None
    props = rec.get("proposals", [])
    had = any(p.get("to") == mine for p in props)
    rec["proposals"] = [p for p in props if p.get("to") != mine]
    if accept and mine not in rec.setdefault("members", []):
        rec["members"].append(mine)
    _jsave(TEAMS_DB, d)
    log(f"  teams op{8 if accept else 7} ({verb} CLAN INVITE): {name} "
        f"0x{mine} {'joins' if accept else 'declines'} {rec.get('name')!r} "
        f"0x{key} (invited by 0x{inviter:016x}"
        + ("" if had else ", but no proposal was on file")
        + f") -- {len(rec['members'])} member(s), "
        f"{len(rec['proposals'])} proposal(s) left")
    # TELL THE INVITER. Without this their roster is stale until they sign in
    # again: `Teams op 21` fires at sign-in and nothing else re-reads it, so the
    # console that sent the invite goes on showing a clan of one. Types 14 and
    # 15 sit unused right beside the 13 this server already pushes, and 14
    # `Caccept` / 15 `Creject` is what they are for.
    if inviter and inviter != me:
        clan_notify(inviter, CLAN_MSG_CACCEPT if accept else CLAN_MSG_CREJECT,
                    tid, rec.get("name") or "", me, name,
                    target=me, target_name=name)
    return 0, None


def _teams_req_pair(dec: dict, op: int):
    """The shape every clan-administration request shares: `[u8 0][u64][u64]`.

    Decoded from the request builders in Phase 40 -- ops 3, 4, 5, 26 and 27 all
    call the same three-field builder, and the two u64s are always (teamId,
    gamerId) IN THAT ORDER. `op 25` is the exception in the family and reads the
    pair the OTHER way round; it has no handler, which is why nothing noticed.
    """
    r = lsg_request_params(dec)
    r.u8()
    return r.u64(), r.u64()


def _teams_actor(peer_ip: str, who):
    return account_for(peer_ip), (who or (rigconfig.USERNAME, 0))[0]


def teams_set_rank(promote: bool, dec: dict, who=None, peer_ip: str = ""):
    """Teams op 3 (promote to administrator) / op 26 (demote to member).

    `[u8 0][u64 teamId][u64 gamerId]`. Both are OWNER-only in the client: the
    rows are conditional adds, so an ordinary member is not shown a greyed
    button, the verb simply is not on the menu (`0x08a06444` promote,
    `0x08a06e4c` demote).

    The rank is written into the team record's `ranks` map, which is exactly
    what `team_rank()` already reads -- so the whole of promote/demote is one
    number in the store, and the client picks it up at its next `Teams op 21`.

    **Demote cannot be reached until promote works**, and that is not a UI
    quirk: the demote row is gated on the target's rank being ADMINISTRATOR,
    and until Phase 40 this server only ever served 0 or 2. So the two verbs had
    to be built together or neither could be tested.
    """
    op = 3 if promote else 26
    verb = "PROMOTE" if promote else "DEMOTE"
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, op)
    except Exception as e:
        log(f"  (teams op{op} decode failed: {e})")
        return 0, None
    d = teams_db()
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = d["teams"].get(key)
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
    _jsave(TEAMS_DB, d)
    log(f"  teams op{op} ({verb} CLAN MEMBER): {name} 0x{mine} sets 0x{them} "
        f"to {'administrator' if promote else 'member'} (rank "
        f"{ranks[them]}) in {rec.get('name')!r} 0x{key}")
    clan_notify(target, CLAN_MSG_CADMIN if promote else CLAN_MSG_CORDINARY,
                tid, rec.get("name") or "", me, name,
                target=target, target_name=account_name(target))
    return 0, None


def teams_remove_member(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 4 -- remove a member from the clan ("Remove from clan").

    `[u8 0][u64 teamId][u64 gamerId]`, ADMIN or OWNER. Its launcher
    (`0x089ae364`) is shared with cancel-invite and branches on a per-gamer
    relationship flag (0x800): a real member gets op 4, a pending invitee gets
    op 25 from the same button.
    """
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, 4)
    except Exception as e:
        log(f"  (teams op4 decode failed: {e})")
        return 0, None
    d = teams_db()
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = d["teams"].get(key)
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
    _jsave(TEAMS_DB, d)
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
    """Teams op 5 -- leave the clan, DISBAND it, or remove a member. All three.

    `[u8 0][u64 teamId][u64 gamerId]`, and the three meanings are told apart by
    the caller's role and by whether the gamer id is zero:

        target == 0, caller is not the owner   -> the caller leaves
        target == 0, caller IS the owner       -> DISBAND the whole clan
        target != 0                            -> remove that member

    **There is no separate disband opcode, and there is no disband menu row.**
    Ten `%CLAN%` verbs map to nine wire verbs. For the owner, `Leave clan`
    becomes the disband chain: it asks "Transfer ownership of clan X?" first,
    and pressing CIRCLE there -- declining the transfer -- is the step FORWARD
    to "Disband clan X?". The two launchers (`0x089ba4c4` no-gamer and
    `0x089ba65c` selected-gamer) put identical bytes on the wire for leave and
    disband, both with target 0, so the server cannot tell them apart from the
    request and must decide from the caller's role. That is not a guess: the
    no-gamer launcher loads its target from a static pair at `0x08d39b98`, which
    is zero.
    """
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, 5)
    except Exception as e:
        log(f"  (teams op5 decode failed: {e})")
        return 0, None
    d = teams_db()
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = d["teams"].get(key)
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
        _jsave(TEAMS_DB, d)
        log(f"  teams op5 (REMOVE FROM CLAN): {name} 0x{mine} removes 0x{them} "
            f"from {cname!r} 0x{key} -- {len(rec['members'])} member(s) left")
        clan_notify(target, CLAN_MSG_CKICKED, tid, cname or "", me, name,
                    target=target, target_name=account_name(target))
        return 0, None
    if rec.get("owner") == mine:
        members = [m for m in rec.get("members", []) if m != mine]
        del d["teams"][key]
        _jsave(TEAMS_DB, d)
        log(f"  teams op5 (DISBAND CLAN): {name} 0x{mine} disbands {cname!r} "
            f"0x{key} -- {len(members)} other member(s) lose it")
        for m in members:
            clan_notify(int(m, 16), CLAN_MSG_CDISBAND, tid, cname or "", me, name,
                        target=me, target_name=name)
        return 0, None
    _team_drop(rec, mine)
    _jsave(TEAMS_DB, d)
    log(f"  teams op5 (LEAVE CLAN): {name} 0x{mine} leaves {cname!r} 0x{key} "
        f"-- {len(rec['members'])} member(s) left")
    for m in rec.get("members", []):
        clan_notify(int(m, 16), CLAN_MSG_CLEFT, tid, cname or "", me, name,
                    target=me, target_name=name)
    return 0, None


def teams_transfer_owner(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 27 -- hand the clan to another member ("Transfer ownership").

    `[u8 0][u64 teamId][u64 gamerId]`, OWNER only -- the row is not added at all
    otherwise (`0x089cda18` skips the whole add), so there is nothing greyed to
    see. Picking the new owner is a second screen, `UserProfileClanOwnerSelect`,
    whose list is `[empty]` in a one-member clan.

    The OLD OWNER BECOMES AN ORDINARY MEMBER here. Nothing in the client says
    what should happen to them -- `Net.Ack.SetOwner` only names the new owner --
    so this is the server's choice, and it is the conservative one: no lingering
    administrator rights that nobody granted.
    """
    me, name = _teams_actor(peer_ip, who)
    try:
        tid, target = _teams_req_pair(dec, 27)
    except Exception as e:
        log(f"  (teams op27 decode failed: {e})")
        return 0, None
    d = teams_db()
    key, mine, them = f"{tid:016x}", f"{me:016x}", f"{target:016x}"
    rec = d["teams"].get(key)
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
    ranks.pop(them, None)                      # the owner's rank is implied
    ranks[mine] = TEAM_RANK_MEMBER
    _jsave(TEAMS_DB, d)
    log(f"  teams op27 (TRANSFER OWNERSHIP): {name} 0x{mine} hands "
        f"{rec.get('name')!r} 0x{key} to 0x{them}; the old owner is now an "
        f"ordinary member")
    clan_notify(target, CLAN_MSG_COWNER, tid, rec.get("name") or "", me, name,
                target=target, target_name=account_name(target))
    return 0, None


def teams_op10(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 10 -- `[u8 0][u64 gamerId]`, and NOT one of the ten clan verbs.

    All ten are placed elsewhere, and this one carries no team id at all. Its
    single trigger in the whole image is inside the BLOCK-A-GAMER chain
    (`0x08a0f948`), one state after the same chain fires op 7 (decline clan
    invite) on the same gamer -- so it is the second half of a clan cleanup
    performed when you block someone. Two readings fit and the client cannot
    separate them: withdraw my outstanding proposal to this gamer (the Teams
    analogue of `Friends op 13`), or remove them from my clan without naming it.

    Logged rather than acted on. A bare reply is right either way -- op 10 is on
    the dispatcher's "reads nothing" arm -- and guessing wrong here would delete
    a membership nobody asked to lose. To settle it: block a gamer you have
    invited to your clan, and see which id arrives.
    """
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

    Fires at every sign-in, so it is the clan equivalent of `Friends op 19` +
    the mailbox: whatever `Teams op 6` filed shows up here next time the invited
    console signs in. Whether the client ALSO expects a lobby push (there is a
    `Clan %CLAN% invite from %GAMER%` inbox string) is not established -- the
    clan message type ids are somewhere in the 8 / 11..33 block that
    `net::tBuddy` stubs out, and no table for them has been found yet.
    """
    me = account_for(peer_ip)
    mine = f"{me:016x}"
    fd = friends_db()
    rows = []
    for tid, rec in teams_db()["teams"].items():
        for pr in rec.get("proposals", []):
            if pr.get("to") == mine:
                rows.append((int(tid, 16), int(pr["from"], 16),
                             rec.get("name", ""),
                             pr.get("from_name") or fd["names"].get(pr["from"], "")))
    log(f"  teams op24 (clan proposals) for 0x{mine}: {len(rows)}"
        + ("".join(f" -> {n!r} from {who_!r}" for _t, _f, n, who_ in rows)
           if rows else ""))
    if not rows:
        return 0, None        # a bare numResults=0 is a legal empty answer

    def emit(w):
        for tid, inviter, tname, iname in rows:
            w.u64(tid)
            w.u64(inviter)
            w.str_(tname, 63)
            w.str_(iname, 63)
    return len(rows), emit


# ------------------------------------------------------------- downloads
#
# bdStorage ops 7 and 8 are the Downloads menu. Op 8 (list everything global)
# and op 7 (list one account's files) both fire during sign-in and both read a
# [u32 numResults]; the Downloads SCREEN itself makes no request at all, it just
# draws what those two returned. Row layout (container method 0x08c2616c, the
# per-row tail 0x08c268ac):
#
#   [u32 size][u64 fileID][u32 created][u32 modified][bool isPrivate]
#   [bool ?][u64 ownerID][str filename]      filename <= 127 chars
#
# isPrivate is not a guess: net::tStorage prints "private:\%s" when it is set
# and "public:\%s" when it is not (0x08d38ba4 / 0x08d38b98).
#
# capture/storage-db.json lists what to serve; the bytes live beside it in
# capture/storage/. Empty (the default) is a legal, quiet answer.
STORAGE_DB = CAP / "storage-db.json"
STORAGE_DIR = CAP / "storage"


def storage_files() -> list:
    d = _jload(STORAGE_DB, {})
    return d.get("files", []) if isinstance(d.get("files"), list) else []


def storage_list_result(op: int, dec: dict, who=None, peer_ip: str = ""):
    """Storage op 7 (by owner) / op 8 (global). Both reply [u32 n] + n rows.

    Phase 29: op 7 is "list the files owned by THIS ENTITY", and the entity is a
    REQUEST PARAMETER, not the caller. bddump of every op 7 in
    session-20260911-135207.log shows eight distinct ids in field [2], nine of
    them 0x5ed7f893cb52b73e -- which is player3, fired by console 4 while
    downloading player3's profile. (op 8, the global list, has no such field:
    its request is [u8 op][u8 0][u32][u16] and stops there.)

    Until now the server ignored that id and answered with `account_for(peer_ip)`
    -- the CALLER's own files -- so every remote profile was told it owned
    whatever the viewer owned. WOW2_NO_STORAGE_OWNER=1 restores the old
    behaviour for a bisect.

    NOT yet proven to change anything on screen: a remote profile's
    `View shared landscapes` / `View shared schemes` rows stayed greyed even when
    the op 7 reply carried valid `.sl1` / `.ss2` names (measured twice, Phase 29),
    so something other than this list decides that. The fix is made because the
    old answer was factually wrong, not because a screen was seen to change.
    """
    me = account_for(peer_ip)
    owner = me
    if op == 7 and os.environ.get("WOW2_NO_STORAGE_OWNER") != "1":
        try:
            r = lsg_request_params(dec)
            r.u8()                          # leading flags byte
            owner = r.u64() or me
        except Exception as e:
            log(f"  (storage op7 owner decode failed: {e}; falling back to caller)")
    files = storage_files()
    if op == 7:
        files = [f for f in files if f.get("owner") in (None, f"{owner:016x}")]
    else:
        files = [f for f in files if not f.get("owner")]
    log(f"  storage op{op} ({'by owner' if op == 7 else 'global'}) for "
        f"0x{owner:016x}"
        + (f" (asked by 0x{me:016x})" if owner != me else "")
        + f": {len(files)} file(s)"
        + (" -> " + ", ".join(f.get("name", "?") for f in files) if files else ""))

    def emit(w):
        # NO count here: build_lsg_taskreply_encrypted already wrote the
        # [u32 numResults] this arm reads. Writing it again would put the rows
        # one field late -- the mistake that cost Phase 22 five sign-ins.
        for i, f in enumerate(files, start=1):
            body = storage_bytes(f)
            w.u32(len(body))                                  # size
            w.u64(int(f.get("id", i)))                        # file id
            w.u32(int(f.get("created", 0)))
            w.u32(int(f.get("modified", 0)))
            w.bool_(bool(f.get("private")))
            w.bool_(False)
            w.u64(int(f.get("owner", "0"), 16) if f.get("owner") else 0)
            w.str_(f.get("name", ""), 127)
    return len(files), emit


def storage_bytes(f: dict) -> bytes:
    if f.get("data") is not None:
        return str(f["data"]).encode("latin1", "replace")
    try:
        return (STORAGE_DIR / f.get("file", "")).read_bytes()
    except OSError:
        return b""


def storage_get_result(dec: dict, who=None, peer_ip: str = ""):
    """Storage op 5 -- fetch one file's bytes. ONE row, and the arm at
    0x08c275bc calls the container with a hard-coded count of 1, so this reply
    must NOT carry a numResults field (same trap as Teams op 1)."""
    try:
        r = lsg_request_params(dec)
        r.u8()
        fid = r.u64()
    except Exception as e:
        log(f"  (storage op5 decode failed: {e})")
        return 0, None
    f = next((x for x in storage_files() if int(x.get("id", 0)) == fid), None)
    body = storage_bytes(f) if f else b""
    log(f"  storage op5 (get file 0x{fid:x}): "
        + (f"{f.get('name')!r} {len(body)} bytes" if f else "no such file"))

    def emit(w):
        w.blob(body)
    # A MISS MUST STILL BE ONE ROW. The op-5 arm (0x08c275bc) calls its
    # container with a hard-coded count of 1, so `0 results` leaves the
    # deserializer reading a blob that is not there: the container returns
    # false and the client drops the whole LSG connection ~330 ms later
    # ("Connection Lost"). An empty blob is the quiet answer.
    return None, emit


# bdStorage op 1 -- UPLOAD. First seen 2026-09-11 (Phase 27), fired by
# `Upload flag` and by `View shared schemes` -> Upload on the User profile edit
# screen:
#
#   [u8 0][bool published][str filename <=128][bool isPrivate][blob data]
#
# The reply is ONE typed u64 -- the file id the server assigns -- and NO
# numResults field: the single-result arm (0x08c275bc) hard-codes a count of 1
# at 0x08c275fc, the same trap as Teams op 1 and Storage op 5. The id must be
# NON-ZERO; 0 is the client's "no id yet" sentinel, which is exactly the bug
# that made the session id and the security key unusable in Phase 14-17.
#
# WHAT MAKES A FILE VISIBLE is the FILENAME, not the owner or any flag: each
# screen applies a hard-coded extension whitelist (Downloads wants `.da0` /
# `.flg`, shared landscapes `<7 chars>.sl<0-7>`, shared schemes
# `<6 chars>.ss<0-7>`), and `private` must be false because the client prefixes
# `public:\` and indexes the type letter at the fixed offset name+8.
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
    d = _jload(STORAGE_DB, {})
    files = d.setdefault("files", [])
    fid = 0
    for f in files:
        if f.get("name") == name and int(f.get("owner", 0) or 0) == me:
            fid = int(f.get("id", 0) or 0)
            break
    if not fid:
        used = {int(f.get("id", 0) or 0) for f in files}
        fid = next(i for i in range(0x5001, 0x5001 + 4096) if i not in used)
    blob_name = f"{fid:x}-{name}"
    try:
        STORAGE_DIR.mkdir(parents=True, exist_ok=True)
        # Atomic, same reason as _jsave: a torn write would leave a half file
        # that the client later downloads as a corrupt landscape or scheme.
        blob_tmp = STORAGE_DIR / f"{blob_name}.tmp-{os.getpid()}"
        blob_tmp.write_bytes(data)
        os.replace(blob_tmp, STORAGE_DIR / blob_name)
    except OSError as e:
        log(f"  (storage op1 could not write {blob_name}: {e})")
    rec = {"id": fid, "name": name, "owner": me, "file": blob_name,
           "private": bool(private), "size": len(data)}
    files[:] = [f for f in files if int(f.get("id", 0) or 0) != fid] + [rec]
    _jsave(STORAGE_DB, d)
    log(f"  storage op1 (UPLOAD): {name!r} {len(data)} bytes from "
        f"0x{me:016x} -> file id 0x{fid:x} "
        f"(published={published} private={private})")

    def emit(w):
        w.u64(fid)
    return None, emit


def storage_overwrite_result(dec: dict, who=None, peer_ip: str = ""):
    """Storage op 2 -- replace a file's contents, by id.

    `[u8 0][u64 fileId][blob data]`, read straight off the request builder at
    `0x08c26e18` (ROADMAP A3): `tag 3` + a zero byte, `tag 0xa` + 64 bits, then
    `tag 0x13` + `tag 8` length + the bytes.

    READS NOTHING. The reply dispatcher (`0x08c27490`) sends only ops 1 and 5 to
    the single-result arm and ops 7/8 to the row arm; 2, 3, 4 and 6 fall through
    to the exit. So the bare `err=0, 0 results` is right, and unlike op 1 there
    is no id to hand back.
    """
    me = account_for(peer_ip)
    try:
        r = lsg_request_params(dec)
        r.u8()
        fid = r.u64()
        data = r.blob()
    except Exception as e:
        log(f"  (storage op2 decode failed: {e})")
        return 0, None
    d = _jload(STORAGE_DB, {})
    files = d.setdefault("files", [])
    rec = next((f for f in files if int(f.get("id", 0) or 0) == fid), None)
    if rec is None:
        log(f"  storage op2 (OVERWRITE): no file 0x{fid:x} -- ignored")
        return 0, None
    owner = int(rec.get("owner", 0) or 0)
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
    rec["size"] = len(data)
    _jsave(STORAGE_DB, d)
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
    d = _jload(STORAGE_DB, {})
    files = d.setdefault("files", [])
    rec = next((f for f in files if int(f.get("id", 0) or 0) == fid), None)
    if rec is None:
        log(f"  storage op4 (DELETE): no file 0x{fid:x} -- ignored")
        return 0, None
    owner = int(rec.get("owner", 0) or 0)
    if owner and owner != me:
        log(f"  storage op4 (DELETE): file 0x{fid:x} {rec.get('name')!r} "
            f"belongs to 0x{owner:016x}, not 0x{me:016x} -- REFUSED")
        return 0, None
    files[:] = [f for f in files if int(f.get("id", 0) or 0) != fid]
    _jsave(STORAGE_DB, d)
    # The blob is kept. A delete here removes the file from every listing, which
    # is what the client asked for; leaving the bytes on disk costs nothing and
    # has twice saved a landscape that was deleted from the wrong console.
    log(f"  storage op4 (DELETE): file 0x{fid:x} {rec.get('name')!r} removed by "
        f"0x{me:016x} ({len(files)} file(s) left; the blob is kept on disk)")
    return 0, None


def teams_create_result(dec: dict, who=None, peer_ip: str = ""):
    """Teams op 1 -- create a clan. Returns exactly ONE result: [u64 teamID].

    bdCreateTeamResult::deserialize (0x08c27ddc) reads one typed u64 and asserts
    on anything but 0 or 1 results, so a clan needs an id and nothing else.
    """
    me = account_for(peer_ip)
    who_name = (who or (rigconfig.USERNAME, 0))[0]
    try:
        r = lsg_request_params(dec)
        r.u8()                                       # always 0
        clan = r.str_(64)
    except Exception as e:
        log(f"  (teams op1 decode failed: {e})")
        return 0, None
    d = teams_db()
    mine = f"{me:016x}"
    existing = next((tid for tid, rec in d["teams"].items()
                     if rec.get("name", "").lower() == clan.lower()), "")
    if existing:
        rec = d["teams"][existing]
        if mine not in rec["members"]:
            rec["members"].append(mine)
        tid = int(existing, 16)
        log(f"  teams op1 (CREATE): {who_name} joined existing clan {clan!r} "
            f"id=0x{tid:016x} ({len(rec['members'])} member(s))")
    else:
        tid = TEAM_ID_BASE + d["next"]
        d["next"] += 1
        d["teams"][f"{tid:016x}"] = {"name": clan, "owner": mine, "members": [mine],
                                     "created": ts()}
        log(f"  teams op1 (CREATE): {who_name} created clan {clan!r} "
            f"id=0x{tid:016x} ({len(d['teams'])} clan(s))")
    _jsave(TEAMS_DB, d)
    friends_note_name(me, who_name)

    def emit(w):
        w.u64(tid)
    return None, emit          # None = no [u32 numResults]; see the reply builder


def lsg_result_block(svc: int, op: int, dec: dict,
                     who: tuple[str, int] | None = None,
                     peer_ip: str = "", ident_key: str = ""):
    """(num_results, writer-callback|None) for one service RPC. Services not listed
    here still take a bare error=0 / numResults=0 reply, which they accept.

    TWO identity arguments, and the distinction matters. `ident_key` is WHO --
    the account name once the connection has said who it is, falling back to the
    source address. `peer_ip` is WHERE -- a real address, and only the Sessions
    family wants it, because a session record stores its host's address and the
    search reply rewrites it. Everything else was using the address as an
    identity, which is why two consoles behind one router were one player.
    """
    if os.environ.get("WOW2_LSG_NORESULTS") == "1":
        return 0, None                      # bisect: go back to Phase 11 behaviour
    if svc == LSG_SERVICE_STATS and op == 1:
        return stats_write_upload(dec, who, ident_key)
    if svc == LSG_SERVICE_STATS and op == 4:
        return stats_read_results(dec, who, ident_key)
    if svc == LSG_SERVICE_STATS and op == 5:
        return stats_pivot_results(dec, who, ident_key)
    if svc == LSG_SERVICE_SESSIONS and op == 1:
        return sessions_create_result(dec, peer_ip)
    if svc == LSG_SERVICE_SESSIONS and op == 2:
        return sessions_update(dec, peer_ip)
    if svc == LSG_SERVICE_SESSIONS and op == 3:
        return sessions_delete(dec)
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
        # NEVER OBSERVED. Phase 22 paired it with op 2 as "decline", by symmetry.
        # Phase 28 measured the decline and it is op 4, so op 3 is an unknown
        # that no screen has ever fired. Left wired because the handler is
        # harmless and a bare reply is right for it either way.
        return friends_answer(dec, False, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 4:
        return friends_revoke(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 6:
        return friends_block(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 8:
        return friends_match_invite(dec, who, ident_key)
    if svc == LSG_SERVICE_FRIENDS and op == 10:
        return friends_match_decline(dec, who, ident_key)
    if svc == LSG_SERVICE_PROFILE and op == 2:
        return profile_read_public(dec, who, ident_key)
    if svc == LSG_SERVICE_PROFILE and op == 4:
        return profile_upload(dec, who, ident_key)
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
    """The two typed fields every auth request opens with: (iv_seed, titleId).

    Auth request bodies are bd BIT STREAMS, exactly like LSG messages -- they were
    read as raw hexdumps for a long time, which is why the title id looked like a
    stray `ea 98 00` smeared across a byte boundary instead of a typed u32. The
    shape is
        [u8 msgType][1 bit type_checked=1][tag u32][u32 iv_seed][tag u32][u32 titleId]
    and then whatever that message type appends. Verified against all 64 captured
    auth bodies: field[1] is 0x131d in every one of them, both message types.
    """
    r = bd.BdReader(body)
    msg_type = r.u8()
    r.bitmode = True
    r.read_type_checked_bit()
    r.type_checked = True
    return msg_type, r.u32(), r.u32(), r


def auth_cbc_decrypt(ct: bytes, key24: bytes, iv: bytes) -> bytes:
    """3DES-EDE-CBC as the CLIENT does it, degenerate keys and all.

    pycryptodome refuses a DES3 key whose halves repeat, and both keys the auth
    path actually uses are degenerate: the bootstrap key has K1 == K2, and the
    rig's session key is one byte repeated. EDE with K1 == K2 is just E_K3, so
    fall back to single DES on K3 rather than pretending the key is illegal.
    """
    k1, k2, k3 = key24[0:8], key24[8:16], key24[16:24]
    if k1 == k2:
        return DES.new(k3, DES.MODE_CBC, iv).decrypt(ct)
    if k1 == k3:                      # EDE with K1 == K3 is still a real 2-key 3DES
        return DES3.new(key24, DES3.MODE_CBC, iv).decrypt(ct)
    return DES3.new(key24, DES3.MODE_CBC, iv).decrypt(ct)


def auth_payload_decrypt(ct: bytes, key24: bytes, iv_seed: int) -> bytes | None:
    """Decrypt an auth payload and check its magic. None means the key was wrong.

    The magic is the client's own integrity check -- a 32-bit value at a known
    offset, so a wrong key is caught with ~2^-32 false accepts. That is what lets
    the server VERIFY a password without ever holding one: try the stored hash as
    the key and see whether the magic comes back.
    """
    pt = auth_cbc_decrypt(ct, key24, tiger_iv(iv_seed))
    if int.from_bytes(pt[:4], "little") != BD_AUTH_MAGIC:
        return None
    return pt


def parse_login(body: bytes) -> dict:
    """Decode a 0x0a (login) request. It IDENTIFIES THE ACCOUNT -- 19 bytes:

        [u8 0x0a][tc bit][u32 iv_seed][u32 titleId][64 raw bits]

    and the 64-bit field is `Tiger192(username)[:8]`, checked against **180 of
    180** captured login requests across eight consoles. The project had this
    down as "type, iv_seed, proof" and the server ignored it, guessing identity
    from the source IP instead -- which is the single thing that made two players
    behind one router into one player.

    There is no password proof in this message, and that is not an oversight: the
    authentication runs the other way. The client says who it is, and the SERVER
    proves it knows the account by encrypting the login reply with
    Tiger192(password) -- a server that does not know it cannot produce a reply
    the client accepts. `build_login_reply(session_key, key24=...)`.
    """
    msg_type, seed, title, r = parse_auth_header(body)
    r.type_checked = False
    return {"type": msg_type, "iv_seed": seed, "title_id": title,
            "handle": bytes(r.read_bits(64)[:8])}


def parse_lsg_connect(payload: bytes) -> dict | None:
    """Pull the ClientOpaqueAuthProof out of an LSG connect message (service 7).

        [u8 enc=0][u8 service=7][tc bit][u32 titleId][u32 0][128B proof, raw]
        16 + 1 + 37 + 37 + 1024 = 1115 bits -> 140 bytes, the captured length.

    The proof is the one `build_client_opaque_proof()` issued at login and the
    client relays verbatim; it is UNENCRYPTED by design. It carries the username
    and the session key, so **the LSG connection can identify itself from its own
    first message** -- no source address anywhere in the chain.

    (Correction while decoding this: the server has always logged service 7 as
    `op=29`. There is no op. 29 is the low byte of the title id, 0x131d & 0xff,
    read by a `u8()` where the field is a typed u32. Harmless -- nothing branches
    on it -- but it is not an opcode and `gapmap` should not grow one.)
    """
    if len(payload) < 4 or payload[0] == 1:
        return None
    magic = struct.pack("<Q", OPAQUE_PROOF_MAGIC)
    r = bd.BdReader(payload)
    r.bitmode = True
    try:
        r.read_bits(16 + 1 + 37 + 37)       # enc, service, tc bit, titleId, u32 0
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
    """Decode a 0x00 (create account) request -- username and password, in clear.

    Read off the builder at `0x08c141b4` (`sb $zero, ($sp)` is the type byte) and
    confirmed by decrypting all 62 captured requests, which yielded every
    console's real name and `Tiger192('123456')`, the rig's password, with zero
    failures:

        [u8 0x00][tc bit][u32 iv_seed][u32 titleId]
        [ 64 bits zero ]        <- hash64(account), and there is no account yet
        [768 bits ciphertext, 96 bytes]
            key = BD_BOOTSTRAP_KEY          (see its comment: effectively DES-0)
            iv  = Tiger192(iv_seed as LE u32)[:8]
            plaintext = [u32 LE 0xEFBDADDE]
                        [char username[64], zero-filled then NUL-terminated]
                        [Tiger192(password), 24 bytes]
                        [4 bytes pad]

    THE POINT: `password_hash` is exactly `account_key(password)` -- the key the
    login proof is encrypted with. So a credential store can hold the digest and
    never a password, and the server never needs to know what the player typed.
    """
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
    """Decode a 0x02 (change password) request.

    Read straight off the builder at `0x08c14400` (reached from
    bdAuthService::changePassword `0x08c13a20`, which the game calls at
    `0x08971200`). After the common header it writes two RAW, UNTAGGED fields --
    `0x08be619c(buf, src, nbits)` with 0x40 and 0x100 bits:

        [u8 0x02][tc bit][u32 iv_seed][u32 titleId]
        [ 8B user hash  ]      <- 0x08c19fbc(username), a 64-bit digest
        [32B ciphertext ]      <- E(key = hash(currentPassword), iv = f(iv_seed))
                                  over [u32 0xEFBDADDE][hash(newPassword)][pad]

    The bit arithmetic is exact: 8 + 1 + (5+32) + (5+32) + 64 + 256 = 403 bits
    = 51 bytes, which is the captured body length to the byte.

    All of it is confirmed against a live capture with a KNOWN current password:
    console 1 typed 123456 / 135790 and the payload decrypted to
    `deadbdef` + `Tiger192('135790')` + four zero bytes, exact.

    `candidate_keys` are (label, 24-byte key) pairs to try. The magic is the
    client's own integrity check, so a key that reproduces it IS the account's
    password hash -- which is how the current password gets VERIFIED without the
    server ever holding a password.
    """
    msg_type, seed, title, r = parse_auth_header(body)
    r.type_checked = False          # the rest is raw bits, no type tags
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
    """Reproduce bd auth response framing (response.rs::to_response):
    bit-mode: u8 type (untyped) -> type_checked_bit=1 -> u32 error (typed) ->
    auth_data (raw bytes, already bit/byte-shaped by caller). Then wrap
    unencrypted: [u32 le len][0x00][payload]."""
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(reply_type)                 # 8 bits, untyped
    w.type_checked = True
    w.write_bits(b"\x01", 1)         # type_checked_bit = 1
    w.u32(error_code)                # typed u32 (5-bit tag 8 + 32 bits)
    payload = w.getvalue()
    if auth_data:
        payload += auth_data         # ticket/proof appended at byte boundary
    return bd.frame_unencrypted(payload)


#: Live connections per source address, for the concurrency cap.
CONNS_PER_IP: dict[str, int] = {}


class AuthConnection(asyncio.Protocol):
    def connection_made(self, transport):
        self.t = transport
        self.peer_ip, self.peer_port = transport.get_extra_info("peername")[:2]
        self.peer = f"{self.peer_ip}:{self.peer_port}"
        self.ident = identity_for(self.peer_ip)
        self.buf = b""
        self.rx_bytes = 0          # byte COUNT, not the bytes
        self.msg_window = [0.0, 0]  # [window start, messages in it]
        self.counted = False       # did we take a slot in CONNS_PER_IP?
        self.next_txn = 0          # TaskReply transaction ids, like the reference
        self.is_lsg = False        # set by the buffer-size announce (LSG conns only)
        self.account = None        # bound at login / at LSG connect, from the WIRE
        self.session_key = None    # per-sign-in LSG key; None until bound
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
        """Per-connection caps. A peer that misbehaves loses its OWN connection.

        `self.rx` used to be the whole byte stream, kept forever and used for
        nothing but its length in a log line -- so any peer could grow the
        server's memory without bound just by sending. It is a counter now, and
        the counter itself is capped.
        """
        self.rx_bytes += len(data)
        if self.rx_bytes > serverconfig.MAX_STREAM_BYTES:
            log(f"  (!! {self.peer} sent {self.rx_bytes}B this connection, over "
                f"limits.max_stream_bytes -- closing)")
            return True
        return False

    def over_msg_rate(self, n: int) -> bool:
        """Count MESSAGES, not reads. Counting `data_received` calls does not
        work: TCP coalesces, and 400 keepalive frames sent back to back arrive
        as one read -- measured, the cap never fired. Frames are what a handler
        costs, so frames are what is limited."""
        now = time.monotonic()
        if now - self.msg_window[0] >= 1.0:
            self.msg_window = [now, n]
        else:
            self.msg_window[1] += n
        # Check AFTER both branches. Checking only the accumulate branch let a
        # single burst through untouched -- 400 frames in one write opened a
        # fresh window and was never compared against anything, which is exactly
        # the shape of the attack the cap is for. Measured: the cap did not fire.
        if self.msg_window[1] > serverconfig.MAX_MSGS_PER_SEC:
            log(f"  (!! {self.peer} sent {self.msg_window[1]} messages in a "
                f"second, over limits.max_msgs_per_sec -- closing)")
            return True
        return False

    def resolve_login(self, body: bytes) -> tuple[str, int, bytes, str]:
        """(username, user_id, proof key, how) for a 0x0a request.

        The handle is authoritative when we recognise it. The source-address
        guess survives only as a fallback for a console whose name we have never
        seen -- on the rig that is nobody, because IDENTITIES names every console
        and a name is all a handle needs.
        """
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
                        f"handle {req['handle'].hex()}, stored credential"
                if serverconfig.SHARED_PASSWORD_FALLBACK:
                    # DEVELOPMENT default: an account with no stored credential
                    # signs in on the shared rig password. It is what lets the
                    # eight-console rig work with an empty store. A deployment
                    # sets accounts.shared_password_fallback = false, and then
                    # only accounts that actually created themselves can sign in.
                    return name, uid, account_key(ACCOUNT_PASSWORD), \
                        f"handle {req['handle'].hex()}, shared password"
                log(f"  (!! {name!r} has no stored credential and the shared "
                    f"password fallback is off -> refusing by answering with a "
                    f"key it cannot have)")
                return name, uid, secrets.token_bytes(24), \
                    f"handle {req['handle'].hex()}, NO CREDENTIAL"
            log(f"  (!! login handle {req['handle'].hex()} is not an account we "
                f"know -- falling back to the source address, which is a GUESS)")
        uname, uid = self.ident
        self.account = uname
        return uname, uid, account_key(ACCOUNT_PASSWORD), "by source address"

    def bind_lsg(self, payload: bytes) -> None:
        """Bind this LSG connection to an account, from its own first message.

        The connect message relays the opaque proof we issued at login, in clear,
        carrying the username and the session key. So the LSG connection does not
        have to be correlated with the login connection by address -- it says who
        it is. That is the last place the source IP decided identity.
        """
        proof = parse_lsg_connect(payload)
        if proof is None:
            log("  (LSG connect carried no readable proof -- identity stays "
                "keyed by source address for this connection)")
            return
        name = proof["username"]
        if session_key_is_ours(name, proof["session_key"]):
            # RE-KEY the push route. LSG_CONNS is populated at the buffer-size
            # announce, which arrives BEFORE this message -- so it went in under
            # the source address, and without this the account-keyed lookup in
            # push_to_account() would never match and connection_lost() would
            # leak the stale entry. Caught by watching a live clan invite log
            # "PUSH type 17 to 10.42.0.2" instead of "to testuser".
            was = self.ident_key
            self.account = name
            self.ident = (name, proof["user_id"] or self.ident[1])
            self.session_key = proof["session_key"]
            if LSG_CONNS.get(was) is self and was != self.ident_key:
                del LSG_CONNS[was]
            if self.is_lsg:
                LSG_CONNS[self.ident_key] = self
            log(f"  LSG connect: account {name!r} id={proof['user_id']} "
                f"(session key verified as one we issued)")
        else:
            # Either a stale key from before a restart, or a client presenting a
            # key we never issued. Name the case rather than trusting it.
            log(f"  (!! LSG connect for {name!r} presents a session key we did "
                f"not issue: {proof['session_key'].hex()[:16]}.. -- "
                f"using the fixed key and the source address)")

    @property
    def ident_key(self) -> str:
        """What identity-keyed state hangs off: the ACCOUNT when we know it.

        Everything used to hang off `peer_ip`, which is why two consoles behind
        one router were one player. Handlers that need a real ADDRESS (the
        Sessions family, which stores a host address and rewrites it) still get
        `peer_ip`; everything else gets this.
        """
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
            # Not framing noise to shrug off -- record it. This is the console's
            # NAT/STUN struct (see bd.parse_frame) and is worth reversing later.
            path = CAP / f"unframed-{self.peer_ip.replace('.', '_')}.bin"
            with open(path, "ab") as f:
                f.write(skipped)
            log(f"  (!! {len(skipped)}B could not be framed; resynchronised past it "
                f"-> {path.name}: {skipped[:32].hex()}...)")
        # Anything the framer could not consume is either a partial frame (fine) or
        # evidence that our length convention is wrong (not fine). Either way, show
        # it -- the LSG connect leaves exactly 1 byte here and it used to be silently
        # discarded, which is precisely the kind of thing that hides a whole message.
        # Logged before handle() because the LSG path drops the buffer to realign.
        if self.buf:
            debug(f"  (leftover {len(self.buf)}B in parse buffer: {self.buf.hex()})")
        if frames and self.over_msg_rate(len(frames)):
            self.t.close()
            return
        for kind, payload in frames:
            # One bad message must not take the connection down with it. Every
            # handler already guards its own parse, but a handler is a lot of
            # code and this is the backstop: drop the message, keep the peer.
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
            # Only bdRemoteTaskManager::onConnected sends this, and it sends it first
            # -- so it is a reliable marker that this socket is the LSG, which matters
            # because the LSG connect message itself carries enc=0 (like the auth
            # messages) and would otherwise be read as an auth request.
            self.is_lsg = True
            LSG_CONNS[self.ident_key] = self        # so a push can be routed here
            n = int.from_bytes(payload, "little")
            log(f"  <- recv BUFSIZE announce: {n} bytes available (no reply); "
                f"this connection is the LSG")
            return
        # kind == msg
        enc, body = bd.unwrap_message(payload)
        debug(f"  <- recv MSG {len(payload)}B enc={enc}\n{hexdump(payload)}")
        if self.is_lsg or enc == 1:
            # LSG (bdLobbyConnection) traffic. Every message is
            #   [u8 enc][u8 service_id][bit-mode: tc-bit, typed u8 op_id, params]
            # (encrypted ones wrap that in [u32 seed][3DES-CBC([u32 hmac] ...)]).
            # Service 7 is the connect/auth presentation and wants a ConnectionId;
            # everything else is a bdRemoteTask RPC and wants a TaskReply carrying
            # the SAME op id back -- the game's own state machine checks it.
            # The connect message is enc=0, so it is readable before any key is
            # bound -- and it is the message that carries the key. Bind first.
            if enc == 0 and len(payload) > 1 and payload[1] == LSG_SERVICE_LOBBY:
                self.bind_lsg(payload)
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
                # The client took session_key=\x42*24 from the login proof (verified
                # live), so it can decrypt an ENCRYPTED reply. Per bd_response.rs the
                # ConnectionId reply is `encrypted_if_available`; the client has the
                # key, so reply encrypted (enc=1). WOW2_LSG_MODE selects the experiment.
                mode = os.environ.get("WOW2_LSG_MODE", "enc_connid")
                if mode == "enc_connid":
                    reply = build_lsg_connid_reply_encrypted(1, session_key)
                    desc = "encrypted LsgServiceConnectionId (enc=1, DES-CBC session key)"
                elif mode == "proof":
                    reply = build_login_reply(session_key, account_key(ACCOUNT_PASSWORD))
                    desc = "0x0b auth proof"
                else:  # plain_connid
                    reply = build_lsg_connid_reply(1)
                    desc = "unencrypted LsgServiceConnectionId (type 4)"
                log(f"  -> send LSG connect reply [{desc}] {len(reply)}B")
                debug(hexdump(reply))
                self.t.write(reply)
                return

            # A service RPC. bdRemoteTaskManager::startTask (0x08c2486c) registered a
            # pending bdRemoteTask for it and the game blocks until it completes, so
            # every request needs an answer -- an unanswered one hangs sign-in forever
            # (the task's timeout is 0 = never).
            # WOW2_LSG_HOLD="svc:op,svc:op" leaves those RPCs unanswered. The client's
            # task timeout is 0 (never), so a held RPC parks the game at "Signing in..."
            # instead of failing -- which is how you bisect *which* reply it rejects:
            # hold one, and if the failure disappears that RPC's result data is the
            # problem, not anything earlier in the chain.
            if f"{svc}:{op}" in os.environ.get("WOW2_LSG_HOLD", "").split(","):
                log(f"  (WOW2_LSG_HOLD: not answering service={svc} op={op})")
                return
            err = int(os.environ.get("WOW2_LSG_ERR", "0"), 0)  # BdErrorCode 0 = NoError
            txn = self.next_txn
            self.next_txn += 1
            nres, results = lsg_result_block(svc, op, dec, self.ident, self.peer_ip,
                                             self.ident_key)
            reply = build_lsg_taskreply_encrypted(session_key, transaction_id=txn,
                                                  error_code=err, operation_id=op or 0,
                                                  num_results=nres, results=results)
            desc = (f"TaskReply (type 1, txn={txn}, service={svc}, op={op}, "
                    f"err={err}, "
                    f"{'1 result, no count field' if nres is None else f'{nres} results'})"
                    f" {len(reply)}B")
            # WOW2_LSG_DELAY holds the reply back N seconds. The client's task timeout
            # is 0 (= never), so it waits happily -- and the pause is a window in which
            # `wow2 mem read` can snapshot the task/connection before *and* after the
            # reply lands. That is the only instrument left when the debugger's
            # breakpoint channel has gone deaf but memory reads still work.
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
            # This request carries the account's REAL name and the key its login
            # proof must be built with, in a payload the client encrypts with a
            # constant it ships (see BD_BOOTSTRAP_KEY). Decoding it is what makes
            # a per-account server possible at all -- until now identity was
            # guessed from the source IP.
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
                    note_account(req["username"], req["password_hash"], self.peer_ip)
            except Exception as e:
                log(f"  (couldn't decode the create-account request: {e})")
            if CREATE_MODE == "name_exists":
                reply = build_auth_reply(AUTH_CREATE_ACCOUNT_REPLY, BD_AUTH_CREATE_USERNAME_EXISTS)
                log(f"  -> send CreateAccountReply (0x01, error 707 name-exists) {len(reply)}B")
            else:
                # Success: account created. Client should proceed to login (0x0a).
                reply = build_auth_reply(AUTH_CREATE_ACCOUNT_REPLY, BD_AUTH_NO_ERROR)
                log(f"  -> send CreateAccountReply (0x01, SUCCESS 700, no body) {len(reply)}B")
            self.t.write(reply)
        elif auth_type == 0x0A:
            # LOGIN. The request says WHO -- Tiger192(username)[:8] -- so identity
            # comes off the wire, not off the source address. The server then
            # proves it knows the account by encrypting the reply with
            # Tiger192(password): a server without the credential cannot produce
            # a reply the client will accept, which is what authentication means
            # here. (The client sends no password proof of its own.)
            uname, uid, kc, how = self.resolve_login(body)
            session_key = new_session_key(uname)
            reply = build_login_reply(session_key, kc, username=uname,
                                      user_id=uid, license_id=uid)
            log(f"  -> send LoginReply (0x0b proof for {uname!r} id={uid} [{how}], "
                f"proof key={kc.hex()[:16]}.., "
                f"session key={session_key.hex()[:16]}..) {len(reply)}B")
            self.t.write(reply)
        elif auth_type == AUTH_CHANGE_PASSWORD_REQ:
            # WHY THIS EXISTS AT ALL: with no reply the console hangs FOREVER.
            # `Change password` on the User profile edit screen opens a new auth
            # TCP connection and its state machine polls the task every frame
            # (`0x089712ec: jal 0x08c13c70 / bnez $v0, return`). m_status is only
            # cleared when a reply is processed, so silence is an infinite lock --
            # every button inert, measured at 48 minutes, recoverable only by
            # restarting the emulator. It is one row from `Upload flag`.
            #
            # ANY reply frees it: the reply dispatcher (`0x08c14764`) reads the
            # typed u32 error FIRST and, when it is not 700, branches straight to
            # `0x08c14db8` ("Task returned with error code %u") and completes the
            # task -- the reply-type byte is never even looked at. The game then
            # maps the code to a string and transitions to its own error state.
            # So an honest refusal is safe and needs none of the unknowns below.
            err = BD_AUTH_UNKNOWN_ERROR
            try:
                # The request names its own account: the 8-byte field is the same
                # Tiger192(username)[:8] the login request carries. So this does
                # not depend on which connection it arrived on -- and it must not,
                # because Change password opens a BRAND NEW auth connection that
                # has never logged in.
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
                    # Say what to do, because this is a dead end for the
                    # console and it cannot tell you so. A change-password
                    # request names its account by HANDLE, which is a one-way
                    # hash, and the name is only ever sent once -- in the create
                    # message. So a server that missed that message, or lost its
                    # store, can never learn the name from any later traffic,
                    # and the console cannot write its own credential by any
                    # route. Only the operator can, and only if a human
                    # remembers the name.
                    log("    no account with that handle -> 704 "
                        "BD_AUTH_BAD_ACCOUNT")
                    log("    (the name is not recoverable from a handle. If you "
                        "know it: wow2-account set <name>, then have the console "
                        "sign in with that password)")
                elif pt is None:
                    # The magic did not come back, so the player mistyped their
                    # CURRENT password. A real answer, and the client has a string
                    # for it.
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
            # REPLY TYPE: 0x03 by the 0x00 -> 0x01 convention. It is NOT confirmed
            # -- the client's only reply-type jump table covers 0x0b..0x13 (real
            # handlers at 0x0b/0x0d/0x0f/0x11, all of which read a user ticket) and
            # 0x03 is outside it. That is harmless here precisely because a non-700
            # error short-circuits before the switch; it would matter for a SUCCESS
            # reply, which this server cannot send yet anyway.
            # REPLY TYPE: 0x03, by the 0x00 -> 0x01 convention. Still not
            # confirmed, and it does not have to be. The client's only reply
            # dispatcher (0x08c14764) reads the error FIRST; a non-700 error
            # short-circuits to 0x08c14db8, and on 700 an out-of-range type falls
            # through 0x08c14d78 to the same `move $v0, $s2` -- so the task
            # completes carrying 700 either way. The reply type matters only for
            # the four handlers that read a user TICKET (0x0b/0x0d/0x0f/0x11), and
            # change-password does not want one.
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
        if LSG_CONNS.get(self.ident_key) is self:
            del LSG_CONNS[self.ident_key]
        log(f"TCP {self.peer} closed ({exc})")
        sessions_host_gone(self.peer_ip)


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
    """What to tell a console its OWN address is, in the 0x1f/0x15 reply.

    This is not cosmetic: the console publishes what we say here. A live create
    request announced private `7f 00 00 01 03 0c`, byte for byte the
    `1f 02 00 7f 00 00 01 03 0c` we had just sent it, and it re-sends that same
    bdCommonAddr *inside the peer protocol*, where the server never sees the
    bytes and host_addr_for() cannot reach them. Telling console 1 "you are
    127.0.0.1" therefore hands every namespaced joiner an address that resolves
    to the joiner's own empty loopback -- and the joiner does try it: right after
    the host's 96-byte session message it fires bdNAT intro requests at both
    announced endpoints, 192.168.178.72:3075 and 127.0.0.1:3075.

    The bridge address is reachable from the host itself and from every
    namespace, so for a loopback client it is strictly the better answer. Only
    rewrite when the bridge actually exists, so a single-console rig with no
    namespaces is untouched. WOW2_NO_SELF_REWRITE=1 disables it.
    """
    if NO_SELF_REWRITE or not BRIDGE_UP or not ip.startswith("127."):
        return ip
    return rigconfig.NETNS_BRIDGE_IP


def server_address_for(client_ip: str) -> str:
    """OUR address, as the console at `client_ip` reaches us.

    Not to be confused with `discovered_self()`, which answers the opposite
    question -- what to tell the console ITS address is. Mixing the two hands a
    console its own address as the server's, and it is not always a harmless
    mistake: the NAT type probe SENDS test 3 to whatever we name here, so a
    console told "the server is you" probes itself and the test silently never
    happens.
    """
    ip = natrelay.server_addr_for(client_ip)
    # The rig's bridge correction, for the same reason as in discovered_self():
    # loopback is right for the host console and useless to every namespaced
    # one. An operator who set `public_address` explicitly is never second-
    # guessed.
    if (ip.startswith("127.") and BRIDGE_UP and not NO_SELF_REWRITE
            and not natrelay.PUBLIC_ADDRESS):
        ip = rigconfig.NETNS_BRIDGE_IP
    return ip


def discovered_endpoint(addr: tuple[str, int]) -> tuple[str, int]:
    """The (ip, port) to tell a console its own public address is.

    WITHOUT the relay this is `discovered_self()` and the console's own source
    port -- a plain STUN-style reflection.

    WITH the relay it is the console's MAILBOX, and that single substitution is
    what makes the whole thing work. The console publishes this address: in the
    `bdCommonAddr` of its create request, in `addrA` of every introduction it
    originates, and -- the one that matters -- in the copy it re-advertises
    inside the encrypted peer protocol, which the server cannot see and could
    never rewrite. Because it is only ever told one address for itself, that
    unreachable-by-the-server copy is correct by construction.
    """
    mb = natrelay.RELAY.mailbox_for(addr)
    if mb is None:
        return discovered_self(addr[0]), addr[1]
    # The mailbox is on US, so the address has to be ours -- and reachable by the
    # console's FUTURE PEER, not by the console itself. A loopback client would
    # otherwise be told the server is at 127.0.0.1, and the namespaced joiner it
    # is about to play would dial its own empty loopback.
    return server_address_for(addr[0]), mb.port


# ---------------------------------------------------------------- NAT TYPE
# The game's own three-test STUN probe, `bdNATTypeDiscoveryClient`. It fires at
# the `stun.*` names, which our DNS points here, and we ignored every packet --
# so the console spent three timeouts at startup and learned nothing.
#
# THE REQUEST IS FOUR BYTES: [u8 0x14][u16 2][u8 changeFlags], built by the
# constructor at 0x08c93974 (`sb 0x14; sh 2, +2; sw flags, +4`) and written by
# the serialiser at 0x08c93990 as 1 + 2 + 1 bytes. The flags are RFC 3489's
# CHANGE-REQUEST bits, read straight off the three call sites:
#
#   test 1  flags 0   plain binding request     -> MAPPED + CHANGED
#   test 2  flags 3   change IP *and* port      -> reply received = BD_NAT_OPEN
#   test 3  flags 2   change port only          -> reply received = BD_NAT_MODERATE
#                                                  no reply         = BD_NAT_STRICT
#
# THE REPLY IS [u8 0x15][u16 2][bdAddr mapped][bdAddr changed] -- first the
# console's own public address, then ours. The client stores them at +0x14 and
# +0xc of the discovery object (0x08c92d3c) and then:
#
#   * test 2's reply is accepted only if its source IP EQUALS changed.ip and its
#     source port DIFFERS from changed.port (0x08c92e84). So `changed` is what
#     decides where test 2 may come from, and it is ours to choose.
#   * test 3's reply is accepted from ANY source; the only check is that the
#     mapped address still matches test 1's (0x08c92f20). Which is why answering
#     test 3 from the MAIN port is worthless: it always arrives, so it always
#     says MODERATE. The distinction the test exists to make is made by the
#     SOURCE PORT, so the reply has to go out of a different socket.
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
        # Nothing should ever dial these; a console only ever talks to the main
        # port. Log it rather than drop it in silence -- if it happens, some
        # assumption above is wrong.
        log(f"UDP {addr[0]}:{addr[1]} -> {self.name} socket, {len(data)}B "
            f"(unexpected): {data[:32].hex()}")


NAT_TYPE_PORT_SOCK: NatTypeSocket | None = None   # same IP, different port
NAT_TYPE_ADDR_SOCK: NatTypeSocket | None = None   # different IP and port


def nat_type_changed_addr(addr: tuple[str, int]) -> tuple[str, int]:
    """What to advertise as CHANGED. It does TWO jobs, and the second is easy to
    miss: it is the address test 2's reply must come from, AND IT IS WHERE THE
    CONSOLE SENDS TEST 3 (`addiu $a1, $a1, 0xc` at 0x08c929f8, against `+4` for
    tests 1 and 2). Name an address the console cannot reach and test 3 is not
    slow or rejected -- it never arrives anywhere, and the probe ends with no
    NAT type at all.

    With a second public address configured this names it, and test 2 becomes a
    real full-cone test. Without one it names us, which is honest and still
    useful -- test 3 comes back here and is answered from the alternate PORT --
    and we then decline to answer test 2 rather than answer it from this address,
    because a reply from the same IP passes the client's check and would declare
    BD_NAT_OPEN for a NAT that is merely address-restricted.
    """
    alt = serverconfig.NAT_TYPE_ALT_ADDRESS
    return (alt or server_address_for(addr[0])), serverconfig.PORT


_UNKNOWN_UDP: list[tuple[str, bytes]] = []

# ------------------------------------------------- bdNAT traversal brokering
#
# bdNATTravClient (the game's own source path string is bdNATTravClient.cpp).
# Its packets are 29 bytes and share one class, bdNATTraversalPacket:
#
#   [0]      u8   type
#   [1:3]    u16  version, always 2 -- the deserialiser bails if it reads < 2
#   [3:13]   u8   hmac[10]
#   [13:17]  u32  identifier        (the peer's bdCommonAddr id; the key the
#                                    originator files its pending request under)
#   [17:23]  bdAddr addrA           4 in_addr bytes + u16 LE port
#   [23:29]  bdAddr addrB
#
# Types, from the switch at +0x48cec4 (dispatcher +0x48a4a4 admits 0x0a..0x13,
# the switch then handles only these five and silently drops the rest):
#
#   0x0a  INTRO NAT REQ   client -> introducer (us). On a CLIENT this case is a
#                         no-op that warns "Received server packet in client
#                         code" -- it is addressed to the server, and we are it.
#   0x0b  relayed intro   introducer -> the target peer. The target flips the
#                         type to 0x0c and sends it to the packet's addrA.
#   0x0c  INTRO REPLY     peer -> originator. HMAC-verified, then the pending
#                         entry's callback is handed the DATAGRAM'S SOURCE
#                         ADDRESS as where the peer can be reached.
#   0x0d  INTRO REQ       peer -> peer directly, same flip-to-0x0c reply.
#   0x0e  keep alive      every 15 s (a literal 15.0f compare in pump()).
#                         Its case body is `b <return>` -- it wants NO reply.
#
# So there is no 0x0f: the "0x1e->0x1f / 0x14->0x15" pattern does not extend
# here, and our silence on 0x0e was correct all along.
#
# Our whole job is one line of work: on 0x0a, put 0x0b in byte 0 and send the
# SAME 29 bytes to addrB. Nothing else may change, because the 10-byte HMAC
# covers identifier|addrA|addrB under a key only the originator has -- the
# relay cannot recompute it and does not need to.
#
# Rewriting an address here is not a small mistake, it is a redirect. An early
# attempt answered the joiner with 0x0b carrying the JOINER's own address in
# addrA; the joiner dutifully sent its 0x0c there, received it, verified the
# (untouched, still valid) HMAC, and took the source address of that datagram
# as the peer -- so it opened a full session handshake with itself, 30/169/106/
# 32-byte datagrams to 10.42.0.2:3074 looping straight back.
NAT_INTRO_REQ = 0x0A
NAT_INTRO_RELAY = 0x0B
NAT_INTRO_REPLY = 0x0C
NAT_KEEPALIVE = 0x0E
NAT_MSG_SIZE = 29
NAT_ADDR_SIZE = 6
NAT_ADDR_UNSET = bytes.fromhex("00ff00ff0000")   # a default-constructed bdAddr

NAT_BROKER = os.environ.get("WOW2_NAT_BROKER", "relay").lower()

# ...re-read per request from capture/nat-broker.mode if that file exists,
# because every server restart costs a full re-drive of BOTH consoles (sign in,
# host, browse) before a join can be attempted again.
#
#   relay   the real thing: 0x0b to the host, verbatim but for byte 0
#   reply   answer the joiner 0x0c ourselves. The HMAC still checks out, but
#           0x0c's callback believes the SOURCE of the datagram is the peer,
#           so this tells the joiner the host is US. Diagnostic only -- it
#           proves the joiner's parse without involving the host at all.
#   off     drop it, i.e. the behaviour before any of this existed
NAT_MODE_FILE = CAP / "nat-broker.mode"


def nat_broker_mode() -> str:
    try:
        line = NAT_MODE_FILE.read_text().split("#")[0].strip().lower()
        return line.partition("=")[2].strip() if "=" in line else (line or NAT_BROKER)
    except OSError:
        return NAT_BROKER


# Where each console's bdNAT socket really is, learned from its keepalives.
# This matters because the addrB a joiner asks for is the address WE gave it:
# host_addr_for() rewrote the host's own 192.168.178.72 to the bridge, so the
# relay has to be SENT to console 1's real 127.0.0.1:3075 while the bytes on
# the wire keep saying 10.42.0.1:3075 -- change them and the HMAC dies.
NAT_PEERS: dict[tuple[str, int], str] = {}


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
    """Translate an advertised peer address to where that console really is.

    A console only ever learns a peer address from us, so the address it names
    is ours to undo. Matching on the port is enough and stays honest: each
    console keepalives from its own single bdNAT socket, so "the endpoint on
    that port which is not the sender" is unambiguous with two consoles, and
    this returns None rather than guessing if that ever stops being true.
    """
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
                # The ONLY reply the console is known to publish (Phase 15: a
                # create request carried these nine bytes back verbatim), so it
                # is the only one that gets a relay mailbox.
                reply = b"\x1f\x02\x00" + bd_addr(*discovered_endpoint(addr))
            elif data[0] == NAT_TYPE_REQ:
                # A different socket asks this one -- measured on the rig, the
                # 0x1e and the bdNAT keepalives both come from the game's bd
                # socket on 3075 while 0x14 comes from an ephemeral port that
                # then says nothing else at all. Handing it a mailbox would burn
                # a port on a console that will never use it and invent a second
                # peer at the same address, so it keeps the plain reflection.
                self.nat_type(data, addr)
                return
        if reply:
            self.t.sendto(reply, addr)
            log(f"UDP {peer} disc 0x{data[0]:02x} -> reply {reply.hex()}")
            return

        msg = nat_parse(data)
        if msg and msg[0] == NAT_KEEPALIVE:
            # One line the first time a console turns up and silence after
            # that: it is every 15 s per console, which buried the log, but
            # never printing it left no way to tell whether the endpoint table
            # the relay depends on had been populated at all.
            if addr not in NAT_PEERS:
                log(f"UDP {peer} bdNAT keepalive -- console registered "
                    f"(now {len(NAT_PEERS) + 1} known)")
            NAT_PEERS[addr] = peer
            # The keepalive is what holds this mapping open, and the mapping is
            # where the bootstrap 0x0b has to be sent -- so it is also the right
            # place to make sure the console has a mailbox even if we somehow
            # missed its discovery request.
            natrelay.RELAY.mailbox_for(addr)
            return
        if msg and msg[0] == NAT_INTRO_REQ and nat_broker_mode() != "off":
            self.introduce(data, msg, addr)
            return

        # Anything else used to be dropped in silence, and that hid the most
        # interesting traffic on the rig: joining a game sends 29-byte datagrams
        # to UDP 3074 -- OUR port, not the host console's -- roughly once a
        # second before the joiner moves on to the host's 3075. They arrived,
        # matched neither discovery opcode, and vanished without a line, so the
        # "'Joining game...' sends nothing to the server" reading was wrong: it
        # sends plenty, we just never printed it.
        _UNKNOWN_UDP.append((peer, data))
        log(f"UDP {peer} UNRECOGNISED {len(data)}B (no reply sent)")
        for off in range(0, min(len(data), 64), 16):
            chunk = data[off:off + 16]
            log("    " + f"{off:04x}  " + " ".join(f"{b:02x}" for b in chunk).ljust(47)
                + " " + "".join(chr(b) if 32 <= b < 127 else "." for b in chunk))
        try:
            path = CAP / f"udp-unknown-{addr[0].replace('.', '_')}-{addr[1]}.bin"
            with open(path, "ab") as fh:
                fh.write(data)
        except OSError:
            pass

    def nat_type(self, data: bytes, addr: tuple[str, int]) -> None:
        """Answer one test of the console's NAT type probe.

        The reply for test 3 goes out of a DIFFERENT SOCKET on purpose; see the
        NAT TYPE block above for why answering it from here would turn the whole
        probe into a constant.
        """
        peer = f"{addr[0]}:{addr[1]}"
        flags = data[3] if len(data) > 3 else NAT_CHANGE_NONE
        name = {NAT_CHANGE_NONE: "test 1", NAT_CHANGE_PORT: "test 3 (change port)",
                NAT_CHANGE_BOTH: "test 2 (change ip+port)"}.get(flags, f"flags {flags}")
        if not serverconfig.NAT_TYPE:
            log(f"UDP {peer} NAT type {name} -- ignored (type discovery off)")
            return
        # MAPPED is always what the request arrived from. It is the same in every
        # test because every test goes to this same socket, which is the point:
        # the client compares test 3's against test 1's to catch a NAT that
        # remapped underneath it.
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
            # A SECOND ADDRESS THAT IS THE FIRST ONE IS NOT A SECOND ADDRESS.
            # The client only checks that the source IP equals the advertised
            # CHANGED ip and the port differs -- so `alt = <our own address>`
            # passes, and the console reports OPEN for a NAT that merely lets
            # our IP back in on any port. That is the one wrong answer with a
            # cost: OPEN means "skip the relay, punch directly", and the punch
            # then fails. Refuse rather than over-report.
            # Compare against both the routed answer and the raw one: the rig
            # rewrites loopback to the bridge, so either alone can miss an
            # operator who wrote the other form.
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
            # Not a failure: an unanswerable test is how the console learns its
            # NAT is restrictive. Say so, because "no reply" and "no socket" look
            # identical from the console and only one of them is a measurement.
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
            # With the relay on, addrB is a mailbox we handed out, so this is an
            # exact lookup rather than the port-matching guess below. Pairing the
            # two consoles here is what lets the host's 0x0c be attributed when
            # it arrives from an endpoint we have never seen.
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
        # Byte 0 and nothing else. The address bytes stay as the joiner wrote
        # them even though we are sending them somewhere else -- they are under
        # the HMAC, and the host reads addrA (the joiner) to know where to
        # answer, which is correct as written.
        out = bytes([NAT_INTRO_RELAY]) + data[1:]
        self.t.sendto(out, target)
        log(f"    0x0b -> {target[0]}:{target[1]}  {out.hex()}")


#: Tiger192 of the empty string. Any implementation that gets this wrong is not
#: the hash this protocol is built on.
TIGER_EMPTY = "3293ac630c13f0245f92bbb1766e16167a4e58492dde73f3"


def check_tiger() -> None:
    """Refuse to start if Tiger192 is unavailable or wrong.

    Tiger192 is the hash the entire auth path depends on -- the login proof key,
    the account handle, the credential store -- and it comes from the `rhash`
    binary because no Python standard library provides it. Without it,
    `resolve_login()` raises, the dispatch backstop drops the message, and the
    console gets a TCP connection that accepts its login and then says nothing
    at all. Which is a maddening thing to debug: the port is open, the server is
    running, the log looks healthy, and sign-in simply hangs.

    That happened on the first real deployment. `apt install rhash python3-venv`
    aborted on an unrelated 404, apt rolled the whole transaction back, and rhash
    was never installed. Everything else worked. Checking it here turns an hour
    of packet captures into one line at startup.
    """
    try:
        got = tiger192(b"").hex()
    except FileNotFoundError:
        raise SystemExit(
            "!! `rhash` is not installed, and this server cannot run without it.\n"
            "   Tiger192 is the hash the whole auth path is built on and no Python\n"
            "   standard library provides it. Without rhash a console connects,\n"
            "   sends its login and never gets an answer.\n"
            "       Debian/Ubuntu:  apt install rhash\n"
            "       Arch:           pacman -S rhash")
    except Exception as e:
        raise SystemExit(f"!! could not run `rhash`: {e}")
    if got != TIGER_EMPTY:
        raise SystemExit(
            f"!! `rhash` produced the wrong Tiger192 digest.\n"
            f"   got      {got}\n   expected {TIGER_EMPTY}\n"
            f"   Every login proof built with it would be wrong.")


async def start_nat_type_sockets(loop, bind: str) -> None:
    """Bind the extra source addresses the NAT type probe needs.

    A bind that fails is logged and survived: the console then times that test
    out and reports a more restrictive NAT, which is the safe direction to be
    wrong in.
    """
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
        # EPHEMERAL PORT, deliberately. It cannot share `alt_port`: with the
        # usual bind of 0.0.0.0 the change-port socket above already holds that
        # port on every address, including this one. And it does not need a
        # fixed port -- the client's only requirement for test 2 is that the
        # source port differs from the advertised CHANGED port, which is the
        # main one. So there is nothing here for an operator to open or
        # remember.
        try:
            _tr, NAT_TYPE_ADDR_SOCK = await loop.create_datagram_endpoint(
                lambda: NatTypeSocket("nat-type change-addr"),
                local_addr=(alt_addr, 0))
        except OSError as e:
            log(f"!! NAT type: could not bind UDP {alt_addr}:0 ({e}) -- "
                f"test 2 will go unanswered, so no console can report OPEN")


async def main():
    check_tiger()
    loop = asyncio.get_running_loop()
    bind, port = serverconfig.BIND, serverconfig.PORT
    server = await loop.create_server(AuthConnection, bind, port)
    await loop.create_datagram_endpoint(lambda: Discovery(), local_addr=(bind, port))
    natrelay.set_logger(log)
    await natrelay.RELAY.start(bind)
    await start_nat_type_sockets(loop, bind)
    log(f"WOW2 server up: TCP+UDP {bind}:{port}")
    for line in serverconfig.describe().split("\n"):
        log(line)
    log(f"logging to {SESSION_LOG.name}")
    async with server:
        await server.serve_forever()


def cli() -> None:
    """Console entry point (`wow2-server`). Same as running this file."""
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    cli()
