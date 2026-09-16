#!/usr/bin/env python3
"""A11/A12: prove the auth surface refuses what it should, with a peer the game
cannot be.

    .venv/bin/python tools/lsgauth.py                  # isolated server, all six
    .venv/bin/python tools/lsgauth.py --keep           # leave the log to read
    .venv/bin/python tools/lsgauth.py --revert         # the pre-fix behaviour, as a control
    .venv/bin/python tools/lsgauth.py --as player1       # sign in as an account, against
                                                       # the LIVE server, and hold it

WHAT IT IS FOR. The login reply carries the LSG session key TWICE: inside the
3DES ticket, keyed on `Tiger192(password)`, and again in the 128-byte opaque
proof written bit-continuous right after it **in clear**. The opaque copy is
the one the client relays at the LSG connect. So everything the password is
supposed to protect hangs on a value that goes out unencrypted, and the only
thing that can make it mean anything is the server refusing a key it did not
issue. Until §54 it did not:

  * `new_session_key()` registered the key before anyone decided whether to
    refuse, so a REFUSED login still handed out a registered, working
    credential -- the refusal garbled the ticket, which the attacker did not
    need to read;
  * `bind_lsg()` met an unrecognised key with a `!!` and carried on "using the
    fixed key and the source address", i.e. it fell back to the identity model
    the whole project spent Phase 33 removing;
  * and the connect could simply be SKIPPED, since an unencrypted RPC needs no
    key to build.

Each of those is one check below. The point of the tool is that it is a peer
the game cannot be: a real console always presents the proof it was given, so
no amount of driving the rig can ask these questions.

HOW IT RUNS. Its own `authserver` on a spare port with a scratch data dir, like
`relaytest.py` -- nothing here touches the live rig, its accounts or its
consoles. The store is seeded with ONE account that has a credential, so the
positive control has something honest to be; `shared_password_fallback` is off,
which is the deployment setting and the one the refusal paths need.

The positive control is not decoration. Four of the five checks pass if the
server simply closes every LSG connection it is offered, which is also what a
badly broken server does -- so check 1 signs in properly, and check 6 repeats it
after the hostile ones to show the server is still serving.
"""
from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import bdproto as bd                                            # noqa: E402
import rigconfig                                                # noqa: E402

BD_AUTH_NO_ERROR = 700
BD_AUTH_CREATE_USERNAME_EXISTS = 707

HERE = Path(__file__).resolve().parent     # beside authserver.py in both trees
PORT = 3874                 # not 3074: the live rig keeps that one
TITLE_ID = 0x131D
GOOD_ACCOUNT = "lsgauthok"          # seeded with a credential
GOOD_PASSWORD = "314159"
NEW_ACCOUNT = "lukas1"              # A12: nobody holds this yet
NEW_PASSWORD = "271828"
IMPOSTOR_PASSWORD = "161803"        # a second player, same profile name
KNOWN_NO_CRED = "player1"             # in IDENTITIES, so the server knows the NAME
UNKNOWN_ACCOUNT = "nobodyatall"     # not in IDENTITIES and not in the store


# ------------------------------------------------------------------ the wire
def tiger192(data: bytes) -> bytes:
    """Same digest the server uses. Imported rather than reimplemented."""
    sys.path.insert(0, str(HERE))
    from authserver import tiger192 as t
    return t(data)


def create_request(username: str, password: str, seed: int = 0x1234) -> bytes:
    """A 0x00 create-account request, exactly as the console builds one.

        [u8 0x00][tc bit][u32 iv_seed][u32 titleId][64 bits zero]
        [768 bits 3DES-CBC(BD_BOOTSTRAP_KEY, iv=Tiger192(seed))]
            plaintext = [u32 0xEFBDADDE][char name[64]][Tiger192(password)][pad]

    The 64 zero bits are the account handle field, and they are zero because
    there is no account yet. Note what this message does NOT contain: any proof
    that the sender is entitled to the name. It cannot -- it is the message that
    establishes the credential. That is why a duplicate has to be refused rather
    than checked.
    """
    sys.path.insert(0, str(HERE))
    from authserver import (BD_BOOTSTRAP_KEY, TICKET_MAGIC, cbc_3des_encrypt,
                            tiger_iv)
    nb = username.encode()[:63]
    plain = (struct.pack("<I", TICKET_MAGIC) + nb + b"\x00" * (64 - len(nb))
             + tiger192(password.encode()) + b"\x00" * 4)
    assert len(plain) == 96, len(plain)
    # K1 == K2 in the bootstrap key, so EDE collapses to single DES on K3 and
    # pycryptodome refuses the 24-byte form. Encrypt the way the client does.
    from Crypto.Cipher import DES
    ct = DES.new(BD_BOOTSTRAP_KEY[16:24], DES.MODE_CBC,
                 tiger_iv(seed)).encrypt(plain)
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(0x00)
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    w.u32(seed)
    w.u32(TITLE_ID)
    w.type_checked = False
    w.write_bits(b"\x00" * 8, 64)
    w.write_bits(ct, len(ct) * 8)
    return bd.frame_unencrypted(w.getvalue())


def login_request(handle: bytes, seed: int = 0x1234) -> bytes:
    """[u8 0x0a][tc bit][u32 iv_seed][u32 titleId][64 raw bits handle] -- 19 B.

    There is no password anywhere in it, which is the whole reason this tool
    exists: nothing can be validated when a login request arrives.
    """
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(0x0A)
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    w.u32(seed)
    w.u32(TITLE_ID)
    w.type_checked = False
    w.write_bits(handle, 64)
    return bd.frame_unencrypted(w.getvalue())


def short_login_request(seed: int = 0x1234) -> bytes:
    """A 0x0a with the header and NO handle -- 11 bytes where a console sends
    19. `parse_login()` raises on it, which is the path §64 closes."""
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(0x0A)
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    w.u32(seed)
    w.u32(TITLE_ID)
    return bd.frame_unencrypted(w.getvalue())


def lsg_connect(proof: bytes) -> bytes:
    """[u8 service=7][tc bit][u32 titleId][u32 0][128 B proof] -- 140 B framed."""
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(7)
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    w.u32(TITLE_ID)
    w.u32(0)
    w.type_checked = False
    w.write_bits(proof, 128 * 8)
    return bd.frame_unencrypted(w.getvalue())


def lsg_rpc(service: int, op: int) -> bytes:
    """A bare unencrypted service RPC. Storage op 7 needs no parameters to be
    recognisably itself, and recognisable is all this has to be."""
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.u8(service)
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    w.u8(op)
    return bd.frame_unencrypted(w.getvalue())


def lsg_rpc_encrypted(key: bytes, seed: int, service: int, op: int) -> bytes:
    """The same RPC the way a console sends it (§60): [u8 1][u32 seed] then
    3DES-CBC under `key` (IV = Tiger192(seed)[:8]) of [u32 hmac slot][u8
    service][bits], padded to the block with the seed's low byte, which is
    what the client does (169 of 169 logged plaintexts)."""
    sys.path.insert(0, str(HERE))
    from authserver import session_cbc_encrypt, tiger_iv
    w = bd.BdWriter()
    w.bitmode = True
    w.type_checked = False
    w.write_bits(b"\x01", 1)
    w.type_checked = True
    w.u8(op)
    plain = struct.pack("<I", 0) + bytes([service]) + w.getvalue()
    plain += bytes([seed & 0xFF]) * ((-len(plain)) % 8)
    body = b"\x01" + struct.pack("<I", seed) + session_cbc_encrypt(plain, key, tiger_iv(seed))
    return struct.pack("<I", len(body)) + body


def ticket_key(ticket: bytes, password: str) -> bytes | None:
    """The session key INSIDE the ticket -- readable only with the password."""
    sys.path.insert(0, str(HERE))
    from authserver import TICKET_MAGIC, auth_cbc_decrypt, tiger_iv
    try:
        plain = auth_cbc_decrypt(ticket, tiger192(password.encode()), tiger_iv(0))
    except Exception:
        return None
    if struct.unpack_from("<I", plain, 0)[0] != TICKET_MAGIC:
        return None
    return plain[97:121]


def reply_opens(frame: bytes, key: bytes) -> bool:
    """Does an encrypted server frame (connect reply or TaskReply) decrypt
    under `key`? The client's own test: the first plaintext u32 is 0xDEADBEEF."""
    sys.path.insert(0, str(HERE))
    from authserver import session_cbc_decrypt, tiger_iv
    if not frame or frame[0] != 1:
        return False
    seed = int.from_bytes(frame[1:5], "little")
    try:
        pt = session_cbc_decrypt(frame[5:], key, tiger_iv(seed))
    except Exception:
        return False
    return struct.unpack_from("<I", pt, 0)[0] == 0xDEADBEEF


def bufsize_announce(n: int = 0xFFFF) -> bytes:
    """[u32 180][u32 free] -- the marker that says this socket is the LSG."""
    return struct.pack("<II", bd.BUFSIZE_ANNOUNCE, n)


def read_login_reply(body: bytes) -> tuple[bytes, bytes]:
    """(ticket, opaque) out of a 0x0b reply. Both 128 B, and the SECOND is clear.

    Bit 51 is where the proof starts -- 8 (type) + 1 (tc) + 37 (typed u32 error)
    + 5 filler. The client reads exactly here; so does this.
    """
    r = bd.BdReader(body)
    r.bitmode = True
    r.read_bits(8 + 1 + 37 + 5)
    return bytes(r.read_bits(1024)), bytes(r.read_bits(1024))


def read_reply_error(body: bytes) -> int:
    """The typed u32 error out of any auth reply: [u8 type][tc bit][u32 err]."""
    r = bd.BdReader(body)
    r.u8()
    r.bitmode = True
    r.read_type_checked_bit()
    r.type_checked = True
    return r.u32()


def ticket_opens(ticket: bytes, password: str) -> bool:
    """Can `password` decrypt this login ticket? This is the client's own test.

    The client 3DES-CBC-decrypts the proof with Tiger192(password) and IV
    Tiger192(0), then looks for the magic. No magic, no sign-in -- it draws an
    error and never opens the LSG connection. So this one boolean IS "would the
    console have signed in".
    """
    sys.path.insert(0, str(HERE))
    from authserver import TICKET_MAGIC, auth_cbc_decrypt, tiger_iv
    try:
        plain = auth_cbc_decrypt(ticket, tiger192(password.encode()), tiger_iv(0))
    except Exception:
        return False
    return struct.unpack_from("<I", plain, 0)[0] == TICKET_MAGIC


def create_account(host: str, port: int, username: str, password: str) -> int:
    """Send a create-account and return the BdErrorCode the server answered."""
    p = Peer(host, port)
    p.send(create_request(username, password))
    for kind, data in p.frames(timeout=4.0):
        if kind == "msg":
            _enc, body = bd.unwrap_message(data)
            if body and body[0] == 0x01:
                p.close()
                return read_reply_error(body)
    p.close()
    raise SystemExit(f"no CreateAccountReply for {username!r}")


def proof_session_key(proof: bytes) -> bytes:
    return proof[36:60]


def proof_username(proof: bytes) -> str:
    return proof[60:124].split(b"\x00")[0].decode("ascii", "replace")


def retag(proof: bytes, key: bytes) -> bytes:
    """Put a different session key in an otherwise valid proof."""
    return proof[:36] + key + proof[60:]


# ----------------------------------------------------------------- the peer
class Peer:
    """One TCP connection to the server, spoken to in frames."""

    def __init__(self, host: str, port: int):
        self.s = socket.create_connection((host, port), timeout=5)
        self.buf = b""

    def send(self, data: bytes) -> None:
        self.s.sendall(data)

    def frames(self, timeout: float = 2.0) -> list[tuple[str, bytes]]:
        """Everything readable within `timeout`, framed. [] on EOF or silence."""
        self.s.settimeout(timeout)
        try:
            chunk = self.s.recv(65536)
        except socket.timeout:
            return []
        if chunk == b"":
            self.closed = True
            return []
        self.buf += chunk
        out, self.buf, _skipped = bd.parse_frame(self.buf)
        return out

    def is_closed(self, timeout: float = 2.5) -> bool:
        """Did the SERVER hang up? A quiet socket is not a closed one, so read
        until EOF or the timeout and say which happened."""
        self.s.settimeout(timeout)
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                if self.s.recv(65536) == b"":
                    return True
            except socket.timeout:
                return False
            except OSError:
                return True
        return False

    def close(self) -> None:
        try:
            self.s.close()
        except OSError:
            pass


def login(host: str, port: int, username: str) -> tuple[bytes, bytes]:
    """Sign in as `username` and return (ticket, opaque proof).

    Note what this does NOT need: the password. The request carries a handle
    and nothing else, and the reply comes back regardless -- a refusal is a
    reply encrypted under a key we cannot read, not a silence.
    """
    p = Peer(host, port)
    p.send(login_request(tiger192(username.encode())[:8]))
    for kind, data in p.frames(timeout=4.0):
        if kind == "msg":
            _enc, body = bd.unwrap_message(data)
            if body and body[0] == 0x0B:
                p.close()
                return read_login_reply(body)
    p.close()
    raise SystemExit(f"no LoginReply for {username!r}")


def present(host: str, port: int, proof: bytes) -> tuple[bool, list]:
    """Open an LSG connection and present `proof`. (server_closed, replies)."""
    p = Peer(host, port)
    p.send(bufsize_announce())
    p.send(lsg_connect(proof))
    replies = p.frames(timeout=2.0)
    closed = not replies and p.is_closed()
    if replies:
        closed = p.is_closed(timeout=1.0)
    p.close()
    return closed, replies


# ---------------------------------------------------------------- the server
def start_server(tmp: Path, revert: bool) -> subprocess.Popen:
    env = dict(os.environ,
               WOW2_PORT=str(PORT),
               WOW2_DATA_DIR=str(tmp),
               WOW2_HEXDUMPS="0",
               WOW2_LOG_LEVEL="info",
               WOW2_SHARED_PASSWORD_FALLBACK="false",
               WOW2_NO_NAT_TYPE="1")
    if revert:
        # Everything this tool tests, put back the way it was. One flag and not
        # two, because the question `--revert` answers is "would these checks
        # have caught it?" -- the per-behaviour switches stay separate in the
        # server for bisecting.
        env["WOW2_LSG_NO_KEY_CHECK"] = "1"      # §54
        env["WOW2_CREATE_MODE"] = "success"     # §56
        env["WOW2_NO_PROOF_HANDLE"] = "1"       # §60
    # The readiness probe below is a TCP connect, so a server that is already
    # on this port -- somebody else's -- would pass it, and every check would
    # then run against that server with that server's store (Phase 64: an
    # installed public build on 3874 failed two checks that way).
    try:
        socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
    except OSError:
        pass
    else:
        raise SystemExit(f"something already listens on 127.0.0.1:{PORT}; "
                         f"stop it first -- the checks would test THAT server")
    proc = subprocess.Popen([sys.executable, str(HERE / "authserver.py")],
                            env=env, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, text=True, bufsize=1)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", PORT), timeout=0.3).close()
            return proc
        except OSError:
            pass
        if proc.poll() is not None:
            print(proc.stdout.read())
            raise SystemExit("server died on startup")
        time.sleep(0.1)
    raise SystemExit("server never listened")


def seed_store(tmp: Path) -> None:
    """One account with a real credential, so the positive control is honest.

    The digest IS the credential -- `Tiger192(password)` is exactly the key the
    login reply is encrypted with -- so this is what a store looks like after a
    console has created an account, and it holds no password.
    """
    tmp.mkdir(parents=True, exist_ok=True)
    (tmp / "accounts.json").write_text(json.dumps({
        GOOD_ACCOUNT: {"pwhash": tiger192(GOOD_PASSWORD.encode()).hex(),
                       "user_id": 101,
                       "handle": tiger192(GOOD_ACCOUNT.encode())[:8].hex(),
                       "first_seen": "2026-09-13T00:00:00",
                       "last_seen": "2026-09-13T00:00:00"}}, indent=2))


def sign_in_as(host: str, port: int, account: str, hold: float,
               bad_key: bool = False, password: str | None = None) -> int:
    """A headless console: log in as `account` and hold the LSG connection.

    This is how A7 is tested with ONE real console. The interesting half of
    "two consoles, one account" is what the FIRST one does when it is evicted,
    and the second only has to be something the server will bind -- so it may as
    well be forty lines instead of an emulator and a renamed game profile.

    It is also, unavoidably, the demonstration of what §54 could not fix: this
    needs no password, because the opaque proof comes back in clear beside the
    ticket. Do not read a successful run as a test of the credential.
    """
    ticket, proof = login(host, port, account)
    print(f"logged in as {proof_username(proof)!r} "
          f"(user_id {struct.unpack_from('<Q', proof, 28)[0]}, "
          f"clear proof carries {proof_session_key(proof).hex()[:16]}..)")
    key = ticket_key(ticket, password) if password else None
    if password and key is None:
        print("  the password does not open the ticket -- a console would draw "
              "Net.Err.AccDen here and never connect; connecting anyway")
    if bad_key:
        # What a WRONG PASSWORD looks like from the server's side. A real client
        # that cannot decrypt the ticket draws Net.Err.AccDen and never opens an
        # LSG connection at all, so the server sees no completed bind -- exactly
        # what this produces, and the reason A7's eviction is gated here.
        proof = retag(proof, b"\x5A" * 24)
        print("  presenting a session key we were never issued (--bad-key)")
    p = Peer(host, port)
    p.send(bufsize_announce())
    p.send(lsg_connect(proof))
    replies = p.frames(timeout=3.0)
    if not replies:
        print("REFUSED: the server did not answer the LSG connect")
        p.close()
        return 1
    print(f"LSG connect answered ({len(replies)} frame(s))"
          + (" -- and the reply decrypts under the ticket key" if key and any(
              reply_opens(d, key) for kind, d in replies if kind == "msg") else ""))
    if key:
        # §60: the connect only binds PROVISIONALLY. What completes it is an
        # RPC that decrypts under the ticket key -- the thing a console does
        # ~70 ms later, and the thing nothing can do without the password.
        p.send(lsg_rpc_encrypted(key, 0, 10, 7))
        rep = [d for kind, d in p.frames(timeout=3.0) if kind == "msg"]
        ok = bool(rep) and reply_opens(rep[0], key)
        print("  first RPC under the ticket key -> "
              + ("served; the bind is complete and this is now the account's "
                 "connection (A7 signs the other one out)" if ok
                 else "NOT served"))
    else:
        print("  no --password: this connection can present the clear proof and "
              "nothing else, so it stays provisional -- it is not the account's "
              "connection and signs nobody out (§60)")
    print(f"holding for {hold:.0f}s")
    deadline = time.time() + hold
    while time.time() < deadline:
        for kind, data in p.frames(timeout=1.0):
            print(f"  <- {kind} {len(data)}B")
    p.close()
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--as", dest="as_account", metavar="ACCOUNT",
                    help="sign in as this account against a RUNNING server and "
                         "hold the LSG connection -- a headless second console")
    ap.add_argument("--host", default="127.0.0.1", help="with --as")
    ap.add_argument("--port", type=int, default=3074, help="with --as")
    ap.add_argument("--hold", type=float, default=20.0, help="with --as")
    ap.add_argument("--bad-key", action="store_true",
                    help="with --as: present a session key we never issued, "
                         "which is what a wrong password looks like server-side")
    ap.add_argument("--password", metavar="PW",
                    help="with --as: open the ticket and COMPLETE the bind with "
                         "an RPC under its key, as a console does (§60). Without "
                         "it the connection stays provisional")
    ap.add_argument("--revert", action="store_true",
                    help="put back everything these checks cover "
                         "(WOW2_LSG_NO_KEY_CHECK=1, create_mode=success) -- most "
                         "of them should then FAIL, which is what makes them "
                         "worth running")
    ap.add_argument("--keep", action="store_true", help="keep the scratch data dir")
    args = ap.parse_args()
    if args.as_account:
        return sign_in_as(args.host, args.port, args.as_account, args.hold,
                          args.bad_key, args.password)

    tmp = Path(tempfile.mkdtemp(prefix="lsgauth-"))
    seed_store(tmp)
    proc = start_server(tmp, args.revert)
    host = "127.0.0.1"
    fails = []

    def check(ok: bool, what: str):
        print(f"  {'PASS' if ok else 'FAIL'}  {what}")
        if not ok:
            fails.append(what)

    try:
        print(f"lsgauth against an isolated server on {host}:{PORT}"
              + ("  [--revert: pre-54 behaviour]" if args.revert else ""))

        # 1. POSITIVE CONTROL. An account with a stored credential signs in and
        #    its proof is accepted. Without this the rest proves nothing: a
        #    server that closes every LSG connection passes checks 2-5.
        _ticket, good = login(host, PORT, GOOD_ACCOUNT)
        check(proof_username(good) == GOOD_ACCOUNT,
              f"login for {GOOD_ACCOUNT!r} returns a proof naming it")
        closed, replies = present(host, PORT, good)
        check(bool(replies) and not closed,
              "a session key we issued is ACCEPTED (connid reply, socket open)")

        # 2. A key that was never issued at all. This is the branch that used to
        #    log `!!` and carry on with the source address.
        closed, replies = present(host, PORT, retag(good, b"\xA5" * 24))
        check(closed and not replies,
              "a session key we never issued is REFUSED (connection closed)")

        # 3. A refusal must not hand out a credential. `player1` is a name the
        #    server knows (IDENTITIES) with no stored credential, and the
        #    fallback is off -- so the ticket is garbage. The opaque proof is
        #    not, and that is the whole finding.
        _t, refused_known = login(host, PORT, KNOWN_NO_CRED)
        check(proof_username(refused_known) == KNOWN_NO_CRED,
              f"a REFUSED login still returns a readable clear proof for "
              f"{KNOWN_NO_CRED!r} (this is the hole, not the fix)")
        closed, replies = present(host, PORT, refused_known)
        check(closed and not replies,
              "the clear proof from a NO CREDENTIAL refusal is REFUSED")

        # 4. Same again for a name the server has never heard of.
        _t, refused_unknown = login(host, PORT, UNKNOWN_ACCOUNT)
        closed, replies = present(host, PORT, refused_unknown)
        check(closed and not replies,
              "the clear proof from an UNKNOWN ACCOUNT refusal is REFUSED")

        # 5. Skip the connect entirely. Closing the connect that fails to bind
        #    is not enough on its own -- an unencrypted RPC needs no key to
        #    build, so a peer that never presents one must not be served.
        p = Peer(host, PORT)
        p.send(bufsize_announce())
        p.send(lsg_rpc(10, 7))              # Storage: list my files
        replies = p.frames(timeout=2.0)
        closed = not replies and p.is_closed()
        p.close()
        check(closed and not replies,
              "an RPC on a connection that never bound is REFUSED")

        # 6. The positive control again, after the hostile ones.
        _ticket2, good2 = login(host, PORT, GOOD_ACCOUNT)
        closed, replies = present(host, PORT, good2)
        check(bool(replies) and not closed,
              "and the server still signs in an honest peer afterwards")

        # ---- §60: the clear proof is a handle; the ticket key gates the lobby --
        print("\n  -- the ticket key gates the lobby (§60) --")
        ticket3, good3 = login(host, PORT, GOOD_ACCOUNT)
        k = ticket_key(ticket3, GOOD_PASSWORD)
        check(k is not None and proof_session_key(good3) != k,
              "the clear proof carries a HANDLE, not the key the ticket holds")

        # 7. The handle alone: the connect is answered (provisionally) but an
        #    unencrypted RPC on it is refused -- a console never sends one.
        p = Peer(host, PORT)
        p.send(bufsize_announce())
        p.send(lsg_connect(good3))
        first = p.frames(timeout=2.0)
        p.send(lsg_rpc(10, 7))
        later = p.frames(timeout=2.0)
        closed = not later and p.is_closed()
        p.close()
        check(bool(first) and closed,
              "an UNENCRYPTED RPC after a handle-only connect is REFUSED")

        # 8. Encrypted, but under the handle value itself (all a reader of the
        #    clear proof has): does not decrypt under the ticket key -> refused.
        p = Peer(host, PORT)
        p.send(bufsize_announce())
        p.send(lsg_connect(good3))
        p.frames(timeout=2.0)
        p.send(lsg_rpc_encrypted(proof_session_key(good3), 0, 10, 7))
        later = p.frames(timeout=2.0)
        closed = not later and p.is_closed()
        p.close()
        check(closed,
              "an RPC encrypted under the HANDLE value is REFUSED")

        # 9. Positive control of the gate: under the ticket key it is served,
        #    and the reply is readable under that key.
        p = Peer(host, PORT)
        p.send(bufsize_announce())
        p.send(lsg_connect(good3))
        p.frames(timeout=2.0)
        p.send(lsg_rpc_encrypted(k, 0, 10, 7))
        rep = [d for kind, d in p.frames(timeout=2.0) if kind == "msg"]
        check(bool(rep) and reply_opens(rep[0], k),
              "an RPC encrypted under the TICKET key is served (reply under it)")
        # keep p open: it is now the account's connection, for check 10

        # 10. A handle-only connection does not sign the account's other
        #     console out; one that completes its bind does (A7 unchanged).
        ticket4, good4 = login(host, PORT, GOOD_ACCOUNT)
        q = Peer(host, PORT)
        q.send(bufsize_announce())
        q.send(lsg_connect(good4))
        q.frames(timeout=2.0)
        still_open = not p.is_closed(timeout=1.5)
        check(still_open,
              "a second connection showing only the clear proof does NOT sign "
              "the first one out")
        q.send(lsg_rpc_encrypted(ticket_key(ticket4, GOOD_PASSWORD), 0, 10, 7))
        q.frames(timeout=2.0)
        check(p.is_closed(timeout=2.5),
              "...and once it decrypts under its ticket key it does (A7)")
        p.close()
        q.close()

        # ---- A12: two players, one profile name (§56) ----------------------
        # The online account name is the LOCAL player profile's name -- nothing
        # is ever typed for it -- so two people who both call a profile
        # `lukas1` are one account and neither is warned. What the server does
        # about that is the whole of this group.
        print("\n  -- A12: two players pick the same profile name --")
        err = create_account(host, PORT, NEW_ACCOUNT, NEW_PASSWORD)
        check(err == BD_AUTH_NO_ERROR,
              f"a create for an unused name is accepted (700), got {err}")
        _t, pr = login(host, PORT, NEW_ACCOUNT)
        check(ticket_opens(_t, NEW_PASSWORD),
              "...and its owner can sign in with the password they chose")

        err = create_account(host, PORT, NEW_ACCOUNT, IMPOSTOR_PASSWORD)
        check(err == BD_AUTH_CREATE_USERNAME_EXISTS,
              f"a SECOND player picking the same name is refused (707), got {err}")

        # The refusal only means something if the credential survived it. This
        # is the takeover: pre-§56 the request overwrote the digest and the
        # server then answered 700, so the newcomer owned the account.
        owner_t, _pr = login(host, PORT, NEW_ACCOUNT)
        check(ticket_opens(owner_t, NEW_PASSWORD),
              "...the ORIGINAL owner's password still opens the ticket")
        check(not ticket_opens(owner_t, IMPOSTOR_PASSWORD),
              "...and the impostor's does not, so their console draws "
              "'already in use' instead of signing in")

        # ---- §64: a login the server cannot DECODE ---------------------------
        # Every refusal above sits behind `if req is not None`. A 0x0a whose
        # body is too short to carry the handle raised in parse_login(), and the
        # handler fell through to the source-address guess -- the pre-§33
        # identity model -- fallback or no fallback, and answered with a
        # complete proof for an invented `playerN` under the shared rig
        # password, which is in the public source. Nothing a console sends
        # looks like this; a peer that is not a console can send it in one line.
        print("\n  -- a login that cannot be decoded (§64) --")
        p = Peer(host, PORT)
        p.send(short_login_request())
        short_ticket = short_proof = None
        for kind, data in p.frames(timeout=4.0):
            if kind == "msg":
                _enc, body = bd.unwrap_message(data)
                if body and body[0] == 0x0B:
                    short_ticket, short_proof = read_login_reply(body)
        p.close()
        check(short_proof is not None,
              "a truncated login is still ANSWERED (a refusal is a reply, "
              "not a silence)")
        if short_proof is not None:
            check(not ticket_opens(short_ticket, rigconfig.ACCOUNT_PASSWORD),
                  "...and the ticket does NOT open under the shared password")
            closed, replies = present(host, PORT, short_proof)
            check(closed and not replies,
                  "...and its clear proof is REFUSED at the LSG")

    finally:
        proc.terminate()
        try:
            out = proc.stdout.read()
        except Exception:
            out = ""
        proc.wait(timeout=10)
        if args.keep:
            (tmp / "server.log").write_text(out)
            print(f"\nserver log -> {tmp / 'server.log'}")
        else:
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    print(f"\n{'FAILED: ' + '; '.join(fails) if fails else 'all checks passed'}")
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
