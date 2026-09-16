"""Single source of truth for values the SERVER and the INPUT DRIVER must agree on.

Why this file exists: the account password is used on BOTH sides of the rig —
the game types it at the on-screen keyboard, and the server derives the
login-proof key K_client = Tiger192(password) from it. If the two ever drift
apart the client's magic check fails and sign-in dies with a misleading
"Couldn't sign in" / "name already in use" dialog that looks like a protocol
bug. They used to be two independent literals (a sequences.json step that typed
"111111" vs. a WOW2_PASSWORD env default of "123456"), which cost a lot of
debugging time. Import from here instead of hardcoding.

(This is the server's half of the file. The private repository's copy goes on
to describe the emulator rig -- window geometry, network namespaces -- which a
deployment has no use for.)

Each auth cycle CREATES A NEW ACCOUNT (create-account 0x00 -> reply 700), so
this is not a credential that must match anything previously stored on disk —
it only has to be identical on the two sides of the same cycle, and legal per
the game's rule (6-12 characters).

Digits only, please: tools/login.py types the password on the OSK's digit row
and deliberately never presses the same key twice in a row (the keyboard
de-bounces rapid same-key presses); letters would need the rest of the grid
mapped and verified first.
"""
from __future__ import annotations

import os

# 6-12 chars, digits only. Overridable via env for one-off experiments, but keep
# the DEFAULT authoritative -- both sides read this same value.
ACCOUNT_PASSWORD = os.environ.get("WOW2_PASSWORD", "123456")

# The 24-byte LSG session key the server assigned in the login proof before
# Phase 33; the client copies it to authobj+0xA0 and uses it for the lobby
# connection. Every sign-in gets its own key now, and this constant is used
# only under the `WOW2_FIXED_SESSION_KEY=1` bisect switch.
SESSION_KEY = bytes.fromhex(os.environ.get("WOW2_SESSION_KEY", "42" * 24))

# Identity the server issues for the account (mirrored in both the encrypted
# AuthTicket and the opaque proof relayed to the LSG).
USERNAME = os.environ.get("WOW2_USERNAME", "player1")
USER_ID = int(os.environ.get("WOW2_USER_ID", "1"))
LICENSE_ID = int(os.environ.get("WOW2_LICENSE_ID", "1"))
TITLE_ID = 0x131D

# Console 2..N each run inside their own network namespace, because the game
# binds UDP 3075 and two of them on one host collide (see tools/netns.sh for
# the full reasoning and the bridge layout). Console 1 stays in the host
# namespace, so `emu_netns("1")` is None and nothing about it changes. The
# server needs the bridge address too: a host on loopback is advertised to a
# namespaced joiner as this (`server_address_for`).
NETNS_BRIDGE_IP = "10.42.0.1"
