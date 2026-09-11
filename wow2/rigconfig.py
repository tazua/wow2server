"""Single source of truth for values the SERVER and the INPUT DRIVER must agree on.

Why this file exists: the account password is used on BOTH sides of the rig —
the game types it at the on-screen keyboard, and the server derives the
login-proof key K_client = Tiger192(password) from it. If the two ever drift
apart the client's magic check fails and sign-in dies with a misleading
"Couldn't sign in" / "name already in use" dialog that looks like a protocol
bug. They used to be two independent literals (a sequences.json step that typed
"111111" vs. a WOW2_PASSWORD env default of "123456"), which cost a lot of
debugging time. Import from here instead of hardcoding.

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

# The 24-byte LSG session key the server assigns in the login proof; the client
# copies it to authobj+0xA0 and uses it for the lobby connection.
SESSION_KEY = bytes.fromhex(os.environ.get("WOW2_SESSION_KEY", "42" * 24))

# Identity the server issues for the account (mirrored in both the encrypted
# AuthTicket and the opaque proof relayed to the LSG).
USERNAME = os.environ.get("WOW2_USERNAME", "player1")
USER_ID = int(os.environ.get("WOW2_USER_ID", "1"))
LICENSE_ID = int(os.environ.get("WOW2_LICENSE_ID", "1"))
TITLE_ID = 0x131D

# --------------------------------------------------------------- emu instances
# The rig can drive more than one PPSSPP at a time -- one hosts the online game,
# the other joins it -- because joining is peer-to-peer and needs a second
# console. Instance "1" is the original rig emulator and keeps every historical
# path (~/.config/ppsspp, capture/observer/); instance N>1 gets a completely
# separate memstick under emuN/, which means its own savedata (its own game
# profile and therefore its own online name), its own ppsspp.ini and therefore
# its own debugger port, and its own observer directory. Nothing but the state
# library (capture/states/) is shared -- both emulators show the same screens.
#
# Select with WOW2_EMU=2 in the environment; every rig tool honours it:
#     WOW2_EMU=2 tools/wow2 launch      # boot the second console
#     WOW2_EMU=2 tools/wow2 tap cross   # ... and press X on THAT one
from pathlib import Path

ROOT = Path(os.environ.get("WOW2_ROOT", Path(__file__).resolve().parent.parent))
EMU = os.environ.get("WOW2_EMU", "1")


def emu_config_home(emu: str | None = None) -> Path:
    """XDG_CONFIG_HOME for an instance -- PPSSPP puts its whole PSP/ tree
    (memstick + SYSTEM/ppsspp.ini) in $XDG_CONFIG_HOME/ppsspp, so this one
    variable forks everything: config, savedata, debugger port."""
    emu = emu or EMU
    return Path.home() / ".config" if emu == "1" else ROOT / f"emu{emu}"


def emu_ini(emu: str | None = None) -> Path:
    return emu_config_home(emu) / "ppsspp/PSP/SYSTEM/ppsspp.ini"


def emu_observer_dir(emu: str | None = None) -> Path:
    emu = emu or EMU
    return ROOT / "capture" / ("observer" if emu == "1" else f"observer{emu}")


def emu_tag(emu: str | None = None) -> str:
    """Short label for logs/prompts: '' for the original, ' [emu2]' otherwise."""
    emu = emu or EMU
    return "" if emu == "1" else f" [emu{emu}]"


# Console 2..N each run inside their own network namespace, because the game
# binds UDP 3075 and two of them on one host collide (see tools/netns.sh for
# the full reasoning and the bridge layout). Console 1 stays in the host
# namespace, so `emu_netns("1")` is None and nothing about it changes.
NETNS_BRIDGE_IP = "10.42.0.1"


def emu_netns(emu: str | None = None) -> str | None:
    emu = emu or EMU
    return None if emu == "1" else f"wow2emu{emu}"


def emu_ip(emu: str | None = None) -> str:
    """The address this console is reachable at -- from the host and from the
    other consoles. Console 1 is just the host itself."""
    emu = emu or EMU
    return "127.0.0.1" if emu == "1" else f"10.42.0.{emu}"


# Where each console's window is parked. The observer grabs the window by its
# geometry, and the two consoles must not overlap or one of them captures the
# other's pixels -- so the rig places them explicitly rather than leaving it to
# the tiling layout, which resizes them whenever a window opens or closes.
# Override with WOW2_EMU_WINDOW="x,y,w,h" for a different screen setup.
EMU_WINDOWS = {
    # --- HDMI-A-5, workspace 3: THE MATCH RIG -------------------------------
    # Four quarters of a 1920x1080 at (2560,180). maxPlayers=4 in the create
    # request, so a full lobby fits on one screen and one glance shows the
    # whole match.
    "1": (3530, 202, 928, 508),      # top-right     (host namespace)
    "2": (3530, 730, 928, 508),      # bottom-right
    "3": (2582, 202, 928, 508),      # top-left
    "4": (2582, 730, 928, 508),      # bottom-left
    # --- DP-3, workspace 4: THE RECON BENCH ---------------------------------
    # The monitor the user left empty. Four more quarters of a 1920x1080 at
    # (-1920,180), for solo recon that must not disturb a match in progress.
    # The 4K DP-4 is deliberately never used.
    "5": (-1898, 202, 928, 508),     # top-left
    "6": (-950, 202, 928, 508),      # top-right
    "7": (-1898, 730, 928, 508),     # bottom-left
    "8": (-950, 730, 928, 508),      # bottom-right
}

# Which workspace each console's window is parked on. It is per-console because
# the consoles span two monitors and in Hyprland a workspace belongs to exactly
# one monitor -- parking console 5 on workspace 3 would drag it back to
# HDMI-A-5 on top of the match rig.
EMU_WORKSPACES = {
    "1": "3", "2": "3", "3": "3", "4": "3",      # HDMI-A-5
    "5": "4", "6": "4", "7": "4", "8": "4",      # DP-3
}
# Kept for callers that predate EMU_WORKSPACES; console 1's workspace.
EMU_WORKSPACE = os.environ.get("WOW2_EMU_WORKSPACE", "3")


def emu_workspace(emu: str | None = None) -> str:
    emu = emu or EMU
    env = os.environ.get("WOW2_EMU_WORKSPACE")
    if env:
        return env
    return EMU_WORKSPACES.get(emu, EMU_WORKSPACE)


def emu_debug_port(emu: str | None = None) -> int:
    """PPSSPP's webserver/debugger port for an instance (RemoteISOPort in that
    instance's ppsspp.ini). The rig reads the ini live -- this is only the
    value a NEW memstick is seeded with, so the ports stay predictable."""
    emu = emu or EMU
    return 33574 + int(emu)


def emu_window(emu: str | None = None) -> tuple[int, int, int, int] | None:
    emu = emu or EMU
    env = os.environ.get("WOW2_EMU_WINDOW")
    if env:
        x, y, w, h = (int(v) for v in env.replace("x", ",").split(","))
        return x, y, w, h
    return EMU_WINDOWS.get(emu)
