"""The values the server and the input driver must agree on: the account
password, the issued identity, the bridge address. Import from here instead of hardcoding.

(This is the server's half of the file. The private repository's copy goes on
to describe the emulator rig -- window geometry, network namespaces -- which a
deployment has no use for.)
"""
from __future__ import annotations

import os

ACCOUNT_PASSWORD = os.environ.get("WOW2_PASSWORD", "123456")    # the rig's; a deployment uses it only with accounts.shared_password_fallback on

SESSION_KEY = bytes.fromhex(os.environ.get("WOW2_SESSION_KEY", "42" * 24))    # only under WOW2_FIXED_SESSION_KEY=1, a bisect; a sign-in gets a random key

USERNAME = os.environ.get("WOW2_USERNAME", "player1")
USER_ID = int(os.environ.get("WOW2_USER_ID", "1"))
LICENSE_ID = int(os.environ.get("WOW2_LICENSE_ID", "1"))
TITLE_ID = 0x131D

NETNS_BRIDGE_IP = "10.42.0.1"
