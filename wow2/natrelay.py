#!/usr/bin/env python3
"""The bdNAT relay: every console gets a UDP socket on the server and is told
that socket is its own public address, so the peer session is carried here
when a punch cannot (netrecon §35-§37; tools/README.md "natrelay.py").
"""
from __future__ import annotations

import asyncio
import socket
import os
import time

import serverconfig

_log = print


def set_logger(fn) -> None:
    """The server owns the session log; borrow it rather than opening another."""
    global _log
    _log = fn


# ------------------------------------------------------------------ our address
_ADDR_CACHE: dict[str, str] = {}


def server_addr_for(client_ip: str) -> str:
    if PUBLIC_ADDRESS:
        return PUBLIC_ADDRESS
    hit = _ADDR_CACHE.get(client_ip)
    if hit:
        return hit
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((client_ip, 9))
            ip = s.getsockname()[0]
        finally:
            s.close()
    except OSError:
        ip = client_ip
    _ADDR_CACHE[client_ip] = ip
    return ip


ENABLED = str(serverconfig.get("nat", "relay")).lower() in ("1", "true", "on", "always")
PORT_BASE = int(serverconfig.get("nat", "relay_port_base"))
PORT_COUNT = int(serverconfig.get("nat", "relay_ports"))
IDLE_TIMEOUT = float(serverconfig.get("nat", "relay_idle_timeout"))
PUBLIC_ADDRESS = str(serverconfig.get("nat", "public_address") or "")
PER_ADDRESS_MAX = int(os.environ.get("WOW2_RELAY_PER_ADDRESS", "8"))


class Console:
    """One console, and every endpoint we have seen it speak from."""

    __slots__ = ("key", "mailbox", "seen", "peers", "last")

    def __init__(self, key: tuple[str, int]):
        self.key = key
        self.mailbox: "Mailbox | None" = None
        self.seen: dict[int, tuple[str, int]] = {}
        self.peers: set["Console"] = set()
        self.last = time.time()

    def __repr__(self) -> str:
        p = self.mailbox.port if self.mailbox else "-"
        return f"<{self.key[0]}:{self.key[1]} mailbox {p}>"


class Mailbox(asyncio.DatagramProtocol):
    """One UDP socket, owned by one console, and that console's public address."""

    __slots__ = ("relay", "port", "owner", "transport", "rx", "tx", "dropped",
                 "_last_drop_log")

    def __init__(self, relay: "Relay", port: int):
        self.relay = relay
        self.port = port
        self.owner: Console | None = None
        self.transport = None
        self.rx = self.tx = self.dropped = 0
        self._last_drop_log = 0.0

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data: bytes, src: tuple[str, int]) -> None:
        self.rx += 1
        owner = self.owner
        if owner is None:
            return
        owner.last = time.time()
        sender = self.relay.sender_for(self, src, data)
        if sender is None:
            self._drop(f"cannot tell who {src[0]}:{src[1]} is "
                       f"(mailbox {self.port} belongs to {owner}, "
                       f"peers {sorted(repr(p) for p in owner.peers)})")
            return
        sender.last = owner.last
        if sender.seen.get(self.port) != src:
            _log(f"RELAY learn: {sender} talks to :{self.port} from "
                 f"{src[0]}:{src[1]}")
            sender.seen[self.port] = src
        self.relay.link(owner, sender)

        out = sender.mailbox
        if out is None or out.transport is None:
            self._drop(f"{sender} has no mailbox")
            return
        dest = owner.seen.get(out.port)
        if dest is None:
            self._drop(f"no return path to {owner} on :{out.port} yet "
                       f"(waiting for it to dial SERVER:{out.port})")
            return
        out.transport.sendto(data, dest)
        out.tx += 1

    def port_str(self) -> str:
        return str(self.port)

    def _drop(self, why: str) -> None:
        self.dropped += 1
        now = time.time()
        if now - self._last_drop_log > 2.0:
            self._last_drop_log = now
            _log(f"RELAY drop on :{self.port}: {why} [{self.dropped} so far]")

    def release(self) -> None:
        self.owner = None
        self.rx = self.tx = self.dropped = 0


def _bd_addr_at(data: bytes, off: int) -> tuple[str, int] | None:
    """A bdAddr: 4 in_addr bytes then a LITTLE-endian u16 port."""
    if len(data) < off + 6:
        return None
    try:
        return socket.inet_ntoa(data[off:off + 4]), int.from_bytes(data[off + 4:off + 6], "little")
    except OSError:
        return None


class Relay:
    def __init__(self) -> None:
        self.enabled = ENABLED
        self.mailboxes: list[Mailbox] = []
        self.by_port: dict[int, Mailbox] = {}
        self.consoles: dict[tuple[str, int], Console] = {}
        self.exhausted = 0

    # ----------------------------------------------------------------- startup
    async def start(self, bind: str) -> None:
        """Bind the whole pool up front."""
        if not self.enabled:
            return
        loop = asyncio.get_running_loop()
        for port in range(PORT_BASE, PORT_BASE + PORT_COUNT):
            mb = Mailbox(self, port)
            try:
                await loop.create_datagram_endpoint(lambda mb=mb: mb,
                                                    local_addr=(bind, port))
            except OSError as e:
                _log(f"RELAY: cannot bind UDP {bind}:{port} ({e}) -- pool is "
                     f"{len(self.mailboxes)} ports")
                break
            self.mailboxes.append(mb)
            self.by_port[port] = mb
        if not self.mailboxes:
            self.enabled = False
            _log("RELAY: no ports could be bound -- relay DISABLED")
            return
        _log(f"RELAY: on. {len(self.mailboxes)} mailboxes, UDP "
             f"{PORT_BASE}-{PORT_BASE + len(self.mailboxes) - 1} "
             f"-- THESE PORTS MUST BE OPEN IN THE FIREWALL")
        asyncio.get_running_loop().create_task(self._report())

    async def _report(self) -> None:
        """A traffic line whenever something moved, and silence otherwise."""
        last = None
        while True:
            await asyncio.sleep(60)
            self.sweep()
            now = (sum(mb.rx for mb in self.mailboxes),
                   sum(mb.tx for mb in self.mailboxes))
            if now != last and now != (0, 0):
                _log("RELAY " + self.describe())
            last = now

    def sweep(self, now: float | None = None) -> int:
        """Forget every console idle past IDLE_TIMEOUT. How many went."""
        now = time.time() if now is None else now
        idle = [c for c in list(self.consoles.values()) if now - c.last > IDLE_TIMEOUT]
        for c in idle:
            _log(f"RELAY: {c} idle {now - c.last:.0f}s -- forgotten")
            self.forget(c)
        return len(idle)

    # -------------------------------------------------------------- allocation
    def mailbox_for(self, endpoint: tuple[str, int]) -> Mailbox | None:
        """The mailbox for the console that speaks from `endpoint`, allocating
        one if this is the first we have seen of it.
        """
        if not self.enabled:
            return None
        c = self.consoles.get(endpoint)
        if c is not None:
            c.last = time.time()
            return c.mailbox
        mb = self._free_mailbox(endpoint[0])
        if mb is None:
            self.exhausted += 1
            _log(f"RELAY: pool exhausted ({len(self.mailboxes)} ports, all in "
                 f"use) -- {endpoint[0]}:{endpoint[1]} gets the direct path")
            return None
        c = self.consoles[endpoint] = Console(endpoint)
        mb.owner = c
        c.mailbox = mb
        _log(f"RELAY: {endpoint[0]}:{endpoint[1]} -> mailbox :{mb.port}")
        return mb

    def _free_mailbox(self, ip: str = "") -> Mailbox | None:
        same = [c for c in self.consoles.values() if c.key[0] == ip and c.mailbox]
        if ip and len(same) >= PER_ADDRESS_MAX:
            victim = min(same, key=lambda c: c.last)
            _log(f"RELAY: {ip} already holds {len(same)} mailboxes -- recycling "
                 f":{victim.mailbox.port} from {victim} "
                 f"(idle {time.time() - victim.last:.0f}s)")
            mb = victim.mailbox
            self.forget(victim)
            return mb
        for mb in self.mailboxes:
            if mb.owner is None:
                return mb
        now = time.time()
        stale = [mb for mb in self.mailboxes
                 if mb.owner and now - mb.owner.last > IDLE_TIMEOUT]
        if not stale:
            return None
        stale.sort(key=lambda mb: mb.owner.last)
        mb = stale[0]
        _log(f"RELAY: reclaiming :{mb.port} from {mb.owner} "
             f"(idle {now - mb.owner.last:.0f}s)")
        self.forget(mb.owner)
        return mb

    def forget(self, c: Console) -> None:
        if c.mailbox is not None:
            c.mailbox.release()
            c.mailbox = None
        for p in c.peers:
            p.peers.discard(c)
        c.peers.clear()
        self.consoles.pop(c.key, None)

    # ------------------------------------------------------------------ lookup
    def console_at(self, endpoint: tuple[str, int]) -> Console | None:
        return self.consoles.get(endpoint)

    def owner_of_advertised(self, addr: tuple[str, int] | None) -> Console | None:
        """Whoever owns the mailbox an advertised address names."""
        if addr is None:
            return None
        mb = self.by_port.get(addr[1])
        return mb.owner if mb else None

    def sender_for(self, mb: Mailbox, src: tuple[str, int],
                   data: bytes) -> Console | None:
        """Which console sent this, in order of how much it is worth trusting."""
        for c in self.consoles.values():
            if c.key == src or src in c.seen.values():
                return c
        if len(data) == 29 and data[1:3] == b"\x02\x00":
            c = self.owner_of_advertised(_bd_addr_at(data, 17))
            if c is not None and c is not mb.owner:
                if c.key[0] == src[0]:
                    return c
                _log(f"RELAY: {src[0]}:{src[1]} names {c}'s mailbox in addrA "
                     f"but is not at {c.key[0]} -- not attributed")
                return None
        if mb.owner and len(mb.owner.peers) == 1:
            peer = next(iter(mb.owner.peers))
            if peer.key[0] == src[0]:
                return peer
        return None

    def link(self, a: Console, b: Console) -> None:
        if a is not b:
            a.peers.add(b)
            b.peers.add(a)

    def pair(self, a: Console | None, b: Console | None) -> None:
        """Called when an introduction names two consoles, before either has
        sent the other anything. Seeds `peers` so rule 3 above can fire.
        """
        if a is not None and b is not None:
            self.link(a, b)

    # ------------------------------------------------------------------ status
    def describe(self) -> str:
        if not self.enabled:
            return "relay: off"
        live = [mb for mb in self.mailboxes if mb.owner]
        rx = sum(mb.rx for mb in live)
        tx = sum(mb.tx for mb in live)
        drop = sum(mb.dropped for mb in live)
        return (f"relay: {len(live)}/{len(self.mailboxes)} mailboxes in use, "
                f"{rx} in / {tx} out / {drop} dropped")


RELAY = Relay()
