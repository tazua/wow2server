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
_udp_log = lambda _ip, msg: _log(msg)


def set_logger(fn, udp_fn=None) -> None:
    """The server owns the session log; borrow it rather than opening another.
    `udp_fn(ip, msg)` is its rate-limited form, for lines a datagram caused."""
    global _log, _udp_log
    _log = fn
    if udp_fn is not None:
        _udp_log = udp_fn


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
SILENCE = float(os.environ.get("WOW2_RELAY_SILENCE", "90"))
GRACE = float(os.environ.get("WOW2_RELAY_GRACE", "300"))
TRUST = float(os.environ.get("WOW2_RELAY_TRUST", str(24 * 3600)))
REBIND_IDLE = float(os.environ.get("WOW2_RELAY_REBIND_IDLE", "30"))
TRUST_MAX = 65536
HOST_ALIASES: dict[str, str] = {}


def same_host(a: str, b: str) -> bool:
    """One machine's two source addresses are one host: on the rig console 1
    reaches 3074 as loopback and every mailbox as the bridge address (§80l)."""
    return HOST_ALIASES.get(a, a) == HOST_ALIASES.get(b, b)


class Console:
    """One console, and every endpoint we have seen it speak from."""

    __slots__ = ("key", "mailbox", "seen", "seen_at", "prev", "peers", "last", "born")

    def __init__(self, key: tuple[str, int]):
        self.key = key
        self.mailbox: "Mailbox | None" = None
        self.seen: dict[int, tuple[str, int]] = {}
        self.seen_at: dict[int, float] = {}
        self.prev: dict[int, tuple[str, int]] = {}
        self.peers: set["Console"] = set()
        self.last = self.born = time.time()

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
        sender = self.relay.sender_for(self, src, data)
        if sender is None:
            self._drop(src[0], f"cannot tell who {src[0]}:{src[1]} is "
                       f"(mailbox {self.port} belongs to {owner}, "
                       f"peers {sorted(repr(p) for p in owner.peers)})")
            return
        now = time.time()
        cur = sender.seen.get(self.port)
        if cur != src:
            if not self.relay.may_move(sender, self.port, src, now):
                self._drop(src[0], f"{sender} speaks to :{self.port} from {cur[0]}:{cur[1]} "
                           f"({now - sender.seen_at.get(self.port, 0.0):.0f} s ago); "
                           f"{src[0]}:{src[1]} does not move its return path")
                return
            _udp_log(src[0], f"RELAY learn: {sender} talks to :{self.port} from "
                     f"{src[0]}:{src[1]}")
            self.relay.move(sender, self.port, src)
        sender.seen_at[self.port] = sender.last = now
        self.relay.link(owner, sender)

        out = sender.mailbox
        if out is None or out.transport is None:
            self._drop(src[0], f"{sender} has no mailbox")
            return
        dest = owner.seen.get(out.port)
        if dest is None:
            self._drop(src[0], f"no return path to {owner} on :{out.port} yet "
                       f"(waiting for it to dial SERVER:{out.port})")
            return
        out.transport.sendto(data, dest)
        out.tx += 1

    def port_str(self) -> str:
        return str(self.port)

    def _drop(self, ip: str, why: str) -> None:
        self.dropped += 1
        now = time.time()
        if now - self._last_drop_log > 2.0:
            self._last_drop_log = now
            _udp_log(ip, f"RELAY drop on :{self.port}: {why} [{self.dropped} so far]")

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
        self.in_use = 0
        self.per_ip: dict[str, int] = {}
        self.signed_in: dict[str, int] = {}
        self.signed_out: dict[str, float] = {}
        self._full_until = 0.0
        self._refused_at = 0.0
        self._refused_n = 0

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
        """Forget every console silent past its limit. How many went."""
        now = time.time() if now is None else now
        self._full_until = 0.0
        idle = [c for c in list(self.consoles.values()) if self._gone(c, now)]
        for c in idle:
            _udp_log(c.key[0], f"RELAY: {c} idle {now - c.last:.0f}s"
                     f"{'' if self.trusted(c.key[0], now) else ', nobody signed in from there'}"
                     f" -- forgotten")
            self.forget(c)
        stale = [ip for ip, t in self.signed_out.items() if now - t >= TRUST]
        for ip in stale:
            del self.signed_out[ip]
        return len(idle)

    def _gone(self, c: Console, now: float) -> bool:
        """Silent past IDLE_TIMEOUT, or past SILENCE with no sign-in behind it:
        a console sends a keepalive every 15 s from discovery on."""
        return now - c.last > (IDLE_TIMEOUT if self.trusted(c.key[0], now) else SILENCE)

    # ------------------------------------------------------------------- trust
    def note_sign_in(self, ip: str) -> None:
        """An account's sign-in from `ip` completed (§60)."""
        self.signed_in[ip] = self.signed_in.get(ip, 0) + 1

    def note_sign_out(self, ip: str, now: float | None = None) -> None:
        n = self.signed_in.get(ip, 0) - 1
        if n > 0:
            self.signed_in[ip] = n
        else:
            self.signed_in.pop(ip, None)
        self.signed_out.pop(ip, None)
        self.signed_out[ip] = time.time() if now is None else now
        while len(self.signed_out) > TRUST_MAX:
            del self.signed_out[next(iter(self.signed_out))]

    def trusted(self, ip: str, now: float | None = None) -> bool:
        """Has an account signed in from this address within TRUST?"""
        if ip in self.signed_in:
            return True
        t = self.signed_out.get(ip)
        return t is not None and (time.time() if now is None else now) - t < TRUST

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
            self._refused(endpoint)
            return None
        c = self.consoles[endpoint] = Console(endpoint)
        mb.owner = c
        c.mailbox = mb
        self.in_use += 1
        self.per_ip[endpoint[0]] = self.per_ip.get(endpoint[0], 0) + 1
        _udp_log(endpoint[0], f"RELAY: {endpoint[0]}:{endpoint[1]} -> mailbox :{mb.port}")
        return mb

    def _refused(self, endpoint: tuple[str, int]) -> None:
        """One line a minute, however many are turned away."""
        self.exhausted += 1
        now = time.time()
        if now - self._refused_at < 60:
            return
        n = self.exhausted - self._refused_n
        self._refused_at, self._refused_n = now, self.exhausted
        why = (f"{endpoint[0]} holds {PER_ADDRESS_MAX}, each heard from in the last "
               f"{SILENCE:.0f}s" if self.per_ip.get(endpoint[0], 0) >= PER_ADDRESS_MAX
               else f"each of the {len(self.mailboxes)} is held by a console that may keep it")
        _log(f"RELAY: no mailbox for {endpoint[0]}:{endpoint[1]} ({why}) -- it gets "
             f"the direct path" + (f"; {n} turned away since the last line" if n > 1 else ""))

    def _free_mailbox(self, ip: str = "") -> Mailbox | None:
        now = time.time()
        if ip and self.per_ip.get(ip, 0) >= PER_ADDRESS_MAX:
            same = [c for c in self.consoles.values() if c.key[0] == ip and c.mailbox]
            victim = min(same, key=lambda c: c.last)
            if now - victim.last <= SILENCE:
                return None
            _udp_log(ip, f"RELAY: {ip} already holds {len(same)} mailboxes -- recycling "
                     f":{victim.mailbox.port} from {victim} "
                     f"(idle {now - victim.last:.0f}s)")
            mb = victim.mailbox
            self.forget(victim)
            return mb
        if self.in_use < len(self.mailboxes):
            for mb in self.mailboxes:
                if mb.owner is None:
                    return mb
        claimant = self.trusted(ip, now)
        if not claimant and now < self._full_until:
            return None
        idle = unproven = None
        soonest = float("inf")
        for mb in self.mailboxes:
            c = mb.owner
            if c is None:
                return mb
            proven = self.trusted(c.key[0], now)
            limit = IDLE_TIMEOUT if proven else SILENCE
            if now - c.last > limit:
                if idle is None or c.last < idle.last:
                    idle = c
                continue
            soonest = min(soonest, c.last + limit)
            if proven:
                continue
            if claimant or now - c.born > GRACE:
                if unproven is None or c.born < unproven.born:
                    unproven = c
            else:
                soonest = min(soonest, c.born + GRACE)
        victim = idle or unproven
        if victim is None:
            if not claimant:
                self._full_until = soonest
            return None
        mb = victim.mailbox
        why = (f"idle {now - victim.last:.0f}s" if victim is idle else
               f"nobody has signed in from {victim.key[0]} in the "
               f"{now - victim.born:.0f}s it has held it")
        _udp_log(ip, f"RELAY: reclaiming :{mb.port} from {victim} ({why}) for {ip}")
        self.forget(victim)
        return mb

    def forget(self, c: Console) -> None:
        if c.mailbox is not None:
            c.mailbox.release()
            c.mailbox = None
            self.in_use -= 1
            n = self.per_ip.get(c.key[0], 0) - 1
            if n > 0:
                self.per_ip[c.key[0]] = n
            else:
                self.per_ip.pop(c.key[0], None)
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
                if same_host(c.key[0], src[0]):
                    return c
                _udp_log(src[0], f"RELAY: {src[0]}:{src[1]} names {c}'s mailbox in "
                         f"addrA but is not at {c.key[0]} -- not attributed")
                return None
        if mb.owner:
            same_ip = [p for p in mb.owner.peers if same_host(p.key[0], src[0])]
            if len(same_ip) == 1:
                return same_ip[0]
        return None

    @staticmethod
    def may_move(c: Console, port: int, src: tuple[str, int], now: float) -> bool:
        """A console's return path on a mailbox moves when it has none, when the
        endpoint an idle move replaced speaks again, or after REBIND_IDLE of
        silence (a NAT that remapped the console while it idled, §79)."""
        if port not in c.seen or c.prev.get(port) == src:
            return True
        return now - c.seen_at.get(port, 0.0) >= REBIND_IDLE

    @staticmethod
    def move(c: Console, port: int, src: tuple[str, int]) -> None:
        if c.prev.get(port) == src:
            del c.prev[port]
        elif port in c.seen:
            c.prev[port] = c.seen[port]
        c.seen[port] = src

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
        signed = sum(1 for mb in live if self.trusted(mb.owner.key[0]))
        return (f"relay: {len(live)}/{len(self.mailboxes)} mailboxes in use "
                f"({signed} from a signed-in address), "
                f"{rx} in / {tx} out / {drop} dropped")


RELAY = Relay()
