#!/usr/bin/env python3
"""bdNAT relay -- carry the peer session through the server when punching cannot.

WHY THIS EXISTS (netrecon Phase 35). The introduction broker works: a joiner's
`0x0a` is relayed to the host as `0x0b`, both directions, measured across two
real NATs. The punch still fails, because each console's NAT mapping was created
by talking to the SERVER and the punch arrives from the OTHER CONSOLE. Carrier
NAT drops that, and carrier NAT is most mobile connections and a growing share
of domestic ones. A relay is not a fallback for exotic networks; for two players
on mobile data it is the only route there is.

THE IDEA IS ONE SENTENCE: give every console a UDP socket on the server and tell
it that socket IS its own public address. It publishes what we tell it -- that is
already proven, `discovered_self()` exists because of it -- so from then on every
address either console can possibly learn points at us:

    * the host's `bdCommonAddr` in the create request, which the search reply
      hands to the joiner
    * `addrA` in the joiner's introduction request, which is how the host learns
      where to answer (measured on hardware: the PSP wrote its own NAT-mapped
      `80.187.87.236:17689` there, i.e. exactly what we had told it it was)
    * the copy the console re-advertises INSIDE the encrypted peer protocol,
      which the server cannot reach and could never rewrite

That last one is the point. It was written down as the risk that could sink this
whole approach -- if the peer acts on an address the server cannot touch, a relay
is bypassed. It cannot be rewritten, so instead it is never wrong: the console is
only ever told one address for itself, and that address is its mailbox.

HOW A DATAGRAM MOVES. Mailbox `S_X` belongs to console X. It is the address
everyone else dials to reach X, and the address X sees replies come from.

    J believes  "I am SERVER:S_J, and H is at SERVER:S_H"
    H believes  "I am SERVER:S_H, and J is at SERVER:S_J"

    J --> SERVER:S_H   arrives on S_H, so it is FOR H
                       leaves from S_J, so H sees the address it knows
    H --> SERVER:S_J   arrives on S_J, so it is FOR J
                       leaves from S_H, likewise

Two sockets, no parsing, no decryption, no address rewriting anywhere in the
payload -- which matters, because the 10-byte HMAC on a bdNAT packet covers
`identifier|addrA|addrB` under a key only the originator holds. We never touch
those bytes, so it never has to verify.

WHERE EACH CONSOLE REALLY IS is learned, never configured: the source address of
whatever it sends us. `Console.seen[port]` is "the endpoint this console talks to
our socket `port` from", one entry per socket, because a symmetric NAT gives a
different mapping per destination and the reply has to go back to the mapping the
packet came from. Since we always answer out of the socket the peer dialled, the
mapping we learned is by construction the right one. That is the whole reason a
relay works where a punch does not: every packet the console receives comes from
an address it has itself sent to.

THE BOOTSTRAP IS THE EXISTING `0x0b` RELAY, and it is not redundant. Before H has
ever sent anything to `S_J`, H's NAT has no mapping that would admit a packet
from `S_J` -- a port-restricted cone drops it. But H's mapping toward the main
UDP port is alive, because bdNAT keepalives run every 15 s. So:

    1. J fires `0x0d` straight at SERVER:S_H  ->  we learn J's mapping toward S_H
    2. J fires `0x0a` at the main port        ->  we relay `0x0b` to H from the
                                                  main port, where H's mapping IS
                                                  alive
    3. H flips it to `0x0c` and answers `addrA` = SERVER:S_J
                                              ->  H's mapping toward S_J is now
                                                  created, and we have learned it
    4. we forward that `0x0c` out of S_H to J ->  J verifies the untouched HMAC
                                                  and takes the datagram's source,
                                                  SERVER:S_H, as where H lives

Both mappings now exist, both directions are known, and the match traffic that
follows is pure forwarding.

COST: ~7 datagrams/sec each way per pair (Phase 18), so a four-player match is
roughly 50 KB/s through the server.

OPERATIONALLY: the relay ports must be open in the firewall, exactly like the
main UDP port. The server logs the range at startup for that reason.
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
#
# What the console should be told the server's address is. Not the same question
# as "what address did we bind": the bind is a wildcard, the rig reaches us on a
# bridge address and a VPS on a public one, and the console has to be handed
# something it can actually dial. The kernel already knows -- connecting a UDP
# socket performs a route lookup and nothing else, so getsockname() on it is the
# source address we would use to reach that client.
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
            s.connect((client_ip, 9))          # discard port; no packet is sent
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
#: Mailboxes one source ADDRESS may hold at once (§65). A household behind one
#: NAT has a few consoles; a run of forged keepalives from one address has as
#: many source ports as it likes, and without this it took the whole pool.
#: Past the cap the longest-idle console from that address is recycled, so a
#: real console that restarted (new mapped port) still gets in.
PER_ADDRESS_MAX = int(os.environ.get("WOW2_RELAY_PER_ADDRESS", "8"))


class Console:
    """One console, and every endpoint we have seen it speak from."""

    __slots__ = ("key", "mailbox", "seen", "peers", "last")

    def __init__(self, key: tuple[str, int]):
        #: where it contacted bdDiscovery from -- its mapping toward the MAIN
        #: port, which the keepalives hold open. The bootstrap `0x0b` goes here.
        self.key = key
        self.mailbox: "Mailbox | None" = None
        #: our socket port -> the endpoint this console talks to that socket from.
        #: One entry per socket on purpose: a symmetric NAT maps per destination.
        self.seen: dict[int, tuple[str, int]] = {}
        self.peers: set["Console"] = set()
        self.last = time.time()

    def __repr__(self) -> str:
        p = self.mailbox.port if self.mailbox else "-"
        return f"<{self.key[0]}:{self.key[1]} mailbox {p}>"


class Mailbox(asyncio.DatagramProtocol):
    """One UDP socket, owned by one console, and that console's public address.

    Everything arriving here is FOR the owner. Everything leaving here was sent
    BY the owner -- so the peer sees the address it dialled, which is the whole
    trick and the reason there are two sockets per pair rather than one.
    """

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
        if owner is None:                      # a stale mapping to a freed port
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
            # The owner has never spoken to that socket, so its NAT has no
            # mapping that would admit us. Dropping is right: the bootstrap is
            # the `0x0b` on the main port, and the client retries.
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
        if now - self._last_drop_log > 2.0:      # one line per two seconds
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
        """Bind the whole pool up front.

        Lazily would be tidier and is not worth it: allocation happens inside a
        datagram callback, which is synchronous, and an idle UDP socket costs
        nothing. Binding here also means a port conflict is a startup error
        rather than a join that mysteriously does not work.
        """
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
        """A traffic line whenever something moved, and silence otherwise.

        Worth having because a relayed session is INVISIBLE in every other log
        the server keeps: the peer protocol is encrypted, it never reaches a
        handler, and the only evidence that a match is being carried at all is
        the packet count. Rate-limited to a minute so it cannot become the noise
        that hexdumps were.
        """
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
        """Forget every console idle past IDLE_TIMEOUT. How many went.

        Reclaiming used to happen only when the pool ran dry, so a console
        that stopped talking kept its mailbox and its entry until then. A
        keepalive every 15 s is what holds a console's NAT mapping open, so
        ten silent minutes means nothing behind that endpoint is reachable
        any more, and the sweep costs nothing (§65).
        """
        now = time.time() if now is None else now
        idle = [c for c in list(self.consoles.values()) if now - c.last > IDLE_TIMEOUT]
        for c in idle:
            _log(f"RELAY: {c} idle {now - c.last:.0f}s -- forgotten")
            self.forget(c)
        return len(idle)

    # -------------------------------------------------------------- allocation
    def mailbox_for(self, endpoint: tuple[str, int]) -> Mailbox | None:
        """The mailbox for the console that speaks from `endpoint`, allocating
        one if this is the first we have seen of it."""
        if not self.enabled:
            return None
        c = self.consoles.get(endpoint)
        if c is not None:
            c.last = time.time()
            return c.mailbox
        mb = self._free_mailbox(endpoint[0])
        if mb is None:
            # No Console object either (§65): one used to be made here and
            # kept for ever, since only a mailbox owner was ever reclaimed.
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
        # Nothing free: reclaim the longest-idle console past the timeout.
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
        """Whoever owns the mailbox an advertised address names.

        A console only ever learns an address from us, so any address it repeats
        back is one of ours -- which makes this an exact identification and not a
        heuristic. The IP is deliberately not checked: the console was told
        whichever of our addresses is reachable from where it sits, and the port
        alone is unique across the pool.
        """
        if addr is None:
            return None
        mb = self.by_port.get(addr[1])
        return mb.owner if mb else None

    def sender_for(self, mb: Mailbox, src: tuple[str, int],
                   data: bytes) -> Console | None:
        """Which console sent this, in order of how much it is worth trusting."""
        # 1. We have seen this exact endpoint before. Always true after the first
        #    packet of a path, and true from the start behind a cone NAT.
        for c in self.consoles.values():
            if c.key == src or src in c.seen.values():
                return c
        # 2. A bdNAT introduction carries the originator's OWN address in addrA
        #    (29 bytes, version 2; addrA at 17). It names a mailbox, so it names
        #    a console. This is what identifies a symmetric-NAT console on the
        #    first packet of a new path, where its endpoint is unrecognisable.
        #
        #    ...unrecognisable by PORT. A symmetric NAT maps a new port per
        #    destination and keeps the address, so the source address still
        #    has to be the console's own (§65). Without that, a 29-byte
        #    datagram from anywhere naming a live mailbox port in addrA was
        #    taken for that console, and `seen[port]` -- where the owner's
        #    replies are sent -- moved to wherever it came from. Rule 3 gets
        #    the same condition for the same reason.
        if len(data) == 29 and data[1:3] == b"\x02\x00":
            c = self.owner_of_advertised(_bd_addr_at(data, 17))
            if c is not None and c is not mb.owner:
                if c.key[0] == src[0]:
                    return c
                _log(f"RELAY: {src[0]}:{src[1]} names {c}'s mailbox in addrA "
                     f"but is not at {c.key[0]} -- not attributed")
                return None
        # 3. This mailbox has exactly one peer, so there is nothing to confuse it
        #    with. Covers the host's `0x0c`, whose addrA names the joiner.
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
        sent the other anything. Seeds `peers` so rule 3 above can fire."""
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
