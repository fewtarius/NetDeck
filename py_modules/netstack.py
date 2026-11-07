# SPDX-License-Identifier: GPL-3.0-or-later
"""Embedded DHCP server and DNS forwarder for shared-mode access points.

Pure Python replacements for external daemons that are unavailable on
immutable distributions. Runs inside the plugin's asyncio loop.
"""
import asyncio
import logging
import os
import random
import socket
import struct
import time
from typing import Dict, Optional, Tuple

logger = logging.getLogger("NetDeck.netstack")

# DHCP protocol constants (RFC 2131)
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
DHCP_NAK = 6
DHCP_RELEASE = 7

BOOTREQUEST = 1
BOOTREPLY = 2

MAGIC_COOKIE = b"\x63\x82\x53\x63"

OPT_SUBNET = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_HOSTNAME = 12
OPT_REQUESTED_IP = 50
OPT_LEASE_TIME = 51
OPT_DHCP_MSG = 53
OPT_SERVER_ID = 54
OPT_PARAM_REQ = 55
OPT_END = 255


class DhcpLease:
    __slots__ = ("mac", "ip", "hostname", "expires")

    def __init__(self, mac: str, ip: str, hostname: str, expires: float):
        self.mac = mac
        self.ip = ip
        self.hostname = hostname
        self.expires = expires

    def active(self) -> bool:
        return time.time() < self.expires


class DhcpServer(asyncio.DatagramProtocol):
    """Minimal DHCP server bound to the AP interface.

    Serves one /24 subnet. Allocates addresses from a pool, honors
    re-requests from existing clients, and answers parameter requests
    for gateway, DNS, and lease time.
    """

    def __init__(self, interface: str, gateway_ip: str, subnet_mask: str,
                 pool_start: int = 100, pool_end: int = 200,
                 lease_seconds: int = 3600):
        self.interface = interface
        self.gateway_ip = gateway_ip
        self.subnet_mask = subnet_mask
        self.pool_start = pool_start
        self.pool_end = pool_end
        self.lease_seconds = lease_seconds
        self.leases: Dict[str, DhcpLease] = {}  # mac -> lease
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._prefix = ".".join(gateway_ip.split(".")[:3])

    # --- lifecycle -------------------------------------------------

    async def start(self) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Lock the socket to the AP interface so upstream DHCP traffic
        # is not intercepted. Requires CAP_NET_RAW (plugin runs as root).
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE,
                            self.interface.encode("ascii") + b"\0")
        except OSError as e:
            logger.warning("SO_BINDTODEVICE failed on %s: %s", self.interface, e)
        # Required to send replies to 255.255.255.255; without it sendto raises EACCES
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        try:
            sock.bind(("0.0.0.0", 67))
        except OSError as e:
            sock.close()
            raise RuntimeError(f"Cannot bind DHCP port 67: {e}") from e
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self, sock=sock)
        logger.info("DHCP server listening on %s (%s-%s)",
                    self.gateway_ip, self._prefix + f".{self.pool_start}",
                    self._prefix + f".{self.pool_end}")

    def stop(self) -> None:
        if self.transport:
            self.transport.close()
            self.transport = None
        self.leases.clear()

    # --- datagram handling -----------------------------------------

    def connection_made(self, transport) -> None:  # noqa: D102
        self.transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        logger.debug("DHCP packet from %s (%d bytes)", addr, len(data))
        try:
            self._process(data)
        except Exception:
            logger.exception("DHCP packet processing error")

    def _process(self, data: bytes) -> None:
        if len(data) < 240:
            return
        msg_type_raw, hw_type, hw_len, _hops = struct.unpack("!BBBB", data[:4])
        xid, _secs, _flags, _ciaddr, _yiaddr, _siaddr, _giaddr = \
            struct.unpack("!IHHIIII", data[4:28])
        chaddr = data[28:28 + 16]
        if msg_type_raw != BOOTREQUEST or data[236:240] != MAGIC_COOKIE:
            return

        mac = ":".join(f"{b:02x}" for b in chaddr[:hw_len])
        options = self._parse_options(data[240:])

        msg_type_opt = options.get(OPT_DHCP_MSG)
        msg_type = msg_type_opt[0] if msg_type_opt else None
        if msg_type in (DHCP_DISCOVER, DHCP_REQUEST):
            self._serve(xid, chaddr[:hw_len], mac, msg_type, options)
        elif msg_type == DHCP_RELEASE:
            lease = self.leases.pop(mac, None)
            if lease:
                logger.info("Released %s from %s (%s)",
                            lease.ip, mac, lease.hostname)

    def _parse_options(self, blob: bytes) -> Dict[int, bytes]:
        opts: Dict[int, bytes] = {}
        i = 0
        while i < len(blob):
            code = blob[i]
            if code == 0:
                i += 1
                continue
            if code == OPT_END or i + 1 >= len(blob):
                break
            length = blob[i + 1]
            opts[code] = blob[i + 2:i + 2 + length]
            i += 2 + length
        return opts

    def _serve(self, xid: int, hwaddr: bytes, mac: str,
               msg_type: int, options: Dict[int, bytes]) -> None:
        hostname = options.get(OPT_HOSTNAME, b"").decode(
            "ascii", "ignore").strip(".")
        lease = self.leases.get(mac)
        requested = options.get(OPT_REQUESTED_IP)

        if lease and lease.active():
            ip = lease.ip
        elif lease and not lease.active():
            # Expired: honor re-request if address still free, else new
            ip = (requested.decode() if requested and
                  self._ip_free(requested.decode(), mac)
                  else self._allocate(mac))
        else:
            ip = self._allocate(mac)

        if not ip:
            self._send(xid, hwaddr, DHCP_NAK, "0.0.0.0", options, b"")
            return

        self.leases[mac] = DhcpLease(mac, ip, hostname,
                                     time.time() + self.lease_seconds)
        if msg_type == DHCP_DISCOVER:
            reply_type = DHCP_OFFER
        else:
            reply_type = DHCP_ACK
        self._send(xid, hwaddr, reply_type, ip, options, hostname)

    def _allocate(self, mac: str) -> Optional[str]:
        used = {l.ip for l in self.leases.values() if l.active()}
        for n in range(self.pool_start, self.pool_end + 1):
            candidate = f"{self._prefix}.{n}"
            if candidate not in used:
                return candidate
        # Pool exhausted: reclaim oldest expired lease
        expired = sorted((l for l in self.leases.values() if not l.active()),
                         key=lambda l: l.expires)
        if expired:
            mac_old = expired[0].mac
            ip = self.leases[mac_old].ip
            del self.leases[mac_old]
            return ip
        return None

    def _ip_free(self, ip: str, mac: str) -> bool:
        holder = self.leases.get(mac)
        if holder and holder.ip == ip:
            return True
        return all(l.ip != ip for l in self.leases.values() if l.active())

    def _send(self, xid: int, hwaddr: bytes, msg_type: int, ip: str,
              req_opts: Dict[int, bytes], hostname: str) -> None:
        packet = bytearray(240)
        struct.pack_into("!BBBB", packet, 0, BOOTREPLY, 1, len(hwaddr), 0)
        struct.pack_into("!I", packet, 4, xid)
        struct.pack_into("!HH", packet, 8, 0, 0x8000)  # broadcast flag
        packet[28:28 + len(hwaddr)] = hwaddr
        packet[236:240] = MAGIC_COOKIE
        packet[16:20] = socket.inet_aton(ip)

        opts = bytearray()
        opts.append(OPT_DHCP_MSG)
        opts.append(1)
        opts.append(msg_type)

        if msg_type in (DHCP_OFFER, DHCP_ACK):
            lease_le = struct.pack("!I", self.lease_seconds)
            server = socket.inet_aton(self.gateway_ip)
            opts += struct.pack("!BB", OPT_LEASE_TIME, 4) + lease_le
            opts += struct.pack("!BB", OPT_SUBNET, 4) + \
                socket.inet_aton(self.subnet_mask)
            opts += struct.pack("!BB", OPT_ROUTER, 4) + server
            opts += struct.pack("!BB", OPT_DNS, 4) + server
            opts += struct.pack("!BB", OPT_SERVER_ID, 4) + server
            if hostname:
                h = hostname[:63].encode("ascii", "ignore")
                opts += struct.pack("!BB", OPT_HOSTNAME, len(h)) + h
        opts.append(OPT_END)
        if len(opts) % 2:
            opts.append(0)  # pad for word alignment
        packet += opts

        if self.transport:
            try:
                self.transport.sendto(bytes(packet), ("<broadcast>", 68))
                logger.debug("Sent %s to %02x:%02x:%02x:%02x:%02x:%02x (xid=%08x)",
                             "OFFER" if msg_type == DHCP_OFFER else
                             "ACK" if msg_type == DHCP_ACK else "NAK",
                             *hwaddr[:6], xid)
            except OSError as e:
                logger.error("Failed to send DHCP reply: %s", e)


class DnsForwarder(asyncio.DatagramProtocol):
    """UDP DNS proxy.

    Forwards client queries to upstream resolvers read from
    /etc/resolv.conf, falling back to a public resolver. Uses raw
    datagram pass-through: query bytes are relayed unmodified and the
    reply is returned to the originating client, so no DNS packet
    re-assembly is required.
    """

    def __init__(self, upstream: Optional[str] = None):
        self.upstream = upstream or self._read_upstream()
        self.transport: Optional[asyncio.DatagramTransport] = None
        self._upstream_transport: Optional[asyncio.DatagramTransport] = None
        self._pending: Dict[bytes, Tuple[Tuple[str, int], float]] = {}
        self._upstream_protocol: Optional["_UpstreamProtocol"] = None

    @staticmethod
    def _read_upstream() -> str:
        try:
            with open("/etc/resolv.conf", "r", encoding="ascii") as fh:
                for line in fh:
                    parts = line.split()
                    if len(parts) >= 2 and parts[0] == "nameserver":
                        return parts[1]
        except OSError:
            pass
        return "1.1.1.1"

    async def start(self, bind_ip: str = "0.0.0.0", port: int = 53) -> None:
        loop = asyncio.get_running_loop()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind((bind_ip, port))
        except OSError as e:
            sock.close()
            raise RuntimeError(f"Cannot bind DNS port 53: {e}") from e
        self.transport, _ = await loop.create_datagram_endpoint(
            lambda: self, sock=sock)
        logger.info("DNS forwarder listening on %s:%d -> %s",
                    bind_ip, port, self.upstream)

    def stop(self) -> None:
        if self.transport:
            self.transport.close()
            self.transport = None
        if self._upstream_transport:
            self._upstream_transport.close()
            self._upstream_transport = None
        self._pending.clear()

    def connection_made(self, transport) -> None:  # noqa: D102
        # The client listener is created first; the upstream socket uses
        # the same protocol instance, so only accept the first transport.
        if self.transport is None:
            self.transport = transport

    async def _ensure_upstream(self) -> None:
        if self._upstream_transport is None:
            loop = asyncio.get_running_loop()
            self._upstream_protocol = _UpstreamProtocol(self)
            # asyncio refuses remote_addr together with a pre-made socket;
            # let it create and connect the upstream socket itself.
            self._upstream_transport, _ = await loop.create_datagram_endpoint(
                lambda: self._upstream_protocol,
                remote_addr=(self.upstream, 53))

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        logger.debug("DNS query from %s (%d bytes, qid=%s)",
                     addr, len(data), data[0:2].hex() if len(data) >= 2 else "?")
        try:
            asyncio.get_running_loop().create_task(self._relay(data, addr))
        except Exception:
            logger.exception("DNS relay error")

    async def _relay(self, data: bytes, addr: Tuple[str, int]) -> None:
        try:
            if len(data) < 12:
                return
            await self._ensure_upstream()
            qid = data[0:2]
            self._pending[qid] = (addr, time.time())
            # Prune stale entries
            now = time.time()
            stale = [k for k, (_, t) in self._pending.items() if now - t > 15]
            for k in stale:
                del self._pending[k]
            if self._upstream_transport:
                self._upstream_transport.sendto(data)
                logger.debug("DNS relayed qid=%s to upstream %s",
                             qid.hex(), self.upstream)
            else:
                logger.error("DNS upstream transport missing; dropping query")
        except Exception:
            logger.exception("DNS relay task failed")

    def error_received(self, exc: Exception) -> None:
        logger.debug("DNS forwarder error: %s", exc)


class _UpstreamProtocol(asyncio.DatagramProtocol):
    """Separate protocol instance for the upstream resolver socket.

    Using a dedicated protocol avoids the fragile address-based check
    (_is_from_upstream) that could misroute packets when a client
    happens to share the upstream's IP:port.
    """

    def __init__(self, forwarder: "DnsForwarder"):
        self.forwarder = forwarder

    def connection_made(self, transport) -> None:  # noqa: D102
        self.forwarder._upstream_transport = transport

    def datagram_received(self, data: bytes, addr: Tuple[str, int]) -> None:
        logger.debug("DNS upstream reply (%d bytes, qid=%s)",
                     len(data), data[0:2].hex() if len(data) >= 2 else "?")
        try:
            route_reply_for(self.forwarder, data)
        except Exception:
            logger.exception("DNS upstream relay error")

    def error_received(self, exc: Exception) -> None:
        logger.debug("DNS upstream error: %s", exc)


def route_reply_for(forwarder: DnsForwarder, data: bytes) -> None:
    """Helper invoked when upstream data arrives; routes to client."""
    if len(data) < 2:
        return
    target = forwarder._pending.pop(data[0:2], None)
    if target and forwarder.transport:
        forwarder.transport.sendto(data, target[0])
