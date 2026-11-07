#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Run the DHCP server and DNS forwarder as a root subprocess.

The NetDeck backend runs as the unprivileged `deck` user, which cannot
bind privileged ports (UDP 67/53).  This helper runs the same netstack
servers with root privileges and periodically persists leases to a
state file the plugin can read.
"""
import argparse
import asyncio
import json
import os
import signal
import sys
import time

here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, here)
sys.path.insert(0, os.path.join(here, "py_modules"))
from netstack import DhcpServer, DnsForwarder  # noqa: E402


async def amain() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--interface", required=True)
    ap.add_argument("--gateway", required=True)
    ap.add_argument("--mask", required=True)
    ap.add_argument("--dns", default=None, help="Upstream DNS server")
    ap.add_argument("--state", required=True, help="Lease state file path")
    args = ap.parse_args()

    state_path = args.state
    dhcp: DhcpServer = None  # type: ignore[assignment]
    dns: DnsForwarder = None  # type: ignore[assignment]

    def write_state() -> None:
        data = {"pid": os.getpid(), "updated": time.time(), "leases": []}
        if dhcp is not None:
            now = time.time()
            data["leases"] = [
                {"mac": lease.mac, "ip": lease.ip,
                 "hostname": lease.hostname, "expires": lease.expires}
                for lease in dhcp.leases.values() if lease.active()
            ]
        tmp = state_path + ".tmp"
        try:
            with open(tmp, "w") as fh:
                json.dump(data, fh)
            os.replace(tmp, state_path)
        except OSError:
            pass

    async def periodic() -> None:
        while True:
            await asyncio.sleep(2)
            write_state()

    loop = asyncio.get_running_loop()
    stopping: asyncio.Future = loop.create_future()

    def request_stop(*_: object) -> None:
        if not stopping.done():
            stopping.set_result(None)

    for sig in (signal.SIGTERM, signal.SIGINT):
        loop.add_signal_handler(sig, request_stop)

    dhcp = DhcpServer(args.interface, args.gateway, args.mask)
    await dhcp.start()
    dns = DnsForwarder(upstream=args.dns)
    await dns.start()
    write_state()
    writer = asyncio.ensure_future(periodic())

    try:
        await stopping
    finally:
        writer.cancel()
        dns.stop()
        dhcp.stop()
        write_state()


if __name__ == "__main__":
    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        pass
