#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""NetDeck plugin for network management on SteamOS / Decky Loader.

Self-contained: no external daemon dependencies. Provides MAC address
configuration, WiFi hotspot with DHCP/DNS, internet sharing via nftables,
and layered connectivity status.
"""
import asyncio
import contextlib
import decky  # type: ignore
import hashlib
import ipaddress
import json
import os
import random
import re
import secrets
import shutil
import ssl
import sys
import tempfile
import time
import urllib.request
import zipfile
from typing import Any, Dict, List, Optional, Tuple

# Make py_modules importable when bundled by Decky
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "py_modules"))

CONFIG_DIR = os.path.expanduser("~/.config/netdeck")
os.makedirs(CONFIG_DIR, exist_ok=True)


def _load_prefs() -> Dict[str, Any]:
    """Load preferences from the config directory (module-level helper)."""
    path = os.path.join(CONFIG_DIR, "preferences.json")
    if os.path.exists(path):
        try:
            with open(path) as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
    return {}

VALID_BANDS = ("2.4GHz", "5GHz")


def normalize_band(band: str) -> str:
    """Map any case variant of a band name to the canonical form."""
    lower = (band or "").strip().lower()
    return "2.4GHz" if lower == "2.4ghz" else "5GHz" if lower == "5ghz" else band
CHANNELS_2GHZ = (1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13)
CHANNELS_5GHZ = (36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112,
                 116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165)
NFT_TABLE = "netdeck"

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")
IFACE_RE = re.compile(r"^[a-zA-Z0-9_.-]{1,15}$")
UPDATE_HOSTS = ("github.com", "api.github.com",
                "objects.githubusercontent.com",
                "release-assets.githubusercontent.com")
UPDATE_URL_RE = re.compile(
    r"^https://(" + "|".join(UPDATE_HOSTS) + r")/", re.IGNORECASE)


def get_plugin_version() -> str:
    for candidate in ("VERSION", "plugin.json"):
        path = os.path.join(os.path.dirname(__file__), candidate)
        try:
            if candidate == "VERSION":
                with open(path, "r") as fh:
                    v = fh.read().strip()
                    if v:
                        return v
            else:
                with open(path, "r") as fh:
                    return json.load(fh).get("version", "unknown")
        except OSError:
            continue
    return "unknown"


# ---------------------------------------------------------------------------
# Version comparison
# ---------------------------------------------------------------------------

def _parse_version(v: str) -> Tuple[int, ...]:
    """Parse a dotted version string into a comparable tuple.

    Non-numeric suffixes (e.g. '-rc1') are stripped.  Missing segments
    default to 0.
    """
    parts = []
    for seg in v.split("."):
        num = ""
        for ch in seg:
            if ch.isdigit():
                num += ch
            else:
                break
        parts.append(int(num) if num else 0)
    return tuple(parts)


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------

def _ok(value: bool, error: str) -> Dict[str, Any]:
    return {"success": value, "error": error} if not value else {"success": True}


def validate_interface(name: str) -> Dict[str, Any]:
    if not name or not IFACE_RE.match(name):
        return _ok(False, "Invalid interface name")
    return {"success": True}


def validate_ssid(ssid: str) -> Dict[str, Any]:
    if not ssid or len(ssid) > 32 or any(ord(c) < 32 for c in ssid):
        return _ok(False, "SSID must be 1-32 printable characters")
    return {"success": True}


def validate_password(pw: str) -> Dict[str, Any]:
    if not pw:
        return _ok(False, "Password required")
    if len(pw) == 64 and all(c in "0123456789abcdefABCDEF" for c in pw):
        return {"success": True}
    if 8 <= len(pw) <= 63 and all(32 <= ord(c) < 127 for c in pw):
        return {"success": True}
    return _ok(False, "Password must be 8-63 printable chars or 64 hex digits")


def validate_mac(mac: str) -> Dict[str, Any]:
    if not MAC_RE.match(mac):
        return _ok(False, "Invalid MAC address format")
    octets = [int(x, 16) for x in mac.split(":")]
    if octets[0] & 0x01:
        return _ok(False, "Multicast MAC not allowed")
    if octets[0] == 0xFF:
        return _ok(False, "Broadcast MAC not allowed")
    return {"success": True}


def validate_subnet(subnet: str) -> Dict[str, Any]:
    try:
        net = ipaddress.IPv4Network(subnet, strict=False)
    except ValueError:
        return _ok(False, "Invalid subnet")
    if net.prefixlen != 24:
        return _ok(False, "Only /24 subnets supported")
    return {"success": True, "network": net}


def validate_channel(ch: int, band: str) -> Dict[str, Any]:
    band = normalize_band(band)
    pool = CHANNELS_5GHZ if band == "5GHz" else CHANNELS_2GHZ
    if ch not in pool:
        return _ok(False, f"Channel {ch} not valid for {band}")
    return {"success": True}


def validate_band(band: str) -> Dict[str, Any]:
    band = normalize_band(band)
    if band not in VALID_BANDS:
        return _ok(False, f"Band must be one of {VALID_BANDS}")
    return {"success": True}


def validate_update_url(url: str) -> Dict[str, Any]:
    if not url or not UPDATE_URL_RE.match(url):
        return _ok(False, "Download URL must point to a GitHub host")
    return {"success": True}


# ---------------------------------------------------------------------------
# Command execution (argv-based, no shell)
# ---------------------------------------------------------------------------

class CommandRunner:
    """Runs commands via argv lists — never through a shell."""

    @staticmethod
    async def run(argv: List[str], timeout: int = 30) -> Dict[str, Any]:
        try:
            # The backend runs as the unprivileged `deck` user; network
            # tools (nmcli, nft, sysctl, firewall-cmd) need root.  The deck
            # user has passwordless sudo on SteamOS.
            argv = list(argv)
            if os.geteuid() != 0:
                argv = ["sudo", "-n"] + argv
            # PyInstaller's onefile runtime puts its extraction dir in
            # LD_LIBRARY_PATH; child processes inherit it and resolve
            # bundled libraries (e.g. libtinfo) that may not match the
            # system glibc, breaking every spawned tool.  Child tools
            # must link against the system libraries.
            env = os.environ.copy()
            env.pop("LD_LIBRARY_PATH", None)
            env.pop("LD_PRELOAD", None)
            proc = await asyncio.create_subprocess_exec(
                *argv,
                env=env,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE)
            try:
                out, err = await asyncio.wait_for(proc.communicate(), timeout)
            except asyncio.TimeoutExpired:
                proc.kill()
                await proc.communicate()
                return {"success": False, "error": "Command timeout",
                        "stdout": "", "stderr": "", "returncode": -1}
            return {
                "success": proc.returncode == 0,
                "stdout": out.decode(errors="replace").strip(),
                "stderr": err.decode(errors="replace").strip(),
                "returncode": proc.returncode,
            }
        except FileNotFoundError:
            return {"success": False, "error": f"Command not found: {argv[0]}",
                    "stdout": "", "stderr": "", "returncode": -1}
        except Exception as e:
            return {"success": False, "error": str(e),
                    "stdout": "", "stderr": "", "returncode": -1}

    @staticmethod
    async def run_shell(cmd: str, timeout: int = 30) -> Dict[str, Any]:
        """Only for fixed, non-user-controlled shell strings."""
        return await CommandRunner.run(["/bin/bash", "-c", cmd], timeout)


# ---------------------------------------------------------------------------
# Network helpers
# ---------------------------------------------------------------------------

async def get_interfaces() -> List[Dict[str, str]]:
    r = await CommandRunner.run(["ip", "link", "show"])
    if not r["success"]:
        return []
    result = []
    for line in r["stdout"].splitlines():
        if ":" in line and "state" in line:
            parts = line.split(":")
            if len(parts) >= 2:
                name = parts[1].strip()
                if name != "lo":
                    result.append({"name": name,
                                   "state": "UP" if "UP" in line else "DOWN"})
    return result


async def get_hwaddr(interface: str) -> Optional[str]:
    r = await CommandRunner.run(
        ["nmcli", "-t", "-f", "GENERAL.HWADDR", "device", "show", interface])
    if r["success"] and r["stdout"]:
        return r["stdout"].strip()
    r2 = await CommandRunner.run(["cat", f"/sys/class/net/{interface}/address"])
    if r2["success"]:
        return r2["stdout"].strip()
    return None


async def get_permanent_hwaddr(interface: str) -> Optional[str]:
    """Read the permanent hardware MAC, preferring saved original over current.

    NetworkManager's GENERAL.HWADDR reflects the *current* MAC (which may
    be a spoofed/cloned address).  When a MAC has already been changed we
    must not treat the spoofed value as the original.  We therefore check
    the saved preferences first, then fall back to the current address
    only when no saved original exists.
    """
    prefs = _load_prefs()
    saved = prefs.get("mac_addresses", {}).get(interface, {})
    original = saved.get("original_mac")
    if original:
        return original
    return await get_hwaddr(interface)


async def get_current_mac(interface: str) -> Optional[str]:
    r = await CommandRunner.run(["ip", "link", "show", interface])
    if r["success"]:
        for line in r["stdout"].splitlines():
            if "link/ether" in line:
                return line.strip().split()[1]
    return None


async def get_active_profile(interface: str) -> Optional[str]:
    r = await CommandRunner.run(
        ["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"])
    if not r["success"]:
        return None
    for line in r["stdout"].splitlines():
        name, dev = line.split(":", 1)
        if dev == interface:
            return name
    return None


async def validate_connectivity() -> bool:
    r = await CommandRunner.run(["ip", "route", "show", "default"])
    if not r["success"] or not r["stdout"]:
        return False
    for line in r["stdout"].splitlines():
        if "default via" in line:
            gw = line.split()[2]
            ping = await CommandRunner.run(
                ["ping", "-c", "1", "-W", "3", gw])
            return ping["success"]
    return False


async def get_gateway_interface() -> Optional[str]:
    r = await CommandRunner.run(["ip", "route", "show", "default"])
    if r["success"]:
        for line in r["stdout"].splitlines():
            if "default via" in line:
                parts = line.split()
                for i, p in enumerate(parts):
                    if p == "dev" and i + 1 < len(parts):
                        return parts[i + 1]
    return None


# ---------------------------------------------------------------------------
# nftables backend
# ---------------------------------------------------------------------------

class NftBackend:
    """Owns a dedicated nftables table for NAT + packet normalization."""

    def __init__(self, wan_iface: str, ap_iface: str, subnet: str):
        # Validate interface names to prevent nftables ruleset injection.
        # wan_iface comes from get_gateway_interface() (not user input) but
        # is still validated for defense in depth.
        for name in (wan_iface, ap_iface):
            if not name or not IFACE_RE.match(name):
                raise ValueError(f"Invalid interface name: {name!r}")
        self.wan = wan_iface
        self.ap = ap_iface
        net = ipaddress.IPv4Network(subnet, strict=False)
        self.subnet = str(net)
        self.ap_ip = str(net.network_address + 1)

    def _ruleset(self) -> str:
        return f"""table ip {NFT_TABLE} {{
    chain postrouting {{
        type nat hook postrouting priority srcnat; policy accept;
        oifname "{self.wan}" ip saddr {self.subnet} masquerade fully-random
    }}
    chain forward {{
        type filter hook forward priority filter; policy accept;
        iifname "{self.ap}" oifname "{self.wan}" ip saddr {self.subnet} ip ttl set 64
        iifname "{self.ap}" oifname "{self.wan}" ip saddr {self.subnet} accept
        iifname "{self.wan}" oifname "{self.ap}" ct state established,related accept
        iifname "{self.ap}" udp dport 67 accept
        iifname "{self.ap}" udp dport 53 accept
        iifname "{self.ap}" tcp dport 53 accept
        iifname "{self.ap}" drop
    }}
    chain input {{
        type filter hook input priority -10; policy accept;
        iifname "{self.ap}" udp dport 67 accept
        iifname "{self.ap}" udp dport 53 accept
        iifname "{self.ap}" tcp dport 53 accept
        iifname "{self.ap}" drop
    }}
}}
"""

    async def apply(self) -> Dict[str, Any]:
        ruleset = self._ruleset()
        # CommandRunner handles sudo + clean env; keep everything in a
        # temp file since nft reads rulesets from files or stdin.
        tmp = os.path.join(CONFIG_DIR, "netdeck.nft")
        with open(tmp, "w") as fh:
            fh.write(ruleset)
        check = await CommandRunner.run(["nft", "--check", "--file", tmp])
        if not check["success"]:
            os.unlink(tmp)
            return {"success": False,
                    "error": f"nft check failed: {check['stderr']}"}
        applied = await CommandRunner.run(["nft", "--file", tmp])
        os.unlink(tmp)
        if not applied["success"]:
            return {"success": False,
                    "error": f"nft apply failed: {applied['stderr']}"}
        return {"success": True}

    async def delete(self) -> Dict[str, Any]:
        r = await CommandRunner.run(["nft", "delete", "table", "ip", NFT_TABLE])
        if not r["success"] and "no such table" not in r["stderr"].lower():
            return {"success": False, "error": r["stderr"]}
        return {"success": True}

    async def exists(self) -> bool:
        r = await CommandRunner.run(["nft", "list", "table", "ip", NFT_TABLE])
        return r["success"]


# ---------------------------------------------------------------------------
# Firewalld helper
# ---------------------------------------------------------------------------

class FirewalldHelper:
    ZONE = "netdeck"
    POLICY = "netdeck-forward"

    def _available(self) -> bool:
        return shutil.which("firewall-cmd") is not None

    async def provision(self, ap_iface: str) -> Dict[str, Any]:
        if not self._available():
            return {"success": True, "skipped": "firewalld not installed"}
        r = await CommandRunner.run(["firewall-cmd", "--new-zone", self.ZONE, "--permanent"])
        # NAME_CONFLICT means the zone already exists from an earlier run.
        if not r["success"] and not any(s in r["stderr"] for s in
                                        ("already exists", "NAME_CONFLICT")):
            return {"success": False, "error": f"new-zone failed: {r['stderr']}"}
        for svc in ("dhcp", "dns"):
            r = await CommandRunner.run(
                ["firewall-cmd", "--zone", self.ZONE, "--permanent", "--add-service", svc])
            if not r["success"]:
                return {"success": False, "error": f"add-service {svc} failed: {r['stderr']}"}
        for port in ("67/udp", "53/udp", "53/tcp"):
            r = await CommandRunner.run(
                ["firewall-cmd", "--zone", self.ZONE, "--permanent", "--add-port", port])
            if not r["success"] and "already" not in r["stderr"]:
                return {"success": False, "error": f"add-port {port} failed: {r['stderr']}"}
        r = await CommandRunner.run(["firewall-cmd", "--zone", self.ZONE, "--permanent", "--query-interface", ap_iface])
        if not r["success"]:
            r2 = await CommandRunner.run(
                ["firewall-cmd", "--zone", self.ZONE, "--permanent", "--change-interface", ap_iface])
            if not r2["success"]:
                return {"success": False, "error": f"change-interface failed: {r2['stderr']}"}
        r = await CommandRunner.run(["firewall-cmd", "--reload"])
        if not r["success"]:
            return {"success": False, "error": f"reload failed: {r['stderr']}"}
        pol = await self._provision_policy()
        if not pol.get("success"):
            return pol
        r = await CommandRunner.run(["firewall-cmd", "--reload"])
        if not r["success"]:
            return {"success": False, "error": f"reload failed: {r['stderr']}"}
        return {"success": True}

    async def _provision_policy(self) -> Dict[str, Any]:
        """Create a firewalld policy allowing forwarded traffic out of the
        netdeck zone.  Without this, firewalld's zone-pair reject rule
        blocks wlan1 -> wlan0 forwarding even though our nft table accepts
        it (accept in one base chain does not bypass later base chains).
        """
        r = await CommandRunner.run(
            ["firewall-cmd", "--permanent", "--new-policy", self.POLICY])
        if not r["success"] and not any(s in r["stderr"] for s in
                                        ("already exists", "NAME_CONFLICT")):
            return {"success": False, "error": f"new-policy failed: {r['stderr']}"}
        for arg in (("--add-ingress-zone", self.ZONE),
                    ("--add-egress-zone", "ANY")):
            r = await CommandRunner.run(
                ["firewall-cmd", "--permanent", "--policy", self.POLICY, arg[0], arg[1]])
            if not r["success"] and "ALREADY_ENABLED" not in r["stderr"] \
                    and "already" not in r["stderr"]:
                return {"success": False, "error": f"policy {arg[0]} failed: {r['stderr']}"}
        r = await CommandRunner.run(
            ["firewall-cmd", "--permanent", "--policy", self.POLICY,
             "--set-target", "ACCEPT"])
        if not r["success"] and "ALREADY_SET" not in r["stderr"]:
            return {"success": False, "error": f"policy set-target failed: {r['stderr']}"}
        return {"success": True}

    async def cleanup(self, ap_iface: str) -> Dict[str, Any]:
        if not self._available():
            return {"success": True, "skipped": "firewalld not installed"}
        await CommandRunner.run(
            ["firewall-cmd", "--zone", self.ZONE, "--permanent", "--remove-interface", ap_iface])
        await CommandRunner.run(
            ["firewall-cmd", "--permanent", "--delete-policy", self.POLICY])
        r = await CommandRunner.run(["firewall-cmd", "--delete-zone", self.ZONE, "--permanent"])
        if not r["success"] and "not found" not in r["stderr"] and "NO_DEFAULT" not in r["stderr"]:
            return {"success": False, "error": f"delete-zone failed: {r['stderr']}"}
        r = await CommandRunner.run(["firewall-cmd", "--reload"])
        if not r["success"]:
            return {"success": False, "error": f"reload failed: {r['stderr']}"}
        return {"success": True}


# ---------------------------------------------------------------------------
# Main plugin class
# ---------------------------------------------------------------------------

class NetDeckPlugin:
    def __init__(self):
        self.original_mac: Dict[str, str] = {}
        self.hotspot_active = False
        self.hotspot_config: Dict[str, Any] = {}
        self._netstack_proc: Optional[asyncio.subprocess.Process] = None
        self._lock = asyncio.Lock()
        self._ip_forward_was = 0
        self._bridge_cache: Tuple[float, bool] = (0.0, False)

        creds = self._load_credentials()
        self.adhoc_config = {
            "enabled": False, "ssid": creds["ssid"], "password": creds["password"],
            "channel": 6, "interface": None, "band": "2.4GHz",
            "subnet": "192.168.5.0/24", "hidden": False,
        }

    # --- preferences -------------------------------------------------

    async def _reconcile_state(self) -> None:
        """Restore saved state from preferences after a plugin restart.

        Loads saved MAC address configurations so that get_network_status
        can report the correct spoofed/original state.  Does NOT set
        hotspot_active=True because the Python-side DHCP/DNS services
        are not running after a restart; stop_adhoc_network handles
        cleanup of orphaned nftables rules if the user starts a new hotspot.
        """
        prefs = self._load_preferences()
        mac_configs = prefs.get("mac_addresses", {})
        for iface, cfg in mac_configs.items():
            if cfg.get("enabled") and cfg.get("original_mac"):
                self.original_mac[iface] = cfg["original_mac"]
        saved_hotspot = prefs.get("hotspot_autostart", {})
        if saved_hotspot.get("enabled"):
            self.hotspot_config = saved_hotspot
        # Re-apply saved MAC addresses that may have been lost across restart
        for iface, cfg in mac_configs.items():
            if not cfg.get("enabled"):
                continue
            desired = cfg.get("desired_mac")
            if not desired:
                continue
            current = await get_current_mac(iface)
            if current and current.lower() != desired.lower():
                decky.logger.info(f"Re-applying saved MAC for {iface}: {desired}")
                await self.set_mac_address(iface, desired, save_config=True)
        # Delete orphaned AP profiles left behind by previous sessions.
        await self._cleanup_orphaned_ap_profiles()
        # Kill any stale DHCP/DNS helper left over from a previous plugin
        # instance; it holds privileged ports the new instance needs.
        r = await CommandRunner.run(
            ["pkill", "-f", "netstack_runner.py"])
        if r["success"]:
            decky.logger.info("Killed stale netstack helper from previous session")
        try:
            os.unlink(self._netstack_state_path())
        except OSError:
            pass
        await CommandRunner.run(["nft", "delete", "table", "ip", NFT_TABLE])

    async def _cleanup_orphaned_ap_profiles(self) -> None:
        """Delete stale WiFi AP profiles and legacy netdeck-* profiles.

        The Python-side DHCP/DNS services do not survive a plugin restart,
        so any AP-mode profile that is active when the plugin starts is
        orphaned: clients could join it but would receive no address.
        NetworkManager profiles that are not in AP mode (client
        connections such as the user's home WiFi) are left untouched.
        """
        r = await CommandRunner.run(
            ["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
        if not r["success"]:
            return
        for line in r["stdout"].splitlines():
            if ":" not in line:
                continue
            name, ctype = line.split(":", 1)
            if ctype != "802-11-wireless":
                continue
            mode = None
            m = await CommandRunner.run(
                ["nmcli", "-t", "-f", "802-11-wireless.mode",
                 "connection", "show", name])
            if m["success"] and m["stdout"]:
                mode = m["stdout"].strip().split(":", 1)[-1].strip()
            if mode == "ap" or name.startswith("netdeck-"):
                decky.logger.info(
                    f"Cleaning up orphaned/legacy AP profile: {name}")
                await CommandRunner.run(["nmcli", "connection", "down", name])
                await CommandRunner.run(["nmcli", "connection", "delete", name])

    def _load_credentials(self) -> Dict[str, str]:
        path = os.path.join(CONFIG_DIR, "preferences.json")
        if os.path.exists(path):
            try:
                with open(path) as fh:
                    prefs = json.load(fh)
                    c = prefs.get("secure_credentials", {})
                    if c.get("ssid") and c.get("password"):
                        return c
            except (OSError, json.JSONDecodeError):
                pass
        return {"ssid": self._gen_ssid(), "password": self._gen_password()}

    def _save_preferences(self, prefs: Dict[str, Any]) -> None:
        path = os.path.join(CONFIG_DIR, "preferences.json")
        try:
            with open(path, "w") as fh:
                json.dump(prefs, fh, indent=2)
        except OSError as e:
            decky.logger.error(f"Failed to save preferences: {e}")

    def _load_preferences(self) -> Dict[str, Any]:
        path = os.path.join(CONFIG_DIR, "preferences.json")
        if os.path.exists(path):
            try:
                with open(path) as fh:
                    return json.load(fh)
            except (OSError, json.JSONDecodeError):
                pass
        return {}

    @staticmethod
    def _gen_ssid() -> str:
        words = ("amazing brilliant clever dazzling eager fantastic glorious "
                 "happy incredible joyful keen lively magnificent noble "
                 "outstanding peaceful quick radiant stellar triumphant "
                 "unique vibrant wonderful excellent zestful agile bold "
                 "creative dynamic energetic fearless graceful heroic").split()
        nouns = ("apple butterfly compass diamond eagle falcon galaxy "
                 "horizon island journey kite lighthouse mountain nebula "
                 "ocean phoenix quasar rainbow sunset tiger universe valley "
                 "whale beacon crystal discovery element fountain grove haven").split()
        return f"{random.choice(words)}-{random.choice(nouns)}-{random.randint(1000, 9999)}"

    @staticmethod
    def _gen_password() -> str:
        alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
        return "".join(secrets.choice(alphabet) for _ in range(10))

    # --- interface helpers ------------------------------------------

    async def get_network_interfaces(self) -> List[Dict[str, str]]:
        return await get_interfaces()

    async def get_current_mac(self, interface: str) -> Optional[str]:
        return await get_current_mac(interface)

    # --- MAC address configuration ----------------------------------

    async def set_mac_address(self, interface: str, new_mac: str,
                              save_config: bool = True) -> Dict[str, Any]:
        async with self._lock:
            v = validate_interface(interface)
            if not v["success"]:
                return v
            v = validate_mac(new_mac)
            if not v["success"]:
                return v
            hwaddr = await get_permanent_hwaddr(interface)
            if not hwaddr:
                return {"success": False, "error": "Could not read hardware address"}
            if interface not in self.original_mac:
                self.original_mac[interface] = hwaddr
            profile = await get_active_profile(interface)
            if not profile:
                return {"success": False,
                        "error": "No active NetworkManager connection for this interface"}
            r = await CommandRunner.run(
                ["nmcli", "connection", "modify", profile,
                 "802-11-wireless.cloned-mac-address", new_mac])
            if not r["success"]:
                return {"success": False, "error": r["stderr"]}
            up = await CommandRunner.run(["nmcli", "connection", "up", profile])
            if not up["success"]:
                return {"success": False, "error": up["stderr"]}
            if save_config:
                prefs = self._load_preferences()
                prefs.setdefault("mac_addresses", {})[interface] = {
                    "desired_mac": new_mac, "original_mac": hwaddr, "enabled": True}
                self._save_preferences(prefs)
            return {"success": True, "message": f"MAC set to {new_mac} on {interface}"}

    async def restore_original_mac(self, interface: str) -> Dict[str, Any]:
        async with self._lock:
            v = validate_interface(interface)
            if not v["success"]:
                return v
            hwaddr = await get_permanent_hwaddr(interface)
            if not hwaddr:
                return {"success": False, "error": "Could not read hardware address"}
            profile = await get_active_profile(interface)
            if not profile:
                return {"success": False,
                        "error": "No active NetworkManager connection"}
            r = await CommandRunner.run(
                ["nmcli", "connection", "modify", profile,
                 "802-11-wireless.cloned-mac-address", hwaddr])
            if not r["success"]:
                return {"success": False, "error": r["stderr"]}
            await CommandRunner.run(["nmcli", "connection", "up", profile])
            self.original_mac.pop(interface, None)
            prefs = self._load_preferences()
            prefs.get("mac_addresses", {}).pop(interface, None)
            self._save_preferences(prefs)
            return {"success": True, "message": f"MAC restored to {hwaddr}"}

    # --- hotspot ----------------------------------------------------

    async def start_adhoc_network(self, interface: str, ssid: str, password: str,
                                  channel: int, subnet: str = "192.168.5.0/24",
                                  band: str = "2.4GHz", hidden: bool = False) -> Dict[str, Any]:
        async with self._lock:
            for val, fn in [(interface, validate_interface), (ssid, validate_ssid),
                            (password, validate_password), (band, validate_band)]:
                v = fn(val)
                if not v["success"]:
                    decky.logger.error(f"Hotspot start rejected: {v['error']}")
                    return v
            v = validate_channel(channel, band)
            if not v["success"]:
                decky.logger.error(f"Hotspot start rejected: {v['error']}")
                return v
            v = validate_subnet(subnet)
            if not v["success"]:
                decky.logger.error(f"Hotspot start rejected: {v['error']}")
                return v
            net: ipaddress.IPv4Network = v["network"]
            ap_ip = str(net.network_address + 1)

            if self.hotspot_active:
                await self.stop_adhoc_network()

            primary = await get_gateway_interface()
            if not primary:
                decky.logger.error("Hotspot start rejected: no gateway interface")
                return {"success": False, "error": "No internet-connected interface found"}
            if interface == primary:
                decky.logger.error(f"Hotspot start rejected: {interface} is primary")
                return {"success": False,
                        "error": f"{interface} is the primary connection; use a different interface"}

            if not await validate_connectivity():
                decky.logger.error("Hotspot start rejected: no connectivity on primary")
                return {"success": False, "error": "Primary interface has no connectivity"}

            # Create AP profile
            conn_name = f"netdeck-{ssid}"
            await CommandRunner.run(["nmcli", "connection", "delete", conn_name])
            r = await CommandRunner.run([
                "nmcli", "connection", "add", "type", "wifi",
                "ifname", interface, "con-name", conn_name, "ssid", ssid])
            if not r["success"]:
                decky.logger.error(f"Hotspot start failed: create connection: {r['stderr']}")
                return {"success": False, "error": f"Failed to create connection: {r['stderr']}"}

            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "802-11-wireless.mode", "ap"])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "802-11-wireless.channel", str(channel)])
            band_val = "a" if normalize_band(band) == "5GHz" else "bg"
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "802-11-wireless.band", band_val])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "802-11-wireless.hidden", "true" if hidden else "false"])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "802-11-wireless-security.key-mgmt", "wpa-psk"])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "802-11-wireless-security.psk", password])
            # Order matters: addresses first, then method
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "ipv4.addresses", f"{ap_ip}/{net.prefixlen}"])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "ipv4.method", "manual"])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "ipv4.never-default", "yes"])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "ipv6.method", "disabled"])
            await CommandRunner.run(["nmcli", "connection", "modify", conn_name,
                                     "connection.autoconnect", "no"])

            up = await CommandRunner.run(["nmcli", "connection", "up", conn_name])
            if not up["success"]:
                await CommandRunner.run(["nmcli", "connection", "delete", conn_name])
                decky.logger.error(f"Hotspot start failed: activate AP: {up['stderr']}")
                return {"success": False, "error": f"Failed to activate AP: {up['stderr']}"}
            await asyncio.sleep(1)

            if not await validate_connectivity():
                await CommandRunner.run(["nmcli", "connection", "down", conn_name])
                await CommandRunner.run(["nmcli", "connection", "delete", conn_name])
                decky.logger.error("Hotspot start failed: primary connectivity lost, rolled back")
                return {"success": False,
                        "error": "Primary connectivity lost after AP activation; rolled back"}

            # Start DHCP + DNS as a root subprocess (privileged ports)
            ns = await self._start_netstack(interface, ap_ip, str(net.netmask))
            if not ns["success"]:
                await CommandRunner.run(["nmcli", "connection", "down", conn_name])
                await CommandRunner.run(["nmcli", "connection", "delete", conn_name])
                decky.logger.error(f"Hotspot start failed: {ns['error']}")
                return ns

            # nftables NAT + packet normalization
            fw = FirewalldHelper()
            fwr = await fw.provision(interface)
            if not fwr.get("success"):
                await self._rollback_hotspot(conn_name)
                decky.logger.error(
                    f"Hotspot start failed: firewalld: {fwr.get('error')}")
                return fwr
            try:
                nft = NftBackend(primary, interface, subnet)
                nft_r = await nft.apply()
            except ValueError as e:
                nft_r = {"success": False, "error": str(e)}
            if not nft_r.get("success"):
                await self._rollback_hotspot(conn_name)
                decky.logger.error(f"Hotspot start failed: nft backend: {e}")
                return {"success": False, "error": str(e)}

            # Enable IP forwarding
            rfwd = await CommandRunner.run(["cat", "/proc/sys/net/ipv4/ip_forward"])
            self._ip_forward_was = int(rfwd["stdout"].strip() or "0")
            await CommandRunner.run(["sysctl", "-w", "net.ipv4.ip_forward=1"])

            self.hotspot_active = True
            self.hotspot_config = {
                "enabled": True, "ssid": ssid, "password": password,
                "channel": channel, "band": band, "interface": interface,
                "ap_interface": interface, "primary_interface": primary,
                "connection_name": conn_name, "ap_ip": ap_ip,
                "subnet": subnet, "hidden": hidden,
            }
            self._save_hotspot_config(self.hotspot_config)
            decky.logger.info(f"Hotspot started: {ssid} on {interface}, "
                              f"internet via {primary}")
            return {"success": True,
                    "message": f"Hotspot '{ssid}' started on {interface}",
                    "ap_interface": interface, "primary_interface": primary}

    async def stop_adhoc_network(self) -> Dict[str, Any]:
        async with self._lock:
            if not self.hotspot_active:
                return {"success": True, "message": "No hotspot running"}
            cfg = self.hotspot_config
            # Reverse order
            try:
                nft = NftBackend(cfg.get("primary_interface", ""),
                                 cfg.get("ap_interface", ""),
                                 cfg.get("subnet", "192.168.5.0/24"))
                await nft.delete()
            except ValueError:
                pass  # Config may have empty strings after partial start
            fw = FirewalldHelper()
            await fw.cleanup(cfg.get("ap_interface", ""))
            await self._stop_netstack()
            await CommandRunner.run(["sysctl", "-w",
                                     f"net.ipv4.ip_forward={self._ip_forward_was}"])
            await CommandRunner.run(["nmcli", "connection", "down",
                                     cfg.get("connection_name", "")])
            await CommandRunner.run(["nmcli", "connection", "delete",
                                     cfg.get("connection_name", "")])
            self.hotspot_active = False
            self.hotspot_config = {}
            self._save_hotspot_config({})
            return {"success": True, "message": "Hotspot stopped"}

    def _save_hotspot_config(self, cfg: Dict[str, Any]) -> None:
        prefs = self._load_preferences()
        prefs["hotspot_autostart"] = cfg
        self._save_preferences(prefs)

    def _netstack_state_path(self) -> str:
        return os.path.join(CONFIG_DIR, "netstack_state.json")

    def _netstack_runner_path(self) -> Optional[str]:
        base = os.environ.get("DECKY_PLUGIN_DIR") or os.path.dirname(
            os.path.abspath(__file__))
        runner = os.path.join(base, "netstack_runner.py")
        if os.path.exists(runner):
            return runner
        return None

    async def _start_netstack(self, interface: str, ap_ip: str,
                              netmask: str) -> Dict[str, Any]:
        """Start DHCP/DNS as a root subprocess.

        The backend runs as the unprivileged `deck` user and cannot bind
        privileged ports; the helper runs them with root privileges and
        publishes leases to a state file.
        """
        runner = self._netstack_runner_path()
        if not runner:
            return {"success": False, "error": "netstack_runner.py not found"}
        state = self._netstack_state_path()
        try:
            os.unlink(state)
        except OSError:
            pass
        self._netstack_proc = await asyncio.create_subprocess_exec(
            "sudo", "-n", "/usr/bin/python3", runner,
            "--interface", interface, "--gateway", ap_ip, "--mask", netmask,
            "--state", state,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.PIPE)
        for _ in range(20):
            await asyncio.sleep(0.25)
            if self._netstack_proc.returncode is not None:
                _, err = await self._netstack_proc.communicate()
                decky.logger.error(
                    f"netstack exited: {err.decode(errors='replace').strip()}")
                return {"success": False, "error": "DHCP/DNS helper failed to start"}
            if os.path.exists(state):
                return {"success": True}
        return {"success": False, "error": "DHCP/DNS helper did not become ready"}

    async def _stop_netstack(self) -> None:
        proc = self._netstack_proc
        if proc is None or proc.returncode is not None:
            self._netstack_proc = None
            return
        proc.terminate()
        try:
            await asyncio.wait_for(proc.wait(), timeout=5)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
        self._netstack_proc = None

    async def _rollback_hotspot(self, conn_name: str) -> None:
        await self._stop_netstack()
        await CommandRunner.run(["nmcli", "connection", "down", conn_name])
        await CommandRunner.run(["nmcli", "connection", "delete", conn_name])

    async def get_adhoc_status(self) -> Dict[str, Any]:
        return {"active": self.hotspot_active, "config": self.hotspot_config}

    # --- DHCP leases ------------------------------------------------

    async def get_dhcp_leases(self) -> Dict[str, Any]:
        path = self._netstack_state_path()
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, json.JSONDecodeError):
            return {"leases": [], "count": 0}
        now = time.time()
        leases = [l for l in data.get("leases", []) if l.get("expires", 0) > now]
        return {"leases": leases, "count": len(leases)}

    # --- connected clients ------------------------------------------

    async def get_connected_clients(self) -> List[Dict[str, str]]:
        if not self.hotspot_config:
            return []
        ap_iface = self.hotspot_config.get("ap_interface", "")
        if not ap_iface:
            return []
        ap_ip = self.hotspot_config.get("ap_ip", "")
        r = await CommandRunner.run(["ip", "neigh", "show", "dev", ap_iface])
        if not r["success"]:
            return []
        # Build a MAC->hostname map from DHCP leases for enrichment
        lease_map: Dict[str, str] = {}
        try:
            with open(self._netstack_state_path()) as fh:
                now = time.time()
                for lease in json.load(fh).get("leases", []):
                    if lease.get("expires", 0) > now and lease.get("hostname"):
                        lease_map[str(lease.get("mac", "")).lower()] = lease["hostname"]
        except (OSError, json.JSONDecodeError):
            pass
        clients = []
        for line in r["stdout"].splitlines():
            parts = line.split()
            if len(parts) >= 5 and parts[0] != ap_ip:
                mac = parts[4].lower()
                clients.append({
                    "ip": parts[0],
                    "mac": parts[4],
                    "hostname": lease_map.get(mac, "")
                })
        return clients

    # --- network status ---------------------------------------------

    async def get_network_status(self) -> Dict[str, Any]:
        # Frontend expects a dict keyed by interface name with per-iface
        # MAC state, not a list.
        raw = await get_interfaces()
        interfaces: Dict[str, Dict[str, Any]] = {}
        for info in raw:
            name = info.get("name") or info.get("interface")
            if not name:
                continue
            current_mac = await get_current_mac(name)
            original_mac = await get_permanent_hwaddr(name) or current_mac
            interfaces[name] = {
                "state": info.get("state", "unknown"),
                "current_mac": current_mac,
                "original_mac": original_mac,
                "mac_spoofed": current_mac is not None and original_mac is not None
                    and current_mac.lower() != original_mac.lower(),
            }
        connected = await validate_connectivity()
        gateway = await get_gateway_interface()
        mac = None
        if gateway:
            mac = await get_current_mac(gateway)
        # bridge_active reflects actual NAT state (nftables table presence),
        # not just the user's nat_forwarding preference.  Cached briefly to
        # avoid hammering sudo on every status poll.
        now = time.time()
        cached_ts, cached_val = self._bridge_cache
        if now - cached_ts < 10:
            bridge_active = cached_val
        else:
            r = await CommandRunner.run(["nft", "list", "table", "ip", NFT_TABLE])
            bridge_active = r["success"]
            self._bridge_cache = (now, bridge_active)
        return {
            # Current frontend schema
            "connectivity": connected,
            "interfaces": interfaces,
            "adhoc_active": self.hotspot_active,
            "adhoc_config": self.hotspot_config,
            "bridge_active": bridge_active,
            # Legacy fields kept for older consumers
            "connected": connected,
            "gateway_interface": gateway,
            "gateway_mac": mac,
            "hotspot_active": self.hotspot_active,
            "hotspot_config": self.hotspot_config,
            "dhcp_leases": await self.get_dhcp_leases(),
            "connected_clients": await self.get_connected_clients(),
        }

    # --- IP forwarding ----------------------------------------------

    async def get_ip_forwarding_status(self) -> Dict[str, Any]:
        r = await CommandRunner.run(["cat", "/proc/sys/net/ipv4/ip_forward"])
        return {"enabled": r["stdout"].strip() == "1"}

    async def toggle_ip_forwarding(self, enable: bool) -> Dict[str, Any]:
        val = "1" if enable else "0"
        r = await CommandRunner.run(["sysctl", "-w", f"net.ipv4.ip_forward={val}"])
        return {"success": r["success"], "enabled": enable}

    # --- NAT preference (stored, applied with hotspot) --------------

    async def get_nat_forwarding_preference(self) -> Dict[str, Any]:
        prefs = self._load_preferences()
        return {"enabled": prefs.get("nat_forwarding", True)}

    async def set_nat_forwarding_preference(self, enabled: bool) -> Dict[str, Any]:
        prefs = self._load_preferences()
        prefs["nat_forwarding"] = enabled
        self._save_preferences(prefs)
        return {"success": True, "enabled": enabled}

    # --- interface preferences --------------------------------------

    async def get_interface_preferences(self) -> Dict[str, Any]:
        prefs = self._load_preferences()
        return {"selected_interface": prefs.get("selected_interface"),
                "adhoc_interface": prefs.get("adhoc_interface")}

    async def set_interface_preferences(self, selected_interface: str = None,
                                        adhoc_interface: str = None) -> Dict[str, Any]:
        prefs = self._load_preferences()
        if selected_interface is not None:
            prefs["selected_interface"] = selected_interface
        if adhoc_interface is not None:
            prefs["adhoc_interface"] = adhoc_interface
        self._save_preferences(prefs)
        return {"success": True}

    # --- band / channel preferences ---------------------------------

    async def get_band_preference(self) -> Dict[str, Any]:
        prefs = self._load_preferences()
        # Stored values may predate canonical naming; normalize on read.
        return {"band": normalize_band(prefs.get("band_preference", "2.4GHz"))}

    async def set_band_preference(self, band: str) -> Dict[str, Any]:
        band = normalize_band(band)
        v = validate_band(band)
        if not v["success"]:
            return v
        prefs = self._load_preferences()
        prefs["band_preference"] = band
        self._save_preferences(prefs)
        return {"success": True, "band": band}

    async def get_channel_preference(self, band: str = "2.4GHz") -> Dict[str, Any]:
        prefs = self._load_preferences()
        band = normalize_band(band)
        # Fall back to the legacy lowercase preference key.
        channel = prefs.get(f"channel_preference_{band}",
                            prefs.get(f"channel_preference_{band.lower()}", 6))
        # Validate the stored channel against the requested band; fall back
        # to the band default if it's invalid (e.g. stored for a different band).
        v = validate_channel(channel, band)
        if not v["success"]:
            channel = 6 if band == "2.4GHz" else 36
        return {"channel": channel}

    async def set_channel_preference(self, channel: int, band: str = "2.4GHz") -> Dict[str, Any]:
        band = normalize_band(band)
        v = validate_channel(channel, band)
        if not v["success"]:
            return v
        prefs = self._load_preferences()
        prefs[f"channel_preference_{band}"] = channel
        self._save_preferences(prefs)
        return {"success": True, "channel": channel}

    # --- adhoc config preferences -----------------------------------

    async def get_adhoc_config_preference(self) -> Dict[str, Any]:
        return {"ssid": self.adhoc_config["ssid"],
                "password": self.adhoc_config["password"],
                "channel": self.adhoc_config["channel"],
                "band": self.adhoc_config["band"],
                "subnet": self.adhoc_config["subnet"],
                "hidden": self.adhoc_config["hidden"]}

    async def set_adhoc_config_preference(self, ssid: str = None,
                                          password: str = None) -> Dict[str, Any]:
        prefs = self._load_preferences()
        creds = prefs.get("secure_credentials", {})
        if ssid is not None:
            v = validate_ssid(ssid)
            if not v["success"]:
                return v
            creds["ssid"] = ssid
            self.adhoc_config["ssid"] = ssid
        if password is not None:
            v = validate_password(password)
            if not v["success"]:
                return v
            creds["password"] = password
            self.adhoc_config["password"] = password
        prefs["secure_credentials"] = creds
        self._save_preferences(prefs)
        return {"success": True}

    async def regenerate_secure_credentials(self) -> Dict[str, Any]:
        prefs = self._load_preferences()
        prefs["secure_credentials"] = {
            "ssid": self._gen_ssid(), "password": self._gen_password()}
        self._save_preferences(prefs)
        self.adhoc_config["ssid"] = prefs["secure_credentials"]["ssid"]
        self.adhoc_config["password"] = prefs["secure_credentials"]["password"]
        return {"success": True, "ssid": self.adhoc_config["ssid"],
                "password": self.adhoc_config["password"]}

    async def get_current_credentials(self) -> Dict[str, Any]:
        return {"ssid": self.adhoc_config["ssid"],
                "password": self.adhoc_config["password"]}

    # --- supported channels -----------------------------------------

    async def get_supported_channels(self, interface: str = None) -> Dict[str, Any]:
        # Frontend indexes by band key and reads per-entry .channel values.
        return {"2.4GHz": [{"channel": ch} for ch in CHANNELS_2GHZ],
                "5GHz": [{"channel": ch} for ch in CHANNELS_5GHZ]}

    # --- emergency restore ------------------------------------------

    async def emergency_network_restore(self) -> Dict[str, Any]:
        results = []
        if self.hotspot_active:
            r = await self.stop_adhoc_network()
            results.append(r.get("message", r.get("error", "stop")))
        for iface in list(self.original_mac.keys()):
            r = await self.restore_original_mac(iface)
            results.append(f"{iface}: {r.get('message', r.get('error'))}")
        await CommandRunner.run(["sysctl", "-w", "net.ipv4.ip_forward=0"])
        return {"success": True, "actions": results}

    # --- version & updates ------------------------------------------

    async def get_current_version(self) -> str:
        return get_plugin_version()

    async def get_latest_version(self) -> str:
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(
                    "https://api.github.com/repos/fewtarius/NetDeck/releases/latest",
                    timeout=10, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                tag = data.get("tag_name", "")
                return tag.lstrip("v") if tag else "unknown"
        except Exception as e:
            decky.logger.error(f"Failed to get latest version: {e}")
            return "unknown"

    async def get_update_status(self) -> Dict[str, Any]:
        current = get_plugin_version()
        latest = await self.get_latest_version()
        return {"update_available": _parse_version(latest) > _parse_version(current),
                "current_version": current, "latest_version": latest}

    async def check_for_updates(self) -> Dict[str, Any]:
        status = await self.get_update_status()
        if not status["update_available"]:
            return status
        try:
            ctx = ssl.create_default_context()
            with urllib.request.urlopen(
                    "https://api.github.com/repos/fewtarius/NetDeck/releases/latest",
                    timeout=10, context=ctx) as resp:
                data = json.loads(resp.read().decode())
                assets = data.get("assets", [])
                download_url = next(
                    (a.get("browser_download_url") for a in assets
                     if "netdeck" in a.get("name", "").lower() or
                     a.get("name", "").endswith(".zip")),
                    f"https://github.com/fewtarius/NetDeck/archive/"
                    f"refs/tags/v{status['latest_version']}.zip")
                status["download_url"] = download_url
                status["release_notes"] = data.get("body", "")
        except Exception as e:
            status["error"] = str(e)
        return status

    async def download_and_install_update(self, download_url: str,
                                          version: str) -> Dict[str, Any]:
        v = validate_update_url(download_url)
        if not v["success"]:
            return v
        try:
            ctx = ssl.create_default_context()
            with tempfile_dir() as td:
                archive = os.path.join(td, "netdeck.zip")
                with urllib.request.urlopen(download_url, timeout=60, context=ctx) as resp:
                    data = resp.read()
                with open(archive, "wb") as fh:
                    fh.write(data)
                # Verify size sanity
                if len(data) < 10000:
                    return {"success": False, "error": "Archive too small; possible corruption"}
                # Verify members
                with zipfile.ZipFile(archive) as zf:
                    names = zf.namelist()
                    if not any(n.endswith("main.py") for n in names):
                        return {"success": False, "error": "Invalid archive: no main.py"}
                    if not any(n.endswith("plugin.json") for n in names):
                        return {"success": False, "error": "Invalid archive: no plugin.json"}
                    for n in names:
                        if n.startswith("/") or ".." in n:
                            return {"success": False, "error": "Archive contains unsafe paths"}
                    # SHA-256
                    sha = hashlib.sha256(data).hexdigest()
                    decky.logger.info(f"Downloaded update {version}, sha256={sha}")
                    zf.extractall(td)
                # Find plugin dir
                src = None
                for root, _, files in os.walk(td):
                    if "main.py" in files and "plugin.json" in files:
                        src = root
                        break
                if not src:
                    return {"success": False, "error": "Plugin directory not found in archive"}
                dest = "/home/deck/homebrew/plugins/NetDeck"
                backup = f"/home/deck/plugin_backups/NetDeck.backup.{version}"
                os.makedirs("/home/deck/plugin_backups", exist_ok=True)
                if os.path.exists(dest):
                    if os.path.exists(backup):
                        shutil.rmtree(backup)
                    shutil.copytree(dest, backup)
                # Remove dest before copytree (which requires dest to not exist)
                if os.path.exists(dest):
                    shutil.rmtree(dest)
                shutil.copytree(src, dest)
                # Restart plugin loader so the new version takes effect
                restart = await CommandRunner.run(
                    ["sudo", "systemctl", "restart", "plugin_loader"])
                if not restart["success"]:
                    decky.logger.warning(
                        f"Plugin loader restart failed: {restart['stderr']}")
                return {"success": True, "message": f"Updated to v{version}",
                        "sha256": sha,
                        "restart_required": True}
        except Exception as e:
            decky.logger.error(f"Update failed: {e}")
            return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Decky plugin facade
# ---------------------------------------------------------------------------

plugin = NetDeckPlugin()


class Plugin:
    """Decky plugin entry point — thin delegating facade."""

    async def _main(self):
        decky.logger.info("NetDeck plugin started")
        await plugin._reconcile_state()

    async def _unload(self):
        decky.logger.info("NetDeck unloading")
        if plugin.hotspot_active:
            await plugin.stop_adhoc_network()
        for iface in list(plugin.original_mac.keys()):
            await plugin.restore_original_mac(iface)

    # Each method delegates to the global plugin instance
    async def get_network_interfaces(self):
        return await plugin.get_network_interfaces()

    async def get_current_mac(self, interface: str):
        return await plugin.get_current_mac(interface)

    async def validate_connectivity(self):
        return await validate_connectivity()

    async def set_mac_address(self, interface: str, new_mac: str, save_config: bool = True):
        return await plugin.set_mac_address(interface, new_mac, save_config)

    async def restore_original_mac(self, interface: str):
        return await plugin.restore_original_mac(interface)

    async def start_adhoc_network(self, interface: str, ssid: str, password: str,
                                  channel: int, subnet: str = "192.168.5.0/24",
                                  band: str = "2.4GHz", hidden: bool = False):
        return await plugin.start_adhoc_network(interface, ssid, password,
                                                channel, subnet, band, hidden)

    async def stop_adhoc_network(self):
        return await plugin.stop_adhoc_network()

    async def get_adhoc_status(self):
        return await plugin.get_adhoc_status()

    async def get_network_status(self):
        return await plugin.get_network_status()

    async def get_connected_clients(self):
        return await plugin.get_connected_clients()

    async def get_dhcp_leases(self):
        return await plugin.get_dhcp_leases()

    async def get_band_preference(self):
        return await plugin.get_band_preference()

    async def set_band_preference(self, band: str):
        return await plugin.set_band_preference(band)

    async def get_channel_preference(self, band: str = "2.4GHz"):
        return await plugin.get_channel_preference(band)

    async def set_channel_preference(self, channel: int, band: str = "2.4GHz"):
        return await plugin.set_channel_preference(channel, band)

    async def get_ip_forwarding_status(self):
        return await plugin.get_ip_forwarding_status()

    async def toggle_ip_forwarding(self, enable: bool):
        return await plugin.toggle_ip_forwarding(enable)

    async def get_nat_forwarding_preference(self):
        return await plugin.get_nat_forwarding_preference()

    async def set_nat_forwarding_preference(self, enabled: bool):
        return await plugin.set_nat_forwarding_preference(enabled)

    async def get_interface_preferences(self):
        return await plugin.get_interface_preferences()

    async def set_interface_preferences(self, selected_interface: str = None,
                                        adhoc_interface: str = None):
        return await plugin.set_interface_preferences(selected_interface, adhoc_interface)

    async def get_adhoc_config_preference(self):
        return await plugin.get_adhoc_config_preference()

    async def set_adhoc_config_preference(self, ssid: str = None, password: str = None):
        return await plugin.set_adhoc_config_preference(ssid, password)

    async def regenerate_secure_credentials(self):
        return await plugin.regenerate_secure_credentials()

    async def get_current_credentials(self):
        return await plugin.get_current_credentials()

    async def get_supported_channels(self, interface: str = None):
        return await plugin.get_supported_channels(interface)

    async def validate_network_safety(self, interface: str):
        v = validate_interface(interface)
        if not v["success"]:
            return v
        ifaces = await get_interfaces()
        exists = any(i["name"] == interface for i in ifaces)
        if not exists:
            return {"success": False, "safe": False, "reason": "Interface does not exist"}
        return {"success": True, "safe": True, "reason": "Validation passed"}

    async def emergency_network_restore(self):
        return await plugin.emergency_network_restore()

    async def get_current_version(self):
        return await plugin.get_current_version()

    async def get_latest_version(self):
        return await plugin.get_latest_version()

    async def get_update_status(self):
        return await plugin.get_update_status()

    async def check_for_updates(self):
        return await plugin.check_for_updates()

    async def download_and_install_update(self, download_url: str, version: str):
        return await plugin.download_and_install_update(download_url, version)

    async def get_interfaces(self):
        return await plugin.get_network_interfaces()


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

@contextlib.contextmanager
def tempfile_dir():
    d = tempfile.mkdtemp(prefix="netdeck-update-")
    try:
        yield d
    finally:
        shutil.rmtree(d, ignore_errors=True)
