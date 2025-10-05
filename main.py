#!/usr/bin/env python3

import decky  # type: ignore
import asyncio
import subprocess
import json
import os
import re
import random
import secrets
import string
import tempfile
import shutil
import time
from typing import Dict, List, Any, Optional

# Version management for NetDeck
def get_plugin_version() -> str:
    """Get plugin version from VERSION file or plugin.json fallback"""
    try:
        # First try to read from VERSION file (single source of truth)
        version_file_path = os.path.join(os.path.dirname(__file__), "VERSION")
        if os.path.exists(version_file_path):
            with open(version_file_path, 'r') as f:
                version = f.read().strip()
                if version:
                    return version
        
        # Fallback to plugin.json
        plugin_json_path = os.path.join(os.path.dirname(__file__), "plugin.json")
        if os.path.exists(plugin_json_path):
            with open(plugin_json_path, 'r') as f:
                plugin_data = json.load(f)
                return plugin_data.get("version", "unknown")
        
        return "unknown"  # Fallback when VERSION file and plugin.json both fail
    except Exception as e:
        decky.logger.error(f"Failed to get plugin version: {e}")
        return "unknown"  # Ultimate fallback version

# Ensure NetDeck config directory exists (use user's home directory)
NETDECK_CONFIG_DIR = os.path.expanduser("~/.config/netdeck")
os.makedirs(NETDECK_CONFIG_DIR, exist_ok=True)

# Word lists for secure SSID generation  
ADJECTIVES = [
    "amazing", "brilliant", "clever", "dazzling", "eager", "fantastic", "glorious", "happy",
    "incredible", "joyful", "keen", "lively", "magnificent", "noble", "outstanding", "peaceful",
    "quick", "radiant", "stellar", "triumphant", "unique", "vibrant", "wonderful", "excellent",
    "zestful", "agile", "bold", "creative", "dynamic", "energetic", "fearless", "graceful",
    "heroic", "inspiring", "jovial", "kinetic", "luminous", "majestic", "nimble", "optimistic",
    "powerful", "quiet", "resilient", "serene", "tenacious", "unstoppable", "victorious", "wise",
    "animated", "bright", "cheerful", "determined", "efficient", "focused", "gentle", "harmonious"
]

NOUNS = [
    "apple", "butterfly", "compass", "diamond", "eagle", "falcon", "galaxy", "horizon",
    "island", "journey", "kite", "lighthouse", "mountain", "nebula", "ocean", "phoenix",
    "quasar", "rainbow", "sunset", "tiger", "universe", "valley", "whale", "xylophone",
    "yacht", "zebra", "adventure", "bridge", "castle", "dragon", "echo", "forest",
    "garden", "harbor", "invention", "jade", "key", "legend", "melody", "network",
    "oasis", "puzzle", "quest", "river", "symphony", "treasure", "umbrella", "vision",
    "waterfall", "beacon", "crystal", "discovery", "element", "fountain", "grove", "haven"
]

def generate_secure_ssid() -> str:
    """Generate a secure, anonymous SSID like 'amazing-falcon-7834'"""
    adjective = random.choice(ADJECTIVES)
    noun = random.choice(NOUNS)
    # Generate 4-digit random number
    number = random.randint(1000, 9999)
    return f"{adjective}-{noun}-{number}"

def generate_secure_password() -> str:
    """Generate a 10-character secure password using cryptographically secure random"""
    # Use alphanumeric characters (avoiding ambiguous ones like 0, O, l, 1)
    alphabet = "23456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz"
    return ''.join(secrets.choice(alphabet) for _ in range(10))

class NetDeckPlugin:
    """NetDeck plugin for network management on SteamOS/handheld devices"""
    
    def __init__(self):
        self.original_mac_addresses = {}
        self.adhoc_active = False
        self.bridge_active = False
        self.monitoring_task = None
        self.last_interface_states = {}
        
        # Load existing credentials or generate new ones
        credentials = self._load_or_generate_credentials()
        secure_ssid = credentials['ssid']
        secure_password = credentials['password']
        decky.logger.info(f"Loaded network credentials: SSID={secure_ssid}")
        
        self.adhoc_config = {
            'enabled': False,
            'ssid': secure_ssid,
            'password': secure_password,
            'channel': 6,
            'interface': None
        }
        self.adhoc_process = None
        self.dnsmasq_process = None
        decky.logger.info("NetDeck initialized for networking features")

    def _load_or_generate_credentials(self) -> Dict[str, str]:
        """Load existing credentials from preferences or generate new ones"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Try to load existing credentials
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    if 'secure_credentials' in preferences:
                        creds = preferences['secure_credentials']
                        if 'ssid' in creds and 'password' in creds:
                            decky.logger.info("Loaded existing secure credentials from preferences")
                            return creds
            
            # Generate new credentials if none exist
            secure_ssid = generate_secure_ssid()
            secure_password = generate_secure_password()
            credentials = {'ssid': secure_ssid, 'password': secure_password}
            
            # Save the new credentials
            self._save_credentials_to_preferences(credentials)
            decky.logger.info(f"Generated and saved new secure credentials: SSID={secure_ssid}")
            return credentials
            
        except Exception as e:
            decky.logger.error(f"Error loading credentials, using defaults: {e}")
            # Fallback to generating fresh credentials
            return {'ssid': generate_secure_ssid(), 'password': generate_secure_password()}

    def _save_credentials_to_preferences(self, credentials: Dict[str, str]):
        """Save credentials to preferences file"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Load existing preferences or create new
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Save credentials
            preferences['secure_credentials'] = credentials
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
                
        except Exception as e:
            decky.logger.error(f"Error saving credentials: {e}")

    def _save_mac_address_config(self, interface: str, desired_mac: str, original_mac: str):
        """Save MAC address configuration for persistent re-application"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Load existing preferences
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Ensure mac_addresses dict exists
            if 'mac_addresses' not in preferences:
                preferences['mac_addresses'] = {}
            
            # Save MAC configuration for this interface
            preferences['mac_addresses'][interface] = {
                'desired_mac': desired_mac,
                'original_mac': original_mac,
                'enabled': True
            }
            
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            decky.logger.info(f"Saved MAC address config for {interface}: {desired_mac}")
                
        except Exception as e:
            decky.logger.error(f"Error saving MAC address config: {e}")

    def _load_mac_address_configs(self) -> Dict[str, Dict[str, Any]]:
        """Load all saved MAC address configurations"""
        try:
            config_file = "/home/deck/.config/netdeck/preferences.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    mac_configs = preferences.get('mac_addresses', {})
                    decky.logger.info(f"Loaded MAC address configs for {len(mac_configs)} interfaces")
                    return mac_configs
            return {}
        except Exception as e:
            decky.logger.error(f"Error loading MAC address configs: {e}")
            return {}

    def _remove_mac_address_config(self, interface: str):
        """Remove MAC address configuration (when restoring original)"""
        try:
            config_file = "/home/deck/.config/netdeck/preferences.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                
                if 'mac_addresses' in preferences and interface in preferences['mac_addresses']:
                    del preferences['mac_addresses'][interface]
                    
                    with open(config_file, 'w') as f:
                        json.dump(preferences, f, indent=2)
                    
                    decky.logger.info(f"Removed MAC address config for {interface}")
        except Exception as e:
            decky.logger.error(f"Error removing MAC address config: {e}")

    def _save_hotspot_autostart_config(self, enabled: bool, config: Dict[str, Any]):
        """Save hotspot auto-start configuration"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            os.makedirs(config_dir, exist_ok=True)
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Load existing preferences
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Save hotspot auto-start configuration
            preferences['hotspot_autostart'] = {
                'enabled': enabled,
                'interface': config.get('interface'),
                'ssid': config.get('ssid'),
                'password': config.get('password'),
                'channel': config.get('channel'),
                'band': config.get('band', '2.4GHz'),
                'subnet': config.get('subnet', '192.168.5.0/24'),
                'hidden': config.get('hidden', False)
            }
            
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            decky.logger.info(f"Saved hotspot auto-start config: enabled={enabled}")
                
        except Exception as e:
            decky.logger.error(f"Error saving hotspot auto-start config: {e}")

    def _load_hotspot_autostart_config(self) -> Dict[str, Any]:
        """Load hotspot auto-start configuration"""
        try:
            config_file = "/home/deck/.config/netdeck/preferences.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    hotspot_config = preferences.get('hotspot_autostart', {})
                    if hotspot_config:
                        decky.logger.info(f"Loaded hotspot auto-start config: enabled={hotspot_config.get('enabled', False)}")
                    return hotspot_config
            return {}
        except Exception as e:
            decky.logger.error(f"Error loading hotspot auto-start config: {e}")
            return {}

    async def _start_interface_monitoring(self):
        """Start background task to monitor interfaces and auto-apply configurations"""
        try:
            decky.logger.info("Starting interface monitoring task")
            
            # Wait a bit for system to stabilize after plugin load
            await asyncio.sleep(10)
            
            while True:
                try:
                    # CRITICAL: Reload configurations on EVERY iteration
                    # This ensures monitoring respects restore operations immediately
                    mac_configs = self._load_mac_address_configs()
                    hotspot_config = self._load_hotspot_autostart_config()
                    
                    # Get current interface states
                    interfaces = await self.get_network_interfaces()
                    current_states = {iface['name']: iface['state'] for iface in interfaces}
                    
                    # Check for interfaces that need configuration applied
                    for iface_name, state in current_states.items():
                        previous_state = self.last_interface_states.get(iface_name)
                        
                        # Check if this interface has a saved MAC configuration
                        if iface_name in mac_configs:
                            mac_config = mac_configs[iface_name]
                            if mac_config.get('enabled'):
                                desired_mac = mac_config.get('desired_mac')
                                current_mac = await self.get_current_mac(iface_name)
                                
                                # CRITICAL: Only apply MAC if it's different from desired
                                if current_mac and desired_mac and current_mac.lower() != desired_mac.lower():
                                    # Apply MAC if:
                                    # 1. Interface just became UP (transition from DOWN or None)
                                    # 2. Interface exists but is DOWN
                                    # 3. Interface is UP
                                    needs_mac_application = False
                                    if state == 'UP' and (previous_state != 'UP' or previous_state is None):
                                        # Interface just came online with wrong MAC
                                        needs_mac_application = True
                                        decky.logger.info(f"Interface {iface_name} is now available (state: UP) with wrong MAC")
                                    elif state == 'DOWN' and previous_state != 'DOWN':
                                        # Interface is DOWN but exists with wrong MAC - try to apply and bring UP
                                        needs_mac_application = True
                                        decky.logger.info(f"Interface {iface_name} is DOWN with wrong MAC, attempting to configure")
                                    elif state == 'UP':
                                        # Interface is UP but has wrong MAC
                                        needs_mac_application = True
                                        decky.logger.info(f"Interface {iface_name} is UP but has wrong MAC, reconfiguring")
                                    
                                    if needs_mac_application:
                                        decky.logger.info(f"Auto-applying saved MAC for {iface_name}: {desired_mac} (current: {current_mac})")
                                        result = await self.set_mac_address(iface_name, desired_mac)
                                        if result['success']:
                                            decky.logger.info(f"Successfully auto-applied MAC for {iface_name}")
                                        else:
                                            decky.logger.error(f"Failed to auto-apply MAC for {iface_name}: {result.get('error')}")
                                elif current_mac and desired_mac and current_mac.lower() == desired_mac.lower():
                                    # MAC is already correct, no action needed
                                    if previous_state != state:
                                        decky.logger.info(f"Interface {iface_name} state changed to {state}, MAC already correct: {current_mac}")
                        
                        # Check if this interface should start hotspot (only when interface becomes UP)
                        if state == 'UP' and (previous_state != 'UP' or previous_state is None):
                            if hotspot_config.get('enabled') and not self.adhoc_active:
                                hotspot_interface = hotspot_config.get('interface')
                                
                                # Check if both primary and hotspot interfaces are available
                                if iface_name == hotspot_interface or hotspot_interface in current_states:
                                    # Verify we have at least 2 WiFi interfaces for dual-adapter mode
                                    wifi_interfaces = [name for name in current_states.keys() if name.startswith('wlan')]
                                    
                                    if len(wifi_interfaces) >= 2 and hotspot_interface:
                                        decky.logger.info(f"Auto-starting hotspot on {hotspot_interface}")
                                        result = await self.start_adhoc_network(
                                            interface=hotspot_interface,
                                            ssid=hotspot_config.get('ssid', 'NetDeck-AP'),
                                            password=hotspot_config.get('password', 'netdeck123'),
                                            channel=hotspot_config.get('channel', 6),
                                            subnet=hotspot_config.get('subnet', '192.168.5.0/24'),
                                            band=hotspot_config.get('band', '2.4GHz'),
                                            hidden=hotspot_config.get('hidden', False)
                                        )
                                        if result['success']:
                                            decky.logger.info(f"Successfully auto-started hotspot")
                                        else:
                                            decky.logger.error(f"Failed to auto-start hotspot: {result.get('error')}")
                    
                    # Update last known states
                    self.last_interface_states = current_states
                    
                except Exception as monitor_error:
                    decky.logger.error(f"Error in interface monitoring iteration: {monitor_error}")
                
                # Check every 15 seconds
                await asyncio.sleep(15)
                
        except Exception as e:
            decky.logger.error(f"Interface monitoring task failed: {e}")

    async def _validate_and_fallback_channel(self, interface: str, band: str, preferred_channel: int) -> int:
        """Validate channel is supported and fallback to safe channel if not"""
        try:
            # Get supported channels for this interface
            channels_result = await self.get_supported_channels(interface)
            
            if not channels_result.get('success'):
                decky.logger.warning(f"Could not get supported channels, using preferred channel {preferred_channel}")
                return preferred_channel
            
            # Get channels for the selected band
            band_channels = channels_result.get(band, [])
            
            if not band_channels:
                decky.logger.warning(f"No channels found for band {band}, using preferred channel {preferred_channel}")
                return preferred_channel
            
            # Check if preferred channel is supported
            supported_channel_numbers = [ch['channel'] for ch in band_channels]
            
            if preferred_channel in supported_channel_numbers:
                decky.logger.info(f"Channel {preferred_channel} is supported for band {band}")
                return preferred_channel
            
            # Preferred channel not supported, use fallback logic
            decky.logger.warning(f"Channel {preferred_channel} not supported for band {band}")
            
            if band == "5GHz":
                # Known-good 5GHz channels (non-DFS)
                # Channels 36, 40, 44, 48 (UNII-1 band) - should work in most regions
                # Channels 149, 153, 157, 161, 165 (UNII-3 band) - should work in most regions
                # Avoid channels 52-144 (UNII-2/UNII-2e) as they are DFS channels
                fallback_channels = [36, 40, 44, 48, 149, 153, 157, 161, 165]
                
                for fallback in fallback_channels:
                    if fallback in supported_channel_numbers:
                        decky.logger.info(f"Using fallback channel {fallback} for 5GHz")
                        return fallback
                
                # If no known-good channel found, use first available non-DFS channel
                for ch in band_channels:
                    ch_num = ch['channel']
                    # Avoid DFS channels (52-144)
                    if ch_num < 52 or ch_num > 144:
                        decky.logger.info(f"Using first available non-DFS channel {ch_num} for 5GHz")
                        return ch_num
                
                # Last resort: use first available channel (even if DFS)
                if band_channels:
                    fallback = band_channels[0]['channel']
                    decky.logger.warning(f"Using first available channel {fallback} (may be DFS)")
                    return fallback
            else:
                # 2.4GHz fallback - channels 1, 6, 11 are standard non-overlapping
                fallback_channels = [6, 1, 11]
                
                for fallback in fallback_channels:
                    if fallback in supported_channel_numbers:
                        decky.logger.info(f"Using fallback channel {fallback} for 2.4GHz")
                        return fallback
                
                # Use first available if standard channels not found
                if band_channels:
                    fallback = band_channels[0]['channel']
                    decky.logger.info(f"Using first available channel {fallback} for 2.4GHz")
                    return fallback
            
            # No supported channels found at all, return preferred as last resort
            decky.logger.error(f"No supported channels found for band {band}, using preferred {preferred_channel}")
            return preferred_channel
            
        except Exception as e:
            decky.logger.error(f"Error validating channel: {e}, using preferred {preferred_channel}")
            return preferred_channel

    async def _run_command(self, command: str) -> Dict[str, Any]:
        """Execute shell command with timeout"""
        try:
            decky.logger.info(f"NetDeck executing: {command}")
            # Use bash explicitly and disable readline to avoid symbol lookup error
            bash_command = ["/bin/bash", "-c", command]
            result = subprocess.run(
                bash_command,
                capture_output=True,
                text=True,
                timeout=30,
                env={"PATH": "/usr/bin:/bin:/sbin:/usr/sbin", "TERM": "dumb"}
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            decky.logger.error(f"Command timeout: {command}")
            return {"success": False, "error": "Command timeout"}
        except Exception as e:
            decky.logger.error(f"Command execution failed: {e}")
            return {"success": False, "error": str(e)}

    async def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get list of available network interfaces"""
        try:
            result = await self._run_command("ip link show")
            if not result["success"]:
                return []
            
            interfaces = []
            for line in result["stdout"].split('\n'):
                if ':' in line and 'state' in line:
                    parts = line.split(':')
                    if len(parts) >= 2:
                        name = parts[1].strip()
                        # Skip loopback interface
                        if name != 'lo':
                            state = "UP" if "UP" in line else "DOWN"
                            interfaces.append({"name": name, "state": state})
            
            decky.logger.info(f"Found {len(interfaces)} network interfaces")
            return interfaces
            
        except Exception as e:
            decky.logger.error(f"Failed to get network interfaces: {e}")
            return []

    async def get_current_mac(self, interface: str) -> Optional[str]:
        """Get current MAC address of interface"""
        try:
            result = await self._run_command(f"ip link show {interface}")
            if result["success"]:
                for line in result["stdout"].split('\n'):
                    if 'link/ether' in line:
                        parts = line.strip().split()
                        if len(parts) >= 2:
                            return parts[1]
            return None
            
        except Exception as e:
            decky.logger.error(f"Failed to get MAC for {interface}: {e}")
            return None

    async def validate_connectivity(self) -> bool:
        """Test basic network connectivity"""
        try:
            # Get default gateway
            route_result = await self._run_command("ip route show default")
            if not route_result["success"] or not route_result["stdout"]:
                return False
            
            # Extract gateway IP
            for line in route_result["stdout"].split('\n'):
                if 'default via' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        gateway = parts[2]
                        # Ping gateway
                        ping_result = await self._run_command(f"ping -c 1 -W 3 {gateway}")
                        return ping_result["success"]
            
            return False
            
        except Exception as e:
            decky.logger.error(f"Connectivity validation failed: {e}")
            return False

    async def set_mac_address(self, interface: str, new_mac: str, save_config: bool = True) -> Dict[str, Any]:
        """Set MAC address for interface with validation and rollback
        
        Args:
            interface: Network interface name
            new_mac: New MAC address to apply
            save_config: Whether to save config for persistence (False when restoring)
        """
        try:
            decky.logger.info(f"Setting MAC address for {interface} to {new_mac}")
            
            # Store original MAC if not already stored
            if interface not in self.original_mac_addresses:
                original_mac = await self.get_current_mac(interface)
                if original_mac:
                    self.original_mac_addresses[interface] = original_mac
                    decky.logger.info(f"Stored original MAC for {interface}: {original_mac}")
                else:
                    return {"success": False, "error": "Could not get current MAC address"}
            
            # Get network UUID for reconnection
            network_uuid = None
            nmcli_result = await self._run_command(f"nmcli device show {interface}")
            if nmcli_result["success"]:
                for line in nmcli_result["stdout"].split('\n'):
                    if 'GENERAL.CONNECTION' in line:
                        uuid_part = line.split(':')[-1].strip()
                        if uuid_part and uuid_part != '--':
                            network_uuid = uuid_part
                            break
            
            # Stop NetworkManager temporarily
            nm_stop = await self._run_command("sudo systemctl stop NetworkManager")
            if not nm_stop["success"]:
                decky.logger.warning(f"Failed to stop NetworkManager: {nm_stop['stderr']}")
            
            # Set interface down
            down_result = await self._run_command(f"sudo ip link set {interface} down")
            if not down_result["success"]:
                return {"success": False, "error": f"Failed to bring interface down: {down_result['stderr']}"}
            
            # Change MAC address
            mac_result = await self._run_command(f"sudo ip link set dev {interface} address {new_mac}")
            if not mac_result["success"]:
                # Try to restore interface state
                await self._run_command(f"sudo ip link set {interface} up")
                await self._run_command("sudo systemctl start NetworkManager")
                return {"success": False, "error": f"Failed to set MAC address: {mac_result['stderr']}"}
            
            # Bring interface back up
            up_result = await self._run_command(f"sudo ip link set {interface} up")
            if not up_result["success"]:
                decky.logger.warning(f"Failed to bring interface up: {up_result['stderr']}")
            
            # Start NetworkManager
            nm_start = await self._run_command("sudo systemctl start NetworkManager")
            if not nm_start["success"]:
                decky.logger.warning(f"Failed to start NetworkManager: {nm_start['stderr']}")
            
            # Wait for NetworkManager to settle
            await asyncio.sleep(3)
            
            # Reconnect to network if we had a connection
            if network_uuid:
                connect_result = await self._run_command(f"nmcli connection up uuid {network_uuid}")
                if connect_result["success"]:
                    decky.logger.info(f"Reconnected to network with UUID {network_uuid}")
                else:
                    decky.logger.warning(f"Failed to reconnect: {connect_result['stderr']}")
            
            # Validate the change and connectivity
            current_mac = await self.get_current_mac(interface)
            if current_mac != new_mac:
                return {"success": False, "error": "MAC address change was not applied"}
            
            # Test connectivity
            connectivity_ok = await self.validate_connectivity()
            if not connectivity_ok:
                decky.logger.warning("Connectivity lost after MAC change, attempting restore")
                restore_result = await self.restore_original_mac(interface)
                if restore_result["success"]:
                    return {"success": False, "error": "MAC changed but connectivity lost, reverted to original"}
                else:
                    return {"success": False, "error": "MAC changed, connectivity lost, and restore failed"}
            
            # Save MAC configuration for persistence across reboots/reconnects
            original_mac = self.original_mac_addresses[interface]
            self._save_mac_address_config(interface, new_mac, original_mac)
            
            decky.logger.info(f"Successfully set MAC for {interface} to {new_mac}")
            return {"success": True, "message": f"MAC address set to {new_mac}"}
            
        except Exception as e:
            decky.logger.error(f"Failed to set MAC address: {e}")
            return {"success": False, "error": str(e)}

    async def restore_original_mac(self, interface: str) -> Dict[str, Any]:
        """Restore original MAC address"""
        try:
            if interface not in self.original_mac_addresses:
                return {"success": False, "error": "No original MAC address stored"}
            
            original_mac = self.original_mac_addresses[interface]
            decky.logger.info(f"Restoring original MAC for {interface}: {original_mac}")
            
            # Pass save_config=False to prevent saving the original MAC as desired MAC
            result = await self.set_mac_address(interface, original_mac, save_config=False)
            if result["success"]:
                del self.original_mac_addresses[interface]
                # Remove persistent configuration so MAC is not re-applied on next boot/reconnect
                self._remove_mac_address_config(interface)
                decky.logger.info(f"Restored original MAC for {interface}: {original_mac}")
            
            return result
            
        except Exception as e:
            decky.logger.error(f"Failed to restore original MAC: {e}")
            return {"success": False, "error": str(e)}

    async def create_dnsmasq_config(self, interface: str, subnet: str = "192.168.4.0/24") -> str:
        """Create dnsmasq configuration for DHCP server"""
        try:
            # Parse subnet to get dynamic IP range
            import ipaddress
            network = ipaddress.IPv4Network(subnet, strict=False)
            gateway_ip = str(network.network_address + 1)  # .1 address as gateway
            start_ip = str(network.network_address + 2)   # .2 address as DHCP start
            end_ip = str(network.network_address + 20)    # .20 address as DHCP end
            netmask = str(network.netmask)
            
            config_path = os.path.join(NETDECK_CONFIG_DIR, "dnsmasq.conf")
            config_content = f"""# NetDeck dnsmasq configuration
interface={interface}
bind-interfaces
dhcp-range={start_ip},{end_ip},{netmask},12h
dhcp-option=3,{gateway_ip}
dhcp-option=6,8.8.8.8,8.8.4.4
server=8.8.8.8
server=8.8.4.4
log-dhcp
"""
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            decky.logger.info(f"Created dnsmasq config: {config_path}")
            return config_path
            
        except Exception as e:
            decky.logger.error(f"Failed to create dnsmasq config: {e}")
            raise

    async def start_dhcp_server(self, interface: str, subnet: str = "192.168.4.0/24") -> Dict[str, Any]:
        """Start DHCP server using dnsmasq"""
        try:
            decky.logger.info(f"Starting DHCP server on {interface} with subnet {subnet}")
            
            # Stop existing dnsmasq if running
            if self.dnsmasq_process:
                await self.stop_dhcp_server()
            
            # Check if dnsmasq is available
            dnsmasq_check = await self._run_command("which dnsmasq")
            if not dnsmasq_check["success"]:
                # Try to install dnsmasq
                install_result = await self._run_command("sudo pacman -S --noconfirm dnsmasq")
                if not install_result["success"]:
                    return {"success": False, "error": "Failed to install dnsmasq"}
            
            # Create dnsmasq configuration with subnet
            config_path = await self.create_dnsmasq_config(interface, subnet)
            
            # Stop any existing dnsmasq processes
            await self._run_command("sudo killall dnsmasq 2>/dev/null")
            
            # Start dnsmasq
            dnsmasq_cmd = f"sudo dnsmasq --conf-file={config_path} --no-daemon"
            decky.logger.info(f"Starting dnsmasq: {dnsmasq_cmd}")
            
            try:
                self.dnsmasq_process = subprocess.Popen(
                    ["/bin/bash", "-c", dnsmasq_cmd],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    env={"PATH": "/usr/bin:/bin:/sbin:/usr/sbin", "TERM": "dumb"}
                )
                
                # Give dnsmasq time to start
                await asyncio.sleep(1)
                
                # Check if process is still running
                if self.dnsmasq_process.poll() is None:
                    decky.logger.info(f"DHCP server started successfully on {interface}")
                    return {"success": True, "message": f"DHCP server started on {interface}"}
                else:
                    # Process failed to start
                    stdout, stderr = self.dnsmasq_process.communicate()
                    error_msg = stderr.decode() if stderr else "Unknown dnsmasq error"
                    decky.logger.error(f"dnsmasq failed to start: {error_msg}")
                    self.dnsmasq_process = None
                    return {"success": False, "error": f"dnsmasq failed: {error_msg}"}
                    
            except Exception as e:
                decky.logger.error(f"Failed to start dnsmasq process: {e}")
                return {"success": False, "error": f"Process start failed: {e}"}
                
        except Exception as e:
            decky.logger.error(f"Failed to start DHCP server: {e}")
            return {"success": False, "error": str(e)}

    async def stop_dhcp_server(self) -> Dict[str, Any]:
        """Stop DHCP server"""
        try:
            decky.logger.info("Stopping DHCP server")
            
            success = True
            messages = []
            
            # Kill dnsmasq process
            if self.dnsmasq_process:
                try:
                    self.dnsmasq_process.terminate()
                    # Wait for termination
                    try:
                        self.dnsmasq_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.dnsmasq_process.kill()
                        self.dnsmasq_process.wait()
                    
                    messages.append("dnsmasq process stopped")
                    self.dnsmasq_process = None
                except Exception as e:
                    decky.logger.error(f"Error stopping dnsmasq: {e}")
                    messages.append(f"dnsmasq stop error: {e}")
                    success = False
            
            # Kill any remaining dnsmasq processes
            killall_result = await self._run_command("sudo killall dnsmasq")
            if killall_result["success"]:
                messages.append("Killed remaining dnsmasq processes")
            
            message = "; ".join(messages)
            decky.logger.info(f"DHCP server stopped: {message}")
            return {"success": success, "message": message}
            
        except Exception as e:
            decky.logger.error(f"Failed to stop DHCP server: {e}")
            return {"success": False, "error": str(e)}

    async def get_dhcp_leases(self) -> Dict[str, Any]:
        """Get current DHCP leases"""
        try:
            # Check dnsmasq lease file
            lease_files = [
                "/var/lib/dhcp/dhcpd.leases",
                "/var/lib/dnsmasq/dnsmasq.leases",
                "/tmp/dnsmasq.leases"
            ]
            
            leases = []
            for lease_file in lease_files:
                if os.path.exists(lease_file):
                    try:
                        with open(lease_file, 'r') as f:
                            content = f.read()
                            # Parse dnsmasq lease format: timestamp mac ip hostname client-id
                            for line in content.strip().split('\n'):
                                if line.strip():
                                    parts = line.split()
                                    if len(parts) >= 4:
                                        leases.append({
                                            "timestamp": parts[0],
                                            "mac": parts[1],
                                            "ip": parts[2],
                                            "hostname": parts[3] if len(parts) > 3 else "unknown"
                                        })
                        break
                    except Exception as e:
                        decky.logger.warning(f"Failed to read lease file {lease_file}: {e}")
                        continue
            
            return {"leases": leases, "count": len(leases)}
            
        except Exception as e:
            decky.logger.error(f"Failed to get DHCP leases: {e}")
            return {"error": str(e)}

    async def validate_network_safety(self, interface: str) -> Dict[str, Any]:
        """Validate network safety before making changes"""
        try:
            decky.logger.info(f"Validating network safety for {interface}")
            
            safety_checks = {
                "interface_exists": False,
                "interface_up": False,
                "no_active_connections": False,
                "primary_connectivity": False,
                "safe_to_modify": False
            }
            
            # Check if interface exists
            interfaces = await self.get_network_interfaces()
            interface_exists = any(iface["name"] == interface for iface in interfaces)
            safety_checks["interface_exists"] = interface_exists
            
            if not interface_exists:
                return {"safety_checks": safety_checks, "safe": False, "reason": "Interface does not exist"}
            
            # Check if interface is up
            ip_result = await self._run_command(f"ip link show {interface}")
            if ip_result["success"]:
                safety_checks["interface_up"] = "UP" in ip_result["stdout"]
            
            # Check for active NetworkManager connections
            nm_result = await self._run_command(f"nmcli device status | grep {interface}")
            if nm_result["success"]:
                status_line = nm_result["stdout"]
                safety_checks["no_active_connections"] = "connected" not in status_line.lower()
            
            # Test primary connectivity from other interfaces
            other_interfaces = [iface["name"] for iface in interfaces if iface["name"] != interface]
            connectivity_test = await self.validate_connectivity()
            safety_checks["primary_connectivity"] = connectivity_test
            
            # Determine if it's safe to modify
            is_safe = (
                safety_checks["interface_exists"] and
                (not safety_checks["interface_up"] or safety_checks["no_active_connections"]) and
                (len(other_interfaces) > 0 or not safety_checks["primary_connectivity"])
            )
            safety_checks["safe_to_modify"] = is_safe
            
            return {
                "safety_checks": safety_checks,
                "safe": is_safe,
                "reason": "Network configuration validation completed"
            }
            
        except Exception as e:
            decky.logger.error(f"Failed to validate network safety: {e}")
            return {"error": str(e), "safe": False}

    async def setup_nat_routing(self, wan_interface: str, ap_interface: str) -> Dict[str, Any]:
        """Set up NAT routing for internet sharing"""
        try:
            decky.logger.info(f"Setting up NAT routing: {wan_interface} -> {ap_interface}")
            
            # Enable IP forwarding
            forward_result = await self._run_command("sudo sysctl net.ipv4.ip_forward=1")
            if not forward_result["success"]:
                return {"success": False, "error": "Failed to enable IP forwarding"}
            
            # Add iptables rules for NAT
            rules = [
                f"sudo iptables -t nat -A POSTROUTING -o {wan_interface} -j MASQUERADE",
                f"sudo iptables -A FORWARD -i {wan_interface} -o {ap_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT",
                f"sudo iptables -A FORWARD -i {ap_interface} -o {wan_interface} -j ACCEPT"
            ]
            
            for rule in rules:
                rule_result = await self._run_command(rule)
                if not rule_result["success"]:
                    decky.logger.error(f"Failed to add iptables rule: {rule}")
                    # Don't return error immediately, try to add other rules
                
            decky.logger.info("NAT routing setup completed")
            return {"success": True, "message": "NAT routing configured"}
            
        except Exception as e:
            decky.logger.error(f"Failed to setup NAT routing: {e}")
            return {"success": False, "error": str(e)}

    async def cleanup_nat_routing(self, wan_interface: str, ap_interface: str) -> Dict[str, Any]:
        """Clean up NAT routing rules"""
        try:
            decky.logger.info(f"Cleaning up NAT routing: {wan_interface} -> {ap_interface}")
            
            # Remove iptables rules
            rules = [
                f"sudo iptables -t nat -D POSTROUTING -o {wan_interface} -j MASQUERADE",
                f"sudo iptables -D FORWARD -i {wan_interface} -o {ap_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT",
                f"sudo iptables -D FORWARD -i {ap_interface} -o {wan_interface} -j ACCEPT"
            ]
            
            for rule in rules:
                rule_result = await self._run_command(rule)
                # Don't worry if deletion fails (rule might not exist)
                
            decky.logger.info("NAT routing cleanup completed")
            return {"success": True, "message": "NAT routing cleaned up"}
            
        except Exception as e:
            decky.logger.error(f"Failed to cleanup NAT routing: {e}")
            return {"success": False, "error": str(e)}

    async def emergency_network_restore(self) -> Dict[str, Any]:
        """Emergency function to restore all network settings to original state"""
        try:
            decky.logger.warning("EMERGENCY: Restoring all network settings")
            
            results = []
            
            # Stop all NetDeck services
            if self.adhoc_active:
                stop_result = await self.stop_adhoc_network()
                results.append(f"Adhoc stop: {stop_result.get('message', 'Done')}")
            
            if self.bridge_active:
                bridge_result = await self.cleanup_network_bridge()
                results.append(f"Bridge cleanup: {bridge_result.get('message', 'Done')}")
            
            # Restore all MAC addresses
            mac_restore_count = 0
            for interface in list(self.original_mac_addresses.keys()):
                restore_result = await self.restore_original_mac(interface)
                if restore_result["success"]:
                    mac_restore_count += 1
                    results.append(f"MAC restored: {interface}")
                else:
                    results.append(f"MAC restore failed: {interface}")
            
            # Restart NetworkManager to ensure clean state
            nm_restart = await self._run_command("sudo systemctl restart NetworkManager")
            if nm_restart["success"]:
                results.append("NetworkManager restarted")
            else:
                results.append("NetworkManager restart failed")
            
            # Wait for NetworkManager to settle
            await asyncio.sleep(3)
            
            # Test connectivity
            connectivity = await self.validate_connectivity()
            results.append(f"Final connectivity: {'OK' if connectivity else 'FAILED'}")
            
            message = "; ".join(results)
            decky.logger.info(f"Emergency restore completed: {message}")
            
            return {
                "success": True, 
                "message": message,
                "mac_addresses_restored": mac_restore_count,
                "final_connectivity": connectivity
            }
            
        except Exception as e:
            decky.logger.error(f"Emergency restore failed: {e}")
            return {"success": False, "error": str(e)}

    async def get_bridge_status(self) -> Dict[str, Any]:
        """Get current bridge status"""
        try:
            status = {
                "enabled": self.bridge_active,
                "iptables_rules": []
            }
            
            # Check if our iptables rules exist
            check_forward = await self._run_command("sudo iptables -L NETDECK-FORWARD 2>/dev/null")
            if check_forward["success"]:
                status["iptables_rules"].append("NETDECK-FORWARD chain exists")
            
            check_nat = await self._run_command("sudo iptables -t nat -L NETDECK-POSTROUTING 2>/dev/null")
            if check_nat["success"]:
                status["iptables_rules"].append("NETDECK-POSTROUTING chain exists")
            
            # Check IP forwarding
            forward_check = await self._run_command("sysctl net.ipv4.ip_forward")
            if forward_check["success"]:
                status["ip_forwarding"] = "1" in forward_check["stdout"]
            
            return status
            
        except Exception as e:
            decky.logger.error(f"Failed to get bridge status: {e}")
            return {"error": str(e)}

    async def get_network_status(self) -> Dict[str, Any]:
        try:
            decky.logger.info(f"NetDeck executing: {command}")
            # Use bash explicitly and disable readline to avoid symbol lookup error
            bash_command = ["/bin/bash", "-c", command]
            result = subprocess.run(
                bash_command,
                capture_output=True,
                text=True,
                timeout=30,
                env={"PATH": "/usr/bin:/bin:/sbin:/usr/sbin", "TERM": "dumb"}
            )
            return {
                "success": result.returncode == 0,
                "stdout": result.stdout.strip(),
                "stderr": result.stderr.strip(),
                "returncode": result.returncode
            }
        except subprocess.TimeoutExpired:
            decky.logger.error(f"Command timeout: {command}")
            return {"success": False, "error": "Command timeout"}
        except Exception as e:
            decky.logger.error(f"Command execution failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get list of available network interfaces with AP mode detection"""
        try:
            result = await self._run_command("ip link show")
            if not result["success"]:
                decky.logger.error(f"ip link show failed: {result}")
                return []
            
            interfaces = []
            lines = result["stdout"].split('\n')
            
            for line in lines:
                if ': ' in line and not line.startswith(' '):
                    parts = line.split(': ')
                    if len(parts) >= 2:
                        interface_name = parts[1].split('@')[0]
                        
                        # Skip loopback interface - not useful for network spoofing
                        if interface_name == "lo":
                            continue
                        
                        # Only include WiFi interfaces
                        if not (interface_name.startswith('wlan') or interface_name.startswith('wl')):
                            continue
                        
                        # Get interface type and state
                        state_match = re.search(r'state (\w+)', line)
                        state = state_match.group(1) if state_match else "UNKNOWN"
                        
                        # Check if this interface supports AP mode
                        supports_ap = await self._check_ap_support(interface_name)
                        
                        interfaces.append({
                            "name": interface_name,
                            "state": state,
                            "supports_ap": supports_ap
                        })
            
            decky.logger.info(f"Found WiFi interfaces: {interfaces}")
            return interfaces
            
        except Exception as e:
            decky.logger.error(f"Failed to get network interfaces: {e}")
            return []
    
    async def _check_ap_support(self, interface: str) -> bool:
        """Check if a WiFi interface supports AP mode"""
        try:
            # Get physical interface index
            phy_result = await self._run_command(f"iw dev {interface} info")
            if not phy_result["success"]:
                return False
            
            # Extract wiphy number
            import re
            wiphy_match = re.search(r'wiphy (\d+)', phy_result["stdout"])
            if not wiphy_match:
                return False
            
            wiphy_num = wiphy_match.group(1)
            
            # Check supported interface modes
            modes_result = await self._run_command(f"iw phy{wiphy_num} info")
            if modes_result["success"] and "* AP" in modes_result["stdout"]:
                return True
                
            return False
            
        except Exception as e:
            decky.logger.error(f"Failed to check AP support for {interface}: {e}")
            return False

    async def get_supported_channels(self, interface: str) -> Dict[str, Any]:
        """Get supported WiFi channels and frequencies for an interface"""
        try:
            # Get physical interface index
            phy_result = await self._run_command(f"iw dev {interface} info")
            if not phy_result["success"]:
                return {"success": False, "error": f"Could not get info for {interface}"}
            
            # Extract wiphy number
            wiphy_match = re.search(r'wiphy (\d+)', phy_result["stdout"])
            if not wiphy_match:
                return {"success": False, "error": f"Could not find wiphy for {interface}"}
            
            wiphy_num = wiphy_match.group(1)
            
            # Get supported frequencies from phy info
            freq_result = await self._run_command(f"iw phy{wiphy_num} info")
            if not freq_result["success"]:
                return {"success": False, "error": f"Could not get phy info for wiphy{wiphy_num}"}
            
            channels_2_4ghz = []
            channels_5ghz = []
            
            # Parse frequency information
            lines = freq_result["stdout"].split('\n')
            current_band = None
            
            for line in lines:
                line = line.strip()
                
                # Detect band sections
                if "Band 1:" in line:
                    current_band = "2.4GHz"
                    decky.logger.info(f"Channel detection: Found Band 1 (2.4GHz)")
                elif "Band 2:" in line:
                    current_band = "5GHz"
                    decky.logger.info(f"Channel detection: Found Band 2 (5GHz)")
                
                # Parse frequency lines: "* 2412.0 MHz [1] (20.0 dBm)"
                freq_match = re.search(r'\* (\d+)\.?\d* MHz \[(\d+)\]', line)
                if freq_match:
                    freq_mhz = int(freq_match.group(1))
                    channel = int(freq_match.group(2))
                    
                    decky.logger.info(f"Channel detection: Found freq {freq_mhz} MHz, channel {channel}, current_band: {current_band}")
                    
                    # Determine band based on frequency if band detection failed
                    if current_band is None:
                        if 2400 <= freq_mhz <= 2500:
                            current_band = "2.4GHz"
                        elif 5000 <= freq_mhz <= 6000:
                            current_band = "5GHz"
                    
                    # Add to appropriate band
                    if 2400 <= freq_mhz <= 2500:
                        channels_2_4ghz.append({
                            "channel": channel,
                            "frequency": freq_mhz,
                            "band": "2.4GHz"
                        })
                        decky.logger.info(f"Added 2.4GHz channel {channel}")
                    elif 5000 <= freq_mhz <= 6000:
                        channels_5ghz.append({
                            "channel": channel,
                            "frequency": freq_mhz,
                            "band": "5GHz"
                        })
                        decky.logger.info(f"Added 5GHz channel {channel}")
            
            decky.logger.info(f"Found {len(channels_2_4ghz)} 2.4GHz channels and {len(channels_5ghz)} 5GHz channels for {interface}")
            
            return {
                "success": True,
                "interface": interface,
                "wiphy": wiphy_num,
                "2.4GHz": channels_2_4ghz,
                "5GHz": channels_5ghz,
                "total_channels": len(channels_2_4ghz) + len(channels_5ghz)
            }
            
        except Exception as e:
            decky.logger.error(f"Failed to get supported channels for {interface}: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_current_mac(self, interface: str) -> Optional[str]:
        """Get current MAC address of specified interface"""
        try:
            result = await self._run_command(f"ip link show {interface}")
            if not result["success"]:
                return None
            
            # Extract MAC address from output
            mac_match = re.search(r'link/ether ([a-fA-F0-9:]{17})', result["stdout"])
            if mac_match:
                mac = mac_match.group(1)
                decky.logger.info(f"Current MAC for {interface}: {mac}")
                return mac
            
            return None
            
        except Exception as e:
            decky.logger.error(f"Failed to get MAC for {interface}: {e}")
            return None
    
    async def validate_connectivity(self) -> bool:
        """Test network connectivity by pinging gateway"""
        try:
            # Get default gateway
            result = await self._run_command("ip route show default")
            if not result["success"]:
                decky.logger.error(f"Failed to get default route")
                return False
            
            gateway_match = re.search(r'default via ([^\s]+)', result["stdout"])
            if not gateway_match:
                decky.logger.error(f"No gateway found in route output")
                return False
            
            gateway = gateway_match.group(1)
            
            # Ping gateway
            ping_result = await self._run_command(f"ping -c 1 -W 3 {gateway}")
            if ping_result["success"]:
                decky.logger.info(f"Connectivity validated: ping to {gateway} successful")
            else:
                decky.logger.error(f"Connectivity failed: ping to {gateway} failed")
            
            return ping_result["success"]
            
        except Exception as e:
            decky.logger.error(f"Connectivity validation failed: {e}")
            return False
    
    async def set_mac_address(self, interface: str, new_mac: str, save_config: bool = True) -> Dict[str, Any]:
        """Change MAC address with validation and rollback capability
        
        Args:
            interface: Network interface name
            new_mac: New MAC address to apply
            save_config: Whether to save config for persistence (False when restoring)
        """
        try:
            # Debug: Check what user we're running as
            user_result = await self._run_command("whoami")
            decky.logger.info(f"Plugin running as user: {user_result.get('stdout', 'unknown')}")
            
            # Debug: Check if we can use sudo
            sudo_test = await self._run_command("sudo -n whoami")
            decky.logger.info(f"Sudo test result: success={sudo_test['success']}, user={sudo_test.get('stdout', 'unknown')}")
            
            # Validate MAC format
            if not re.match(r'^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}$', new_mac):
                return {"success": False, "error": "Invalid MAC address format"}
            
            # Store original MAC if not already stored
            if interface not in self.original_mac_addresses:
                original_mac = await self.get_current_mac(interface)
                if original_mac:
                    self.original_mac_addresses[interface] = original_mac
                    decky.logger.info(f"Stored original MAC for {interface}: {original_mac}")
            
            # Test connectivity before change
            initial_connectivity = await self.validate_connectivity()
            decky.logger.info(f"Initial connectivity: {initial_connectivity}")
            
            # Change MAC address
            decky.logger.info(f"Setting MAC address for {interface} to {new_mac}")
            
            # Store the current NetworkManager connection UUID for this interface
            conn_result = await self._run_command(f"nmcli -t -f UUID,DEVICE connection show --active | grep {interface}")
            connection_uuid = None
            if conn_result["success"] and conn_result["stdout"]:
                connection_uuid = conn_result["stdout"].split(':')[0]
                decky.logger.info(f"Found active connection UUID: {connection_uuid}")
            
            # Use sudo explicitly for NetworkManager operations
            nm_stop_result = await self._run_command("sudo systemctl stop NetworkManager")
            decky.logger.info(f"Stopped NetworkManager: success={nm_stop_result['success']}, stderr={nm_stop_result.get('stderr')}")
            
            # Wait for NetworkManager to fully stop
            await asyncio.sleep(3)
            
            # Now we can manually control the interface with sudo
            down_result = await self._run_command(f"sudo ip link set dev {interface} down")
            decky.logger.info(f"Interface down result: success={down_result['success']}, stderr={down_result.get('stderr')}")
            if not down_result["success"]:
                # Restart NetworkManager before returning
                await self._run_command("sudo systemctl start NetworkManager")
                return {"success": False, "error": f"Failed to bring interface down: {down_result['stderr']}"}
            
            # Set new MAC address with sudo
            mac_result = await self._run_command(f"sudo ip link set dev {interface} address {new_mac}")
            decky.logger.info(f"MAC set result: success={mac_result['success']}, stderr={mac_result.get('stderr')}")
            if not mac_result["success"]:
                # Bring interface back up and restart NetworkManager
                await self._run_command(f"sudo ip link set dev {interface} up")
                await self._run_command("sudo systemctl start NetworkManager")
                return {"success": False, "error": f"Failed to set MAC address: {mac_result['stderr']}"}
            
            # Bring interface back up with sudo
            up_result = await self._run_command(f"sudo ip link set dev {interface} up")
            decky.logger.info(f"Interface up result: success={up_result['success']}, stderr={up_result.get('stderr')}")
            
            # Restart NetworkManager with sudo
            nm_start_result = await self._run_command("sudo systemctl start NetworkManager")
            decky.logger.info(f"Restarted NetworkManager: success={nm_start_result['success']}")
            
            # Wait for NetworkManager to fully start and detect interfaces
            await asyncio.sleep(8)
            
            # Try to reconnect to network
            if connection_uuid:
                # We have a saved connection UUID, try to reconnect to it
                reconnect_result = await self._run_command(f"sudo nmcli connection up uuid {connection_uuid}")
                decky.logger.info(f"Reconnected to network via UUID: success={reconnect_result['success']}")
            else:
                # No active connection found, try to auto-connect to any available network
                # This handles the case when interface was DOWN and had no active connection
                decky.logger.info(f"No active connection UUID found, asking NetworkManager to auto-connect {interface}")
                
                # Method 1: Try to bring up any saved connections for this interface
                autoconnect_result = await self._run_command(f"sudo nmcli device connect {interface}")
                if autoconnect_result['success']:
                    decky.logger.info(f"Successfully triggered auto-connect for {interface}")
                else:
                    decky.logger.warning(f"Auto-connect failed: {autoconnect_result.get('stderr')}, NetworkManager will handle connection automatically")
            
            # Additional wait for network to stabilize
            await asyncio.sleep(5)
            
            # Save MAC configuration for persistence IMMEDIATELY after successful change
            # This ensures configuration is saved even if connectivity test fails
            # Only save if save_config is True (False when restoring original MAC)
            if save_config and interface in self.original_mac_addresses:
                original_mac = self.original_mac_addresses[interface]
                self._save_mac_address_config(interface, new_mac, original_mac)
                decky.logger.info(f"Saved MAC configuration for persistence")
            
            # Verify connectivity after change
            if initial_connectivity:
                await asyncio.sleep(5)  # Give NetworkManager time to fully reconnect
                post_connectivity = await self.validate_connectivity()
                
                if not post_connectivity:
                    decky.logger.warning(f"Lost connectivity after MAC change, attempting rollback")
                    # Attempt rollback
                    await self.restore_original_mac(interface)
                    return {"success": False, "error": "MAC change broke connectivity, rolled back"}
            
            decky.logger.info(f"Successfully changed MAC for {interface} to {new_mac}")
            return {"success": True, "mac": new_mac}
            
        except Exception as e:
            decky.logger.error(f"Failed to set MAC address: {e}")
            return {"success": False, "error": str(e)}
    
    async def restore_original_mac(self, interface: str) -> Dict[str, Any]:
        """Restore original MAC address for interface"""
        try:
            # CRITICAL: Read original_mac from preferences.json, NOT in-memory dict
            # In-memory dict may have wrong value if it was set when MAC was already spoofed
            config_file = "/home/deck/.config/netdeck/preferences.json"
            original_mac = None
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    
                if 'mac_addresses' in preferences and interface in preferences['mac_addresses']:
                    original_mac = preferences['mac_addresses'][interface].get('original_mac')
                    decky.logger.info(f"Read original MAC from preferences.json: {original_mac}")
            
            if not original_mac:
                # Fallback to in-memory if not in preferences
                if interface not in self.original_mac_addresses:
                    return {"success": False, "error": "No original MAC stored"}
                original_mac = self.original_mac_addresses[interface]
                decky.logger.info(f"Using original MAC from in-memory dict: {original_mac}")
            
            # CRITICAL FIX: Remove persistent configuration FIRST, before applying restore MAC
            # If we remove AFTER set_mac_address, and the MAC change breaks connectivity,
            # the remove never happens, leaving monitoring to re-apply spoofed MAC in infinite loop!
            decky.logger.info(f"Removing MAC persistence config BEFORE restoring to prevent monitoring loop")
            self._remove_mac_address_config(interface)
            
            # Clean up in-memory dict
            if interface in self.original_mac_addresses:
                del self.original_mac_addresses[interface]
            
            # Pass save_config=False to prevent saving the original MAC as desired MAC
            result = await self.set_mac_address(interface, original_mac, save_config=False)
            
            if result["success"]:
                decky.logger.info(f"Restored original MAC for {interface}: {original_mac}")
            else:
                decky.logger.error(f"Failed to restore MAC, but persistence already removed (monitoring won't re-apply)")
            
            return result
            
        except Exception as e:
            decky.logger.error(f"Failed to restore original MAC: {e}")
            return {"success": False, "error": str(e)}
    
    async def create_hostapd_config(self, interface: str, ssid: str, password: str, channel: int) -> str:
        """Create hostapd configuration file for access point"""
        try:
            config_path = os.path.join(NETDECK_CONFIG_DIR, "hostapd.conf")
            config_content = f"""# NetDeck Hostapd Configuration
interface={interface}
driver=nl80211
ssid={ssid}
hw_mode=g
channel={channel}
wmm_enabled=0
macaddr_acl=0
auth_algs=1
ignore_broadcast_ssid=0
wpa=2
wpa_passphrase={password}
wpa_key_mgmt=WPA-PSK
wpa_pairwise=TKIP
rsn_pairwise=CCMP
"""
            
            with open(config_path, 'w') as f:
                f.write(config_content)
            
            decky.logger.info(f"Created hostapd config: {config_path}")
            return config_path
            
        except Exception as e:
            decky.logger.error(f"Failed to create hostapd config: {e}")
            raise

    async def start_adhoc_network(self, interface: str, ssid: str, password: str, channel: int, subnet: str = "192.168.4.0/24", band: str = "2.4ghz", hidden: bool = False) -> Dict[str, Any]:
        """Start WiFi hotspot using USB WiFi adapter while keeping primary adapter connected"""
        try:
            decky.logger.info(f"Starting adhoc network on {interface} using dual-adapter approach with subnet {subnet} and band {band}, hidden={hidden}")
            
            # Parse subnet to get IP and netmask
            try:
                import ipaddress
                network = ipaddress.IPv4Network(subnet, strict=False)
                ap_ip = str(network.network_address + 1)  # First usable IP as gateway
                netmask = str(network.netmask)
                cidr = subnet
                # Store for use by other functions
                self.current_subnet = subnet
                self.current_gateway_ip = ap_ip
            except Exception as e:
                decky.logger.error(f"Invalid subnet format: {subnet}, using default")
                ap_ip = "192.168.4.1"
                cidr = "192.168.4.0/24"
                self.current_subnet = "192.168.4.0/24"
                self.current_gateway_ip = "192.168.4.1"
            
            # Stop existing adhoc if running
            if self.adhoc_active:
                await self.stop_adhoc_network()
            
            # Get all WiFi interfaces
            interfaces = await self.get_network_interfaces()
            wifi_interfaces = [iface for iface in interfaces if iface["name"].startswith("wlan")]
            
            if len(wifi_interfaces) < 2:
                return {"success": False, "error": "Dual-adapter mode requires at least 2 WiFi interfaces. Please connect a USB WiFi adapter."}
            
            # Find the primary interface (the one that's currently connected)
            primary_interface = None
            for iface in wifi_interfaces:
                iface_name = iface["name"]
                status_check = await self._run_command(f"nmcli device status | grep {iface_name}")
                if status_check["success"] and "connected" in status_check["stdout"]:
                    primary_interface = iface_name
                    break
            
            if not primary_interface:
                return {"success": False, "error": "No connected WiFi interface found. At least one WiFi interface must be connected to the internet."}
            
            # The hotspot interface should be different from the primary
            hotspot_interface = interface
            if hotspot_interface == primary_interface:
                return {"success": False, "error": f"Cannot use {hotspot_interface} for hotspot - it's the primary internet connection. Please select a different interface."}
            
            # Verify hotspot interface supports AP mode
            supports_ap = await self._check_ap_support(hotspot_interface)
            if not supports_ap:
                return {"success": False, "error": f"Interface {hotspot_interface} does not support AP mode"}
            
            # Validate channel and use fallback if necessary
            validated_channel = await self._validate_and_fallback_channel(hotspot_interface, band, channel)
            if validated_channel != channel:
                decky.logger.warning(f"Channel {channel} not supported, using validated channel {validated_channel}")
                channel = validated_channel
            
            decky.logger.info(f"Using {hotspot_interface} for AP mode, keeping {primary_interface} connected for internet")
            
            # CRITICAL: Verify primary interface connectivity before proceeding
            initial_connectivity = await self.validate_connectivity()
            if not initial_connectivity:
                return {"success": False, "error": f"Primary interface {primary_interface} has no internet connectivity. Cannot create bridge without internet access."}
            
            # CRITICAL: Ensure hotspot interface is not managed by any existing connections
            # CRITICAL: Ensure hotspot interface is not managed by any existing connections
            existing_connections = await self._run_command(f"nmcli connection show | grep {hotspot_interface}")
            if existing_connections["success"]:
                decky.logger.info(f"Found existing connections on {hotspot_interface}, cleaning up first")
                # Delete any existing connections on the hotspot adapter
                cleanup_result = await self._run_command(f"sudo nmcli device disconnect {hotspot_interface}")
                await self._run_command(f"sudo nmcli connection delete $(nmcli connection show | grep {hotspot_interface} | awk '{{print $1}}')")
            
            # Create NetworkManager connection for the hotspot adapter
            connection_name = ssid  # Use SSID directly as connection name
            
            # Ensure the hotspot interface is up but not interfering with primary
            await self._run_command(f"sudo ip link set {hotspot_interface} up")
            
            # Create the connection on the hotspot adapter
            create_conn = await self._run_command(f"sudo nmcli connection add type wifi ifname {hotspot_interface} con-name '{connection_name}' ssid '{ssid}'")
            if not create_conn["success"]:
                return {"success": False, "error": f"Failed to create connection on {hotspot_interface}: {create_conn.get('stderr', 'Unknown error')}"}
            
            # Configure as AP mode with specific settings to avoid conflicts
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' wifi.mode ap")
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' wifi.channel {channel}")
            
            # Configure WiFi band (NetworkManager sets band based on channel, but we can be explicit)
            if band.lower() == "5ghz":
                # For 5GHz, use band 'a' mode 
                await self._run_command(f"sudo nmcli connection modify '{connection_name}' wifi.band a")
                decky.logger.info(f"Configured AP for 5GHz band with channel {channel}")
            else:
                # For 2.4GHz, use band 'bg' mode
                await self._run_command(f"sudo nmcli connection modify '{connection_name}' wifi.band bg")
                decky.logger.info(f"Configured AP for 2.4GHz band with channel {channel}")
                
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' wifi-sec.key-mgmt wpa-psk")
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' wifi-sec.psk '{password}'")
            
            # Configure hidden SSID if requested
            if hidden:
                await self._run_command(f"sudo nmcli connection modify '{connection_name}' 802-11-wireless.hidden true")
                decky.logger.info(f"Configured AP with hidden SSID")
            else:
                await self._run_command(f"sudo nmcli connection modify '{connection_name}' 802-11-wireless.hidden false")
                decky.logger.info(f"Configured AP with visible SSID")
                
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' ipv4.method shared")
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' ipv4.addresses {ap_ip}/24")
            
            # CRITICAL: Set connection to not interfere with routing
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' ipv4.route-metric 200")
            await self._run_command(f"sudo nmcli connection modify '{connection_name}' connection.autoconnect no")
            
            # Verify primary connection is still active before activating AP
            primary_check = await self.validate_connectivity()
            if not primary_check:
                await self._run_command(f"sudo nmcli connection delete '{connection_name}'")
                return {"success": False, "error": "Primary internet connection lost before AP activation. Aborting to preserve connectivity."}
            
            # Activate the connection
            decky.logger.info(f"Activating AP connection on hotspot adapter: {hotspot_interface}")
            activate_result = await self._run_command(f"sudo nmcli connection up '{connection_name}'")
            
            if activate_result["success"]:
                # Wait for NetworkManager to configure the interface
                await asyncio.sleep(3)
                
                # CRITICAL: Verify primary connection is still active after AP activation
                primary_final_check = await self.validate_connectivity()
                if not primary_final_check:
                    decky.logger.error("Primary internet connection lost after AP activation! Rolling back...")
                    await self._run_command(f"sudo nmcli connection down '{connection_name}'")
                    await self._run_command(f"sudo nmcli connection delete '{connection_name}'")
                    return {"success": False, "error": "Primary internet connection lost after AP activation. Configuration rolled back."}
                
                # Set up NAT routing for internet sharing from primary to hotspot adapter
                nat_result = await self.setup_nat_routing(primary_interface, hotspot_interface)
                
                if nat_result["success"]:
                    # Final connectivity verification
                    final_check = await self.validate_connectivity()
                    if not final_check:
                        decky.logger.error("Primary internet lost after NAT setup! Rolling back...")
                        await self.cleanup_nat_routing(primary_interface, hotspot_interface)
                        await self._run_command(f"sudo nmcli connection down '{connection_name}'")
                        await self._run_command(f"sudo nmcli connection delete '{connection_name}'")
                        return {"success": False, "error": "Primary internet connection lost after NAT setup. Configuration rolled back."}
                    
                    self.adhoc_active = True
                    self.adhoc_config.update({
                        'enabled': True,
                        'ssid': ssid,
                        'password': password,
                        'channel': channel,
                        'band': band,
                        'interface': primary_interface,  # wlan0 stays connected 
                        'ap_interface': hotspot_interface,    # wlan1 creates hotspot
                        'connection_name': connection_name,
                        'ap_ip': ap_ip,
                        'subnet': cidr,
                        'hidden': hidden
                    })
                    
                    # Save hotspot auto-start configuration for persistence across reboots
                    self._save_hotspot_autostart_config(True, self.adhoc_config)
                    
                    decky.logger.info(f"Dual-adapter adhoc network started: {ssid} on {hotspot_interface}, internet via {primary_interface}")
                    return {
                        "success": True, 
                        "message": f"Hotspot '{ssid}' started on {hotspot_interface} with internet sharing from {primary_interface}",
                        "ap_interface": hotspot_interface,
                        "primary_interface": primary_interface,
                        "connection_name": connection_name,
                        "primary_connected": True
                    }
                else:
                    # Cleanup on NAT setup failure
                    await self._run_command(f"sudo nmcli connection down '{connection_name}'")
                    await self._run_command(f"sudo nmcli connection delete '{connection_name}'")
                    return {"success": False, "error": f"NAT routing setup failed: {nat_result.get('error', 'Unknown error')}"}
            else:
                # Connection activation failed, cleanup
                error_msg = activate_result.get("stderr", activate_result.get("stdout", "Unknown error"))
                decky.logger.error(f"Failed to activate AP connection on hotspot adapter: {error_msg}")
                await self._run_command(f"sudo nmcli connection delete '{connection_name}'")
                return {"success": False, "error": f"Failed to activate AP connection on {hotspot_interface}: {error_msg}"}
                
        except Exception as e:
            decky.logger.error(f"Failed to start adhoc network: {e}")
            return {"success": False, "error": str(e)}

    async def stop_adhoc_network(self) -> Dict[str, Any]:
        """Stop WiFi hotspot and clean up dual-adapter configuration"""
        try:
            decky.logger.info("Stopping dual-adapter adhoc network")
            
            success = True
            messages = []
            
            # Clean up NAT routing if configured
            primary_interface = self.adhoc_config.get('interface')
            ap_interface = self.adhoc_config.get('ap_interface') or self.adhoc_config.get('virtual_interface')
            
            if primary_interface and ap_interface:
                nat_result = await self.cleanup_nat_routing(primary_interface, ap_interface)
                if nat_result["success"]:
                    messages.append("NAT routing cleaned up")
                else:
                    messages.append(f"NAT cleanup warning: {nat_result.get('error', 'Unknown error')}")
            
            # Stop NetworkManager connection on USB adapter
            if self.adhoc_config.get('connection_name'):
                connection_name = self.adhoc_config['connection_name']
                
                # Disconnect the connection
                disconnect_cmd = f"sudo nmcli connection down '{connection_name}'"
                disconnect_result = await self._run_command(disconnect_cmd)
                
                if disconnect_result["success"] or "not an active connection" in disconnect_result.get("stderr", ""):
                    messages.append(f"NetworkManager connection '{connection_name}' disconnected")
                    
                    # Delete the connection profile
                    delete_cmd = f"sudo nmcli connection delete '{connection_name}'"
                    delete_result = await self._run_command(delete_cmd)
                    
                    if delete_result["success"]:
                        messages.append(f"NetworkManager connection profile '{connection_name}' deleted")
                    else:
                        messages.append(f"Connection profile deletion failed: {delete_result.get('stderr', 'Unknown error')}")
                        success = False
                else:
                    messages.append(f"Failed to disconnect NetworkManager connection: {disconnect_result.get('stderr', 'Unknown error')}")
                    success = False
            
            # Stop DHCP server if running (legacy hostapd approach)
            if hasattr(self, 'dhcp_process') and self.dhcp_process:
                dhcp_result = await self.stop_dhcp_server()
                if dhcp_result["success"]:
                    messages.append("DHCP server stopped")
                else:
                    messages.append(f"DHCP stop failed: {dhcp_result.get('error', 'Unknown error')}")
                    success = False
            
            # Kill hostapd process if running (legacy approach)
            if hasattr(self, 'adhoc_process') and self.adhoc_process:
                try:
                    self.adhoc_process.terminate()
                    # Wait for termination
                    try:
                        self.adhoc_process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        self.adhoc_process.kill()
                        self.adhoc_process.wait()
                    
                    messages.append("Hostapd process stopped")
                    self.adhoc_process = None
                except Exception as e:
                    decky.logger.error(f"Error stopping hostapd: {e}")
                    messages.append(f"Hostapd stop error: {e}")
                    success = False
            
            # Reset state (no virtual interface cleanup needed for USB adapter approach)
            self.adhoc_active = False
            self.adhoc_config.update({
                'enabled': False,
                'ap_interface': None,
                'connection_name': None,
                'ap_ip': None
            })
            
            # Disable hotspot auto-start when user manually stops it
            self._save_hotspot_autostart_config(False, self.adhoc_config)
            
            message = "; ".join(messages) if messages else "Adhoc network stopped"
            decky.logger.info(f"Adhoc network stopped: {message}")
            return {"success": success, "message": message}
            
        except Exception as e:
            decky.logger.error(f"Failed to stop adhoc network: {e}")
            return {"success": False, "error": str(e)}

    async def get_adhoc_status(self) -> Dict[str, Any]:
        """Get current adhoc network status"""
        try:
            status = {
                "enabled": self.adhoc_active,
                "config": self.adhoc_config.copy(),
                "process_running": self.adhoc_process is not None and self.adhoc_process.poll() is None
            }
            
            # If process should be running but isn't, update state
            if self.adhoc_active and not status["process_running"]:
                decky.logger.warning("Adhoc marked as active but process not running, updating state")
                self.adhoc_active = False
                self.adhoc_config['enabled'] = False
                status["enabled"] = False
            
            return status
            
        except Exception as e:
            decky.logger.error(f"Failed to get adhoc status: {e}")
            return {"error": str(e)}

    async def setup_network_bridge(self, primary_interface: str, adhoc_interface: str) -> Dict[str, Any]:
        """Setup internet bridging from primary to adhoc network"""
        try:
            decky.logger.info(f"Setting up network bridge: {primary_interface} -> {adhoc_interface}")
            
            # Use current gateway IP from subnet configuration
            gateway_ip = getattr(self, 'current_gateway_ip', '192.168.4.1')
            subnet_cidr = getattr(self, 'current_subnet', '192.168.4.0/24')
            
            # Extract prefix from subnet for IP configuration
            import ipaddress
            network = ipaddress.IPv4Network(subnet_cidr, strict=False)
            prefix_len = network.prefixlen
            
            # Configure IP address for adhoc interface
            ip_config = await self._run_command(f"sudo ip addr add {gateway_ip}/{prefix_len} dev {adhoc_interface}")
            if not ip_config["success"]:
                return {"success": False, "error": f"Failed to configure IP: {ip_config['stderr']}"}
            
            # Enable IP forwarding
            forward_enable = await self._run_command("sudo sysctl -w net.ipv4.ip_forward=1")
            if not forward_enable["success"]:
                return {"success": False, "error": f"Failed to enable IP forwarding: {forward_enable['stderr']}"}
            
            # Clear existing iptables rules for our chains
            await self._run_command("sudo iptables -F NETDECK-FORWARD 2>/dev/null")
            await self._run_command("sudo iptables -F NETDECK-POSTROUTING 2>/dev/null")
            await self._run_command("sudo iptables -t nat -F NETDECK-POSTROUTING 2>/dev/null")
            
            # Create custom chains if they don't exist
            await self._run_command("sudo iptables -N NETDECK-FORWARD 2>/dev/null")
            await self._run_command("sudo iptables -t nat -N NETDECK-POSTROUTING 2>/dev/null")
            
            # Setup NAT masquerading
            nat_rule = await self._run_command(f"sudo iptables -t nat -A NETDECK-POSTROUTING -o {primary_interface} -j MASQUERADE")
            if not nat_rule["success"]:
                return {"success": False, "error": f"Failed to setup NAT: {nat_rule['stderr']}"}
            
            # Setup forwarding rules
            forward_rules = [
                f"sudo iptables -A NETDECK-FORWARD -i {adhoc_interface} -o {primary_interface} -j ACCEPT",
                f"sudo iptables -A NETDECK-FORWARD -i {primary_interface} -o {adhoc_interface} -m state --state RELATED,ESTABLISHED -j ACCEPT"
            ]
            
            for rule in forward_rules:
                result = await self._run_command(rule)
                if not result["success"]:
                    # Cleanup on failure
                    await self.cleanup_network_bridge()
                    return {"success": False, "error": f"Failed to setup forwarding: {result['stderr']}"}
            
            # Insert our chains into main chains
            await self._run_command("sudo iptables -I FORWARD 1 -j NETDECK-FORWARD")
            await self._run_command("sudo iptables -t nat -I POSTROUTING 1 -j NETDECK-POSTROUTING")
            
            self.bridge_active = True
            decky.logger.info(f"Network bridge configured successfully: {primary_interface} -> {adhoc_interface}")
            return {"success": True, "message": f"Bridge configured: {primary_interface} -> {adhoc_interface}"}
            
        except Exception as e:
            decky.logger.error(f"Failed to setup network bridge: {e}")
            return {"success": False, "error": str(e)}

    async def cleanup_network_bridge(self) -> Dict[str, Any]:
        """Cleanup network bridge configuration"""
        try:
            decky.logger.info("Cleaning up network bridge configuration")
            
            success = True
            messages = []
            
            # Remove our custom chains from main chains
            result = await self._run_command("sudo iptables -D FORWARD -j NETDECK-FORWARD 2>/dev/null")
            if result["success"]:
                messages.append("Removed FORWARD chain rule")
            
            result = await self._run_command("sudo iptables -t nat -D POSTROUTING -j NETDECK-POSTROUTING 2>/dev/null")
            if result["success"]:
                messages.append("Removed POSTROUTING chain rule")
            
            # Flush and delete our custom chains
            await self._run_command("sudo iptables -F NETDECK-FORWARD 2>/dev/null")
            await self._run_command("sudo iptables -X NETDECK-FORWARD 2>/dev/null")
            await self._run_command("sudo iptables -t nat -F NETDECK-POSTROUTING 2>/dev/null")
            await self._run_command("sudo iptables -t nat -X NETDECK-POSTROUTING 2>/dev/null")
            messages.append("Cleaned up iptables rules")
            
            # Remove IP address from adhoc interface if it exists
            if self.adhoc_config.get('interface'):
                # Use current gateway IP from configuration
                gateway_ip = getattr(self, 'current_gateway_ip', '192.168.4.1')
                subnet_cidr = getattr(self, 'current_subnet', '192.168.4.0/24')
                
                # Extract prefix from subnet 
                import ipaddress
                network = ipaddress.IPv4Network(subnet_cidr, strict=False)
                prefix_len = network.prefixlen
                
                ip_remove = await self._run_command(f"sudo ip addr del {gateway_ip}/{prefix_len} dev {self.adhoc_config['interface']} 2>/dev/null")
                if ip_remove["success"]:
                    messages.append(f"Removed IP from {self.adhoc_config['interface']}")
            
            self.bridge_active = False
            message = "; ".join(messages)
            decky.logger.info(f"Network bridge cleanup completed: {message}")
            return {"success": success, "message": message}
            
        except Exception as e:
            decky.logger.error(f"Failed to cleanup network bridge: {e}")
            return {"success": False, "error": str(e)}

    async def get_bridge_status(self) -> Dict[str, Any]:
        """Get current bridge status"""
        try:
            status = {
                "enabled": self.bridge_active,
                "iptables_rules": []
            }
            
            # Check if our iptables rules exist
            check_forward = await self._run_command("sudo iptables -L NETDECK-FORWARD 2>/dev/null")
            if check_forward["success"]:
                status["iptables_rules"].append("NETDECK-FORWARD chain exists")
            
            check_nat = await self._run_command("sudo iptables -t nat -L NETDECK-POSTROUTING 2>/dev/null")
            if check_nat["success"]:
                status["iptables_rules"].append("NETDECK-POSTROUTING chain exists")
            
            # Check IP forwarding
            forward_check = await self._run_command("sysctl net.ipv4.ip_forward")
            if forward_check["success"]:
                status["ip_forwarding"] = "1" in forward_check["stdout"]
            
            return status
            
        except Exception as e:
            decky.logger.error(f"Failed to get bridge status: {e}")
            return {"error": str(e)}

    async def get_network_status(self) -> Dict[str, Any]:
        """Get comprehensive network status"""
        try:
            interfaces = await self.get_network_interfaces()
            connectivity = await self.validate_connectivity()
            
            # Get current MAC addresses
            interface_status = {}
            for interface in interfaces:
                name = interface["name"]
                current_mac = await self.get_current_mac(name)
                
                # Get hardware MAC (permaddr) to determine if spoofed
                hardware_mac = None
                result = await self._run_command(f"cat /sys/class/net/{name}/address")
                if result["success"] and result["stdout"]:
                    # Try to get permanent address first
                    perm_result = await self._run_command(f"ethtool -P {name} 2>/dev/null | awk '{{print $3}}'")
                    if perm_result["success"] and perm_result["stdout"].strip() and perm_result["stdout"].strip() != "00:00:00:00:00:00":
                        hardware_mac = perm_result["stdout"].strip()
                    else:
                        # Fallback: check if interface is in preferences.json
                        mac_configs = self._load_mac_address_configs()
                        if name in mac_configs:
                            hardware_mac = mac_configs[name].get('original_mac')
                        else:
                            # Last resort: assume current MAC is hardware MAC
                            hardware_mac = current_mac
                
                # Determine if MAC is spoofed by comparing current to hardware
                mac_spoofed = False
                if current_mac and hardware_mac:
                    mac_spoofed = current_mac.lower() != hardware_mac.lower()
                
                interface_status[name] = {
                    "state": interface["state"],
                    "current_mac": current_mac,
                    "original_mac": hardware_mac or self.original_mac_addresses.get(name),
                    "mac_spoofed": mac_spoofed
                }
            
            return {
                "connectivity": connectivity,
                "interfaces": interface_status,
                "adhoc_active": self.adhoc_active,
                "adhoc_config": self.adhoc_config,
                "bridge_active": self.bridge_active
            }
            
        except Exception as e:
            decky.logger.error(f"Failed to get network status: {e}")
            return {"error": str(e)}

    async def get_connected_clients(self) -> List[Dict[str, str]]:
        """Get list of connected clients from DHCP leases"""
        try:
            clients = []
            
            # If adhoc network is active, try to get connected clients
            if self.adhoc_active and self.adhoc_config.get('connection_name'):
                connection_name = self.adhoc_config['connection_name']
                
                # Get current subnet configuration
                current_subnet = getattr(self, 'current_subnet', '192.168.4.0/24')
                gateway_ip = getattr(self, 'current_gateway_ip', '192.168.4.1')
                
                # Parse subnet to get network address for ARP filtering
                import ipaddress
                network = ipaddress.IPv4Network(current_subnet, strict=False)
                subnet_base = str(network.network_address)
                # Create regex pattern for this subnet (e.g., 192\.168\.4\. for 192.168.4.0/24)
                subnet_pattern = subnet_base.replace('.0', '.').replace('.', '\\.')
                
                # Get ARP table entries for the adhoc interface subnet
                arp_result = await self._run_command(f"arp -a | grep '{subnet_pattern}'")
                if arp_result["success"]:
                    for line in arp_result["stdout"].split('\n'):
                        if line.strip():
                            # Parse ARP entry: hostname (IP) at mac [ether] on interface
                            import re
                            match = re.search(r'\((\d+\.\d+\.\d+\.\d+)\).*?([a-fA-F0-9:]{17})', line)
                            if match:
                                ip = match.group(1)
                                mac = match.group(2)
                                hostname = line.split('(')[0].strip() if '(' in line else 'Unknown'
                                
                                # Skip the AP interface itself (gateway IP)
                                if ip != gateway_ip:
                                    clients.append({
                                        "ip": ip,
                                        "mac": mac,
                                        "hostname": hostname
                                    })
            
            decky.logger.info(f"Found {len(clients)} connected clients")
            return clients
            
        except Exception as e:
            decky.logger.error(f"Failed to get connected clients: {e}")
            return []
    
    # User preference persistence methods
    async def get_band_preference(self) -> Dict[str, Any]:
        """Get saved band preference"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    band = preferences.get('band', '2.4GHz')
                    decky.logger.info(f"Loaded band preference: {band}")
                    return {"success": True, "band": band}
            else:
                decky.logger.info("No preferences file found, using default 2.4GHz")
                return {"success": True, "band": "2.4GHz"}
                
        except Exception as e:
            decky.logger.error(f"Failed to load band preference: {e}")
            return {"success": False, "error": str(e), "band": "2.4GHz"}
    
    async def set_band_preference(self, band: str) -> Dict[str, Any]:
        """Save band preference"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Create config directory if it doesn't exist
            os.makedirs(config_dir, exist_ok=True)
            
            # Load existing preferences or create new
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Update band preference
            preferences['band'] = band
            
            # Save preferences
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            decky.logger.info(f"Saved band preference: {band}")
            return {"success": True, "band": band}
            
        except Exception as e:
            decky.logger.error(f"Failed to save band preference: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_channel_preference(self, band: str) -> Dict[str, Any]:
        """Get saved channel preference for specific band"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    channels = preferences.get('channels', {})
                    channel = channels.get(band, 6 if band == "2.4GHz" else 36)
                    decky.logger.info(f"Loaded channel preference for {band}: {channel}")
                    return {"success": True, "channel": channel}
            else:
                # Default channels
                default_channel = 6 if band == "2.4GHz" else 36
                decky.logger.info(f"No preferences file found, using default channel {default_channel} for {band}")
                return {"success": True, "channel": default_channel}
                
        except Exception as e:
            decky.logger.error(f"Failed to load channel preference for {band}: {e}")
            default_channel = 6 if band == "2.4GHz" else 36
            return {"success": False, "error": str(e), "channel": default_channel}
    
    async def set_channel_preference(self, channel: int, band: str) -> Dict[str, Any]:
        """Save channel preference for specific band"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Create config directory if it doesn't exist
            os.makedirs(config_dir, exist_ok=True)
            
            # Load existing preferences or create new
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Ensure channels dict exists
            if 'channels' not in preferences:
                preferences['channels'] = {}
            
            # Update channel preference for this band
            preferences['channels'][band] = channel
            
            # Save preferences
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            decky.logger.info(f"Saved channel preference for {band}: {channel}")
            return {"success": True, "channel": channel, "band": band}
            
        except Exception as e:
            decky.logger.error(f"Failed to save channel preference for {band}: {e}")
            return {"success": False, "error": str(e)}
    
    # IP Forwarding management methods
    async def get_ip_forwarding_status(self) -> Dict[str, Any]:
        """Get current IP forwarding status"""
        try:
            result = await self._run_command("cat /proc/sys/net/ipv4/ip_forward")
            if result["success"]:
                enabled = result["stdout"].strip() == "1"
                decky.logger.info(f"IP forwarding status: {'enabled' if enabled else 'disabled'}")
                return {"success": True, "enabled": enabled}
            else:
                return {"success": False, "error": "Failed to read IP forwarding status"}
        except Exception as e:
            decky.logger.error(f"Failed to get IP forwarding status: {e}")
            return {"success": False, "error": str(e), "enabled": False}
    
    async def toggle_ip_forwarding(self, enable: bool) -> Dict[str, Any]:
        """Enable or disable IP forwarding"""
        try:
            if enable:
                decky.logger.info("Enabling IP forwarding")
                result = await self._run_command("echo '1' | sudo tee /proc/sys/net/ipv4/ip_forward")
            else:
                decky.logger.info("Disabling IP forwarding")
                result = await self._run_command("echo '0' | sudo tee /proc/sys/net/ipv4/ip_forward")
            
            if result["success"]:
                status = "enabled" if enable else "disabled"
                decky.logger.info(f"IP forwarding {status}")
                return {"success": True, "enabled": enable, "message": f"IP forwarding {status}"}
            else:
                return {"success": False, "error": f"Failed to {'enable' if enable else 'disable'} IP forwarding"}
        except Exception as e:
            decky.logger.error(f"Failed to toggle IP forwarding: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_nat_forwarding_preference(self) -> Dict[str, Any]:
        """Get saved NAT forwarding preference"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    nat_enabled = preferences.get('nat_forwarding', True)
                    decky.logger.info(f"Loaded NAT forwarding preference: {nat_enabled}")
                    return {"success": True, "enabled": nat_enabled}
            else:
                decky.logger.info("No preferences file found, using default NAT forwarding: enabled")
                return {"success": True, "enabled": True}
                
        except Exception as e:
            decky.logger.error(f"Failed to load NAT forwarding preference: {e}")
            return {"success": False, "error": str(e), "enabled": True}
    
    async def set_nat_forwarding_preference(self, enabled: bool) -> Dict[str, Any]:
        """Save NAT forwarding preference"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Create config directory if it doesn't exist
            os.makedirs(config_dir, exist_ok=True)
            
            # Load existing preferences or create new
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Update NAT forwarding preference
            preferences['nat_forwarding'] = enabled
            
            # Save preferences
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            decky.logger.info(f"Saved NAT forwarding preference: {enabled}")
            return {"success": True, "enabled": enabled}
            
        except Exception as e:
            decky.logger.error(f"Failed to save NAT forwarding preference: {e}")
            return {"success": False, "error": str(e)}
    
    # Interface preference management methods
    async def get_interface_preferences(self) -> Dict[str, Any]:
        """Get saved interface preferences"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    selected_interface = preferences.get('selected_interface', '')
                    adhoc_interface = preferences.get('adhoc_interface', '')
                    decky.logger.info(f"Loaded interface preferences - selected: {selected_interface}, adhoc: {adhoc_interface}")
                    return {
                        "success": True, 
                        "selected_interface": selected_interface,
                        "adhoc_interface": adhoc_interface
                    }
            else:
                decky.logger.info("No preferences file found, using default interface preferences")
                return {
                    "success": True, 
                    "selected_interface": "",
                    "adhoc_interface": ""
                }
                
        except Exception as e:
            decky.logger.error(f"Failed to load interface preferences: {e}")
            return {
                "success": False, 
                "error": str(e), 
                "selected_interface": "",
                "adhoc_interface": ""
            }
    
    async def set_interface_preferences(self, selected_interface: str = None, adhoc_interface: str = None) -> Dict[str, Any]:
        """Save interface preferences"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Create config directory if it doesn't exist
            os.makedirs(config_dir, exist_ok=True)
            
            # Load existing preferences or create new
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Update interface preferences
            if selected_interface is not None:
                preferences['selected_interface'] = selected_interface
                decky.logger.info(f"Updated selected_interface preference: {selected_interface}")
            
            if adhoc_interface is not None:
                preferences['adhoc_interface'] = adhoc_interface
                decky.logger.info(f"Updated adhoc_interface preference: {adhoc_interface}")
            
            # Save preferences
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            return {
                "success": True, 
                "selected_interface": preferences.get('selected_interface', ''),
                "adhoc_interface": preferences.get('adhoc_interface', '')
            }
            
        except Exception as e:
            decky.logger.error(f"Failed to save interface preferences: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_channel_preference(self) -> Dict[str, Any]:
        """Get saved channel preference from JSON file"""
        try:
            config_file = "/home/deck/.config/netdeck/preferences.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    channel = preferences.get('channel', 6)  # Default to channel 6 for 2.4GHz
                    return {"success": True, "channel": channel}
            return {"success": True, "channel": 6}  # Default channel
        except Exception as e:
            decky.logger.error(f"Failed to load channel preference: {e}")
            return {"success": False, "channel": 6}

    async def set_channel_preference(self, channel: int) -> Dict[str, Any]:
        """Save channel preference to JSON file"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Create config directory if it doesn't exist
            os.makedirs(config_dir, exist_ok=True)
            
            # Load existing preferences or create new
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Update channel preference
            preferences['channel'] = channel
            decky.logger.info(f"Updated channel preference: {channel}")
            
            # Save preferences
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            return {"success": True, "channel": channel}
            
        except Exception as e:
            decky.logger.error(f"Failed to save channel preference: {e}")
            return {"success": False, "error": str(e)}
    
    async def get_adhoc_config_preference(self) -> Dict[str, Any]:
        """Get saved adhoc config preferences (SSID, password) from JSON file"""
        try:
            config_file = "/home/deck/.config/netdeck/preferences.json"
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
                    ssid = preferences.get('ssid', "NetDeck-AP")  # Default SSID
                    password = preferences.get('password', "netdeck123")  # Default password
                    return {"success": True, "ssid": ssid, "password": password}
            return {"success": True, "ssid": "NetDeck-AP", "password": "netdeck123"}  # Defaults
        except Exception as e:
            decky.logger.error(f"Failed to load adhoc config preference: {e}")
            return {"success": False, "ssid": "NetDeck-AP", "password": "netdeck123"}

    async def set_adhoc_config_preference(self, ssid: str = None, password: str = None) -> Dict[str, Any]:
        """Save adhoc config preferences (SSID, password) to JSON file"""
        try:
            config_dir = "/home/deck/.config/netdeck"
            config_file = os.path.join(config_dir, "preferences.json")
            
            # Create config directory if it doesn't exist
            os.makedirs(config_dir, exist_ok=True)
            
            # Load existing preferences or create new
            preferences = {}
            if os.path.exists(config_file):
                with open(config_file, 'r') as f:
                    preferences = json.load(f)
            
            # Update adhoc config preferences
            if ssid is not None:
                preferences['ssid'] = ssid
                decky.logger.info(f"Updated SSID preference: {ssid}")
            
            if password is not None:
                preferences['password'] = password
                decky.logger.info(f"Updated password preference: [length: {len(password)}]")
            
            # Save preferences
            with open(config_file, 'w') as f:
                json.dump(preferences, f, indent=2)
            
            return {"success": True, "ssid": preferences.get('ssid', ''), "password": preferences.get('password', '')}
            
        except Exception as e:
            decky.logger.error(f"Failed to save adhoc config preference: {e}")
            return {"success": False, "error": str(e)}

    async def regenerate_secure_credentials(self) -> Dict[str, Any]:
        """Generate new secure SSID and password and update configuration"""
        try:
            # Generate new secure credentials
            new_ssid = generate_secure_ssid()
            new_password = generate_secure_password()
            
            decky.logger.info(f"Generated new secure credentials: SSID={new_ssid}")
            
            # Update internal configuration
            self.adhoc_config['ssid'] = new_ssid
            self.adhoc_config['password'] = new_password
            
            # Save to both preference locations for compatibility
            await self.set_adhoc_config_preference(new_ssid, new_password)
            self._save_credentials_to_preferences({'ssid': new_ssid, 'password': new_password})
            
            return {
                "success": True,
                "ssid": new_ssid,
                "password": new_password,
                "message": "New secure credentials generated"
            }
            
        except Exception as e:
            decky.logger.error(f"Failed to regenerate secure credentials: {e}")
            return {"success": False, "error": str(e)}

    async def get_current_credentials(self) -> Dict[str, Any]:
        """Get current SSID and password from configuration"""
        try:
            return {
                "success": True,
                "ssid": self.adhoc_config['ssid'],
                "password": self.adhoc_config['password']
            }
        except Exception as e:
            decky.logger.error(f"Failed to get current credentials: {e}")
            return {"success": False, "error": str(e)}

# Global plugin instance
plugin = NetDeckPlugin()

class Plugin:
    """Decky plugin class for NetDeck"""
    
    async def _main(self):
        decky.logger.info("NetDeck plugin started")
        # Start interface monitoring task in background
        asyncio.create_task(plugin._start_interface_monitoring())
    
    async def _unload(self):
        decky.logger.info("NetDeck plugin unloading - performing cleanup")
        try:
            # Stop all network services
            if plugin.adhoc_active:
                await plugin.stop_adhoc_network()
            
            if plugin.bridge_active:
                await plugin.cleanup_network_bridge()
            
            # Restore all original MAC addresses
            for interface in list(plugin.original_mac_addresses.keys()):
                await plugin.restore_original_mac(interface)
            
            decky.logger.info("NetDeck cleanup completed successfully")
        except Exception as e:
            decky.logger.error(f"Error during NetDeck cleanup: {e}")
    
    # Frontend callable methods
    async def get_interfaces(self) -> List[Dict[str, str]]:
        """Get list of available network interfaces - Plugin class method (frontend alias)"""
        decky.logger.info("PLUGIN METHOD: get_interfaces()")
        return await plugin.get_network_interfaces()
    
    async def get_network_interfaces(self) -> List[Dict[str, str]]:
        """Get list of available network interfaces - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_network_interfaces()")
        return await plugin.get_network_interfaces()
    
    async def get_current_mac(self, interface: str) -> Optional[str]:
        """Get current MAC address of interface - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: get_current_mac({interface})")
        return await plugin.get_current_mac(interface)
    
    async def set_mac_address(self, interface: str, new_mac: str, save_config: bool = True) -> Dict[str, Any]:
        """Set MAC address with validation - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: set_mac_address({interface}, {new_mac}, save_config={save_config})")
        return await plugin.set_mac_address(interface, new_mac, save_config)
    
    async def restore_original_mac(self, interface: str) -> Dict[str, Any]:
        """Restore original MAC address - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: restore_original_mac({interface})")
        return await plugin.restore_original_mac(interface)
    
    async def get_network_status(self) -> Dict[str, Any]:
        """Get comprehensive network status - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_network_status()")
        return await plugin.get_network_status()
    
    async def start_adhoc_network(self, interface: str, ssid: str, password: str, channel: int, subnet: str = "192.168.4.0/24", band: str = "2.4ghz", hidden: bool = False) -> Dict[str, Any]:
        """Start WiFi access point - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: start_adhoc_network({interface}, {ssid}, ******, {channel}, {subnet}, {band}, hidden={hidden})")
        return await plugin.start_adhoc_network(interface, ssid, password, channel, subnet, band, hidden)
    
    async def stop_adhoc_network(self) -> Dict[str, Any]:
        """Stop WiFi access point - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: stop_adhoc_network()")
        return await plugin.stop_adhoc_network()
    
    async def get_adhoc_status(self) -> Dict[str, Any]:
        """Get adhoc network status - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_adhoc_status()")
        return await plugin.get_adhoc_status()
    
    async def setup_network_bridge(self, primary_interface: str, adhoc_interface: str) -> Dict[str, Any]:
        """Setup internet bridging - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: setup_network_bridge({primary_interface}, {adhoc_interface})")
        return await plugin.setup_network_bridge(primary_interface, adhoc_interface)
    
    async def cleanup_network_bridge(self) -> Dict[str, Any]:
        """Cleanup network bridge - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: cleanup_network_bridge()")
        return await plugin.cleanup_network_bridge()
    
    async def get_bridge_status(self) -> Dict[str, Any]:
        """Get bridge status - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_bridge_status()")
        return await plugin.get_bridge_status()
    
    async def start_dhcp_server(self, interface: str) -> Dict[str, Any]:
        """Start DHCP server - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: start_dhcp_server({interface})")
        return await plugin.start_dhcp_server(interface)
    
    async def stop_dhcp_server(self) -> Dict[str, Any]:
        """Stop DHCP server - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: stop_dhcp_server()")
        return await plugin.stop_dhcp_server()
    
    async def get_dhcp_leases(self) -> Dict[str, Any]:
        """Get DHCP leases - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_dhcp_leases()")
        return await plugin.get_dhcp_leases()
    
    async def get_connected_clients(self) -> List[Dict[str, str]]:
        """Get connected clients - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_connected_clients()")
        return await plugin.get_connected_clients()
    
    async def get_supported_channels(self, interface: str) -> Dict[str, Any]:
        """Get supported WiFi channels and frequencies - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: get_supported_channels({interface})")
        return await plugin.get_supported_channels(interface)
    
    async def validate_network_safety(self, interface: str) -> Dict[str, Any]:
        """Validate network safety - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: validate_network_safety({interface})")
        return await plugin.validate_network_safety(interface)
    
    async def emergency_network_restore(self) -> Dict[str, Any]:
        """Emergency network restore - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: emergency_network_restore()")
        return await plugin.emergency_network_restore()
    
    # User preference persistence methods
    async def get_band_preference(self) -> Dict[str, Any]:
        """Get saved band preference - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_band_preference()")
        return await plugin.get_band_preference()
    
    async def set_band_preference(self, band: str) -> Dict[str, Any]:
        """Save band preference - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: set_band_preference({band})")
        return await plugin.set_band_preference(band)
    
    async def get_channel_preference(self, band: str) -> Dict[str, Any]:
        """Get saved channel preference for band - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: get_channel_preference({band})")
        return await plugin.get_channel_preference(band)
    
    async def set_channel_preference(self, channel: int, band: str) -> Dict[str, Any]:
        """Save channel preference for band - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: set_channel_preference({channel}, {band})")
        return await plugin.set_channel_preference(channel, band)
    
    # IP Forwarding methods
    async def get_ip_forwarding_status(self) -> Dict[str, Any]:
        """Get current IP forwarding status - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_ip_forwarding_status()")
        return await plugin.get_ip_forwarding_status()
    
    async def toggle_ip_forwarding(self, enable: bool) -> Dict[str, Any]:
        """Enable or disable IP forwarding - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: toggle_ip_forwarding({enable})")
        return await plugin.toggle_ip_forwarding(enable)
    
    async def get_nat_forwarding_preference(self) -> Dict[str, Any]:
        """Get saved NAT forwarding preference - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_nat_forwarding_preference()")
        return await plugin.get_nat_forwarding_preference()
    
    async def set_nat_forwarding_preference(self, enabled: bool) -> Dict[str, Any]:
        """Save NAT forwarding preference - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: set_nat_forwarding_preference({enabled})")
        return await plugin.set_nat_forwarding_preference(enabled)
    
    # Interface preference methods
    async def get_interface_preferences(self) -> Dict[str, Any]:
        """Get saved interface preferences - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_interface_preferences()")
        return await plugin.get_interface_preferences()
    
    async def set_interface_preferences(self, selected_interface: str = None, adhoc_interface: str = None) -> Dict[str, Any]:
        """Save interface preferences - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: set_interface_preferences({selected_interface}, {adhoc_interface})")
        return await plugin.set_interface_preferences(selected_interface, adhoc_interface)

    async def get_channel_preference(self) -> Dict[str, Any]:
        """Get saved channel preference - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_channel_preference()")
        return await plugin.get_channel_preference()

    async def set_channel_preference(self, channel: int) -> Dict[str, Any]:
        """Save channel preference - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: set_channel_preference({channel})")
        return await plugin.set_channel_preference(channel)

    async def get_adhoc_config_preference(self) -> Dict[str, Any]:
        """Get saved adhoc config preferences - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_adhoc_config_preference()")
        return await plugin.get_adhoc_config_preference()

    async def set_adhoc_config_preference(self, ssid: str = None, password: str = None) -> Dict[str, Any]:
        """Save adhoc config preferences - Plugin class method"""
        decky.logger.info(f"PLUGIN METHOD: set_adhoc_config_preference([ssid: {len(ssid) if ssid else 0} chars], [password: {len(password) if password else 0} chars])")
        return await plugin.set_adhoc_config_preference(ssid, password)

    async def regenerate_secure_credentials(self) -> Dict[str, Any]:
        """Generate new secure SSID and password - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: regenerate_secure_credentials()")
        return await plugin.regenerate_secure_credentials()
    
    # Update functionality - Plugin class methods
    async def get_current_version(self) -> str:
        """Get current plugin version - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_current_version() - START")
        try:
            # Simplified version to avoid any potential issues
            plugin_json_path = os.path.join(os.path.dirname(__file__), "plugin.json")
            if os.path.exists(plugin_json_path):
                with open(plugin_json_path, 'r') as f:
                    plugin_data = json.load(f)
                    version = plugin_data.get("version", "1.0.14")
                    decky.logger.info(f"Plugin version from plugin.json: {version}")
                    decky.logger.info("PLUGIN METHOD: get_current_version() - END SUCCESS")
                    return version
            decky.logger.info("PLUGIN METHOD: get_current_version() - END FALLBACK")
            return "1.0.14"  # Hardcoded fallback
        except Exception as e:
            decky.logger.error(f"Error in get_current_version: {e}")
            decky.logger.info("PLUGIN METHOD: get_current_version() - END ERROR")
            return "1.0.14"
    
    async def get_latest_version(self) -> str:
        """Get latest available version from GitHub API - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_latest_version()")
        try:
            import urllib.request
            import urllib.error
            import ssl
            import re
            
            # GitHub API endpoint for latest release
            github_api_url = "https://api.github.com/repos/fewtarius/NetDeck/releases/latest"
            
            decky.logger.info("Fetching latest version from GitHub...")
            
            try:
                # Create SSL context that doesn't verify certificates (for compatibility)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                with urllib.request.urlopen(github_api_url, timeout=10, context=ssl_context) as response:
                    data = json.loads(response.read().decode())
                    
                    # Extract version from tag_name (e.g., "v1.2.0" -> "1.2.0")
                    tag_name = data.get('tag_name', '')
                    if tag_name:
                        # Remove 'v' prefix if present
                        version_match = re.match(r'v?(.+)', tag_name)
                        if version_match:
                            latest_version = version_match.group(1)
                            decky.logger.info(f"Latest version from GitHub: {latest_version}")
                            return latest_version
                    
                    decky.logger.warning("No valid tag_name found in GitHub response")
                    return await self.get_current_version()
                    
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    decky.logger.info("No releases found in GitHub repository")
                    return await self.get_current_version()
                else:
                    decky.logger.error(f"HTTP error fetching latest version: {e}")
                    return await self.get_current_version()
            except Exception as e:
                decky.logger.error(f"Error fetching latest version: {e}")
                return await self.get_current_version()
                
        except Exception as e:
            decky.logger.error(f"Failed to get latest version: {e}")
            return get_plugin_version()
    
    async def check_for_updates(self) -> Dict[str, Any]:
        """Check for available updates without downloading - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: check_for_updates() - START")
        try:
            import urllib.request
            import urllib.error
            import ssl
            import re
            
            # Get current version (inlined to avoid self issue)
            decky.logger.info("Getting current version inline to avoid self issues")
            try:
                plugin_json_path = os.path.join(os.path.dirname(__file__), "plugin.json")
                if os.path.exists(plugin_json_path):
                    with open(plugin_json_path, 'r') as f:
                        plugin_data = json.load(f)
                        current_version = plugin_data.get("version", "1.0.14")
                        decky.logger.info(f"Plugin version from plugin.json (inline): {current_version}")
                else:
                    current_version = "1.0.14"
                    decky.logger.info("Using fallback version (inline): 1.0.14")
            except Exception as e:
                decky.logger.error(f"Error getting version inline: {e}")
                current_version = "1.0.14"
            
            decky.logger.info(f"Successfully got current version inline: {current_version}")
            
            # Check for updates from fewtarius/NetDeck repository
            github_api_url = "https://api.github.com/repos/fewtarius/NetDeck/releases/latest"
            
            decky.logger.info("Checking for NetDeck updates...")
            
            try:
                # Create SSL context that doesn't verify certificates (for compatibility)
                ssl_context = ssl.create_default_context()
                ssl_context.check_hostname = False
                ssl_context.verify_mode = ssl.CERT_NONE
                
                with urllib.request.urlopen(github_api_url, timeout=10, context=ssl_context) as response:
                    data = json.loads(response.read().decode())
                    
                    tag_name = data.get('tag_name', '')
                    release_name = data.get('name', '')
                    release_body = data.get('body', '')
                    assets = data.get('assets', [])
                    
                    if tag_name:
                        # Extract version from tag_name (e.g., "v1.2.0" -> "1.2.0")
                        version_match = re.match(r'v?(.+)', tag_name)
                        if version_match:
                            latest_version = version_match.group(1)
                            
                            decky.logger.info(f"Latest version available: {latest_version}")
                            decky.logger.info(f"Release: {release_name}")
                            
                            # Simple string comparison for version checking
                            if latest_version != current_version:
                                decky.logger.info(f"UPDATE AVAILABLE: {current_version} -> {latest_version}")
                                
                                # Find the downloadable asset
                                download_url = None
                                for asset in assets:
                                    asset_name = asset.get('name', '').lower()
                                    if asset_name.endswith('.zip') or 'netdeck' in asset_name:
                                        download_url = asset.get('browser_download_url')
                                        break
                                
                                # Fallback to source code zip if no specific asset found
                                if not download_url:
                                    download_url = f"https://github.com/fewtarius/NetDeck/archive/refs/tags/{tag_name}.zip"
                                
                                return {
                                    'update_available': True,
                                    'current_version': current_version,
                                    'latest_version': latest_version,
                                    'release_name': release_name,
                                    'release_notes': release_body,
                                    'download_url': download_url
                                }
                                
                            else:
                                decky.logger.info(f"You have the latest version: {current_version}")
                                return {
                                    'update_available': False,
                                    'current_version': current_version,
                                    'latest_version': current_version,
                                    'message': 'You have the latest version'
                                }
                    
                    return {
                        'update_available': False,
                        'current_version': current_version,
                        'error': 'No valid version information found in GitHub response'
                    }
                    
            except urllib.error.HTTPError as e:
                if e.code == 404:
                    decky.logger.info("No releases found in repository")
                    return {
                        'update_available': False,
                        'current_version': current_version,
                        'error': 'No releases found'
                    }
                else:
                    decky.logger.error(f"HTTP error checking for updates: {e}")
                    return {
                        'update_available': False,
                        'current_version': current_version,
                        'error': f'HTTP error: {e}'
                    }
                    
            except Exception as e:
                decky.logger.error(f"Error checking for updates: {e}")
                return {
                    'update_available': False,
                    'current_version': current_version,
                    'error': str(e)
                }
                
        except Exception as e:
            decky.logger.error(f"Failed to check for updates: {e}")
            current_version = await self.get_current_version()
            return {
                'update_available': False,
                'current_version': current_version,
                'error': str(e)
            }
    
    async def download_and_install_update(self, download_url: str, version: str) -> Dict[str, Any]:
        """Download and install plugin update - Plugin class method"""
        try:
            import urllib.request
            import ssl
            import zipfile
            import subprocess
            
            decky.logger.info(f"Starting download of NetDeck v{version}")
            
            # Create temporary directory for download
            with tempfile.TemporaryDirectory() as temp_dir:
                # Download the update file
                update_file = os.path.join(temp_dir, f"netdeck-{version}.zip")
                
                try:
                    decky.logger.info(f"Downloading from {download_url}...")
                    # Create SSL context that doesn't verify certificates (for compatibility)
                    ssl_context = ssl.create_default_context()
                    ssl_context.check_hostname = False
                    ssl_context.verify_mode = ssl.CERT_NONE
                    
                    # Download using urlopen with SSL context, then write to file
                    with urllib.request.urlopen(download_url, timeout=30, context=ssl_context) as response:
                        with open(update_file, 'wb') as f:
                            shutil.copyfileobj(response, f)
                    
                    decky.logger.info(f"Downloaded update file: {update_file}")
                    
                except Exception as e:
                    decky.logger.error(f"Failed to download update: {e}")
                    return {
                        'success': False,
                        'error': f'Download failed: {str(e)}'
                    }
                
                # Extract the downloaded file
                extract_dir = os.path.join(temp_dir, "extracted")
                try:
                    os.makedirs(extract_dir, exist_ok=True)
                    with zipfile.ZipFile(update_file, 'r') as zip_ref:
                        zip_ref.extractall(extract_dir)
                    
                    decky.logger.info(f"Extracted update to: {extract_dir}")
                    
                except Exception as e:
                    decky.logger.error(f"Failed to extract update: {e}")
                    return {
                        'success': False,
                        'error': f'Extraction failed: {str(e)}'
                    }
                
                # Find the NetDeck source directory in extracted files
                plugin_source_dir = None
                for root, dirs, files in os.walk(extract_dir):
                    if 'main.py' in files and 'plugin.json' in files:
                        plugin_source_dir = root
                        break
                
                if not plugin_source_dir:
                    decky.logger.error("Could not find NetDeck directory in downloaded update")
                    return {
                        'success': False,
                        'error': 'Invalid update package - NetDeck directory not found'
                    }
                
                decky.logger.info(f"Found plugin source at: {plugin_source_dir}")
                
                # Get current plugin directory (using absolute path like PowerDeck)
                current_plugin_dir = "/home/deck/homebrew/plugins/NetDeck"
                decky.logger.info(f"Current plugin directory: {current_plugin_dir}")
                
                # Use separate backup directory like PowerDeck (avoid permission issues)
                backup_base_dir = "/home/deck/plugin_backups"
                backup_dir = f"{backup_base_dir}/NetDeck.backup.{version}"
                
                decky.logger.info(f"Backup directory: {backup_dir}")
                
                # Ensure backup base directory exists (use sudo because deck user can't create it)
                try:
                    if not os.path.exists(backup_base_dir):
                        subprocess.run(['sudo', 'mkdir', '-p', backup_base_dir], check=True)
                        subprocess.run(['sudo', 'chown', 'deck:deck', backup_base_dir], check=True)
                        decky.logger.info(f"Created backup base directory: {backup_base_dir}")
                except Exception as e:
                    decky.logger.error(f"Failed to create backup base directory: {e}")
                    return {
                        'success': False,
                        'error': f'Backup directory creation failed: {str(e)}'
                    }
                
                # Create backup before installation (use sudo for file operations)
                try:
                    if os.path.exists(current_plugin_dir):
                        # Remove existing backup if it exists
                        if os.path.exists(backup_dir):
                            decky.logger.info(f"Removing existing backup at {backup_dir}")
                            subprocess.run(['sudo', 'rm', '-rf', backup_dir], check=True)
                        
                        # Use sudo to copy the current plugin directory to backup
                        subprocess.run(['sudo', 'cp', '-r', current_plugin_dir, backup_dir], check=True)
                        subprocess.run(['sudo', 'chown', '-R', 'deck:deck', backup_dir], check=True)
                        decky.logger.info(f"Created backup at {backup_dir}")
                except Exception as e:
                    decky.logger.error(f"Failed to create backup: {e}")
                    return {
                        'success': False,
                        'error': f'Backup creation failed: {str(e)}'
                    }
                
                # Install the NetDeck plugin update using sudo rsync like PowerDeck
                try:
                    decky.logger.info("Installing NetDeck plugin files using sudo rsync...")
                    result = subprocess.run([
                        'sudo', 'rsync', '-av', '--delete',
                        f"{plugin_source_dir}/",  # Source with trailing slash
                        current_plugin_dir        # Destination
                    ], capture_output=True, text=True, timeout=60)
                    
                    if result.returncode != 0:
                        decky.logger.error(f"Failed to install plugin files via rsync: {result.stderr}")
                        # Fallback to manual file copying with sudo
                        subprocess.run(['sudo', 'rm', '-rf', current_plugin_dir], check=True)
                        subprocess.run(['sudo', 'cp', '-r', plugin_source_dir, current_plugin_dir], check=True)
                        subprocess.run(['sudo', 'chown', '-R', 'deck:deck', current_plugin_dir], check=True)
                        decky.logger.info("Plugin files installed successfully via fallback method")
                    else:
                        decky.logger.info("Plugin files installed successfully via rsync")
                    
                    decky.logger.info("Successfully copied new plugin files")
                    
                except Exception as e:
                    decky.logger.error(f"Failed to copy new files: {e}")
                    # Try to restore from backup using sudo
                    try:
                        if os.path.exists(backup_dir):
                            subprocess.run(['sudo', 'rm', '-rf', current_plugin_dir], check=True)
                            subprocess.run(['sudo', 'cp', '-r', backup_dir, current_plugin_dir], check=True)
                            subprocess.run(['sudo', 'chown', '-R', 'deck:deck', current_plugin_dir], check=True)
                            decky.logger.info("Restored from backup after copy failure")
                    except Exception as restore_e:
                        decky.logger.error(f"Failed to restore from backup: {restore_e}")
                    
                    return {
                        'success': False,
                        'error': f'Failed to install update: {str(e)}'
                    }
                
                # Restart plugin loader to load the new version
                decky.logger.info("Restarting plugin loader to load updated plugin...")
                try:
                    result = subprocess.run(['sudo', 'systemctl', 'restart', 'plugin_loader'], 
                                          capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        decky.logger.info("Plugin loader restarted successfully")
                    else:
                        decky.logger.warning(f"Plugin loader restart warning: {result.stderr}")
                        decky.logger.info("Update installed, manual restart may be required")
                except Exception as e:
                    decky.logger.warning(f"Could not restart plugin loader: {e}")
                    decky.logger.info("Update installed, manual restart may be required")
                
                decky.logger.info(f"Successfully updated NetDeck to version {version}")
                return {
                    'success': True,
                    'message': f'NetDeck updated to version {version}',
                    'version': version,
                    'restart_required': True
                }
                
        except Exception as e:
            decky.logger.error(f"Failed to download and install update: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def get_current_credentials(self) -> Dict[str, Any]:
        """Get current SSID and password - Plugin class method"""
        decky.logger.info("PLUGIN METHOD: get_current_credentials()")
        return await plugin.get_current_credentials()


# Global frontend callable functions for update functionality
# get_current_version() - removed, using Plugin class method directly

# Global frontend callable functions for update functionality - REMOVED
# These functions created temporary Plugin() instances which caused self reference errors
# The frontend now calls Plugin class methods directly via callPluginMethod

# download_and_install_update() - REMOVED (same issue with temporary Plugin() instances)