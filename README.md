# Advanced Networking Plugin for SteamOS

[![Release](https://github.com/fewtarius/NetDeck/actions/workflows/release.yml/badge.svg)](https://github.com/fewtarius/NetDeck/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-GPL--3.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/platform-SteamOS%20%7C%20Arch%20Linux-lightgrey.svg)](https://github.com/SteamDeckHomebrew/decky-loader)

NetDeck is a powerful networking plugin for [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader) that provides advanced networking capabilities for Steam Deck and handheld gaming PCs. Turn your device into a versatile networking tool with MAC address spoofing, WiFi hotspot creation, and internet sharing capabilities.

## Features

### MAC Address Spoofing
- **Privacy Protection**: Randomize your device's network identity
- **Safe Rollback**: Automatic restoration of original MAC address

### WiFi Access Point Creation
- **Dual-Adapter Hotspot**: Create WiFi hotspot using USB adapter while maintaining internet connection
- **Secure Anonymous Networks**: Generate random, non-identifying SSIDs (e.g., "amazing-falcon-7834")
- **Hidden SSID Support**: Create invisible networks for enhanced privacy
- **Cryptographically Secure Passwords**: 10-character randomized passwords with regeneration on demand

### Internet Sharing & Bridging
- **NAT-based Internet Sharing**: Share your primary connection through the hotspot
- **Client Monitoring**: Real-time display of connected devices with IP, MAC, and hostname
- **Dynamic Subnet Configuration**: Configurable IP ranges (default: 192.168.5.0/24)
- **Automatic Routing**: Seamless internet access for connected clients

### Security & Privacy Features
- **Randomized SSID Generation**: Word-pair combinations that don't identify your device
- **No Telemetry**: All networking operations are local to your device

## Quick Start

### Prerequisites
- Steam Deck or compatible handheld PC running SteamOS
- [Decky Loader](https://github.com/SteamDeckHomebrew/decky-loader) installed
- USB WiFi adapter (recommended for hotspot functionality)
- Root access for network configuration

### Installation

#### Automatic Installation

The simplest installation method uses the automated installer script:

```bash
curl -L https://raw.githubusercontent.com/fewtarius/NetDeck/main/install.sh | sh
```

After running the installer:
1. Restart the Decky Loader service: `sudo systemctl restart plugin_loader`
2. Reboot your device to ensure all components are loaded
3. Access NetDeck through the Decky Loader overlay

#### Manual Installation

If you prefer manual installation or the automatic method fails:

1. Download the latest release:
   ```bash
   wget https://github.com/fewtarius/NetDeck/releases/latest/download/NetDeck.zip
   ```

2. Extract to the plugins directory:
   ```bash
   sudo unzip NetDeck.zip -d $HOME/homebrew/plugins/NetDeck
   sudo chown -R deck:deck $HOME/homebrew/plugins/NetDeck
   ```

3. Restart services:
   ```bash
   sudo systemctl restart plugin_loader
   sudo reboot
   ```

#### Verification

After installation, verify NetDeck is working:

1. Open the Decky Loader overlay (Quick Access menu)
2. Look for NetDeck in the plugins list
3. The plugin should display your network interfaces and status
4. Test MAC spoofing by changing your interface's MAC address

#### Troubleshooting Installation

**Plugin not appearing in Decky Loader:**
- Verify Decky Loader is installed and running
- Check that plugin files are in the correct directory
- Restart the plugin loader service

**Network features not working:**
- Ensure plugin has root privileges
- Verify NetworkManager is running
- Check that required network interfaces exist

### First Use
1. Open NetDeck from the Decky overlay
2. **For MAC Spoofing**: Select your primary interface and configure MAC address
3. **For Hotspot**: Insert USB WiFi adapter, configure network settings, and start access point
4. **For Internet Sharing**: Enable NAT bridging to share internet with hotspot clients

## Detailed Configuration

### MAC Address Spoofing Setup

```bash
# NetDeck will automatically detect your primary WiFi interface
# Default: wlan0 (built-in adapter)
```

1. **Select Interface**: Choose your primary WiFi adapter (usually `wlan0`)
2. **Configure MAC**: Enter custom MAC or use random generation
3. **Apply Changes**: NetDeck handles network reconnection automatically
4. **Verify**: Check network status to confirm successful spoofing

### Hotspot Configuration

```bash
# Recommended Setup:
# Primary: wlan0 (built-in) - Internet connection
# Hotspot: wlan1 (USB adapter) - Access point
```

1. **Dual Adapter Setup**:
   - Keep built-in adapter (`wlan0`) connected to internet
   - Use USB adapter (`wlan1`) for hotspot creation

2. **Network Settings**:
   - **SSID**: Auto-generated anonymous name (e.g., "clever-hawk-2847")
   - **Password**: 10-character secure random password
   - **Band**: 2.4GHz (recommended for compatibility)
   - **Hidden**: Optional for enhanced privacy

3. **Advanced Configuration**:
   - **Subnet**: Configure IP range (default: 192.168.5.0/24)
   - **Gateway**: Automatic (.1 address of subnet)
   - **DHCP Range**: .2 to .20 of configured subnet

### Internet Sharing Setup

1. **Enable NAT Bridging**: Toggle internet sharing in NetDeck interface
2. **Automatic Routing**: NetDeck configures iptables rules automatically
3. **Client Access**: Connected devices receive internet through your primary connection
4. **Monitoring**: View connected clients in real-time

## Use Cases

### Gaming Parties & LAN Events
- **Problem**: Need local network for multiplayer gaming
- **Solution**: Create isolated gaming network with NetDeck
- **Benefit**: Low-latency local gaming with internet access

### Device Internet Sharing
- **Problem**: Limited internet access for multiple devices
- **Solution**: Share Steam Deck's connection via NetDeck hotspot
- **Benefit**: All devices get internet through one connection

### Streaming & Content
- **Problem**: Need stable connection for streaming devices
- **Solution**: Bridge Steam Deck's connection to other devices
- **Benefit**: Reliable internet for streaming sticks, phones, etc.

## Troubleshooting

### Common Issues

#### MAC Spoofing Not Working
- **Verify interface**: Ensure selected interface exists and is active
- **Check permissions**: NetDeck requires root access for MAC changes
- **Network restart**: Some networks require full disconnection/reconnection

#### Hotspot Creation Fails
- **USB adapter**: Verify USB WiFi adapter is detected (`iw dev`)
- **Interface conflicts**: Ensure both adapters are available
- **NetworkManager**: Check if NetworkManager is managing all interfaces

#### No Internet Through Hotspot
- **NAT configuration**: Verify iptables rules are applied correctly
- **Primary connection**: Ensure primary adapter maintains internet access
- **Routing**: Check IP forwarding is enabled (`sysctl net.ipv4.ip_forward`)

### Debug Commands
```bash
# Check WiFi interfaces
iw dev

# Verify network connections
nmcli connection show

# Check IP configuration
ip addr show

# Monitor network traffic
tcpdump -i wlan1

# Check iptables rules
iptables -t nat -L
iptables -L FORWARD
```

### Log Analysis
```bash
# Plugin-specific logs
journalctl -u plugin_loader | grep -i netdeck

# Network manager logs
journalctl -u NetworkManager --since "10 minutes ago"

# System network logs
dmesg | grep -i "wlan\|wifi\|network"
```

## Uninstallation

To remove NetDeck:

1. Stop the plugin loader:
   ```bash
   sudo systemctl stop plugin_loader
   ```

2. Remove plugin files:
   ```bash
   sudo rm -rf $HOME/homebrew/plugins/NetDeck
   ```

3. Remove configuration data (optional):
   ```bash
   rm -rf ~/.config/netdeck
   sudo rm -rf /root/.config/netdeck
   ```

4. Restart the plugin loader:
   ```bash
   sudo systemctl start plugin_loader
   ```

The uninstallation is complete. Your device will return to default networking behavior.

## License

NetDeck is licensed under the [GNU General Public License v3.0](LICENSE).