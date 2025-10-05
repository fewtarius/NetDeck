import {
  definePlugin,
  staticClasses,
  ServerAPI,
  PanelSection,
  PanelSectionRow,
  ButtonItem,
  TextField,
  Field,
  DropdownItem,
  ToggleField,
} from "decky-frontend-lib";
import React, { useState, useEffect } from "react";
import { FaNetworkWired, FaWifi, FaShareAlt, FaDesktop, FaCog, FaSearch, FaDownload, FaSpinner, FaCheckCircle, FaExclamationTriangle, FaBell } from "react-icons/fa";

interface NetworkInterface {
  name: string;
  state: string;
  supports_ap?: boolean;
}

interface InterfaceStatus {
  state: string;
  current_mac: string | null;
  original_mac: string | null;
  mac_spoofed: boolean;
}

interface NetworkStatus {
  connectivity: boolean;
  interfaces: Record<string, InterfaceStatus>;
  adhoc_active: boolean;
  adhoc_config: {
    enabled: boolean;
    ssid: string;
    password: string;
    channel: number;
    interface: string | null;
    ap_interface?: string;
    subnet?: string;
    band?: string;
  };
  bridge_active: boolean;
}

interface ConnectedClient {
  ip: string;
  mac: string;
  hostname: string;
}

const NetDeck: React.FC<{ serverAPI: ServerAPI }> = ({ serverAPI }) => {
  const [state, setState] = useState({
    networkStatus: null as NetworkStatus | null,
    selectedInterface: "",
    newMacAddress: "",
    isLoading: false,
    error: null as string | null,
    connectedClients: [] as ConnectedClient[],
    adhocConfig: {
      ssid: "",  // Will be loaded from backend secure generator
      password: "",  // Will be loaded from backend secure generator
      channel: 6,
      interface: "",
      subnet: "192.168.5.0/24",
      band: "2.4GHz",
      hidden: false  // Hidden SSID toggle
    },
    supportedChannels: null as any,
    bandPreference: "2.4GHz",
    ipForwardingEnabled: false,
    natForwardingEnabled: true
  });

  // OTA Update system state management (following PowerDeck patterns)
  const [updateState, setUpdateState] = useState<'idle' | 'checking' | 'available' | 'downloading' | 'ready' | 'installing' | 'completed' | 'error'>('idle');
  const [updateMessage, setUpdateMessage] = useState<string>('');
  const [backgroundUpdateStatus, setBackgroundUpdateStatus] = useState<any>(null);
  const [updateInfo, setUpdateInfo] = useState<{currentVersion?: string, latestVersion?: string, downloadUrl?: string} | null>(null);
  const [isCheckingForUpdates, setIsCheckingForUpdates] = useState<boolean>(false);
  const [pluginVersion, setPluginVersion] = useState<string>("Loading...");

  // Get interfaces from networkStatus like the original working version
  const availableInterfaces = state.networkStatus ? Object.keys(state.networkStatus.interfaces) : [];
  
  // Create interface options using the same pattern as working band options
  const interfaceOptions = availableInterfaces.map(ifaceName => {
    const ifaceStatus = state.networkStatus?.interfaces[ifaceName];
    return {
      data: ifaceName,
      label: `${ifaceName} (${ifaceStatus?.state || 'Unknown'})`
    };
  });

  const wifiInterfaceOptions = availableInterfaces
    .filter(ifaceName => ifaceName.startsWith('wlan'))
    .map(ifaceName => ({
      data: ifaceName,
      label: `${ifaceName} (Primary Connection)`
    }));

  // Create band options using the same pattern
  const bandOptions = [
    { data: "2.4GHz", label: "2.4ghz" },
    { data: "5GHz", label: "5ghz" }
  ];
  
  const hasMultipleWifiAdapters = availableInterfaces.filter(iface => 
    iface.startsWith('wlan')
  ).length >= 2;

  // Update status periodically
  useEffect(() => {
    const updateStatus = async () => {
      try {
        console.log("NetDeck: Calling get_network_status...");
        const result = await serverAPI.callPluginMethod("get_network_status", {});
        console.log("NetDeck: get_network_status result:", result);
        
        if (result.success && result.result) {
          const networkStatus = result.result as NetworkStatus;
          console.log("NetDeck: Network status data:", networkStatus);
          setState(prev => ({ 
            ...prev, 
            networkStatus,
            selectedInterface: prev.selectedInterface || Object.keys(networkStatus.interfaces || {})[0] || "",
            error: null 
          }));

          // Update connected clients if adhoc is active
          if (networkStatus.adhoc_active) {
            const clientsResult = await serverAPI.callPluginMethod("get_connected_clients", {});
            if (clientsResult.success && clientsResult.result) {
              setState(prev => ({ ...prev, connectedClients: clientsResult.result as ConnectedClient[] }));
            }
          }
        } else {
          console.error("NetDeck: get_network_status failed:", result);
          setState(prev => ({ ...prev, error: "Failed to get network status" }));
        }
      } catch (error) {
        console.error("NetDeck: Failed to update status:", error);
        setState(prev => ({ 
          ...prev, 
          error: "Failed to get network status" 
        }));
      }
    };

    updateStatus();
    const interval = setInterval(updateStatus, 3000);
    return () => clearInterval(interval);
  }, []);

  // Load band preference and supported channels on initialization
  useEffect(() => {
    const loadPreferences = async () => {
      try {
        let currentBand = "2.4GHz"; // Default band
        
        // Load band preference first
        const bandResult = await serverAPI.callPluginMethod("get_band_preference", {});
        if (bandResult.success && bandResult.result) {
          currentBand = (bandResult.result as any).band || "2.4GHz";
          setState(prev => ({ 
            ...prev, 
            bandPreference: currentBand,
            adhocConfig: { ...prev.adhocConfig, band: currentBand }
          }));
        }

        // Load channel preference with band-appropriate defaults
        const channelResult = await serverAPI.callPluginMethod("get_channel_preference", {});
        let channelToUse = currentBand === "2.4GHz" ? 6 : 36; // Default for band
        if (channelResult.success && channelResult.result) {
          const savedChannel = (channelResult.result as any).channel;
          if (savedChannel) {
            channelToUse = savedChannel;
          }
        }
        setState(prev => ({ 
          ...prev, 
          adhocConfig: { ...prev.adhocConfig, channel: channelToUse }
        }));

        // Load adhoc config preferences (SSID, password) - prefer backend current credentials
        const currentCredentialsResult = await serverAPI.callPluginMethod("get_current_credentials", {});
        if (currentCredentialsResult.success && currentCredentialsResult.result) {
          const currentCreds = currentCredentialsResult.result as any;
          setState(prev => ({ 
            ...prev, 
            adhocConfig: { 
              ...prev.adhocConfig, 
              ssid: currentCreds.ssid || "",
              password: currentCreds.password || ""
            }
          }));
        } else {
          // Fallback to saved preferences if current credentials fail
          const adhocConfigResult = await serverAPI.callPluginMethod("get_adhoc_config_preference", {});
          if (adhocConfigResult.success && adhocConfigResult.result) {
            const adhocConfig = adhocConfigResult.result as any;
            setState(prev => ({ 
              ...prev, 
              adhocConfig: { 
                ...prev.adhocConfig, 
                ssid: adhocConfig.ssid || "",
                password: adhocConfig.password || ""
              }
            }));
          }
        }

        // Load interface preferences
        const interfaceResult = await serverAPI.callPluginMethod("get_interface_preferences", {});
        if (interfaceResult.success && interfaceResult.result) {
          const interfacePrefs = interfaceResult.result as any;
          setState(prev => ({ 
            ...prev, 
            selectedInterface: interfacePrefs.selected_interface || prev.selectedInterface,
            adhocConfig: { 
              ...prev.adhocConfig, 
              interface: interfacePrefs.adhoc_interface || prev.adhocConfig.interface 
            }
          }));
        }

        // Load NAT forwarding preference
        const natResult = await serverAPI.callPluginMethod("get_nat_forwarding_preference", {});
        if (natResult.success && natResult.result) {
          const natEnabled = (natResult.result as any).enabled !== false;
          setState(prev => ({ ...prev, natForwardingEnabled: natEnabled }));
        }

        // Load IP forwarding status
        const ipResult = await serverAPI.callPluginMethod("get_ip_forwarding_status", {});
        if (ipResult.success && ipResult.result) {
          const ipEnabled = (ipResult.result as any).enabled === true;
          setState(prev => ({ ...prev, ipForwardingEnabled: ipEnabled }));
        }

        // Load plugin version and check for background updates
        let currentVersion = "unknown";
        try {
          const versionResult = await serverAPI.callPluginMethod("get_current_version", {});
          if (versionResult.success && versionResult.result) {
            currentVersion = versionResult.result as string;
            setPluginVersion(currentVersion);
            console.log(`NetDeck: Plugin version loaded: ${currentVersion}`);
          }
        } catch (error) {
          console.log("NetDeck: Failed to load plugin version:", error);
        }
        
        // Check background update status
        try {
          const updateStatusResult = await serverAPI.callPluginMethod("get_update_status", {});
          if (updateStatusResult.success && updateStatusResult.result) {
            const bgUpdateStatus = updateStatusResult.result as any;
            setBackgroundUpdateStatus(bgUpdateStatus);
            console.log("NetDeck: Background update status:", bgUpdateStatus);
            
            // If background check found an update, set the button to show it
            if (bgUpdateStatus.update_available && bgUpdateStatus.latest_version) {
              setUpdateState('available');
              setUpdateMessage(`Update available: ${currentVersion} → ${bgUpdateStatus.latest_version}`);
              setUpdateInfo({
                currentVersion: currentVersion,
                latestVersion: bgUpdateStatus.latest_version,
                downloadUrl: bgUpdateStatus.download_url
              });
            }
          }
        } catch (error) {
          console.log("NetDeck: Failed to load background update status:", error);
        }
      } catch (error) {
        console.error("NetDeck: Failed to load preferences:", error);
      }
    };

    loadPreferences();
  }, []);

  // Load supported channels when interface changes
  useEffect(() => {
    const loadSupportedChannels = async () => {
      if (state.adhocConfig.interface) {
        try {
          const channelsResult = await serverAPI.callPluginMethod("get_supported_channels", {
            interface: state.adhocConfig.interface
          });
          if (channelsResult.success && channelsResult.result) {
            setState(prev => ({ ...prev, supportedChannels: channelsResult.result }));
          }
        } catch (error) {
          console.error("NetDeck: Failed to load supported channels:", error);
        }
      }
    };

    loadSupportedChannels();
  }, [state.adhocConfig.interface]);

  const isValidMacAddress = (mac: string): boolean => {
    const macRegex = /^[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}:[a-fA-F0-9]{2}$/;
    return macRegex.test(mac);
  };

  const handleBandChange = async (band: string) => {
    try {
      // Save band preference to backend
      const result = await serverAPI.callPluginMethod("set_band_preference", { band });
      if (result.success) {
        setState(prev => ({ 
          ...prev, 
          bandPreference: band,
          adhocConfig: { ...prev.adhocConfig, band: band }
        }));
        
        // Reset channel to default for the selected band
        const defaultChannel = band === "2.4GHz" ? 6 : 36;
        setState(prev => ({ 
          ...prev, 
          adhocConfig: { ...prev.adhocConfig, channel: defaultChannel }
        }));
      }
    } catch (error) {
      console.error("NetDeck: Failed to save band preference:", error);
    }
  };

  // Handler for primary interface selection changes
  const handleInterfaceChange = async (newInterface: string) => {
    try {
      // Update local state immediately
      setState(prev => ({ ...prev, selectedInterface: newInterface }));
      
      // Save to backend immediately
      await serverAPI.callPluginMethod("set_interface_preferences", { 
        selected_interface: newInterface 
      });
      console.log(`NetDeck: Primary interface preference saved: ${newInterface}`);
    } catch (error) {
      console.error("NetDeck: Failed to save primary interface preference:", error);
    }
  };

  // Handler for adhoc interface selection changes
  const handleAdhocInterfaceChange = async (newInterface: string) => {
    try {
      // Update local state immediately
      setState(prev => ({ 
        ...prev, 
        adhocConfig: { ...prev.adhocConfig, interface: newInterface }
      }));
      
      // Save to backend immediately
      await serverAPI.callPluginMethod("set_interface_preferences", { 
        adhoc_interface: newInterface 
      });
      console.log(`NetDeck: Adhoc interface preference saved: ${newInterface}`);
    } catch (error) {
      console.error("NetDeck: Failed to save adhoc interface preference:", error);
    }
  };

  // Handler for channel selection changes
  const handleChannelChange = async (newChannel: number) => {
    try {
      // Update local state immediately
      setState(prev => ({ 
        ...prev, 
        adhocConfig: { ...prev.adhocConfig, channel: newChannel }
      }));
      
      // Save to backend immediately
      await serverAPI.callPluginMethod("set_channel_preference", { channel: newChannel });
      console.log(`NetDeck: Channel preference saved: ${newChannel}`);
    } catch (error) {
      console.error("NetDeck: Failed to save channel preference:", error);
    }
  };

  // Handler for SSID changes
  const handleSSIDChange = async (newSSID: string) => {
    try {
      // Update local state immediately
      setState(prev => ({ 
        ...prev, 
        adhocConfig: { ...prev.adhocConfig, ssid: newSSID }
      }));
      
      // Save to backend after a short delay to avoid excessive API calls
      await serverAPI.callPluginMethod("set_adhoc_config_preference", { ssid: newSSID });
      console.log(`NetDeck: SSID preference saved: ${newSSID}`);
    } catch (error) {
      console.error("NetDeck: Failed to save SSID preference:", error);
    }
  };

  // Handler for password changes
  const handlePasswordChange = async (newPassword: string) => {
    try {
      // Update local state immediately
      setState(prev => ({ 
        ...prev, 
        adhocConfig: { ...prev.adhocConfig, password: newPassword }
      }));
      
      // Save to backend after a short delay to avoid excessive API calls
      await serverAPI.callPluginMethod("set_adhoc_config_preference", { password: newPassword });
      console.log(`NetDeck: Password preference saved: [length: ${newPassword.length}]`);
    } catch (error) {
      console.error("NetDeck: Failed to save password preference:", error);
    }
  };

  // Handler for regenerating secure credentials
  const handleRegenerateCredentials = async () => {
    try {
      setState(prev => ({ ...prev, isLoading: true }));
      
      const result = await serverAPI.callPluginMethod("regenerate_secure_credentials", {});
      if (result.success) {
        // Update local state with new credentials
        const credentials = result.result as { success: boolean; ssid: string; password: string; message: string };
        setState(prev => ({ 
          ...prev, 
          adhocConfig: { 
            ...prev.adhocConfig, 
            ssid: credentials.ssid,
            password: credentials.password 
          },
          isLoading: false
        }));
        console.log(`NetDeck: New secure credentials generated: ${credentials.ssid}`);
      } else {
        console.error("NetDeck: Failed to regenerate credentials");
        setState(prev => ({ ...prev, isLoading: false }));
      }
    } catch (error) {
      console.error("NetDeck: Error regenerating credentials:", error);
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  // Get available channels for the selected band
  const getAvailableChannels = () => {
    if (!state.supportedChannels) {
      // Fallback to default channels if no hardware detection available
      if (state.adhocConfig.band === "5GHz") {
        return [36, 40, 44, 48, 149, 153, 157, 161, 165].map(ch => ({
          data: ch,
          label: `Channel ${ch}`
        }));
      } else {
        return Array.from({length: 11}, (_, i) => ({
          data: i + 1,
          label: `Channel ${i + 1}`
        }));
      }
    }

    // Use hardware-detected channels
    const bandChannels = state.supportedChannels[state.adhocConfig.band] || [];
    return bandChannels.map((ch: any) => ({
      data: ch.channel,
      label: `Channel ${ch.channel}`
    }));
  };

  const handleIPForwardingToggle = async (enabled: boolean) => {
    try {
      const result = await serverAPI.callPluginMethod("toggle_ip_forwarding", { enable: enabled });
      if (result.success) {
        setState(prev => ({ ...prev, ipForwardingEnabled: enabled }));
      } else {
        setState(prev => ({ ...prev, error: "Failed to toggle IP forwarding" }));
      }
    } catch (error) {
      console.error("NetDeck: Failed to toggle IP forwarding:", error);
      setState(prev => ({ ...prev, error: "Failed to toggle IP forwarding" }));
    }
  };

  const handleNATForwardingToggle = async (enabled: boolean) => {
    try {
      const result = await serverAPI.callPluginMethod("set_nat_forwarding_preference", { enabled });
      if (result.success) {
        setState(prev => ({ ...prev, natForwardingEnabled: enabled }));
      } else {
        setState(prev => ({ ...prev, error: "Failed to save NAT forwarding preference" }));
      }
    } catch (error) {
      console.error("NetDeck: Failed to toggle NAT forwarding:", error);
      setState(prev => ({ ...prev, error: "Failed to save NAT forwarding preference" }));
    }
  };

  const handleMacAddressChange = async () => {
    if (!state.selectedInterface || !isValidMacAddress(state.newMacAddress.trim())) {
      return;
    }

    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const result = await serverAPI.callPluginMethod(
        "set_mac_address", 
        {
          interface: state.selectedInterface,
          new_mac: state.newMacAddress.trim(),
        }
      );

      if (result.success) {
        setState(prev => ({ 
          ...prev, 
          newMacAddress: "",
          error: null 
        }));
      } else {
        setState(prev => ({ 
          ...prev, 
          error: "Failed to set MAC address" 
        }));
      }
    } catch (error) {
      setState(prev => ({ 
        ...prev, 
        error: "Failed to communicate with backend" 
      }));
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  const handleRestoreOriginalMac = async () => {
    if (!state.selectedInterface) return;

    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const result = await serverAPI.callPluginMethod(
        "restore_original_mac", 
        { interface: state.selectedInterface }
      );

      if (!result.success) {
        setState(prev => ({ 
          ...prev, 
          error: "Failed to restore original MAC address" 
        }));
      }
    } catch (error) {
      setState(prev => ({ 
        ...prev, 
        error: "Failed to communicate with backend" 
      }));
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  const handleStartAdhocNetwork = async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const result = await serverAPI.callPluginMethod(
        "start_adhoc_network",
        {
          interface: state.adhocConfig.interface,
          ssid: state.adhocConfig.ssid,
          password: state.adhocConfig.password,
          channel: state.adhocConfig.channel,
          band: state.adhocConfig.band,
          hidden: state.adhocConfig.hidden
        }
      );

      if (!result.success) {
        setState(prev => ({ 
          ...prev, 
          error: "Failed to start adhoc network" 
        }));
      }
    } catch (error) {
      setState(prev => ({ 
        ...prev, 
        error: "Failed to communicate with backend" 
      }));
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  const handleStopAdhocNetwork = async () => {
    setState(prev => ({ ...prev, isLoading: true, error: null }));

    try {
      const result = await serverAPI.callPluginMethod("stop_adhoc_network", {});
      if (!result.success) {
        setState(prev => ({ 
          ...prev, 
          error: "Failed to stop adhoc network" 
        }));
      }
    } catch (error) {
      setState(prev => ({ 
        ...prev, 
        error: "Failed to communicate with backend" 
      }));
    } finally {
      setState(prev => ({ ...prev, isLoading: false }));
    }
  };

  // OTA Update handler following PowerDeck patterns
  const handleUpdateAction = async () => {
    try {
      if (updateState === 'idle') {
        // Step 1: Check for updates
        setUpdateState('checking');
        setUpdateMessage('Checking for updates...');
        console.log("NetDeck: Checking for updates...");
        
        const result = await serverAPI.callPluginMethod("check_for_updates", {});
        
        if (result.success && result.result) {
          const updateResult = result.result as any;
          if (updateResult.update_available) {
            setUpdateState('available');
            setUpdateMessage(`Update available: ${updateResult.current_version} → ${updateResult.latest_version}`);
            setUpdateInfo({
              currentVersion: updateResult.current_version,
              latestVersion: updateResult.latest_version,
              downloadUrl: updateResult.download_url
            });
            console.log(`NetDeck: Update available: ${updateResult.current_version} -> ${updateResult.latest_version}`);
          } else {
            setUpdateState('idle');
            setUpdateMessage(`You have the latest version: ${updateResult.current_version}`);
            console.log(`NetDeck: You have the latest version: ${updateResult.current_version}`);
            
            // Reset message after 3 seconds
            setTimeout(() => {
              setUpdateMessage('');
            }, 3000);
          }
        } else {
          setUpdateState('error');
          setUpdateMessage('Failed to check for updates');
          console.error("NetDeck: Update check failed");
        }
        
      } else if (updateState === 'available') {
        // Step 2: Download and install update (simplified single-step process)
        if (!updateInfo?.downloadUrl || !updateInfo?.latestVersion) {
          setUpdateState('error');
          setUpdateMessage('Missing update information');
          return;
        }
        
        setUpdateState('downloading');
        setUpdateMessage('Downloading and installing update...');
        console.log("NetDeck: Downloading and installing update...");
        
        const installResult = await serverAPI.callPluginMethod("download_and_install_update", {
          download_url: updateInfo.downloadUrl,
          version: updateInfo.latestVersion
        });
        
        if (installResult.success && installResult.result) {
          const installData = installResult.result as any;
          if (installData.success) {
            setUpdateState('completed');
            setUpdateMessage(`Successfully updated to ${updateInfo?.latestVersion}! Plugin loader will restart automatically.`);
            console.log(`NetDeck: Successfully updated to ${updateInfo?.latestVersion}`);
            
            // The backend should handle plugin_loader restart automatically
            // Reset to idle after a delay to allow user to see completion
            setTimeout(() => {
              setUpdateState('idle');
              setUpdateMessage('');
              setUpdateInfo(null);
            }, 5000);
          } else {
            setUpdateState('error');
            setUpdateMessage('Failed to install update');
            console.error("NetDeck: Update installation failed:", installData.error);
          }
        } else {
          setUpdateState('error');
          setUpdateMessage('Failed to download update');
          console.error("NetDeck: Update download failed");
        }
        
      } else if (updateState === 'error') {
        // Reset from error state
        setUpdateState('idle');
        setUpdateMessage('');
        setUpdateInfo(null);
      }
      
    } catch (error) {
      setUpdateState('error');
      setUpdateMessage('Unexpected error occurred');
      console.error("NetDeck: Update process error:", error);
      
      // Reset error state after 5 seconds
      setTimeout(() => {
        setUpdateState('idle');
        setUpdateMessage('');
        setUpdateInfo(null);
      }, 5000);
    }
  };

  return React.createElement("div", { style: { width: "100%", height: "100%" } },
    // Error Display
    state.error ? (
      React.createElement(PanelSection, { title: "Error" },
        React.createElement(PanelSectionRow, null,
          React.createElement("div", { 
            style: { 
              padding: "8px", 
              backgroundColor: "#dc2626", 
              borderRadius: "4px",
              color: "white",
              fontSize: "12px"
            }
          }, state.error)
        )
      )
    ) : null,

    // Network Status
    React.createElement(PanelSection, { title: "Network Status" },
      React.createElement(PanelSectionRow, null,
        React.createElement(Field, { 
          label: "Connectivity",
          icon: React.createElement(FaNetworkWired)
        },
          React.createElement("div", { 
            style: { 
              display: "flex", 
              alignItems: "center", 
              gap: "8px",
              color: state.networkStatus?.connectivity ? "#4ade80" : "#ef4444"
            }
          },
            React.createElement("span", null, state.networkStatus?.connectivity ? "Connected" : "Disconnected")
          )
        )
      )
    ),

    // MAC Address Configuration
    React.createElement(PanelSection, { title: "MAC Address Configuration" },
      React.createElement(PanelSectionRow, null,
        React.createElement(DropdownItem, {
          label: "Interface",
          menuLabel: "Select Interface",
          selectedOption: interfaceOptions.find((opt: any) => opt.data === state.selectedInterface)?.data,
          rgOptions: interfaceOptions,
          onChange: (option: any) => {
            console.log("NetDeck: Interface dropdown onChange, selected:", option.data);
            if (option.data !== state.selectedInterface) {
              console.log("NetDeck: Setting new interface:", option.data);
              handleInterfaceChange(option.data);
            }
          }
        })
      ),

      state.selectedInterface && state.networkStatus?.interfaces[state.selectedInterface] ? (
        React.createElement(PanelSectionRow, null,
          React.createElement(Field, { label: "Current MAC" },
            React.createElement("span", { 
              style: { 
                fontFamily: "monospace",
                color: state.networkStatus.interfaces[state.selectedInterface].mac_spoofed ? "#fbbf24" : "#4ade80"
              }
            }, state.networkStatus.interfaces[state.selectedInterface].current_mac || "Unknown")
          )
        )
      ) : null,

      React.createElement(PanelSectionRow, null,
        React.createElement(TextField, {
          label: "New MAC Address",
          value: state.newMacAddress,
          onChange: (e: any) => setState(prev => ({ ...prev, newMacAddress: e.target.value })),
          placeholder: "XX:XX:XX:XX:XX:XX",
          disabled: state.isLoading
        })
      ),

      // Smart button: Shows "Apply MAC" or "Restore Original MAC" based on current state
      React.createElement(PanelSectionRow, null,
        state.networkStatus?.interfaces[state.selectedInterface]?.mac_spoofed &&
        state.networkStatus.interfaces[state.selectedInterface].current_mac?.toLowerCase() !== 
        state.networkStatus.interfaces[state.selectedInterface].original_mac?.toLowerCase() ? (
          // MAC is spoofed - show Restore button
          React.createElement(ButtonItem, {
            layout: "below",
            onClick: handleRestoreOriginalMac,
            disabled: state.isLoading
          }, state.isLoading ? "Restoring..." : "Restore Original MAC")
        ) : (
          // MAC is at hardware address - show Apply button
          React.createElement(ButtonItem, {
            layout: "below",
            onClick: handleMacAddressChange,
            disabled: state.isLoading || !state.selectedInterface || !isValidMacAddress(state.newMacAddress.trim())
          }, state.isLoading ? "Applying..." : "Apply MAC Address")
        )
      )
    ),

    // Hotspot Network (only show if multiple adapters)
    hasMultipleWifiAdapters ? (
      React.createElement(PanelSection, { title: "Hotspot Network" },
        !state.networkStatus?.adhoc_active ? (
          React.createElement("div", null,
            React.createElement(PanelSectionRow, null,
              React.createElement(DropdownItem, {
                label: "Primary Interface",
                menuLabel: "Select Primary Interface",
                selectedOption: wifiInterfaceOptions.find((opt: any) => opt.data === state.adhocConfig.interface)?.data,
                rgOptions: wifiInterfaceOptions,
                onChange: (option: any) => {
                  console.log("NetDeck: Primary interface dropdown onChange, selected:", option.data);
                  if (option.data !== state.adhocConfig.interface) {
                    console.log("NetDeck: Setting new primary interface:", option.data);
                    handleAdhocInterfaceChange(option.data);
                  }
                }
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(TextField, {
                label: "Network Name (SSID)",
                value: state.adhocConfig.ssid,
                onChange: (e: any) => handleSSIDChange(e.target.value),
                placeholder: "Network Name",
                disabled: state.isLoading
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(TextField, {
                label: "Password",
                value: state.adhocConfig.password,
                onChange: (e: any) => handlePasswordChange(e.target.value),
                placeholder: "Minimum 8 characters",
                disabled: state.isLoading
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(ButtonItem, {
                layout: "below",
                onClick: handleRegenerateCredentials,
                disabled: state.isLoading
              }, state.isLoading ? "Generating..." : "Generate New Credentials")
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(ToggleField, {
                label: "Hidden SSID",
                description: "Hide the access point from WiFi scans",
                checked: state.adhocConfig.hidden,
                onChange: (checked: boolean) => {
                  setState(prev => ({ 
                    ...prev, 
                    adhocConfig: { ...prev.adhocConfig, hidden: checked }
                  }));
                },
                disabled: state.isLoading
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(DropdownItem, {
                label: "WiFi Band",
                menuLabel: "Select WiFi Band",
                selectedOption: bandOptions.find((opt: any) => opt.data === state.adhocConfig.band)?.data,
                rgOptions: bandOptions,
                onChange: (option: any) => {
                  console.log("NetDeck: Band dropdown onChange, selected:", option.data);
                  if (option.data !== state.adhocConfig.band) {
                    console.log("NetDeck: Setting new band:", option.data);
                    handleBandChange(option.data);
                  }
                }
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(DropdownItem, {
                label: "Channel",
                menuLabel: "Select Channel",
                selectedOption: getAvailableChannels().find((opt: any) => opt.data === state.adhocConfig.channel)?.data,
                rgOptions: getAvailableChannels(),
                onChange: (option: any) => {
                  console.log("NetDeck: Channel dropdown onChange, selected:", option.data);
                  if (option.data !== state.adhocConfig.channel) {
                    console.log("NetDeck: Setting new channel:", option.data);
                    handleChannelChange(option.data);
                  }
                }
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(TextField, {
                label: "Subnet",
                value: state.adhocConfig.subnet,
                onChange: (e: any) => setState(prev => ({ 
                  ...prev, 
                  adhocConfig: { ...prev.adhocConfig, subnet: e.target.value }
                })),
                placeholder: "192.168.5.0/24",
                disabled: state.isLoading
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(ButtonItem, {
                layout: "below",
                onClick: handleStartAdhocNetwork,
                disabled: state.isLoading || !state.adhocConfig.interface || !state.adhocConfig.ssid || state.adhocConfig.password.length < 8
              }, state.isLoading ? "Starting..." : "Start Hotspot")
            )
          )
        ) : (
          React.createElement("div", null,
            React.createElement(PanelSectionRow, null,
              React.createElement(Field, { 
                label: "Status",
                icon: React.createElement(FaWifi)
              },
                React.createElement("span", { style: { color: "#4ade80" } }, "Active")
              )
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(Field, { label: "Network Name" },
                React.createElement("span", null, state.networkStatus.adhoc_config.ssid)
              )
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(Field, { label: "Password" },
                React.createElement("span", { style: { fontFamily: "monospace" } }, state.networkStatus.adhoc_config.password)
              )
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(Field, { label: "Primary Interface" },
                React.createElement("span", null, state.networkStatus.adhoc_config.interface)
              )
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(Field, { label: "Hotspot Interface" },
                React.createElement("span", null, state.networkStatus.adhoc_config.ap_interface)
              )
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(Field, { label: "Subnet" },
                React.createElement("span", { style: { fontFamily: "monospace" } }, state.networkStatus.adhoc_config.subnet || "192.168.5.0/24")
              )
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(Field, { label: "Connected Clients" },
                React.createElement("span", { style: { color: "#4ade80" } }, state.connectedClients.length.toString())
              )
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(ToggleField, {
                label: "IP Forwarding",
                description: "Enable IP forwarding for internet access",
                checked: state.ipForwardingEnabled,
                onChange: handleIPForwardingToggle,
                disabled: state.isLoading
              })
            ),

            React.createElement(PanelSectionRow, null,
              React.createElement(ToggleField, {
                label: "NAT Auto-Enable",
                description: "Automatically enable NAT when hotspot starts",
                checked: state.natForwardingEnabled,
                onChange: handleNATForwardingToggle,
                disabled: state.isLoading
              })
            ),

            state.connectedClients.length > 0 ? (
              state.connectedClients.map((client, index) => (
                React.createElement(PanelSectionRow, { key: index },
                  React.createElement("div", { 
                    style: { 
                      padding: "8px", 
                      backgroundColor: "#1a1a1a", 
                      borderRadius: "4px",
                      marginBottom: "4px"
                    }
                  },
                    React.createElement("div", { 
                      style: { fontSize: "12px", color: "#4ade80" }
                    }, `${client.hostname || 'Unknown'}: ${client.ip}`),
                    React.createElement("div", { 
                      style: { fontSize: "10px", color: "#6b7280", fontFamily: "monospace" }
                    }, client.mac)
                  )
                )
              ))
            ) : null,

            React.createElement(PanelSectionRow, null,
              React.createElement(ButtonItem, {
                layout: "below",
                onClick: handleStopAdhocNetwork,
                disabled: state.isLoading
              }, state.isLoading ? "Stopping..." : "Stop Hotspot")
            )
          )
        )
      )
    ) : (
      // Show message when USB adapter is needed
      React.createElement(PanelSection, { title: "Hotspot Network" },
        React.createElement(PanelSectionRow, null,
          React.createElement("div", { 
            style: { 
              padding: "12px", 
              backgroundColor: "#1a1a1a", 
              borderRadius: "4px",
              border: "1px solid #333",
              textAlign: "center"
            }
          },
            React.createElement(FaWifi, { 
              style: { fontSize: "24px", color: "#6b7280", marginBottom: "8px" }
            }),
            React.createElement("div", { 
              style: { fontSize: "14px", color: "#d1d5db", marginBottom: "4px" }
            }, "USB WiFi Adapter Required"),
            React.createElement("div", { 
              style: { fontSize: "12px", color: "#6b7280" }
            }, "Connect a USB WiFi adapter to enable hotspot functionality")
          )
        )
      )
    ),

    // OTA Update Section (following PowerDeck patterns)
    React.createElement(PanelSection, { title: "Software Updates" },
      React.createElement(PanelSectionRow, null,
        React.createElement(ButtonItem, {
          onClick: handleUpdateAction,
          layout: "below",
          disabled: updateState === 'checking' || updateState === 'downloading' || updateState === 'installing'
        },
          updateState === 'checking' ? (
            React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
              React.createElement(FaSpinner, { style: { animation: 'spin 1s linear infinite' } }),
              "Checking for Updates..."
            )
          ) : updateState === 'available' ? (
            React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
              React.createElement(FaDownload),
              "Download Update"
            )
          ) : updateState === 'downloading' ? (
            React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
              React.createElement(FaSpinner, { style: { animation: 'spin 1s linear infinite' } }),
              "Downloading..."
            )
          ) : updateState === 'installing' ? (
            React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
              React.createElement(FaCog, { style: { animation: 'spin 1s linear infinite' } }),
              "Installing..."
            )
          ) : updateState === 'completed' ? (
            React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
              React.createElement(FaCheckCircle),
              "Update Complete!"
            )
          ) : updateState === 'error' ? (
            React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
              React.createElement(FaExclamationTriangle),
              "Retry Update"
            )
          ) : (
            React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
              React.createElement(FaSearch),
              "Check for Updates"
            )
          )
        )
      ),

      updateMessage ? (
        React.createElement(PanelSectionRow, null,
          React.createElement("div", { 
            style: { 
              fontSize: '0.85em', 
              color: updateState === 'error' ? '#ff6b6b' : updateState === 'completed' ? '#51cf66' : '#868e96',
              textAlign: 'center',
              marginTop: '8px',
              padding: '4px 8px',
              borderRadius: '4px',
              backgroundColor: 'rgba(255,255,255,0.05)'
            }
          }, updateMessage)
        )
      ) : null
    ),

    // Plugin Version Section
    React.createElement(PanelSection, null,
      React.createElement(PanelSectionRow, null,
        React.createElement("div", { 
          style: { 
            fontSize: '1.0em', 
            color: '#ccc', 
            textAlign: 'center',
            padding: '0 0 8px 0',
            marginTop: '-4px',
            display: 'flex',
            flexDirection: 'column',
            gap: '4px'
          }
        },
          React.createElement("div", { style: { fontWeight: '500' } },
            `NetDeck v${pluginVersion}`
          ),
          backgroundUpdateStatus ? (
            React.createElement("div", { 
              style: { 
                fontSize: '0.9em', 
                color: backgroundUpdateStatus.update_available ? '#ff6b35' : 
                       updateState === 'checking' ? '#4a9eff' : '#4a9eff',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '6px'
              }
            },
              updateState === 'checking' ? (
                React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
                  React.createElement(FaSpinner, { style: { animation: 'spin 1s linear infinite' } }),
                  "Checking for updates..."
                )
              ) : backgroundUpdateStatus.update_available ? (
                React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
                  React.createElement(FaBell),
                  `Update v${backgroundUpdateStatus.latest_version} available`
                )
              ) : (
                React.createElement("div", { style: { display: "flex", alignItems: "center", gap: "6px" } },
                  React.createElement(FaCheckCircle),
                  "Up to date"
                )
              )
            )
          ) : null,
          backgroundUpdateStatus && backgroundUpdateStatus.hours_since_last_check !== null && updateState !== 'checking' ? (
            React.createElement("div", { style: { 
              fontSize: '0.8em', 
              color: '#888', 
              marginTop: '2px',
              fontStyle: 'italic'
            } },
              `Last checked: ${Math.round(backgroundUpdateStatus.hours_since_last_check * 10) / 10}h ago`
            )
          ) : null
        )
      )
    )
  );
};

export default definePlugin((serverAPI: ServerAPI) => {
  return {
    name: "NetDeck",
    title: React.createElement("span", null, "NetDeck"),
    titleView: React.createElement("div", { 
      style: { display: "flex", alignItems: "center", gap: "8px" } 
    },
      React.createElement(FaNetworkWired),
      React.createElement("span", null, "NetDeck")
    ),
    content: React.createElement(NetDeck, { serverAPI: serverAPI }),
    icon: React.createElement(FaNetworkWired),
    onDismount: () => {
      console.log("NetDeck plugin unmounted");
    },
  };
});