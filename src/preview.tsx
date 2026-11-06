// Browser preview entry: renders the real plugin UI against a mocked
// serverAPI so UI/UX can be tested without deploying to a Steam Deck.
import React from 'react';
import { createRoot } from 'react-dom/client';
import pluginFactory from './index';

// Stateful mock backend mirroring the real plugin method surface.
const mockState = {
  hotspotActive: true,
  ipForwarding: true,
  natForwarding: true,
  band: '2.4GHz',
  channel: 6,
  ssid: 'NetDeck-Hotspot',
  password: 'deckpass123',
  hidden: false,
  apInterface: 'wlan1',
  subnet: '192.168.5.0/24',
  selectedInterface: 'wlan0',
  newMacAddress: '',
  // Recorded backend calls for self-test assertions.
  callLog: [] as { method: string; args: Record<string, any> }[]
};

const networkStatus = () => ({
  connectivity: true,
  interfaces: {
    wlan0: {
      state: 'connected',
      current_mac: 'a2:1b:6c:44:9e:10',
      original_mac: '48:8f:5a:12:34:56',
      mac_spoofed: true
    },
    wlan1: {
      state: 'disconnected',
      current_mac: '00:e0:4c:aa:bb:cc',
      original_mac: '00:e0:4c:aa:bb:cc',
      mac_spoofed: false
    }
  },
  adhoc_active: mockState.hotspotActive,
  adhoc_config: {
    enabled: mockState.hotspotActive,
    ssid: mockState.ssid,
    password: mockState.password,
    channel: mockState.channel,
    interface: 'wlan0',
    ap_interface: mockState.apInterface,
    subnet: mockState.subnet,
    band: mockState.band,
    hidden: mockState.hidden
  },
  bridge_active: mockState.natForwarding,
  connected_clients: [
    { ip: '192.168.5.101', mac: 'd8:3a:dd:11:22:33', hostname: 'pixel-phone' },
    { ip: '192.168.5.102', mac: 'ac:de:48:00:11:22', hostname: 'laptop' }
  ]
});

async function callPluginMethod(method: string, args: Record<string, any> = {}): Promise<any> {
  mockState.callLog.push({ method, args });
  await new Promise((r) => setTimeout(r, 120)); // simulate IPC latency
  console.log('[mock serverAPI]', method, args);
  switch (method) {
    case 'get_network_status':
      return { success: true, result: networkStatus() };
    case 'get_connected_clients':
      return { success: true, result: networkStatus().connected_clients };
    case 'get_band_preference':
      return { success: true, result: { band: mockState.band } };
    case 'set_band_preference':
      mockState.band = args.band;
      return { success: true, result: {} };
    case 'get_channel_preference':
      return { success: true, result: { channel: mockState.channel } };
    case 'set_channel_preference':
      mockState.channel = args.channel;
      return { success: true, result: {} };
    case 'get_supported_channels':
      return {
        success: true,
        result: {
          '2.4GHz': [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11].map((ch) => ({ channel: ch })),
          '5GHz': [36, 40, 44, 48, 149, 153, 157, 161].map((ch) => ({ channel: ch }))
        }
      };
    case 'get_current_credentials':
      return { success: true, result: { ssid: mockState.ssid, password: mockState.password } };
    case 'regenerate_secure_credentials': {
      mockState.ssid = 'NetDeck-' + Math.random().toString(36).slice(2, 7);
      mockState.password = Math.random().toString(36).slice(2, 12);
      return { success: true, result: { ssid: mockState.ssid, password: mockState.password } };
    }
    case 'get_adhoc_config_preference':
    case 'set_adhoc_config_preference':
      if (method.startsWith('set_')) Object.assign(mockState, args);
      return {
        success: true,
        result: {
          ssid: mockState.ssid,
          password: mockState.password,
          channel: mockState.channel,
          interface: 'wlan0',
          subnet: mockState.subnet,
          hidden: mockState.hidden
        }
      };
    case 'get_interface_preferences':
      return { success: true, result: { selected_interface: mockState.selectedInterface } };
    case 'set_interface_preferences':
      if (args.selected_interface) mockState.selectedInterface = args.selected_interface;
      if (args.adhoc_interface) mockState.selectedInterface = args.adhoc_interface;
      return { success: true, result: {} };
    case 'get_ip_forwarding_status':
      return { success: true, result: { enabled: mockState.ipForwarding } };
    case 'toggle_ip_forwarding':
      mockState.ipForwarding = !!args.enable;
      return { success: true, result: { enabled: mockState.ipForwarding } };
    case 'get_nat_forwarding_preference':
      return { success: true, result: { enabled: mockState.natForwarding } };
    case 'set_nat_forwarding_preference':
      mockState.natForwarding = !!args.enabled;
      return { success: true, result: {} };
    case 'set_mac_address':
      return { success: true, result: { mac: args.mac ?? args.new_mac } };
    case 'restore_original_mac':
      return { success: true, result: {} };
    case 'start_adhoc_network':
      mockState.hotspotActive = true;
      return { success: true, result: {} };
    case 'stop_adhoc_network':
      mockState.hotspotActive = false;
      return { success: true, result: {} };
    case 'get_current_version':
      return { success: true, result: '1.0.30' };
    case 'check_for_updates':
      return { success: true, result: { update_available: false, current_version: '1.0.30', latest_version: '1.0.30' } };
    case 'get_update_status':
      return { success: true, result: { update_available: false, current_version: '1.0.30', latest_version: '1.0.30' } };
    case 'download_and_install_update':
      return { success: true, result: {} };
    default:
      console.warn('[mock serverAPI] unhandled method:', method, args);
      return { success: true, result: {} };
  }
}

const serverAPI = { callPluginMethod };
// Exposed for the self-test page to drive backend state.
(window as any).__netdeckMock = mockState;

const plugin = (pluginFactory as any)(serverAPI);
const root = createRoot(document.getElementById('root')!);
root.render(
  React.createElement(
    'div',
    { className: 'netdeck-preview' },
    React.createElement('h1', { className: 'preview-banner' }, 'NetDeck UI Preview (mocked backend)'),
    plugin.content
  )
);
