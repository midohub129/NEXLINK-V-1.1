import type { DeviceRole } from './device';

export interface AppSettings {
  role: DeviceRole | null;
  selectedNotificationApps: string[];
  connectionServiceEnabled: boolean;
  notificationAccessGranted: boolean;
  usageAccessGranted: boolean;
  sessionTimeoutMinutes: number;
  syncIntervalMs: number;
  maxSyncRetries: number;
  relayEndpoint: string;
  testFixtureModeEnabled: boolean;
}

export const DEFAULT_APP_SETTINGS: AppSettings = {
  role: null,
  selectedNotificationApps: [],
  connectionServiceEnabled: false,
  notificationAccessGranted: false,
  usageAccessGranted: false,
  sessionTimeoutMinutes: 30,
  syncIntervalMs: 10000,
  maxSyncRetries: 5,
  relayEndpoint: '/api/relay',
  testFixtureModeEnabled: false,
};
