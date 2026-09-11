// SPDX-License-Identifier: GPL-2.0-or-later
import { addPluginListener, invoke, isTauri } from '@tauri-apps/api/core';
import type { AppSnapshot, ControllerBridge, RequestDetailsView } from './contracts';

function native<T>(command: string, args?: Record<string, unknown>): Promise<T> {
  if (!isTauri()) {
    return Promise.reject(new Error('PC 또는 휴대폰 앱에서 열어 주세요.'));
  }
  return invoke<T>(command, args);
}

export const controllerBridge: ControllerBridge = {
  snapshot: () => native<AppSnapshot>('app_snapshot'),
  savePolicy: (policy) => native<AppSnapshot>('save_notification_policy', { policyJson: JSON.stringify(policy) }),
  controlService: (action) => native<AppSnapshot>('control_service', { action }),
  beginPairing: () => native<AppSnapshot>('begin_pairing'),
  removeDevice: (deviceId) => native<AppSnapshot>('remove_device', { deviceId }),
  decide: (requestId, decision) => native<AppSnapshot>('decide_request', { requestId, decision }),
  requestDetails: (requestId) => native<RequestDetailsView>('request_details', { requestId }),
  watchRequests: async (notify) => {
    if (!isTauri()) return () => Promise.resolve();
    const listener = await addPluginListener('device-state', 'request-review', () => { notify(); });
    return () => listener.unregister();
  },
  clearActivity: () => native<AppSnapshot>('clear_activity'),
  openLockSettings: () => native<void>('open_lock_settings'),
  openNotificationSettings: () => native<void>('open_notification_settings'),
  openPairingScanner: () => native<void>('open_pairing_scanner'),
};
