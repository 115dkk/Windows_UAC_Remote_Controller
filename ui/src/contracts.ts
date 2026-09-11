// SPDX-License-Identifier: GPL-2.0-or-later
// Read-only presentation contracts. The Rust/native owners decide authorization.

export type Platform = 'windows' | 'android' | 'unsupported';
export type AlertMode = 'sound' | 'vibrate_only' | 'silent';
export interface TimeWindow {
  readonly days: number;
  readonly start_minute: number;
  readonly end_minute: number;
}
export type Schedule = { readonly mode: 'always' } | { readonly mode: 'never' }
  | { readonly mode: 'weekly'; readonly windows: readonly TimeWindow[] };
export interface NotificationPolicy { readonly schedule: Schedule; readonly alert: AlertMode }
export type ServiceState = 'stopped' | 'start_pending' | 'stop_pending' | 'running'
  | 'continue_pending' | 'pause_pending' | 'paused';
export type ServiceAction = 'install' | 'start' | 'stop' | 'restart' | 'uninstall';
export interface ServiceView {
  readonly installed: boolean;
  readonly state: ServiceState | null;
  readonly allowedActions: readonly ServiceAction[];
  readonly controlHint: 'needs_installer' | 'available' | 'unsupported';
  readonly remoteRequestsReady: boolean;
}
export interface PhoneServiceView {
  readonly state: 'stopped' | 'preparing' | 'waiting_for_unlock' | 'local_settings_ready' | 'cleanup_pending' | 'unavailable';
  readonly bootEnabled: boolean | null;
  readonly canStart: boolean;
  readonly canStop: boolean;
  readonly policyOwnerReady: boolean;
}
export interface MobileReadiness {
  readonly screenLock: 'configured' | 'missing' | 'unavailable';
  readonly notifications: 'allowed' | 'denied' | 'unavailable';
  readonly canOpenLockSettings: boolean;
  readonly canOpenNotificationSettings: boolean;
  /** Native camera-input entry only, not pairing or an already-granted permission. */
  readonly canOpenPairingScanner: boolean;
}
export interface PairedDeviceView {
  readonly id: string;
  readonly name: string;
  readonly revision: number;
  readonly connected: boolean;
  readonly routePresent: boolean;
  readonly lastSeenLabel: string | null;
}
export interface RequestView {
  readonly id: string;
  readonly computerName: string;
  readonly programName: string;
  readonly executablePath: string;
  readonly programElided: boolean;
  readonly pathElided: boolean;
  readonly hasDetails: boolean;
  readonly remainingSeconds: number;
  readonly refreshAfterMillis: number;
  readonly state: 'pending' | 'authenticating' | 'waiting' | 'sending' | 'awaiting_outcome' | 'unavailable' | 'expired';
  readonly canApprove: boolean;
  readonly canDeny: boolean;
}
export interface RequestDetailsView {
  readonly version: 1;
  readonly id: string;
  readonly programName: string;
  readonly executablePath: string;
  readonly details: string;
  readonly remainingSeconds: number;
  readonly refreshAfterMillis: number;
}
export interface ActivityView {
  readonly id: string;
  readonly timestampMillis: number;
  readonly kind: 'connected' | 'disconnected' | 'service_started' | 'service_stopped'
    | 'expired' | 'cancelled' | 'approved' | 'denied' | 'failure' | 'pc_completed';
}
export interface AppIssue { readonly code: string; readonly message: string; readonly nextAction: string | null }
export interface PairingView {
  readonly phase: 'connecting' | 'waiting_for_admin' | 'helper_running' | 'finished' | 'failed';
  readonly message: string;
  readonly failure: null | 'service_not_ready' | 'user_cancelled' | 'helper_failed' | 'timeout' | 'relay_unconfigured' | 'unavailable';
}
export interface AppSnapshot {
  readonly schemaVersion: 4;
  readonly pairing: PairingView | null;
  readonly platform: Platform;
  readonly computerName: string;
  readonly service: ServiceView | null;
  readonly phoneService: PhoneServiceView | null;
  readonly mobile: MobileReadiness | null;
  readonly policy: NotificationPolicy | null;
  readonly devices: readonly PairedDeviceView[];
  readonly relayConfigured: boolean;
  readonly requests: readonly RequestView[];
  readonly requestCatalog: { readonly status: 'unavailable' | 'reconciling' | 'ready'; readonly revision: string; readonly peerCount: number; readonly connectedPeerCount: number } | null;
  readonly requestReview: { readonly locator: string; readonly revision: string } | null;
  readonly activity: readonly ActivityView[];
  readonly dataAvailability: {
    readonly devices: 'available' | 'unavailable';
    readonly requests: 'available' | 'unavailable';
    readonly activity: 'available' | 'unavailable';
  };
  readonly canPair: boolean;
  readonly canUnpair: boolean;
  readonly canClearActivity: boolean;
  readonly issue: AppIssue | null;
}
export interface ControllerBridge {
  snapshot(): Promise<AppSnapshot>;
  savePolicy(policy: NotificationPolicy): Promise<AppSnapshot>;
  controlService(action: ServiceAction): Promise<AppSnapshot>;
  beginPairing(): Promise<AppSnapshot>;
  removeDevice(deviceId: string): Promise<AppSnapshot>;
  setRelay(address: string): Promise<AppSnapshot>;
  decide(requestId: string, decision: 'approve' | 'deny'): Promise<AppSnapshot>;
  requestDetails(requestId: string): Promise<RequestDetailsView>;
  watchRequests?(notify: () => void): Promise<() => Promise<void>>;
  clearActivity(): Promise<AppSnapshot>;
  openLockSettings(): Promise<void>;
  openNotificationSettings(): Promise<void>;
  openPairingScanner(): Promise<void>;
}
