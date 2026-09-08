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
export interface MobileReadiness {
  readonly screenLock: 'configured' | 'missing' | 'unavailable';
  readonly notifications: 'allowed' | 'denied' | 'unavailable';
  readonly canOpenLockSettings: boolean;
}
export interface PairedDeviceView {
  readonly id: string;
  readonly name: string;
  readonly connected: boolean;
  readonly lastSeenLabel: string | null;
}
export interface RequestView {
  readonly id: string;
  readonly computerName: string;
  readonly programName: string;
  readonly executablePath: string;
  readonly details: string;
  readonly remainingSeconds: number;
  readonly state: 'pending' | 'authenticating' | 'sending' | 'expired';
  readonly canApprove: boolean;
  readonly canDeny: boolean;
}
export interface ActivityView {
  readonly id: string;
  readonly timestampMillis: number;
  readonly kind: 'connected' | 'disconnected' | 'service_started' | 'service_stopped'
    | 'expired' | 'cancelled' | 'approved' | 'denied' | 'failure';
}
export interface AppIssue { readonly code: string; readonly message: string; readonly nextAction: string | null }
export interface AppSnapshot {
  readonly schemaVersion: 1;
  readonly platform: Platform;
  readonly computerName: string;
  readonly service: ServiceView | null;
  readonly mobile: MobileReadiness | null;
  readonly policy: NotificationPolicy;
  readonly devices: readonly PairedDeviceView[];
  readonly requests: readonly RequestView[];
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
  decide(requestId: string, decision: 'approve' | 'deny'): Promise<AppSnapshot>;
  clearActivity(): Promise<AppSnapshot>;
  openLockSettings(): Promise<void>;
}
