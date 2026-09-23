// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot, RelayStatus } from './contracts';

export type InternetState = NonNullable<RelayStatus['internetState']>;

/** Presentation only: never infer a WAN route from readiness or a connected LAN peer. */
export function directConnectionState(snapshot: AppSnapshot, stale = false): InternetState {
  const relay = snapshot.relayStatus;
  if (stale || snapshot.platform !== 'windows' || relay?.mode !== 'embedded' || relay.state === 'unknown') return 'unknown';
  if (snapshot.service?.state === 'stopped' || relay.state === 'stopped') return 'stopped';
  if (!hasLiveEmbeddedListener(snapshot)) return 'unknown';
  return relay.internetState ?? 'unknown';
}

export function hasLiveEmbeddedListener(snapshot: AppSnapshot): boolean {
  return snapshot.platform === 'windows' && snapshot.service?.installed === true
    && snapshot.service.state === 'running' && snapshot.service.controlHint === 'available'
    && snapshot.dataAvailability.devices === 'available'
    && snapshot.relayStatus?.mode === 'embedded' && snapshot.relayStatus.state === 'listening';
}

/** Paired phones are known and none of them is connected right now. */
export function pairedPhonesDisconnected(snapshot: AppSnapshot): boolean {
  return snapshot.dataAvailability.devices === 'available' && snapshot.devices.length > 0
    && !snapshot.devices.some((device) => device.connected);
}
