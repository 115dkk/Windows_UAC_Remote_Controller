// SPDX-License-Identifier: GPL-2.0-or-later
// Phone-side presentation of a paired PC it cannot reach. Timing is display
// only: it never admits a request, extends a lease or starts a dial.
import { useEffect, useState } from 'react';
import type { AppSnapshot, PcConnectionView } from './contracts';

/** A reconnect normally finishes within about a second; past this, say what failed. */
export const RECONNECT_GRACE_MS = 60_000;
/** While the native owner reports a dial in flight, wait this long before failing. */
export const DIALING_GRACE_MS = 120_000;

export type PcConnectionFailure = 'refused' | 'no_answer' | 'unreachable';
export type PcConnectionPresentation =
  | { readonly kind: 'connecting' | 'reconnecting' }
  | { readonly kind: 'failed'; readonly failure: PcConnectionFailure; readonly externalRoute: boolean };

/** Used only to choose guidance while the native owner reports nothing; never shown as a state. */
const unknownConnection: PcConnectionView = { dialing: false, lastFailure: null, externalRoute: true };

export function pcConnectionPresentation(disconnectedMillis: number, everConnected: boolean,
  connection: PcConnectionView | null | undefined): PcConnectionPresentation {
  const view = connection ?? unknownConnection;
  const grace = view.dialing ? DIALING_GRACE_MS : RECONNECT_GRACE_MS;
  if (disconnectedMillis < grace) return { kind: everConnected ? 'reconnecting' : 'connecting' };
  return { kind: 'failed', failure: view.lastFailure ?? 'unreachable', externalRoute: view.externalRoute };
}

/** Only a ready catalogue with a paired PC and none connected is a known disconnection. */
export function knownDisconnected(snapshot: AppSnapshot): boolean {
  const catalog = snapshot.requestCatalog;
  return snapshot.platform === 'android' && catalog?.status === 'ready'
    && catalog.peerCount > 0 && catalog.connectedPeerCount === 0;
}

export interface PcConnectionClock {
  /** A PC was connected at some point in this app session. */
  readonly everConnected: boolean;
  /** Last observation with a connected PC, else the first disconnected one; null while connected or unknown. */
  readonly disconnectedSince: number | null;
  /** Display clock, never behind the latest observation. */
  readonly now: number;
}
export const initialConnectionClock: PcConnectionClock = { everConnected: false, disconnectedSince: null, now: 0 };

interface Observations {
  readonly observedAt: number;
  readonly source: AppSnapshot | null;
  readonly everConnected: boolean;
  readonly lastConnectedAt: number | null;
  readonly firstDisconnectedAt: number | null;
}
const noObservations: Observations = { observedAt: Number.NaN, source: null, everConnected: false, lastConnectedAt: null, firstDisconnectedAt: null };

export function nextObservations(value: Observations, snapshot: AppSnapshot, observedAt: number): Observations {
  if (value.source === snapshot && value.observedAt === observedAt) return value;
  const catalog = snapshot.requestCatalog;
  const next = { ...value, source: snapshot, observedAt };
  // Unknown or reconciling catalogues change nothing: they are not a disconnection.
  if (snapshot.platform !== 'android' || catalog?.status !== 'ready') return next;
  if (catalog.connectedPeerCount > 0) return { ...next, everConnected: true, lastConnectedAt: observedAt, firstDisconnectedAt: null };
  if (catalog.peerCount === 0) return { ...next, lastConnectedAt: null, firstDisconnectedAt: null };
  return { ...next, firstDisconnectedAt: value.firstDisconnectedAt ?? observedAt };
}

/**
 * Tracks, for this app session, when the phone last saw a connected PC.
 * `observedAt` is the controller's performance.now() at the snapshot's arrival.
 */
export function usePcConnectionClock(snapshot: AppSnapshot | null, observedAt: number, connection: PcConnectionView | null | undefined): PcConnectionClock {
  const [observations, setObservations] = useState<Observations>(noObservations);
  const current = snapshot ? nextObservations(observations, snapshot, observedAt) : observations;
  if (current !== observations) setObservations(current);
  const [tick, setTick] = useState(0);
  const disconnected = snapshot !== null && knownDisconnected(snapshot);
  const disconnectedSince = disconnected ? current.lastConnectedAt ?? current.firstDisconnectedAt : null;
  const now = Math.max(tick, observedAt);
  const grace = connection?.dialing ? DIALING_GRACE_MS : RECONNECT_GRACE_MS;
  const deadline = disconnectedSince === null ? null : disconnectedSince + grace;
  useEffect(() => {
    if (deadline === null || now >= deadline) return;
    // One wake-up at the boundary; each new observation reschedules it.
    const timer = window.setTimeout(() => { setTick(performance.now()); }, deadline - now + 1);
    return () => window.clearTimeout(timer);
  }, [deadline, now]);
  return { everConnected: current.everConnected, disconnectedSince, now };
}
