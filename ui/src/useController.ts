// SPDX-License-Identifier: GPL-2.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react';
import type { AppSnapshot, ControllerBridge, NotificationPolicy, ServiceAction } from './contracts';
import { ko } from './messages.ko';
import { ageRequestPresentation, withoutRequestBodies } from './requestPresentation';

export type ClientCommand =
  | { readonly kind: 'service'; readonly action: ServiceAction }
  | { readonly kind: 'pair' }
  | { readonly kind: 'remove'; readonly deviceId: string }
  | { readonly kind: 'clear' }
  | { readonly kind: 'decision'; readonly requestId: string; readonly decision: 'approve' | 'deny' }
  | { readonly kind: 'policy'; readonly policy: NotificationPolicy }
  | { readonly kind: 'lock-settings' }
  | { readonly kind: 'notification-settings' };

interface ViewState {
  readonly owner: ControllerBridge;
  readonly snapshot: AppSnapshot | null;
  readonly refreshing: boolean;
  readonly busy: ClientCommand['kind'] | null;
  readonly stale: boolean;
  readonly error: string | null;
  readonly notice: string | null;
  readonly requestObservedAt: number;
}

function emptyState(owner: ControllerBridge): ViewState {
  return { owner, snapshot: null, refreshing: true, busy: null, stale: false, error: null, notice: null, requestObservedAt: 0 };
}

async function readSnapshot(bridge: ControllerBridge): Promise<AppSnapshot> {
  const started = performance.now();
  let timer: number | undefined;
  try {
    const snapshot = await Promise.race([
      bridge.snapshot(),
      new Promise<never>((_resolve, reject) => { timer = window.setTimeout(() => { reject(new Error('snapshot_timeout')); }, 15000); }),
    ]);
    return ageRequestPresentation(snapshot, performance.now() - started);
  } finally {
    window.clearTimeout(timer);
  }
}

// These are presentation gates only. Every command is checked again by its native owner.
function exposedBySnapshot(snapshot: AppSnapshot, command: ClientCommand): boolean {
  switch (command.kind) {
    case 'service': return snapshot.platform === 'android'
      ? (command.action === 'start' && snapshot.phoneService?.canStart === true)
        || (command.action === 'stop' && snapshot.phoneService?.canStop === true)
      : snapshot.service?.allowedActions.includes(command.action) === true;
    case 'pair': return snapshot.canPair;
    case 'remove': return snapshot.dataAvailability.devices === 'available' && snapshot.canUnpair && snapshot.devices.some((device) => device.id === command.deviceId);
    case 'clear': return snapshot.dataAvailability.activity === 'available' && snapshot.canClearActivity;
    case 'decision': {
      const request = snapshot.requests.find((item) => item.id === command.requestId);
      return snapshot.dataAvailability.requests === 'available' && request !== undefined
        && (command.decision === 'approve' ? request.state === 'pending' && request.canApprove : request.canDeny);
    }
    case 'policy': return snapshot.platform === 'android' && snapshot.policy !== null && snapshot.phoneService?.policyOwnerReady === true;
    case 'lock-settings': return snapshot.mobile?.screenLock === 'missing' && snapshot.mobile.canOpenLockSettings;
    case 'notification-settings': return snapshot.platform === 'android' && snapshot.mobile?.notifications === 'denied' && snapshot.mobile.canOpenNotificationSettings;
  }
}

function dispatch(bridge: ControllerBridge, command: Exclude<ClientCommand, { kind: 'lock-settings' | 'notification-settings' }>): Promise<AppSnapshot> {
  switch (command.kind) {
    case 'service': return bridge.controlService(command.action);
    case 'pair': return bridge.beginPairing();
    case 'remove': return bridge.removeDevice(command.deviceId);
    case 'clear': return bridge.clearActivity();
    case 'decision': return bridge.decide(command.requestId, command.decision);
    case 'policy': return bridge.savePolicy(command.policy);
  }
}

export function useController(bridge: ControllerBridge) {
  const [state, setState] = useState<ViewState>(() => emptyState(bridge));
  const current = useRef<ViewState>(state);
  const revision = useRef(0);
  const liveOwner = useRef<ControllerBridge | null>(null);
  const readPending = useRef(false);
  const commandPending = useRef(false);

  const publish = useCallback((next: ViewState) => {
    current.current = next;
    setState(next);
  }, []);

  const refresh = useCallback(async (announce = false) => {
    if (liveOwner.current !== bridge || commandPending.current || readPending.current) return;
    readPending.current = true;
    const attempt = ++revision.current;
    const previous = current.current.owner === bridge ? current.current : emptyState(bridge);
    publish({ ...previous, refreshing: true, notice: null });
    try {
      const snapshot = await readSnapshot(bridge);
      if (liveOwner.current !== bridge || attempt !== revision.current) return;
      publish({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: announce && !snapshot.issue ? ko.updated : null, requestObservedAt: performance.now() });
    } catch {
      if (liveOwner.current !== bridge || attempt !== revision.current) return;
      const latest = current.current;
      publish({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null, refreshing: false, busy: null, stale: latest.snapshot !== null, error: ko.loadFailure, notice: null });
    } finally {
      if (liveOwner.current === bridge && attempt === revision.current) readPending.current = false;
    }
  }, [bridge, publish]);

  const run = useCallback(async (command: ClientCommand): Promise<AppSnapshot | null> => {
    const previous = current.current;
    if (liveOwner.current !== bridge || commandPending.current || previous.owner !== bridge
      || previous.stale || !previous.snapshot || !exposedBySnapshot(previous.snapshot, command)) return null;
    if (command.kind === 'decision' && previous.snapshot.requests.some((request) => request.id === command.requestId
      && performance.now() - previous.requestObservedAt >= request.refreshAfterMillis)) {
      publish({ ...previous, snapshot: withoutRequestBodies(previous.snapshot) });
      void refresh();
      return null;
    }
    commandPending.current = true;
    readPending.current = false;
    const attempt = ++revision.current; // A command supersedes an older snapshot request.
    publish({ ...previous, refreshing: false, busy: command.kind, error: null, notice: null });
    try {
      if (command.kind === 'lock-settings' || command.kind === 'notification-settings') {
        if (command.kind === 'lock-settings') await bridge.openLockSettings();
        else await bridge.openNotificationSettings();
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        publish({ ...previous, refreshing: false, busy: null, notice: ko.returnFromSettings });
        return null;
      }
      const started = performance.now();
      const snapshot = ageRequestPresentation(await dispatch(bridge, command), performance.now() - started);
      if (liveOwner.current !== bridge || attempt !== revision.current) return null;
      // Native cancellation and errors are AppIssue results, never local success.
      publish({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: null, requestObservedAt: performance.now() });
      return snapshot.issue ? null : snapshot;
    } catch {
      if (liveOwner.current !== bridge || attempt !== revision.current) return null;
      const latest = current.current;
      publish({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null, refreshing: false, busy: null, stale: true, error: command.kind === 'policy' ? ko.saveFailure : ko.actionFailure, notice: null });
      return null;
    } finally {
      if (liveOwner.current === bridge && attempt === revision.current) commandPending.current = false;
    }
  }, [bridge, publish, refresh]);

  useEffect(() => {
    const snapshot = state.snapshot;
    if (!snapshot?.requests.length || state.owner !== bridge) return;
    const delay = Math.max(0, Math.min(...snapshot.requests.map((request) => request.refreshAfterMillis))
      - (performance.now() - state.requestObservedAt));
    const timer = window.setTimeout(() => {
      if (liveOwner.current !== bridge || current.current.snapshot !== snapshot) return;
      publish({ ...current.current, snapshot: withoutRequestBodies(snapshot) });
      if (document.visibilityState === 'visible') void refresh();
    }, delay);
    return () => window.clearTimeout(timer);
  }, [bridge, publish, refresh, state.owner, state.requestObservedAt, state.snapshot]);

  useEffect(() => {
    liveOwner.current = bridge;
    readPending.current = false;
    commandPending.current = false;
    // Defer the initial presentation update; the first render already is loading.
    void Promise.resolve().then(() => refresh());
    const onForeground = () => {
      if (document.visibilityState === 'visible') void refresh();
      else if (current.current.snapshot) publish({ ...current.current, snapshot: withoutRequestBodies(current.current.snapshot) });
    };
    let disposed = false;
    let unsubscribe: (() => Promise<void>) | undefined;
    void bridge.watchRequests?.(onForeground).then((stop) => {
      if (disposed) void stop().catch(() => undefined);
      else unsubscribe = stop;
    }).catch(() => undefined); // Sticky native review + periodic read still work.
    window.addEventListener('focus', onForeground);
    document.addEventListener('visibilitychange', onForeground);
    const timer = window.setInterval(onForeground, 5000);
    return () => {
      disposed = true;
      void unsubscribe?.().catch(() => undefined);
      liveOwner.current = null;
      revision.current += 1;
      window.clearInterval(timer);
      window.removeEventListener('focus', onForeground);
      document.removeEventListener('visibilitychange', onForeground);
    };
  }, [bridge, publish, refresh]);

  return { ...(state.owner === bridge ? state : emptyState(bridge)), refresh, run };
}
