// SPDX-License-Identifier: GPL-2.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react';
import type { AppSnapshot, ControllerBridge, NotificationPolicy, ServiceAction } from './contracts';
import { ko } from './messages.ko';

export type ClientCommand =
  | { readonly kind: 'service'; readonly action: ServiceAction }
  | { readonly kind: 'pair' }
  | { readonly kind: 'remove'; readonly deviceId: string }
  | { readonly kind: 'clear' }
  | { readonly kind: 'decision'; readonly requestId: string; readonly decision: 'approve' | 'deny' }
  | { readonly kind: 'policy'; readonly policy: NotificationPolicy }
  | { readonly kind: 'lock-settings' };

interface ViewState {
  readonly owner: ControllerBridge;
  readonly snapshot: AppSnapshot | null;
  readonly refreshing: boolean;
  readonly busy: ClientCommand['kind'] | null;
  readonly stale: boolean;
  readonly error: string | null;
  readonly notice: string | null;
}

function emptyState(owner: ControllerBridge): ViewState {
  return { owner, snapshot: null, refreshing: true, busy: null, stale: false, error: null, notice: null };
}

async function readSnapshot(bridge: ControllerBridge): Promise<AppSnapshot> {
  let timer: number | undefined;
  try {
    return await Promise.race([
      bridge.snapshot(),
      new Promise<never>((_resolve, reject) => { timer = window.setTimeout(() => { reject(new Error('snapshot_timeout')); }, 15000); }),
    ]);
  } finally {
    window.clearTimeout(timer);
  }
}

// These are presentation gates only. Every command is checked again by its native owner.
function exposedBySnapshot(snapshot: AppSnapshot, command: ClientCommand): boolean {
  switch (command.kind) {
    case 'service': return snapshot.service?.allowedActions.includes(command.action) === true;
    case 'pair': return snapshot.canPair;
    case 'remove': return snapshot.dataAvailability.devices === 'available' && snapshot.canUnpair && snapshot.devices.some((device) => device.id === command.deviceId);
    case 'clear': return snapshot.dataAvailability.activity === 'available' && snapshot.canClearActivity;
    case 'decision': {
      const request = snapshot.requests.find((item) => item.id === command.requestId);
      return snapshot.dataAvailability.requests === 'available' && request?.state === 'pending'
        && (command.decision === 'approve' ? request.canApprove : request.canDeny);
    }
    case 'policy': return snapshot.platform === 'android';
    case 'lock-settings': return snapshot.mobile?.screenLock === 'missing' && snapshot.mobile.canOpenLockSettings;
  }
}

function dispatch(bridge: ControllerBridge, command: Exclude<ClientCommand, { kind: 'lock-settings' }>): Promise<AppSnapshot> {
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
      publish({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: announce && !snapshot.issue ? ko.updated : null });
    } catch {
      if (liveOwner.current !== bridge || attempt !== revision.current) return;
      publish({ ...previous, refreshing: false, busy: null, stale: previous.snapshot !== null, error: ko.loadFailure, notice: null });
    } finally {
      if (liveOwner.current === bridge && attempt === revision.current) readPending.current = false;
    }
  }, [bridge, publish]);

  const run = useCallback(async (command: ClientCommand): Promise<AppSnapshot | null> => {
    const previous = current.current;
    if (liveOwner.current !== bridge || commandPending.current || previous.owner !== bridge
      || previous.stale || !previous.snapshot || !exposedBySnapshot(previous.snapshot, command)) return null;
    commandPending.current = true;
    readPending.current = false;
    const attempt = ++revision.current; // A command supersedes an older snapshot request.
    publish({ ...previous, refreshing: false, busy: command.kind, error: null, notice: null });
    try {
      if (command.kind === 'lock-settings') {
        await bridge.openLockSettings();
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        publish({ ...previous, refreshing: false, busy: null, notice: ko.returnFromSettings });
        return null;
      }
      const snapshot = await dispatch(bridge, command);
      if (liveOwner.current !== bridge || attempt !== revision.current) return null;
      // Native cancellation and errors are AppIssue results, never local success.
      publish({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: null });
      return snapshot.issue ? null : snapshot;
    } catch {
      if (liveOwner.current !== bridge || attempt !== revision.current) return null;
      publish({ ...previous, refreshing: false, busy: null, stale: true, error: command.kind === 'policy' ? ko.saveFailure : ko.actionFailure, notice: null });
      return null;
    } finally {
      if (liveOwner.current === bridge && attempt === revision.current) commandPending.current = false;
    }
  }, [bridge, publish]);

  useEffect(() => {
    liveOwner.current = bridge;
    readPending.current = false;
    commandPending.current = false;
    // Defer the initial presentation update; the first render already is loading.
    void Promise.resolve().then(() => refresh());
    const onForeground = () => {
      if (document.visibilityState === 'visible') void refresh();
    };
    window.addEventListener('focus', onForeground);
    document.addEventListener('visibilitychange', onForeground);
    const timer = window.setInterval(onForeground, 5000);
    return () => {
      liveOwner.current = null;
      revision.current += 1;
      window.clearInterval(timer);
      window.removeEventListener('focus', onForeground);
      document.removeEventListener('visibilitychange', onForeground);
    };
  }, [bridge, refresh]);

  return { ...(state.owner === bridge ? state : emptyState(bridge)), refresh, run };
}
