// SPDX-License-Identifier: GPL-2.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react';
import type { AppSnapshot, ControllerBridge, NotificationPolicy, ServiceAction } from './contracts';
import { ko } from './messages.ko';
import { ageRequestPresentation, withoutRequestBodies } from './requestPresentation';

export type ClientCommand =
  | { readonly kind: 'service'; readonly action: ServiceAction }
  | { readonly kind: 'pair'; readonly transport?: 'usb' }
  | { readonly kind: 'remove'; readonly deviceId: string }
  | { readonly kind: 'relay'; readonly address: string }
  | { readonly kind: 'clear' }
  | { readonly kind: 'diagnostics-folder' }
  | { readonly kind: 'decision'; readonly requestId: string; readonly decision: 'approve' | 'deny' }
  | { readonly kind: 'policy'; readonly policy: NotificationPolicy }
  | { readonly kind: 'lock-settings' }
  | { readonly kind: 'notification-settings' }
  | { readonly kind: 'scan_pairing'; readonly transport?: 'usb' };

/** How long before a request's display lease ends to ask for the next one. The
 * lease is clipped to the end of the wall minute, so this has to be a fraction
 * of the shortest one that clip can produce while still covering a native read
 * on a real device. */
const REQUEST_REFRESH_LEAD_MILLIS = 1200;

interface ViewState {
  readonly owner: ControllerBridge;
  readonly snapshot: AppSnapshot | null;
  readonly refreshing: boolean;
  readonly busy: ClientCommand['kind'] | null;
  readonly stale: boolean;
  readonly error: string | null;
  readonly notice: string | null;
  readonly requestObservedAt: number;
  readonly scannerFocusRevision: number;
}

function emptyState(owner: ControllerBridge): ViewState {
  return { owner, snapshot: null, refreshing: true, busy: null, stale: false, error: null, notice: null, requestObservedAt: 0, scannerFocusRevision: 0 };
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
    case 'relay': return snapshot.platform === 'windows' && snapshot.service?.controlHint === 'available'
      && command.address.trim().length > 0
      && ((snapshot.service.installed === false && snapshot.service.state === null)
        || snapshot.service.state === 'stopped'
        || (snapshot.service.state === 'running' && snapshot.dataAvailability.devices === 'available'));
    case 'clear': return snapshot.dataAvailability.activity === 'available' && snapshot.canClearActivity;
    case 'diagnostics-folder': return snapshot.platform === 'windows';
    case 'decision': {
      const request = snapshot.requests.find((item) => item.id === command.requestId);
      return snapshot.dataAvailability.requests === 'available' && request !== undefined
        && (command.decision === 'approve' ? request.state === 'pending' && request.canApprove : request.canDeny);
    }
    case 'policy': return snapshot.platform === 'android' && snapshot.policy !== null && snapshot.phoneService?.policyOwnerReady === true;
    case 'lock-settings': return snapshot.mobile?.screenLock === 'missing' && snapshot.mobile.canOpenLockSettings;
    case 'notification-settings': return snapshot.platform === 'android' && snapshot.mobile?.notifications === 'denied' && snapshot.mobile.canOpenNotificationSettings;
    case 'scan_pairing': return snapshot.platform === 'android' && snapshot.mobile?.canOpenPairingScanner === true;
  }
}

function dispatch(bridge: ControllerBridge, command: Exclude<ClientCommand, { kind: 'lock-settings' | 'notification-settings' | 'scan_pairing' | 'diagnostics-folder' }>): Promise<AppSnapshot> {
  switch (command.kind) {
    case 'service': return bridge.controlService(command.action);
    case 'pair': return command.transport === 'usb' ? bridge.beginPairing('usb') : bridge.beginPairing();
    case 'remove': return bridge.removeDevice(command.deviceId);
    case 'relay': return bridge.setRelay(command.address);
    case 'clear': return bridge.clearActivity();
    case 'decision': return bridge.decide(command.requestId, command.decision);
    case 'policy': return bridge.savePolicy(command.policy);
  }
}

function scannerFailure(error: unknown, transport?: 'usb'): string {
  const code = error !== null && typeof error === 'object' && 'code' in error ? error.code : null;
  return code === 'pairing_scanner_busy' || code === 'app_busy' ? ko.pairingScannerBusy
    : transport === 'usb' ? 'USB 연결을 사용할 수 없습니다. USB 드라이버와 케이블을 확인하거나 QR 코드로 연결하십시오.'
      : ko.pairingScannerFailure;
}

export function useController(bridge: ControllerBridge) {
  const [state, setState] = useState<ViewState>(() => emptyState(bridge));
  const current = useRef<ViewState>(state);
  const revision = useRef(0);
  const liveOwner = useRef<ControllerBridge | null>(null);
  const readPending = useRef(false);
  const activeRead = useRef<{ owner: ControllerBridge; promise: Promise<AppSnapshot> } | null>(null);
  const commandPending = useRef(false);
  const scannerReturn = useRef({ pending: false, opened: false, wake: false });
  const scannerFocusRevision = useRef(0);
  const dismissScannerReturnFocus = useCallback(() => {
    scannerReturn.current = { pending: false, opened: false, wake: false };
  }, []);

  const scannerReturnRevision = useCallback((snapshot: AppSnapshot) => {
    const flow = scannerReturn.current;
    if (flow.pending && flow.opened && flow.wake && snapshot.platform === 'android'
      && snapshot.mobile?.canOpenPairingScanner === true) {
      scannerReturn.current = { pending: false, opened: false, wake: false };
      scannerFocusRevision.current += 1;
    }
    return scannerFocusRevision.current;
  }, []);

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
    const read = { owner: bridge, promise: readSnapshot(bridge) };
    activeRead.current = read;
    try {
      const snapshot = await read.promise;
      if (liveOwner.current !== bridge || attempt !== revision.current) return;
      publish({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: announce && !snapshot.issue ? ko.updated : null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(snapshot) });
    } catch {
      if (liveOwner.current !== bridge || attempt !== revision.current) return;
      const latest = current.current;
      publish({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null, refreshing: false, busy: null, stale: latest.snapshot !== null, error: ko.loadFailure, notice: null });
    } finally {
      if (activeRead.current === read) activeRead.current = null;
      if (liveOwner.current === bridge && attempt === revision.current) readPending.current = false;
    }
  }, [bridge, publish, scannerReturnRevision]);

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
    // A renderer revision cannot cancel the native read's admission lease.
    // Serialize this camera-entry intent behind that exact read, then recheck
    // its fresh capability. Never queue approval/denial or a generic command.
    const scannerRead = command.kind === 'scan_pairing' && activeRead.current?.owner === bridge ? activeRead.current : null;
    const folderRead = command.kind === 'diagnostics-folder' && activeRead.current?.owner === bridge ? activeRead.current : null;
    commandPending.current = true;
    if (command.kind === 'scan_pairing') scannerReturn.current = { pending: true, opened: false, wake: false };
    else dismissScannerReturnFocus(); // A new explicit task supersedes old modal-return focus.
    readPending.current = false;
    const attempt = ++revision.current; // A command supersedes an older snapshot request.
    publish({ ...previous, refreshing: false, busy: command.kind, error: null, notice: null });
    let scannerOpened = false;
    try {
      if (scannerRead) {
        let snapshot: AppSnapshot;
        try { snapshot = await scannerRead.promise; }
        catch {
          if (liveOwner.current !== bridge || attempt !== revision.current) return null;
          scannerReturn.current = { pending: false, opened: false, wake: false };
          const latest = current.current;
          publish({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null,
            refreshing: false, busy: null, stale: true, error: ko.loadFailure, notice: null });
          return null;
        }
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        const visible = document.visibilityState === 'visible';
        const mayOpen = scannerReturn.current.pending && visible
          && exposedBySnapshot(snapshot, command);
        publish({ ...current.current, snapshot: visible ? snapshot : withoutRequestBodies(snapshot), refreshing: false, busy: mayOpen ? 'scan_pairing' : null,
          stale: false, error: null, notice: null, requestObservedAt: performance.now() });
        if (!mayOpen) {
          scannerReturn.current = { pending: false, opened: false, wake: false };
          return null;
        }
      }
      if (command.kind === 'scan_pairing') {
        if (command.transport === 'usb') await bridge.openPairingScanner('usb');
        else await bridge.openPairingScanner();
        scannerOpened = true;
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        scannerReturn.current.opened = true;
        // Dialog acknowledgement is input-entry only. Refresh native capability,
        // never invent a paired PC, a read result or a success notification.
        const snapshot = await readSnapshot(bridge);
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        publish({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(snapshot) });
        return null;
      }
      if (command.kind === 'lock-settings' || command.kind === 'notification-settings') {
        if (command.kind === 'lock-settings') await bridge.openLockSettings();
        else await bridge.openNotificationSettings();
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        publish({ ...previous, refreshing: false, busy: null, notice: ko.returnFromSettings });
        return null;
      }
      if (command.kind === 'diagnostics-folder') {
        // The folder is independent of service readiness, but its native command
        // shares admission with this exact in-flight read. Wait for that read to
        // release admission; never queue an approval/denial or start another read.
        if (folderRead) {
          try { await folderRead.promise; } catch { /* Diagnostic files can outlive service reads. */ }
          if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        }
        await bridge.openDiagnosticsFolder();
        console.info('UAC_DIAGNOSTIC_FOLDER_V1 outcome=accepted');
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        publish({ ...previous, refreshing: false, busy: null, error: null, notice: null });
        return null;
      }
      const started = performance.now();
      const snapshot = ageRequestPresentation(await dispatch(bridge, command), performance.now() - started);
      if (liveOwner.current !== bridge || attempt !== revision.current) return null;
      // Native cancellation and errors are AppIssue results, never local success.
      publish({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(snapshot) });
      return snapshot.issue ? null : snapshot;
    } catch (failure) {
      if (liveOwner.current !== bridge || attempt !== revision.current) return null;
      if (command.kind === 'diagnostics-folder') {
        const code = failure !== null && typeof failure === 'object' && 'code' in failure ? failure.code : null;
        const category = code === 'app_busy' ? 'busy' : code === 'diagnostics_folder_unavailable' ? 'unavailable' : code === 'app_worker_unavailable' ? 'worker' : 'other';
        const stage = failure !== null && typeof failure === 'object' && 'nativeStage' in failure ? failure.nativeStage : null;
        const nativeCode = failure !== null && typeof failure === 'object' && 'nativeCode' in failure ? failure.nativeCode : null;
        const numeric = typeof stage === 'number' && Number.isInteger(stage) && stage >= 0 && stage <= 255
          && typeof nativeCode === 'number' && Number.isInteger(nativeCode) && nativeCode >= 0 && nativeCode <= 0xffffffff
          ? ` stage=${stage} code=${nativeCode}` : '';
        // Closed diagnosis only: no path, exception text or arbitrary native code.
        console.info(`UAC_DIAGNOSTIC_FOLDER_V1 outcome=failed category=${category}${numeric}`);
        // A failed shell handoff does not invalidate an otherwise usable snapshot.
        publish({ ...previous, refreshing: false, busy: null, error: ko.diagnosticsFolderFailure, notice: null });
        return null;
      }
      if (command.kind === 'scan_pairing' && !scannerOpened) {
        scannerReturn.current = { pending: false, opened: false, wake: false };
        const error = scannerFailure(failure, command.transport);
        let snapshot: AppSnapshot | null = null;
        try { snapshot = await readSnapshot(bridge); } catch { /* Keep recovery, never raw native errors. */ }
        if (liveOwner.current !== bridge || attempt !== revision.current) return null;
        const latest = current.current;
        publish({ ...latest, snapshot: snapshot ?? (latest.snapshot ? withoutRequestBodies(latest.snapshot) : null),
          refreshing: false, busy: null, stale: snapshot === null, error, notice: null,
          requestObservedAt: snapshot ? performance.now() : latest.requestObservedAt });
        return null;
      }
      const latest = current.current;
      publish({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null, refreshing: false, busy: null, stale: true,
        error: scannerOpened ? ko.loadFailure : command.kind === 'policy' || command.kind === 'relay' ? ko.saveFailure : ko.actionFailure, notice: null });
      return null;
    } finally {
      if (liveOwner.current === bridge && attempt === revision.current) commandPending.current = false;
    }
  }, [bridge, dismissScannerReturnFocus, publish, refresh, scannerReturnRevision]);

  // A request's display lease is clipped to the end of the wall minute, so one
  // that arrives at :58 holds a two-second lease. Withdrawing the bodies and
  // only then asking for a fresh snapshot left the screen on its empty state
  // for the whole native round trip, so the request appeared, vanished and came
  // back, sometimes within a second of arriving.
  //
  // Ask early and withdraw on time. The read starts a lead before the lease
  // ends and its answer replaces this snapshot with no gap in between; the
  // withdrawal still runs at the lease itself, for the case where no answer
  // arrives. Neither timer extends what may be displayed by a millisecond.
  useEffect(() => {
    const snapshot = state.snapshot;
    if (!snapshot?.requests.length || state.owner !== bridge) return;
    const remaining = Math.max(0, Math.min(...snapshot.requests.map((request) => request.refreshAfterMillis))
      - (performance.now() - state.requestObservedAt));
    const showing = () => liveOwner.current === bridge && current.current.snapshot === snapshot;
    const early = window.setTimeout(() => {
      if (showing() && document.visibilityState === 'visible') void refresh();
    }, Math.max(0, remaining - REQUEST_REFRESH_LEAD_MILLIS));
    const withdraw = window.setTimeout(() => {
      if (!showing()) return;
      publish({ ...current.current, snapshot: withoutRequestBodies(snapshot) });
      if (document.visibilityState === 'visible') void refresh();
    }, remaining);
    return () => { window.clearTimeout(early); window.clearTimeout(withdraw); };
  }, [bridge, publish, refresh, state.owner, state.requestObservedAt, state.snapshot]);

  useEffect(() => {
    liveOwner.current = bridge;
    readPending.current = false;
    activeRead.current = null;
    commandPending.current = false;
    scannerReturn.current = { pending: false, opened: false, wake: false };
    scannerFocusRevision.current = 0;
    // Defer the initial presentation update; the first render already is loading.
    void Promise.resolve().then(() => refresh());
    const onForeground = () => {
      if (document.visibilityState === 'visible') {
        // The empty native event is an invalidation, not a closed/paired result.
        // A later true capability confirms no active native scan before focus.
        if (scannerReturn.current.pending) scannerReturn.current.wake = true;
        void refresh();
      }
      else {
        if (scannerReturn.current.pending && !scannerReturn.current.opened) dismissScannerReturnFocus();
        if (current.current.snapshot) publish({ ...current.current, snapshot: withoutRequestBodies(current.current.snapshot) });
      }
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
  }, [bridge, dismissScannerReturnFocus, publish, refresh]);

  return { ...(state.owner === bridge ? state : emptyState(bridge)), refresh, run, dismissScannerReturnFocus };
}
