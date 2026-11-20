// SPDX-License-Identifier: GPL-2.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react';
import type { AppSnapshot, ControllerBridge, ExternalAccessInput, NotificationPolicy, RequestDetailsView, ServiceAction } from './contracts';
import { isAuthoredCopy } from './i18n';
import { ko } from './messages.ko';
import { ageRequestPresentation, withoutRequestBodies } from './requestPresentation';

/** A failure line: catalogue keys, rendered through tr(). */
export interface Failure { readonly message: string; readonly nextAction: string | null }

const generic = (message: string): Failure => ({ message, nextAction: null });
const ISSUE_FIELDS = ['code', 'message', 'nextAction'] as const;
const MAX_ISSUE_TEXT = 400;

function authoredText(value: unknown): value is string {
  return typeof value === 'string' && value.length > 0 && value.length <= MAX_ISSUE_TEXT && isAuthoredCopy(value);
}

/** The native owner's own refusal, when a command rejection is exactly a
 * serialized AppIssue ({code, message, nextAction}) whose text is catalogued
 * authored copy. Timeouts, transport errors, extra or missing fields and any
 * text outside the catalogue return null, and the caller shows its generic line. */
export function authoredIssue(rejection: unknown): Failure | null {
  if (rejection === null || typeof rejection !== 'object' || Array.isArray(rejection)) return null;
  const prototype: unknown = Object.getPrototypeOf(rejection);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const fields = Object.keys(rejection);
  if (fields.length !== ISSUE_FIELDS.length || !ISSUE_FIELDS.every((field) => fields.includes(field))) return null;
  const { code, message, nextAction } = rejection as Record<(typeof ISSUE_FIELDS)[number], unknown>;
  if (typeof code !== 'string' || !/^[a-z][a-z0-9_]{0,63}$/u.test(code) || !authoredText(message)) return null;
  if (nextAction === null) return { message, nextAction: null };
  return authoredText(nextAction) ? { message, nextAction } : null;
}

export type ClientCommand =
  | { readonly kind: 'service'; readonly action: ServiceAction }
  | { readonly kind: 'pair'; readonly transport?: 'usb' }
  | { readonly kind: 'remove'; readonly deviceId: string }
  | { readonly kind: 'relay'; readonly address: string }
  | { readonly kind: 'external-access'; readonly access: ExternalAccessInput }
  | { readonly kind: 'clear' }
  | { readonly kind: 'diagnostics-folder' }
  | { readonly kind: 'diagnostics-export' }
  | { readonly kind: 'diagnostics-save' }
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

/** A lease this much later than the one already asked about is a new lease. */
const REQUEST_LEASE_SLACK_MILLIS = 250;

/** Waits between tries while a decision is refused as busy before the native
 * side takes it. Nothing began, so the same tap can be offered again; it is the
 * tap on the card as shown, with the locator that card had. About a second and
 * a half in all, each step still inside the display lease. */
const DECISION_BUSY_WAITS_MILLIS: readonly number[] = [60, 120, 250, 500, 500];

/** The snapshot issue that says the decision itself was not taken. `app_busy`
 * on a snapshot does not say that: the snapshot is read after the decision,
 * and a busy read there says nothing about a decision that may have gone in. */
const DECISION_REFUSED_BUSY = 'request_action_busy';

/** Reads repeated when a background read finds the owner busy. Without them a
 * withdrawn request stayed off the screen until the five-second periodic read. */
const BUSY_READ_WAITS_MILLIS: readonly number[] = [150, 300, 600];

const isBusy = (value: unknown): boolean =>
  value !== null && typeof value === 'object' && 'code' in value && value.code === 'app_busy';

const pause = (millis: number): Promise<void> => new Promise((resolve) => { window.setTimeout(resolve, millis); });

interface ViewState {
  readonly owner: ControllerBridge;
  readonly snapshot: AppSnapshot | null;
  readonly refreshing: boolean;
  readonly busy: ClientCommand['kind'] | null;
  readonly stale: boolean;
  readonly error: Failure | null;
  readonly notice: string | null;
  readonly requestObservedAt: number;
  readonly scannerFocusRevision: number;
}

function emptyState(owner: ControllerBridge): ViewState {
  return { owner, snapshot: null, refreshing: true, busy: null, stale: false, error: null, notice: null, requestObservedAt: 0, scannerFocusRevision: 0 };
}

interface WorkTicket {
  readonly owner: ControllerBridge;
  readonly revision: number;
  readonly visibility: number;
}

/** One renderer owns admission ordering and response publication. Commands
 * reserve the next turn ahead of details; refreshes are coalesced by the hook.
 * The actual bridge promise holds admission even if its UI read times out. */
class ControllerWork {
  owner: ControllerBridge | null = null;
  revision = 0;
  visibility = 0;
  command: WorkTicket | null = null;
  read: { owner: ControllerBridge; promise: Promise<AppSnapshot> } | null = null;
  private active: object | null = null;
  private admissionOwner: ControllerBridge | null = null;
  private readonly queued: { kind: 'read' | 'details' | 'command'; start: () => void }[] = [];

  settled: () => void = () => undefined;

  activate(owner: ControllerBridge) {
    // A replacement bridge is a different owner. Its admission is independent;
    // the old promise still settles, but cannot release the new owner's slot.
    if (this.admissionOwner !== owner) {
      this.admissionOwner = owner;
      this.active = null;
    }
    this.owner = owner;
    this.read = null;
    this.command = null;
    this.drain();
  }

  ticket(owner: ControllerBridge, supersede = false): WorkTicket {
    if (supersede) this.revision += 1;
    return { owner, revision: this.revision, visibility: this.visibility };
  }

  current(ticket: WorkTicket): boolean {
    return this.owner === ticket.owner && this.revision === ticket.revision;
  }

  visible(ticket: WorkTicket): boolean {
    return this.current(ticket) && this.visibility === ticket.visibility && document.visibilityState === 'visible';
  }

  presentation(ticket: WorkTicket, next: ViewState): ViewState | null {
    if (!this.current(ticket)) return null;
    return !this.visible(ticket) && next.snapshot ? { ...next, snapshot: withoutRequestBodies(next.snapshot) } : next;
  }

  get hasCalls(): boolean { return this.active !== null || this.queued.length > 0; }
  get occupied(): boolean { return this.hasCalls || this.command !== null; }

  finishCommand(ticket: WorkTicket) {
    if (this.command === ticket) this.command = null;
    this.drain();
    this.settled();
  }

  call<T>(ticket: WorkTicket, kind: 'read' | 'details' | 'command', action: () => Promise<T>): Promise<T> {
    return new Promise<T>((resolve, reject) => {
      this.queued.push({ kind, start: () => {
        const active = {};
        this.active = active;
        const run = async () => {
          if (!this.current(ticket) || (kind === 'details' && !this.visible(ticket))) throw new Error('superseded');
          const answer = await action();
          if (kind === 'details' && !this.visible(ticket)) throw new Error('superseded');
          return answer;
        };
        void run().then(resolve, reject).finally(() => {
          if (this.active !== active) return;
          this.active = null;
          this.drain();
          this.settled();
        });
      } });
      this.drain();
    });
  }

  private drain() {
    if (this.active) return;
    const next = this.command === null ? 0 : this.queued.findIndex((item) => item.kind === 'command');
    if (next >= 0) this.queued.splice(next, 1)[0]?.start();
  }

  snapshot(ticket: WorkTicket, kind: 'read' | 'command'): Promise<AppSnapshot> {
    const started = performance.now();
    const read = { owner: ticket.owner, promise: readSnapshot(this.call(ticket, kind, () => ticket.owner.snapshot()), started) };
    this.read = read;
    return read.promise.finally(() => {
      if (this.read === read) this.read = null;
    });
  }
}

async function readSnapshot(response: Promise<AppSnapshot>, started: number): Promise<AppSnapshot> {
  let timer: number | undefined;
  try {
    const snapshot = await Promise.race([
      response,
      new Promise<never>((_resolve, reject) => { timer = window.setTimeout(() => { reject(new Error('snapshot_timeout')); }, 15000); }),
    ]);
    return ageRequestPresentation(snapshot, performance.now() - started);
  } finally {
    window.clearTimeout(timer);
  }
}

/** The relay and external-access settings share one installed-helper owner. */
function networkOwnerAvailable(snapshot: AppSnapshot): boolean {
  return snapshot.platform === 'windows' && snapshot.service?.controlHint === 'available'
    && ((snapshot.service.installed === false && snapshot.service.state === null)
      || snapshot.service.state === 'stopped'
      || (snapshot.service.state === 'running' && snapshot.dataAvailability.devices === 'available'));
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
    case 'relay': return command.address.trim().length > 0 && networkOwnerAvailable(snapshot);
    case 'external-access': return networkOwnerAvailable(snapshot);
    case 'clear': return snapshot.dataAvailability.activity === 'available' && snapshot.canClearActivity;
    case 'diagnostics-folder': return snapshot.platform === 'windows';
    case 'diagnostics-export': case 'diagnostics-save': return snapshot.platform === 'android';
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

/** Commands that wait for a background read holding the native admission. */
const QUEUED_OWNER_COMMANDS: ReadonlySet<ClientCommand['kind']> = new Set(['service', 'pair', 'remove', 'relay', 'external-access', 'clear', 'policy']);

function dispatch(bridge: ControllerBridge, command: Exclude<ClientCommand, { kind: 'lock-settings' | 'notification-settings' | 'scan_pairing' | 'diagnostics-folder' | 'diagnostics-export' | 'diagnostics-save' }>): Promise<AppSnapshot> {
  switch (command.kind) {
    case 'service': return bridge.controlService(command.action);
    case 'pair': return command.transport === 'usb' ? bridge.beginPairing('usb') : bridge.beginPairing();
    case 'remove': return bridge.removeDevice(command.deviceId);
    case 'relay': return bridge.setRelay(command.address);
    case 'external-access': return bridge.setExternalAccess(command.access);
    case 'clear': return bridge.clearActivity();
    case 'decision': return bridge.decide(command.requestId, command.decision);
    case 'policy': return bridge.savePolicy(command.policy);
  }
}

function scannerFailure(error: unknown, transport?: 'usb'): string {
  const code = error !== null && typeof error === 'object' && 'code' in error ? error.code : null;
  return code === 'pairing_scanner_busy' || code === 'app_busy' ? ko.pairingScannerBusy
    : transport === 'usb' ? ko.pairingUsbFailure : ko.pairingScannerFailure;
}

export function useController(bridge: ControllerBridge) {
  const [state, setState] = useState<ViewState>(() => emptyState(bridge));
  const current = useRef<ViewState>(state);
  const readPending = useRef(false);
  // Every snapshot read, command and details read shares one native command
  // admission. A change reported while it is held is remembered here and read
  // once the work in flight lets go, instead of waiting for the periodic read.
  const refreshWanted = useRef(false);
  const busyReads = useRef(0);
  const busyReadTimer = useRef<number | undefined>(undefined);
  // The end of the lease the early read was last started for. A lease clipped
  // to the request's own deadline comes back unchanged, and asking again for it
  // read the owner continuously for the last second of every request.
  const earlyReadLeaseEnd = useRef<number | null>(null);
  const resumeRefresh = useRef<() => void>(() => undefined);
  const work = useRef(new ControllerWork());
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

  const publish = useCallback((next: ViewState, ticket = work.current.ticket(next.owner)) => {
    const presentation = work.current.presentation(ticket, next);
    if (presentation === null) return;
    current.current = presentation;
    setState(presentation);
  }, [work]);

  const refresh = useCallback(async (announce = false) => {
    if (work.current.owner !== bridge) return;
    // Dropping this call lost the native wake that announces a new request
    // whenever any other read was running, and the card then waited for the
    // periodic read. The work in flight may already have read past the change.
    if (work.current.occupied || readPending.current || work.current.read !== null) {
      refreshWanted.current = true;
      return;
    }
    refreshWanted.current = false;
    readPending.current = true;
    const attempt = work.current.ticket(bridge, true);
    const post = (next: ViewState) => publish(next, attempt);
    const previous = current.current.owner === bridge ? current.current : emptyState(bridge);
    post({ ...previous, refreshing: true, notice: null });
    const response = work.current.snapshot(attempt, 'read');
    try {
      const snapshot = await response;
      if (!work.current.current(attempt)) return;
      const latest = current.current;
      // The wake for a new request is sent while the native intake still holds
      // the owner, so the read it starts can find the owner busy. That answer
      // observes nothing: keep what is on screen, whose display lease timers
      // still run from its own observation, and let the owner's next wake read
      // again. Only an explicit refresh reports the busy owner.
      if (!announce && snapshot.issue?.code === 'app_busy' && latest.owner === bridge && latest.snapshot !== null) {
        post({ ...latest, refreshing: false });
        // The next wake may be a long way off, and a request whose lease ran
        // out is off the screen until something reads again. Ask a few times.
        const wait = BUSY_READ_WAITS_MILLIS[busyReads.current];
        if (wait !== undefined) {
          busyReads.current += 1;
          window.clearTimeout(busyReadTimer.current);
          busyReadTimer.current = window.setTimeout(() => {
            if (work.current.owner !== bridge) return;
            refreshWanted.current = true;
            resumeRefresh.current();
          }, wait);
        }
        return;
      }
      busyReads.current = 0;
      post({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: announce && !snapshot.issue ? ko.updated : null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(snapshot) });
    } catch (failure) {
      if (!work.current.current(attempt)) return;
      const latest = current.current;
      post({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null, refreshing: false, busy: null, stale: latest.snapshot !== null, error: authoredIssue(failure) ?? generic(ko.loadFailure), notice: null });
    } finally {
      if (work.current.current(attempt)) readPending.current = false;
      resumeRefresh.current();
    }
  }, [bridge, publish, scannerReturnRevision, work]);

  /** Details share admission with every native call. Their display lifetime
   * still includes the wait, and a retired owner or hidden page gets no body. */
  const readDetails = useCallback(async (requestId: string): Promise<RequestDetailsView> => {
    const ticket = work.current.ticket(bridge);
    return work.current.call(ticket, 'details', () => bridge.requestDetails(requestId));
  }, [bridge, work]);

  const run = useCallback(async (command: ClientCommand): Promise<AppSnapshot | null> => {
    const previous = current.current;
    if (work.current.owner !== bridge || work.current.command !== null || previous.owner !== bridge
      || previous.stale || !previous.snapshot || !exposedBySnapshot(previous.snapshot, command)) return null;
    if (command.kind === 'decision' && previous.snapshot.requests.some((request) => request.id === command.requestId
      && performance.now() - previous.requestObservedAt >= request.refreshAfterMillis)) {
      publish({ ...previous, snapshot: withoutRequestBodies(previous.snapshot) });
      void refresh();
      return null;
    }
    const heldRead = work.current.read?.owner === bridge ? work.current.read : null;
    // Capture both outcomes immediately: a UI timeout does not release native
    // admission, and its rejection can precede our turn by an arbitrary time.
    const observation = heldRead?.promise.then(
      (snapshot) => ({ snapshot, observedAt: performance.now(), failure: null }),
      (failure: unknown) => ({ snapshot: null, observedAt: 0, failure }),
    );
    const attempt = work.current.ticket(bridge, true);
    work.current.command = attempt;
    const post = (next: ViewState) => publish(next, attempt);
    const invoke = <T,>(action: () => Promise<T>) => work.current.call(attempt, 'command', action);
    if (command.kind === 'scan_pairing') scannerReturn.current = { pending: true, opened: false, wake: false };
    else dismissScannerReturnFocus(); // A new explicit task supersedes old modal-return focus.
    readPending.current = false;
    post({ ...previous, refreshing: false, busy: command.kind, error: null, notice: null });
    let scannerOpened = false;
    try {
      // Reserve the next turn for this one explicit command, not a FIFO of
      // stale taps. All command kinds wait for the actual admission holder.
      if (work.current.hasCalls) await invoke(() => Promise.resolve());
      if (!work.current.current(attempt)) return null;
      const observed = observation ? await observation : undefined;
      if (!work.current.current(attempt)) return null;
      const fresh = observed?.snapshot ? ageRequestPresentation(observed.snapshot, performance.now() - observed.observedAt) : null;
      if (heldRead && (command.kind === 'scan_pairing' || QUEUED_OWNER_COMMANDS.has(command.kind))) {
        if (fresh === null) {
          if (command.kind === 'scan_pairing') dismissScannerReturnFocus();
          const latest = current.current;
          post({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null,
            refreshing: false, busy: null, stale: true, error: authoredIssue(observed?.failure) ?? generic(ko.loadFailure), notice: null });
          return null;
        }
        const mayRun = exposedBySnapshot(fresh, command)
          && (command.kind !== 'scan_pairing' || (scannerReturn.current.pending && work.current.visible(attempt)));
        if (command.kind === 'scan_pairing' || !mayRun) {
          post({ ...current.current, snapshot: fresh, refreshing: false, busy: mayRun ? command.kind : null,
            stale: false, error: null, notice: null, requestObservedAt: performance.now() });
        }
        if (!mayRun) {
          if (command.kind === 'scan_pairing') dismissScannerReturnFocus();
          return null;
        }
      }
      if (command.kind === 'scan_pairing') {
        if (!scannerReturn.current.pending || !work.current.visible(attempt)) {
          dismissScannerReturnFocus();
          post({ ...current.current, refreshing: false, busy: null });
          return null;
        }
        if (command.transport === 'usb') await invoke(() => bridge.openPairingScanner('usb'));
        else await invoke(() => bridge.openPairingScanner());
        scannerOpened = true;
        if (!work.current.current(attempt)) return null;
        scannerReturn.current.opened = true;
        // Dialog acknowledgement is input-entry only. Refresh native capability,
        // never invent a paired PC, a read result or a success notification.
        const snapshot = await work.current.snapshot(attempt, 'command');
        if (!work.current.current(attempt)) return null;
        post({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(snapshot) });
        return null;
      }
      if (command.kind === 'lock-settings' || command.kind === 'notification-settings') {
        if (command.kind === 'lock-settings') await invoke(() => bridge.openLockSettings());
        else await invoke(() => bridge.openNotificationSettings());
        if (!work.current.current(attempt)) return null;
        post({ ...current.current, refreshing: false, busy: null, notice: ko.returnFromSettings });
        return null;
      }
      if (command.kind === 'diagnostics-export' || command.kind === 'diagnostics-save') {
        let notice: string = ko.diagnosticsExported;
        if (command.kind === 'diagnostics-save') {
          const result = await invoke(() => bridge.saveAndroidDiagnostics());
          if (result !== 'saved' && result !== 'cancelled') throw new Error('invalid_save_result');
          notice = result === 'saved' ? ko.diagnosticsSaved : ko.diagnosticsSaveCancelled;
        } else await invoke(() => bridge.exportAndroidDiagnostics());
        if (!work.current.current(attempt)) return null;
        // Preserve any request-body withdrawal while the Sharesheet was open.
        post({ ...current.current, refreshing: false, busy: null, error: null, notice });
        return null;
      }
      if (command.kind === 'diagnostics-folder') {
        await invoke(() => bridge.openDiagnosticsFolder());
        console.info('UAC_DIAGNOSTIC_FOLDER_V1 outcome=accepted');
        if (!work.current.current(attempt)) return null;
        post({ ...current.current, refreshing: false, busy: null, error: null, notice: null });
        return null;
      }
      if (command.kind === 'decision') {
        const superseded = () => !work.current.current(attempt);
        const visible = () => work.current.visible(attempt);
        // The request as it is on screen now, while its display lease holds. A
        // page that went to the background has already withdrawn it.
        const shown = (): boolean => {
          const latest = current.current;
          const request = latest.snapshot?.requests.find((item) => item.id === command.requestId);
          return visible() && request !== undefined && latest.snapshot !== null && exposedBySnapshot(latest.snapshot, command)
            && performance.now() - latest.requestObservedAt < request.refreshAfterMillis;
        };
        // The tap is given up: nothing is sent, and the next read says what is there.
        const withdrawn = (): null => {
          const latest = current.current;
          post({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null, refreshing: false, busy: null });
          refreshWanted.current = true;
          return null;
        };
        if (heldRead) {
          // The tap is kept and sent once the read lets go. What it answers is
          // still the card that was tapped: the read either shows that same
          // request again, and the tap goes out with the locator it had, or it
          // shows something else, and the tap is dropped in favour of that.
          if (superseded()) return null;
          // Leaving the app withdrew the request, and withdrew the tap with it.
          if (!visible()) return withdrawn();
          if (fresh !== null && fresh.issue?.code !== 'app_busy') {
            if (!exposedBySnapshot(fresh, command)) {
              post({ owner: bridge, snapshot: fresh, refreshing: false, busy: null, stale: false, error: null, notice: null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(fresh) });
              return null;
            }
            post({ ...current.current, snapshot: fresh, refreshing: false, busy: 'decision', stale: false, error: null, notice: null, requestObservedAt: performance.now() });
          } else if (!shown()) return withdrawn();
        }
        if (!shown()) return withdrawn();
        for (let tries = 0; ; tries += 1) {
          const started = performance.now();
          let answer: AppSnapshot | null = null;
          let refusal: unknown = null;
          try { answer = ageRequestPresentation(await invoke(() => dispatch(bridge, command)), performance.now() - started); }
          catch (failure) { refusal = failure; }
          if (superseded()) return null;
          const wait = DECISION_BUSY_WAITS_MILLIS[tries];
          if (answer !== null) {
            const refused = answer.issue?.code === DECISION_REFUSED_BUSY;
            const observed = answer.dataAvailability.requests === 'available';
            if (!visible()) {
              // Answered after the app was left: nothing is offered again, and
              // no request text goes back on a page nobody is looking at.
              post({ owner: bridge, snapshot: withoutRequestBodies(answer), refreshing: false, busy: null, stale: false, error: null, notice: null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(answer) });
              return null;
            }
            if (!observed && (refused || answer.issue?.code === 'app_busy')) {
              // The reads behind this answer found the owner busy, so it shows
              // no requests. That is not a request that went away. Keep the
              // card; offer a refused decision again, and otherwise read.
              if (!(refused && wait !== undefined && shown())) {
                const latest = current.current;
                post({ ...latest, refreshing: false, busy: null, notice: null,
                  error: refused && answer.issue ? { message: answer.issue.message, nextAction: answer.issue.nextAction } : null });
                if (!refused) refreshWanted.current = true;
                return null;
              }
            } else {
              const again = refused && wait !== undefined && exposedBySnapshot(answer, command);
              post({ owner: bridge, snapshot: again ? { ...answer, issue: null } : answer, refreshing: false, busy: again ? 'decision' : null,
                stale: false, error: null, notice: null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(answer) });
              if (!again) return answer.issue ? null : answer;
            }
          } else if (!isBusy(refusal)) throw refusal;
          else if (wait === undefined) {
            // Refused before anything began, so what is on screen is still what
            // the owner holds. Say so and leave the request where it is.
            post({ ...current.current, refreshing: false, busy: null, error: authoredIssue(refusal) ?? generic(ko.actionFailure), notice: null });
            return null;
          }
          await pause(wait ?? 0);
          if (superseded()) return null;
          if (!shown()) return withdrawn();
        }
      }
      const started = performance.now();
      const snapshot = ageRequestPresentation(await invoke(() => dispatch(bridge, command)), performance.now() - started);
      if (!work.current.current(attempt)) return null;
      // Native cancellation and errors are AppIssue results, never local success.
      // A finished repair is otherwise silent: its notice just disappears.
      const repaired = command.kind === 'service' && command.action === 'repair' && !snapshot.issue;
      post({ owner: bridge, snapshot, refreshing: false, busy: null, stale: false, error: null, notice: repaired ? ko.repairDone : null, requestObservedAt: performance.now(), scannerFocusRevision: scannerReturnRevision(snapshot) });
      return snapshot.issue ? null : snapshot;
    } catch (failure) {
      if (!work.current.current(attempt)) return null;
      if (command.kind === 'diagnostics-export' || command.kind === 'diagnostics-save') {
        post({ ...current.current, refreshing: false, busy: null, error: generic(command.kind === 'diagnostics-save' ? ko.diagnosticsSaveFailure : ko.diagnosticsExportFailure), notice: null });
        return null;
      }
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
        post({ ...current.current, refreshing: false, busy: null, error: generic(ko.diagnosticsFolderFailure), notice: null });
        return null;
      }
      if (command.kind === 'scan_pairing' && !scannerOpened) {
        scannerReturn.current = { pending: false, opened: false, wake: false };
        const error = generic(scannerFailure(failure, command.transport));
        let snapshot: AppSnapshot | null = null;
        try { snapshot = await work.current.snapshot(attempt, 'command'); } catch { /* Keep recovery, never raw native errors. */ }
        if (!work.current.current(attempt)) return null;
        const latest = current.current;
        post({ ...latest, snapshot: snapshot ?? (latest.snapshot ? withoutRequestBodies(latest.snapshot) : null),
          refreshing: false, busy: null, stale: snapshot === null, error, notice: null,
          requestObservedAt: snapshot ? performance.now() : latest.requestObservedAt });
        return null;
      }
      // The owner's own refusal names its reason and next step. Anything else,
      // a timeout or a transport failure among them, keeps the generic line.
      const latest = current.current;
      post({ ...latest, snapshot: latest.snapshot ? withoutRequestBodies(latest.snapshot) : null, refreshing: false, busy: null, stale: true,
        error: authoredIssue(failure) ?? generic(scannerOpened ? ko.loadFailure
          : command.kind === 'policy' || command.kind === 'relay' || command.kind === 'external-access' ? ko.saveFailure : ko.actionFailure), notice: null });
      return null;
    } finally {
      work.current.finishCommand(attempt);
    }
  }, [bridge, dismissScannerReturnFocus, publish, refresh, scannerReturnRevision, work]);

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
    const showing = () => work.current.owner === bridge && current.current.snapshot === snapshot;
    const leaseEnd = performance.now() + remaining;
    const asked = earlyReadLeaseEnd.current;
    const early = asked !== null && leaseEnd <= asked + REQUEST_LEASE_SLACK_MILLIS ? undefined : window.setTimeout(() => {
      if (!showing() || document.visibilityState !== 'visible') return;
      earlyReadLeaseEnd.current = leaseEnd;
      void refresh();
    }, Math.max(0, remaining - REQUEST_REFRESH_LEAD_MILLIS));
    const withdraw = window.setTimeout(() => {
      if (!showing()) return;
      publish({ ...current.current, snapshot: withoutRequestBodies(snapshot) });
      if (document.visibilityState === 'visible') void refresh();
    }, remaining);
    return () => { window.clearTimeout(early); window.clearTimeout(withdraw); };
  }, [bridge, publish, refresh, state.owner, state.requestObservedAt, state.snapshot, work]);

  // One more read for the changes remembered while the admission was held. A
  // hidden page reads nothing; becoming visible reads anyway.
  useEffect(() => {
    resumeRefresh.current = () => {
      if (!refreshWanted.current || work.current.owner !== bridge) return;
      if (document.visibilityState !== 'visible') { refreshWanted.current = false; return; }
      void refresh();
    };
    work.current.settled = () => resumeRefresh.current();
    return () => { resumeRefresh.current = () => undefined; };
  }, [bridge, refresh, work]);

  useEffect(() => {
    const ownerWork = work.current;
    ownerWork.activate(bridge);
    readPending.current = false;
    refreshWanted.current = false;
    busyReads.current = 0;
    earlyReadLeaseEnd.current = null;
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
        work.current.visibility += 1;
        if (scannerReturn.current.pending && !scannerReturn.current.opened) dismissScannerReturnFocus();
        if (current.current.snapshot) publish({ ...current.current, snapshot: withoutRequestBodies(current.current.snapshot) });
      }
    };
    let disposed = false;
    let unsubscribe: (() => Promise<void>) | undefined;
    void bridge.watchRequests?.(onForeground).then((stop) => {
      if (disposed) void stop().catch(() => undefined);
      else unsubscribe = stop;
    }).catch(() => undefined); // Sticky native review + periodic read still work.current.
    window.addEventListener('focus', onForeground);
    document.addEventListener('visibilitychange', onForeground);
    const timer = window.setInterval(onForeground, 5000);
    return () => {
      disposed = true;
      void unsubscribe?.().catch(() => undefined);
      ownerWork.owner = null;
      ownerWork.revision += 1;
      window.clearInterval(timer);
      window.clearTimeout(busyReadTimer.current);
      window.removeEventListener('focus', onForeground);
      document.removeEventListener('visibilitychange', onForeground);
    };
  }, [bridge, dismissScannerReturnFocus, publish, refresh, work]);

  return { ...(state.owner === bridge ? state : emptyState(bridge)), refresh, run, readDetails, dismissScannerReturnFocus };
}
