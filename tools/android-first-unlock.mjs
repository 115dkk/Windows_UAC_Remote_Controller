// SPDX-License-Identifier: GPL-2.0-or-later
// Closed disposable-emulator fixture, never a personal-device credential tool.
import { JSDOM } from 'jsdom';

export const SYNTHETIC_CI_PIN = '4938'; // Public test fixture; NEVER a real credential.
export const FIRST_UNLOCK_PHASES = Object.freeze(['verify-no-secure-lock', 'verify-first-unlock']);
// The optional-reveal path uses223 commands before boot/owner polling.
// Fresh recaptures spend this same ceiling; worst-case polling plus recaptures
// need not fit. Exhaustion fails without consuming the diagnostic reserve.
export const FIRST_UNLOCK_COMMANDS = 512;
export const FIRST_UNLOCK_DIAGNOSTIC_RESERVE = 32;
export const MAX_LIFECYCLE_COMMANDS = 400 + FIRST_UNLOCK_COMMANDS;
export const FIRST_UNLOCK_XML_LIMIT = 256 * 1024;
export const FIRST_UNLOCK_UI_MAX_AGE_MS = 5000;
export const FIRST_UNLOCK_MAX_RECAPTURES = 2;
export const FIRST_UNLOCK_MAX_HIERARCHIES = 7 + FIRST_UNLOCK_MAX_RECAPTURES;
const SYSTEM_UI = 'com.android.systemui';
const requireThat = (value, message) => { if (!value) throw new Error(message); };

export function extensionCommandLimits(start) {
  requireThat(Number.isSafeInteger(start) && start > 0 && start <= 400, 'Original command ceiling exceeded.');
  return { operational: start + FIRST_UNLOCK_COMMANDS - FIRST_UNLOCK_DIAGNOSTIC_RESERVE,
    diagnostics: start + FIRST_UNLOCK_COMMANDS };
}

export function requireFirstUnlockDevice(user, encryption) {
  requireThat(user.trim() === '0' && encryption.trim() === 'file', 'First unlock requires current user0 and real file-based encryption.');
}

export function frameworkUserState(text) {
  requireThat(typeof text === 'string' && Buffer.byteLength(text) <= 512 * 1024 &&
    !/Permission Denial|Exception|DUMP TIMEOUT|Error dumping|\0/.test(text), 'Framework user observation unavailable.');
  // AOSP16 UserManagerService.dump: not a keyguard-visible or shell-exit boolean.
  const matches = [...text.replaceAll('\r\n', '\n').matchAll(/^  Started users state: \[([^\]\n]*)\]\s*$/gm)];
  requireThat(matches.length === 1 && /^0=(BOOTING|RUNNING_LOCKED|RUNNING_UNLOCKING|RUNNING_UNLOCKED)$/.test(matches[0][1]),
    'Expected exactly one started framework user0 state.');
  return matches[0][1].slice(2);
}

export function isPassiveWaitingForUnlock(fields) {
  return ['promoted', 'attached', 'wanted', 'application_attached'].every(key => fields[key] === true) &&
    ['owner_present', 'destroyed', 'retiring', 'start_pending', 'construction_uncertain', 'start_rejected', 'activation_pending', 'activation_uncertain'].every(key => fields[key] === false) &&
    fields.owner_phase === 'NONE' && fields.reported_state === 'WAITING_FOR_UNLOCK' && fields.user_unlock === 'LOCKED' &&
    fields.activation_state === 'ON' && ['DEFAULT', 'ENABLED'].includes(fields.boot_component);
}

export function hierarchyPath(nonce, index) {
  requireThat(/^[0-9a-f]{32}$/.test(nonce) && Number.isSafeInteger(index) && index >= 0 && index < FIRST_UNLOCK_MAX_HIERARCHIES, 'Invalid bounded hierarchy identity.');
  return `/data/local/tmp/uac-first-unlock-${nonce}-${index}.xml`;
}

export function requireHierarchyCompletion(stdout, stderr, path) {
  requireThat(/^\/data\/local\/tmp\/uac-first-unlock-[0-9a-f]{32}-[0-8]\.xml$/.test(path) &&
    typeof stdout === 'string' && typeof stderr === 'string' &&
    stdout.trim() === `UI hierchary dumped to: ${path}` && stderr.trim() === '',
  'UI hierarchy command did not confirm the exact fresh file.');
}

function validMonotonic(value) {
  return Number.isFinite(value) && value >= 0 && value <= Number.MAX_SAFE_INTEGER;
}
function hierarchyAge(capturedAt, now) {
  requireThat(validMonotonic(capturedAt) && validMonotonic(now) && now >= capturedAt,
    'Invalid or regressed SystemUI monotonic clock.');
  return now - capturedAt;
}
export function requireHierarchyFresh(capturedAt, now) {
  requireThat(hierarchyAge(capturedAt, now) <= FIRST_UNLOCK_UI_MAX_AGE_MS,
    'SystemUI hierarchy is stale before input dispatch.');
}

export function requireFirstUnlockUiCurrent(state, deadline, now) {
  requireThat(state && ['aborted', 'cancelled', 'cleanupIncomplete', 'deviceOperationMayContinue'].every(key => state[key] === false) &&
    Number.isSafeInteger(state.commandIndex) && state.commandIndex >= 0 &&
    Number.isSafeInteger(state.commandLimit) && state.commandIndex < state.commandLimit && state.commandLimit <= MAX_LIFECYCLE_COMMANDS,
  'Cancelled/uncertain/bounded SystemUI ceremony cannot continue.');
  requireThat(Number.isFinite(deadline) && Number.isFinite(now) && now >= 0 && now < deadline,
    'SystemUI credential interaction deadline.');
}

// Only this post-guard helper can mint a recoverable PRE_DISPATCH_STALE result.
// Invalid clocks and every input failure throw; neither can become a retry.
// This is a CI orchestration seam, not native input/credential authority.
const dispatchOutcomes = new WeakSet();
export async function guardedHierarchyInput(capturedAt, observedAt, input) {
  requireThat(typeof input === 'function', 'Missing guarded SystemUI input operation.');
  const ageMs = hierarchyAge(capturedAt, observedAt);
  const stale = ageMs > FIRST_UNLOCK_UI_MAX_AGE_MS;
  if (!stale) {
    const stdout = await input();
    requireThat(typeof stdout === 'string', 'SystemUI input completion was not confirmed.');
  }
  const outcome = Object.freeze({ kind: stale ? 'PRE_DISPATCH_STALE' : 'INPUT_COMPLETED',
    capturedAt, observedAt, ageMs, inputIssued: !stale });
  dispatchOutcomes.add(outcome);
  return outcome;
}

function bounds(node) {
  const found = /^\[(\d{1,4}),(\d{1,4})\]\[(\d{1,4}),(\d{1,4})\]$/.exec(node.getAttribute('bounds') ?? '');
  requireThat(found, 'Missing exact UI control bounds.');
  const [left, top, right, bottom] = found.slice(1).map(Number);
  requireThat(left < right && top < bottom && right <= 8192 && bottom <= 8192, 'Invalid UI control bounds.');
  return { left, top, right, bottom };
}
function within(inner, outer) {
  return inner.left >= outer.left && inner.top >= outer.top && inner.right <= outer.right && inner.bottom <= outer.bottom;
}
function center(value) {
  return [Math.floor((value.left + value.right) / 2), Math.floor((value.top + value.bottom) / 2)];
}

// Only AOSP16's source-defined classic SystemUI lockscreen/PIN layout is admitted.
// Unknown/Compose layouts must produce evidence and fail, not guessed input.
export function parseSystemUiHierarchy(xml) {
  requireThat(typeof xml === 'string' && Buffer.byteLength(xml) > 0 && Buffer.byteLength(xml) <= FIRST_UNLOCK_XML_LIMIT &&
    !/<!DOCTYPE|<!ENTITY|\0|\uFFFD/i.test(xml), 'Invalid bounded SystemUI hierarchy.');
  const dom = new JSDOM(xml, { contentType: 'text/xml' });
  try {
    const root = dom.window.document.documentElement;
    requireThat(root.tagName === 'hierarchy' && /^[0-3]$/.test(root.getAttribute('rotation') ?? '') && root.children.length === 1,
      'Expected one active display hierarchy.');
    const nodes = [...root.querySelectorAll('*')];
    requireThat(nodes.length > 0 && nodes.length <= 256 && nodes.every(node => node.tagName === 'node' &&
      node.getAttribute('package') === SYSTEM_UI), 'Hierarchy is not exclusively SystemUI.');
    for (const node of nodes) {
      let depth = 0;
      for (let parent = node.parentElement; parent; parent = parent.parentElement) depth++;
      requireThat(depth <= 32, 'Excess UI hierarchy depth.');
    }
    const screen = bounds(root.children[0]);
    const find = id => {
      const matches = nodes.filter(node => node.getAttribute('resource-id') === `${SYSTEM_UI}:id/${id}`);
      requireThat(matches.length <= 1, 'Ambiguous SystemUI control.');
      return matches[0];
    };
    const pin = find('keyguard_pin_view'), entry = find('pinEntry');
    if (pin || entry) {
      requireThat(pin && entry && pin.contains(entry) && entry.getAttribute('enabled') === 'true' &&
        entry.getAttribute('password') === 'true', 'Incomplete SystemUI PIN credential screen.');
      const pinBounds = bounds(pin);
      requireThat(within(pinBounds, screen) && within(bounds(entry), pinBounds), 'PIN screen leaves active window.');
      const controls = {};
      for (const name of [...'0123456789', 'enter']) {
        const node = find(name === 'enter' ? 'key_enter' : `key${name}`);
        requireThat(node && pin.contains(node) && node.getAttribute('enabled') === 'true' && node.getAttribute('clickable') === 'true',
          'PIN keypad control unavailable.');
        const rect = bounds(node);
        requireThat(within(rect, pinBounds) && rect.right - rect.left >= 16 && rect.bottom - rect.top >= 16,
          'PIN control is clipped or outside its credential screen.');
        controls[name] = center(rect);
      }
      requireThat(new Set(Object.values(controls).map(value => value.join(','))).size === 11, 'Overlapping PIN control centers.');
      return { kind: 'pin', rotation: root.getAttribute('rotation'), empty: entry.getAttribute('text') === '', controls };
    }
    const panel = find('notification_panel'), keyguard = find('keyguard_long_press');
    requireThat(panel && keyguard && panel.contains(keyguard), 'Unrecognized SystemUI keyguard layout.');
    const panelBounds = bounds(panel), guardBounds = bounds(keyguard);
    requireThat(within(panelBounds, screen) && within(guardBounds, panelBounds) &&
      guardBounds.right - guardBounds.left >= 100 && guardBounds.bottom - guardBounds.top >= 200,
    'Keyguard reveal surface is unavailable.');
    const [x] = center(guardBounds), height = guardBounds.bottom - guardBounds.top;
    return { kind: 'lockscreen', rotation: root.getAttribute('rotation'),
      swipe: [x, Math.floor(guardBounds.top + height * 0.75), x, Math.floor(guardBounds.top + height * 0.25), 400] };
  } finally { dom.window.close(); }
}

// The actual CI caller supplies guarded native capture/dispatch, the ORIGINAL
// deadline/cancellation check and transcript metadata. Fixtures exercise this
// same closed one-PIN orchestration, but never establish native behavior.
export async function performFirstUnlockUi({ nonce, bootId, capture, dispatch, checkCurrent, monotonicNow, onAction, onDiscard }) {
  requireThat([capture, dispatch, checkCurrent, monotonicNow, onAction, onDiscard].every(value => typeof value === 'function'),
    'Incomplete closed SystemUI ceremony.');
  let captures = 0, recaptures = 0, monotonicFloor = 0;
  const observeClock = value => {
    requireThat(validMonotonic(value) && value >= monotonicFloor, 'Invalid or regressed SystemUI monotonic clock.');
    monotonicFloor = value;
    return value;
  };
  checkCurrent(); observeClock(monotonicNow());
  async function freshScreen() {
    checkCurrent();
    const path = hierarchyPath(nonce, captures++);
    const snapshot = await capture(path);
    checkCurrent();
    requireThat(snapshot?.path === path && snapshot.bootId === bootId && /^[0-9a-f]{64}$/.test(snapshot.xmlSha256),
      'SystemUI capture identity or transcript metadata changed.');
    observeClock(snapshot.capturedAt);
    // Reparse each fresh XML, never borrow controls or stage from a stale reply.
    return { ...parseSystemUiHierarchy(snapshot.xml), path, bootId,
      xmlSha256: snapshot.xmlSha256, capturedAt: snapshot.capturedAt };
  }
  async function action(screen, name, kind, rotation, empty, control) {
    for (;;) {
      checkCurrent();
      requireThat(screen.kind === kind && screen.rotation === rotation && (!empty || screen.empty === true),
        'SystemUI action layout/stage changed during the sole PIN attempt.');
      const point = kind === 'pin' ? screen.controls[control] : null;
      const argv = kind === 'pin' ? ['tap', ...point.map(String)] : ['swipe', ...screen.swipe.map(String)];
      const outcome = await dispatch(argv, screen.capturedAt);
      requireThat(dispatchOutcomes.has(outcome) && outcome.capturedAt === screen.capturedAt,
        'Unrecognized SystemUI pre-dispatch/completion outcome.');
      dispatchOutcomes.delete(outcome); // Each genuine outcome is consumed once.
      observeClock(outcome.observedAt);
      const metadata = { kind: screen.kind, path: screen.path, xmlSha256: screen.xmlSha256, bootId };
      if (outcome.kind === 'PRE_DISPATCH_STALE') {
        checkCurrent(); // Cancellation, original deadline or uncertainty wins.
        onDiscard({ ...metadata, pendingAction: name, reason: 'PRE_DISPATCH_STALE', inputIssued: false,
          capturedAt: outcome.capturedAt, observedAt: outcome.observedAt, ageMs: outcome.ageMs });
        requireThat(recaptures < FIRST_UNLOCK_MAX_RECAPTURES, 'SystemUI pre-dispatch recapture budget exhausted.');
        recaptures++;
        screen = await freshScreen();
        continue;
      }
      requireThat(outcome.kind === 'INPUT_COMPLETED' && outcome.inputIssued === true, 'SystemUI input completion unavailable.');
      const completed = Math.floor(observeClock(monotonicNow()));
      onAction({ ...metadata, action: name, ...(point === null ? {} : { point }), inputCompletedAtMonotonicMs: completed });
      checkCurrent(); // A completed command is retained even if the ceremony now fails.
      return;
    }
  }
  let screen = await freshScreen();
  if (screen.kind === 'lockscreen') {
    await action(screen, 'reveal', 'lockscreen', screen.rotation, false, null);
    screen = await freshScreen();
  }
  requireThat(screen.kind === 'pin' && screen.empty === true, 'Expected an empty recognized PIN entry; no credential guessing or clearing.');
  const rotation = screen.rotation;
  for (let index = 0; index < SYNTHETIC_CI_PIN.length; index++) {
    if (index !== 0) screen = await freshScreen();
    await action(screen, `digit-${index}`, 'pin', rotation, index === 0, SYNTHETIC_CI_PIN[index]);
  }
  screen = await freshScreen();
  await action(screen, 'enter', 'pin', rotation, false, 'enter');
  return { captures, recaptures }; // Counts only, never a passing native receipt.
}

function requireUiCaptureSequence(evidence) {
  const discarded = evidence.discardedUi === undefined ? [] : evidence.discardedUi;
  requireThat(Array.isArray(discarded) && discarded.length <= FIRST_UNLOCK_MAX_RECAPTURES,
    'Invalid discarded SystemUI capture evidence.');
  const paths = Array.from({ length: FIRST_UNLOCK_MAX_HIERARCHIES }, (_, index) => hierarchyPath(evidence.nonce, index));
  const indices = evidence.ui.map(step => paths.indexOf(step.path));
  const discardedIndices = discarded.map(step => paths.indexOf(step.path));
  requireThat(indices.every((value, index) => value >= 0 && (index === 0 || value > indices[index - 1])) &&
    discardedIndices.every((value, index) => value >= 0 && (index === 0 || value > discardedIndices[index - 1])) &&
    [...indices, ...discardedIndices].sort((a, b) => a - b).every((value, index) => value === index),
  'Missing, reused or crossed fresh SystemUI capture paths.');
  for (const [index, step] of discarded.entries()) {
    const next = evidence.ui.find((_, uiIndex) => indices[uiIndex] > discardedIndices[index]);
    const previous = evidence.ui.findLast((_, uiIndex) => indices[uiIndex] < discardedIndices[index]);
    requireThat(next && step.pendingAction === next.action && step.kind === next.kind && step.bootId === evidence.bootId &&
      /^[0-9a-f]{64}$/.test(step.xmlSha256) && step.reason === 'PRE_DISPATCH_STALE' && step.inputIssued === false &&
      !Object.hasOwn(step, 'action') && validMonotonic(step.capturedAt) && validMonotonic(step.observedAt) &&
      step.capturedAt >= (previous?.inputCompletedAtMonotonicMs ?? evidence.locked[2].observedAtMonotonicMs) &&
      step.observedAt - step.capturedAt === step.ageMs && step.ageMs > FIRST_UNLOCK_UI_MAX_AGE_MS &&
      step.observedAt < next.inputCompletedAtMonotonicMs &&
      (index === 0 || step.capturedAt >= discarded[index - 1].observedAt),
    'Discarded stale XML cannot supply input or first-unlock proof.');
  }
}

export function requireFirstUnlockEvidence(evidence, ready) {
  const boot = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
  requireThat(evidence?.scope === 'DISPOSABLE_API36_X86_64_FIRST_UNLOCK' && boot.test(evidence.beforeBoot) &&
    boot.test(evidence.bootId) && evidence.beforeBoot !== evidence.bootId && evidence.setupConfirmed === true,
  'Missing real first-unlock boot/setup evidence.');
  requireThat(evidence.before?.phase === FIRST_UNLOCK_PHASES[0] && evidence.after?.phase === FIRST_UNLOCK_PHASES[1] &&
    evidence.before.activation === 'ON' && evidence.after.activation === 'ON' &&
    evidence.before.checks?.deviceSecureBefore === false && evidence.before.checks?.deviceSecureAfter === false &&
    evidence.after.checks?.deviceSecureBefore === true && evidence.after.checks?.deviceSecureAfter === true &&
    evidence.before.checks?.userUnlockedAfter === true && evidence.after.checks?.userUnlockedAfter === true &&
    evidence.after.bootCount === evidence.before.bootCount + 1 && evidence.before.appSha256 === evidence.after.appSha256 &&
    evidence.before.testSha256 === evidence.after.testSha256 && evidence.before.nonce !== evidence.after.nonce,
  'Native secure-lock observations are incomplete or crossed.');
  requireThat(Array.isArray(evidence.locked) && evidence.locked.length === 3 && evidence.locked.every(sample =>
    sample.bootId === evidence.bootId && sample.frameworkUserState === 'RUNNING_LOCKED' && sample.presence === 'foreground' &&
    sample.beforeActivityOrInstrumentation === true && Number.isSafeInteger(sample.observedAtMonotonicMs) &&
    isPassiveWaitingForUnlock(sample.native)) &&
    evidence.locked[0].observedAtMonotonicMs < evidence.locked[1].observedAtMonotonicMs &&
    evidence.locked[1].observedAtMonotonicMs < evidence.locked[2].observedAtMonotonicMs &&
    evidence.locked[2].observedAtMonotonicMs - evidence.locked[0].observedAtMonotonicMs >= 1000,
  'Missing stable locked no-owner foreground observations.');
  const actions = evidence.ui?.filter(step => step.action !== 'reveal');
  requireThat(Array.isArray(actions) && actions.length === SYNTHETIC_CI_PIN.length + 1 &&
    evidence.ui.length <= SYNTHETIC_CI_PIN.length + 2 &&
    evidence.ui.every((step, index) => step.bootId === evidence.bootId && /^[0-9a-f]{64}$/.test(step.xmlSha256) &&
      Number.isSafeInteger(step.inputCompletedAtMonotonicMs) && step.inputCompletedAtMonotonicMs >
        (index === 0 ? evidence.locked[2].observedAtMonotonicMs : evidence.ui[index - 1].inputCompletedAtMonotonicMs)) &&
    (evidence.ui.length === actions.length || (evidence.ui[0].action === 'reveal' && evidence.ui[0].kind === 'lockscreen')) &&
    actions.every((step, index) => step.action === (index === SYNTHETIC_CI_PIN.length ? 'enter' : `digit-${index}`) &&
      step.kind === 'pin' && Array.isArray(step.point) && step.point.length === 2 &&
      step.point.every(value => Number.isSafeInteger(value) && value >= 0 && value <= 8192)),
  'Missing recognized one-attempt SystemUI PIN input sequence.');
  requireUiCaptureSequence(evidence);
  requireThat(ready?.bootId === evidence.bootId && ready.frameworkUserState === 'RUNNING_UNLOCKED' && ready.presence === 'foreground' &&
    ready.beforeActivityOrInstrumentation === true && Number.isSafeInteger(ready.observedAtMonotonicMs) &&
    ready.observedAtMonotonicMs > evidence.ui.at(-1).inputCompletedAtMonotonicMs &&
    ['promoted', 'attached', 'owner_present', 'wanted', 'application_attached'].every(key => ready.native[key] === true) &&
    ['destroyed', 'retiring', 'start_pending', 'construction_uncertain', 'start_rejected', 'activation_pending', 'activation_uncertain'].every(key => ready.native[key] === false) &&
    ready.native.user_unlock === 'UNLOCKED' && ready.native.owner_phase === 'READY' &&
    ready.native.activation_state === 'ON' &&
    ready.native.reported_state === 'LOCAL_SETTINGS_READY' && ['DEFAULT', 'ENABLED'].includes(ready.native.boot_component),
  'Missing prelaunch unlocked native READY observation.');
}
