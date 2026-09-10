// SPDX-License-Identifier: GPL-2.0-or-later
// Closed disposable-emulator fixture, never a personal-device credential tool.
import { JSDOM } from 'jsdom';

export const SYNTHETIC_CI_PIN = '4938'; // Public test fixture; NEVER a real credential.
export const FIRST_UNLOCK_PHASES = Object.freeze(['verify-no-secure-lock', 'verify-first-unlock']);
// The optional-reveal path uses223 commands before boot/owner polling.
// Preserve room for bounded polling plus failure evidence, never queue retries.
export const FIRST_UNLOCK_COMMANDS = 512;
export const FIRST_UNLOCK_DIAGNOSTIC_RESERVE = 32;
export const MAX_LIFECYCLE_COMMANDS = 400 + FIRST_UNLOCK_COMMANDS;
export const FIRST_UNLOCK_XML_LIMIT = 256 * 1024;
export const FIRST_UNLOCK_UI_MAX_AGE_MS = 5000;
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
    ['owner_present', 'destroyed', 'retiring', 'start_pending', 'construction_uncertain', 'start_rejected'].every(key => fields[key] === false) &&
    fields.owner_phase === 'NONE' && fields.reported_state === 'WAITING_FOR_UNLOCK' && fields.user_unlock === 'LOCKED' &&
    ['DEFAULT', 'ENABLED'].includes(fields.boot_component);
}

export function hierarchyPath(nonce, index) {
  requireThat(/^[0-9a-f]{32}$/.test(nonce) && Number.isSafeInteger(index) && index >= 0 && index < 7, 'Invalid bounded hierarchy identity.');
  return `/data/local/tmp/uac-first-unlock-${nonce}-${index}.xml`;
}

export function requireHierarchyCompletion(stdout, stderr, path) {
  requireThat(/^\/data\/local\/tmp\/uac-first-unlock-[0-9a-f]{32}-[0-6]\.xml$/.test(path) &&
    typeof stdout === 'string' && typeof stderr === 'string' &&
    stdout.trim() === `UI hierchary dumped to: ${path}` && stderr.trim() === '',
  'UI hierarchy command did not confirm the exact fresh file.');
}

export function requireHierarchyFresh(capturedAt, now) {
  requireThat(Number.isFinite(capturedAt) && capturedAt >= 0 && Number.isFinite(now) && now >= capturedAt &&
    now - capturedAt <= FIRST_UNLOCK_UI_MAX_AGE_MS, 'SystemUI hierarchy is stale before input dispatch.');
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

export function requireFirstUnlockEvidence(evidence, ready) {
  const boot = /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
  requireThat(evidence?.scope === 'DISPOSABLE_API36_X86_64_FIRST_UNLOCK' && boot.test(evidence.beforeBoot) &&
    boot.test(evidence.bootId) && evidence.beforeBoot !== evidence.bootId && evidence.setupConfirmed === true,
  'Missing real first-unlock boot/setup evidence.');
  requireThat(evidence.before?.phase === FIRST_UNLOCK_PHASES[0] && evidence.after?.phase === FIRST_UNLOCK_PHASES[1] &&
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
    evidence.ui.every((step, index) => step.path === hierarchyPath(evidence.nonce, index) &&
      step.bootId === evidence.bootId && /^[0-9a-f]{64}$/.test(step.xmlSha256) &&
      Number.isSafeInteger(step.inputCompletedAtMonotonicMs) && step.inputCompletedAtMonotonicMs >
        (index === 0 ? evidence.locked[2].observedAtMonotonicMs : evidence.ui[index - 1].inputCompletedAtMonotonicMs)) &&
    (evidence.ui.length === actions.length || (evidence.ui[0].action === 'reveal' && evidence.ui[0].kind === 'lockscreen')) &&
    actions.every((step, index) => step.action === (index === SYNTHETIC_CI_PIN.length ? 'enter' : `digit-${index}`) &&
      step.kind === 'pin' && Array.isArray(step.point) && step.point.length === 2 &&
      step.point.every(value => Number.isSafeInteger(value) && value >= 0 && value <= 8192)),
  'Missing recognized one-attempt SystemUI PIN input sequence.');
  requireThat(ready?.bootId === evidence.bootId && ready.frameworkUserState === 'RUNNING_UNLOCKED' && ready.presence === 'foreground' &&
    ready.beforeActivityOrInstrumentation === true && Number.isSafeInteger(ready.observedAtMonotonicMs) &&
    ready.observedAtMonotonicMs > evidence.ui.at(-1).inputCompletedAtMonotonicMs &&
    ['promoted', 'attached', 'owner_present', 'wanted', 'application_attached'].every(key => ready.native[key] === true) &&
    ['destroyed', 'retiring', 'start_pending', 'construction_uncertain', 'start_rejected'].every(key => ready.native[key] === false) &&
    ready.native.user_unlock === 'UNLOCKED' && ready.native.owner_phase === 'READY' &&
    ready.native.reported_state === 'LOCAL_SETTINGS_READY' && ['DEFAULT', 'ENABLED'].includes(ready.native.boot_component),
  'Missing prelaunch unlocked native READY observation.');
}
