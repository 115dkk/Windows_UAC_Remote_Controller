// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic parser/guard contracts only; these never run adb or establish native lifecycle behavior.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { AVD, PACKAGE, TEST_PACKAGE, SOURCE_ROOTS, inspectTestManifest, isPassiveReady, parseInstrumentation, parsePassiveDump,
  requireCi, requireDevice, requireSameSource, servicePresence, requireSameBoot, commandEvidenceComplete,
  finalizeLifecycleResult, nativeOperationUnconfirmed } from './android-lifecycle-ci.mjs';
import { SYNTHETIC_CI_PIN, FIRST_UNLOCK_PHASES, extensionCommandLimits, requireFirstUnlockDevice,
  frameworkUserState, isPassiveWaitingForUnlock, hierarchyPath, requireHierarchyCompletion,
  requireHierarchyFresh, parseSystemUiHierarchy, requireFirstUnlockEvidence } from './android-first-unlock.mjs';

test('host admission refuses local, non-Linux and external ADB routing', () => {
  const env = { CI: 'true', GITHUB_ACTIONS: 'true', GITHUB_SHA: 'a'.repeat(40), GITHUB_WORKSPACE: '/workspace' };
  assert.doesNotThrow(() => requireCi(env, 'linux', '/workspace'));
  for (const changes of [{ CI: 'false' }, { GITHUB_ACTIONS: '' }, { GITHUB_SHA: 'main' },
    { GITHUB_WORKSPACE: '/other' }, { ADB_SERVER_SOCKET: 'tcp:remote:5037' }, { ANDROID_SERIAL: 'physical' }]) {
    assert.throws(() => requireCi({ ...env, ...changes }, 'linux', '/workspace'));
  }
  assert.throws(() => requireCi(env, 'win32', '/workspace'));
});

test('instrumentation reuses only a previously built, APK-matched and unchanged Tauri library', () => {
  const workflow = readFileSync(new URL('../.github/workflows/android-lifecycle.yml', import.meta.url), 'utf8');
  assert.ok(workflow.indexOf('Build genuine x86_64 Tauri and controller product APK') < workflow.indexOf('Build instrumentation against that real product flavor'));
  assert.ok(workflow.includes("before = await inspectApk(apk, 'x86_64')"));
  assert.ok(workflow.includes("before.libraries.find(item => item.member === 'lib/x86_64/libcontroller_app_lib.so')?.sha256 !== libraryHash"));
  assert.ok(workflow.includes("'-x', ':app:rustBuildX86_64Debug'"));
  assert.ok(workflow.includes('hash(apk) !== before.apk.sha256 || hash(library) !== libraryHash'));
  assert.ok(workflow.includes("throw new Error('Actual instrumentation build failed')"));
  assert.ok(workflow.includes('instrumentation-prebuilt-binding.json'));
});

test('only one named API36 x86_64 emulator is admitted before mutation', () => {
  const device = { devices: 'List of devices attached\nemulator-5554\tdevice\n', qemu: '1\n', sdk: '36\n', abi: 'x86_64\n', avd: `${AVD}\nOK\n` };
  assert.doesNotThrow(() => requireDevice(device));
  for (const changes of [{ devices: 'List of devices attached\nphysical\tdevice\n' },
    { devices: `${device.devices}physical\tdevice\n` }, { qemu: '0' }, { sdk: '35' }, { abi: 'arm64-v8a' },
    { avd: 'other\nOK' }, { avd: AVD }, { devices: 'List of devices attached\nemulator-5554\toffline\n' }]) {
    assert.throws(() => requireDevice({ ...device, ...changes }));
  }
});

test('prebuild source snapshot rejects changed commit, missing or mutated inputs', () => {
  const source = { version: 1, commit: 'a'.repeat(40), files: { 'fixed/input.kt': { bytes: 5, sha256: 'b'.repeat(64) } } };
  assert.doesNotThrow(() => requireSameSource(source, structuredClone(source)));
  for (const value of [null, { ...source, version: 2 }, { ...source, commit: 'c'.repeat(40) },
    { ...source, files: {} }, { ...source, files: { 'fixed/input.kt': { bytes: 5, sha256: 'c'.repeat(64) } } }]) {
    assert.throws(() => requireSameSource(source, value));
  }
});

test('native lifecycle source binding includes the actual vendored Android implementation', () => {
  assert.ok(Object.isFrozen(SOURCE_ROOTS));
  for (const input of ['Cargo.toml', 'Cargo.lock', 'crates', 'src-tauri', 'vendor', 'tools']) assert.ok(SOURCE_ROOTS.includes(input));
  assert.equal(new Set(SOURCE_ROOTS).size, SOURCE_ROOTS.length);
  assert.throws(() => SOURCE_ROOTS.push('untracked-source'));
  const source = { version: 1, commit: 'a'.repeat(40), files: { 'vendor/wry/src/android/binding.rs': { bytes: 20, sha256: 'b'.repeat(64) } } };
  const changed = structuredClone(source); changed.files['vendor/wry/src/android/binding.rs'].sha256 = 'c'.repeat(64);
  assert.throws(() => requireSameSource(source, changed));
});

test('reboot and package observations stay bound to the expected kernel boot identity', () => {
  const boot = '12345678-1234-1234-1234-123456789abc';
  assert.doesNotThrow(() => requireSameBoot(boot, boot));
  for (const value of ['22345678-1234-1234-1234-123456789abc', null, '', `${boot}\n`]) assert.throws(() => requireSameBoot(boot, value));
});

test('successful command requires its actual retained transcript, including legitimate empty logs', () => {
  const value = { status: 0, error: null, signal: null, cancelled: false, cleanupIncomplete: false };
  const log = { bytes: 0, sha256: 'a'.repeat(64) };
  assert.equal(commandEvidenceComplete(value, log), true);
  for (const transcript of [null, { logUnavailable: true }, { ...log, logUnavailable: true }, { ...log, bytes: -1 }, { ...log, sha256: '' }]) {
    assert.equal(commandEvidenceComplete(value, transcript), false);
  }
  for (const change of [{ status: null }, { signal: 'SIGTERM' }, { cancelled: true }, { cleanupIncomplete: true }, { error: new Error('failed') }]) {
    assert.equal(commandEvidenceComplete({ ...value, ...change }, log), false);
  }
});

test('late cancellation or uncertain cleanup clears a previously prepared passing result', () => {
  const state = { passed: true, firstUnlockVerified: true, cancelled: false, cleanupIncomplete: false, deviceOperationMayContinue: false };
  assert.equal(finalizeLifecycleResult({ ...state }, false).passed, true);
  for (const [change, aborted] of [[{}, true], [{ cancelled: true }, false], [{ cleanupIncomplete: true }, false],
    [{ deviceOperationMayContinue: true }, false], [{ failure: '' }, false]]) {
    assert.equal(finalizeLifecycleResult({ ...state, ...change }, aborted).passed, false);
    assert.equal(finalizeLifecycleResult({ ...state, ...change }, aborted).firstUnlockVerified, false);
  }
});

test('a timed-out native test operation remains uncertain even after adb instrumentation exits', () => {
  assert.equal(nativeOperationUnconfirmed('java.lang.AssertionError: Native entry deadline; completion unconfirmed'), true);
  assert.equal(nativeOperationUnconfirmed('WebView deadline: not ready'), false);
  assert.equal(nativeOperationUnconfirmed('OK (1 test)'), false);
});

const fields = {
  promoted: true, attached: true, destroyed: false, retiring: false, user_unlock: 'UNLOCKED', boot_component: 'ENABLED',
  owner_present: true, owner_phase: 'READY', wanted: true, start_pending: false, application_attached: true,
  construction_uncertain: false, start_rejected: false, reported_state: 'LOCAL_SETTINGS_READY',
  activation_state: 'ON', activation_pending: false, activation_uncertain: false,
};
const dump = (value = fields) => `SERVICE ${PACKAGE}/.background.ControllerForegroundService\n  UAC_LIFECYCLE_BEGIN_V1\n${Object.entries(value).map(([key, v]) => `  ${key}=${v}\n`).join('')}  UAC_LIFECYCLE_END_V1\n`;

test('passive readiness requires all actual owner and FGS facts, not launch acceptance', () => {
  assert.equal(isPassiveReady(parsePassiveDump(dump())), true);
  for (const changes of [{ promoted: false }, { owner_phase: 'STARTING' }, { start_pending: true },
    { owner_present: false }, { application_attached: false }, { user_unlock: 'LOCKED' }, { user_unlock: 'UNAVAILABLE' },
    { boot_component: 'DISABLED' }, { construction_uncertain: true }, { reported_state: 'CLEANUP_PENDING' },
    { activation_state: 'OFF' }, { activation_state: 'LOADING' }, { activation_state: 'LEGACY_MISSING' },
    { activation_pending: true }, { activation_uncertain: true }]) {
    assert.equal(isPassiveReady(parsePassiveDump(dump({ ...fields, ...changes }))), false);
  }
  assert.throws(() => parsePassiveDump('UAC_LIFECYCLE_UNAVAILABLE_V1'));
  assert.throws(() => parsePassiveDump(dump() + dump()));
  assert.throws(() => parsePassiveDump(dump().replace('promoted=true', 'promoted=true\npromoted=true')));
  assert.throws(() => parsePassiveDump(dump({ ...fields, unexpected: false })));
  const missing = { ...fields }; delete missing.owner_phase;
  assert.throws(() => parsePassiveDump(dump(missing)));
  assert.throws(() => parsePassiveDump(dump({ ...fields, owner_phase: 'FAKE_READY' })));
});

const osHeader = 'ACTIVITY MANAGER SERVICES (dumpsys activity services)\n';
const foregroundFacts = '    isForeground=true foregroundId=5587267 types=0x00000010 foregroundNoti=Notification\n';
const osRecord = ({ user = 0, component = `${PACKAGE}/.background.ControllerForegroundService`, facts = foregroundFacts, id = 'abc' } = {}) =>
  `  * ServiceRecord{${id} u${user} ${component} c:${component.split('/')[0]}}\n${facts}`;
const activeServices = (records = osRecord(), user = 0) => `  User ${user} active services:\n${records}`;
const historicalService = (component = 'com.android.systemui/.SystemUIService') =>
  `  Last ANR service:\nServiceRecord{e8d6513 u0 ${component} c:android}\n    intent={cmp=${component}}\n    startForegroundCount=0\n startCommandResult=0\n\n`;

test('OS service result requires one active user0 target with exact connected-device type and notification ID', () => {
  const source = `${osHeader}${activeServices()}`;
  assert.equal(servicePresence(source), 'foreground');
  assert.equal(servicePresence(source.replaceAll('\n', '\r\n')), 'foreground');
  for (const facts of [foregroundFacts.replace('true', 'false'), foregroundFacts.replace('5587267', '1'),
    foregroundFacts.replace('5587267', '05587267'), foregroundFacts.replace('0x00000010', '0x00000020'),
    foregroundFacts.replace('0x00000010', '16'), foregroundFacts.replace('0x00000010', '0x100000010'),
    '', `${foregroundFacts}${foregroundFacts}`, `${foregroundFacts}    isForeground=false foregroundId=0 types=0x00000000\n`]) {
    assert.equal(servicePresence(`${osHeader}${activeServices(osRecord({ facts }))}`), 'other');
  }
});

test('actual API36 historical SystemUI ANR preamble does not veto the valid active controller record', () => {
  // Shape from 9e8e37f/111.log, shortened to fixed synthetic metadata. The ANR
  // record is global/unstarred; the current target has its own active heading.
  const current = osRecord({ id: '2e0727f', facts: `    packageName=${PACKAGE}\n    mAllowStart_noBinding=LOCKED_BOOT_COMPLETED\n${foregroundFacts} startCommandResult=1\n` });
  const source = `${osHeader}${historicalService()}${activeServices(current)}`;
  assert.equal(servicePresence(source), 'foreground');
});

test('normal launch keeps the real Chromium sandbox record and connection section separate', () => {
  // Companion structure from 9e8e37f/052.log, without paths or process identifiers.
  const sandboxName = `${PACKAGE}/org.chromium.content.app.SandboxedProcessService0:0`;
  const sandbox = osRecord({ component: sandboxName, id: 'def', facts: '    startRequested=false\n' });
  const connections = `  Connection bindings to services:\n  * ConnectionRecord{abc u0 CR WPRI ${sandboxName}:@abc flags=0x80000021}\n`;
  assert.equal(servicePresence(`${osHeader}${activeServices(sandbox + osRecord())}${connections}`), 'foreground');
});

test('history alone is neither active presence nor a completed absence observation', () => {
  const history = historicalService(`${PACKAGE}/.background.ControllerForegroundService`);
  assert.throws(() => servicePresence(`${osHeader}${history}`));
  assert.throws(() => servicePresence(`${osHeader}${historicalService()}`));
  assert.throws(() => servicePresence(osHeader));
  // Actual 85354bf/200.log empty shape, also valid after an independent ANR preamble.
  assert.equal(servicePresence(`${osHeader}  (nothing)\n`), 'absent');
  assert.equal(servicePresence(`${osHeader}${history}  (nothing)\n`), 'absent');
  assert.throws(() => servicePresence(`${osHeader}${activeServices()}  (nothing)\n`));
  assert.throws(() => servicePresence(`${osHeader}  (nothing)\n${activeServices()}`));
});

test('target-looking historical and global records cannot supply another active record foreground facts', () => {
  const target = `${PACKAGE}/.background.ControllerForegroundService`;
  const history = historicalService(target).replace('    startForegroundCount=0\n', foregroundFacts);
  const other = osRecord({ component: 'other.package/.ForegroundService', id: 'def' });
  assert.equal(servicePresence(`${osHeader}${history}${activeServices(other)}`), 'absent');
  const unready = osRecord({ facts: '    isForeground=false foregroundId=0 types=0x00000000\n' });
  assert.equal(servicePresence(`${osHeader}${history}${activeServices(unready + other)}`), 'other');
  assert.equal(servicePresence(`${osHeader}${activeServices(other + unready)}`), 'other');
  for (const name of ['Pending services', 'Restarting services', 'Destroying services', 'Connection bindings to services']) {
    const global = `  ${name}:\n${osRecord()}`;
    assert.equal(servicePresence(`${osHeader}${global}`), 'other');
    assert.equal(servicePresence(`${osHeader}${activeServices(other)}${global}`), 'other');
    assert.equal(servicePresence(`${osHeader}${activeServices(unready)}${global}`), 'other');
  }
  // Even convincing fields after a section boundary cannot be borrowed.
  assert.equal(servicePresence(`${osHeader}${activeServices(unready)}  Connection bindings to services:\n${other}`), 'other');
  assert.equal(servicePresence(`${osHeader}${activeServices()}  Connection bindings to services:\n${other}`), 'foreground');
});

test('active user sections cannot lend target identity or facts across users or duplicates', () => {
  const foreignTarget = activeServices(osRecord({ user: 10 }), 10);
  assert.equal(servicePresence(`${osHeader}${foreignTarget}`), 'other');
  assert.equal(servicePresence(`${osHeader}${activeServices()}${foreignTarget}`), 'other');
  const foreignOther = activeServices(osRecord({ user: 10, component: 'other.package/.ForegroundService' }), 10);
  assert.equal(servicePresence(`${osHeader}${foreignOther}${activeServices()}`), 'foreground');
  assert.equal(servicePresence(`${osHeader}${activeServices(osRecord() + osRecord({ id: 'def' }))}`), 'other');
  assert.throws(() => servicePresence(`${osHeader}${activeServices()}${activeServices()}`));
  assert.throws(() => servicePresence(`${osHeader}${activeServices(osRecord({ user: 10 }))}`));
  assert.throws(() => servicePresence(`${osHeader}${activeServices(osRecord(), 10)}`));
});

test('OS dump errors and malformed or truncated structure remain fail closed', () => {
  const valid = `${osHeader}${activeServices()}`;
  for (const source of ['', 'Permission Denial', 'No arbitrary service result', `${osHeader}${osRecord()}`,
    `${osHeader}  User 0 active services:\n`, valid.trimEnd(), valid.replace('ServiceRecord{abc', 'ServiceRecord{malformed'),
    valid.replace('User 0 active services:', 'User 00 active services:'), `${valid}${osHeader}`,
    `${valid}  Unknown service section:\n${osRecord()}`, `${valid}\0\n`, `${osHeader}${' '.repeat(512 * 1024)}\n`]) {
    assert.throws(() => servicePresence(source));
  }
  for (const failure of ['Permission Denial', 'java.lang.Exception', 'DUMP TIMEOUT', 'Failure while dumping the service', 'Error dumping service']) {
    assert.throws(() => servicePresence(`${valid}    ${failure}\n`));
    assert.throws(() => servicePresence(`${osHeader}  (nothing)\n${failure}\n`));
  }
});

const expected = { phase: 'initial', nonce: 'a'.repeat(32), appSha256: 'b'.repeat(64), testSha256: 'c'.repeat(64) };
const receipt = { ...expected, version: 1, package: PACKAGE, sdk: 36, abi: 'x86_64', bootCount: 1,
  ready: true, stopped: false, component: 'ENABLED', activation: 'ON', ownerPhase: 'READY', notificationPresent: true,
  checks: { initialWebViewReady: true, finalWebViewReady: true, recreatedWebViewReady: true, relaunchedWebViewReady: true,
    retiredNativeHttpReadRejected: true, sameCurrentNativeHttpReadSucceeded: true,
    retiredPostMessagePreservedReadyOwner: true, sameCurrentPostMessageStoppedOwner: true, staleOriginProbeRestartReady: true,
    sameOwnerAfterRecreate: true, sameOwnerAfterRepeatedStart: true, oldOwnerClosed: true,
    manualRelaunchStayedDisabled: true, explicitStartCreatedOwnerAfterClose: true } };
const output = (value = receipt) => `INSTRUMENTATION_STATUS: uac_lifecycle_receipt=${Buffer.from(JSON.stringify(value)).toString('base64')}\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n`;

test('one passing test and fresh exact APK-bound receipt are both mandatory', () => {
  assert.deepEqual(parseInstrumentation(output(), expected), receipt);
  for (const changes of [{ nonce: 'd'.repeat(32) }, { appSha256: 'e'.repeat(64) }, { testSha256: 'f'.repeat(64) },
    { phase: 'stop' }, { ready: false }, { ownerPhase: 'STARTING' }, { sdk: 35 }, { checks: {} }, { bootCount: -1 },
    { activation: undefined }, { activation: 'OFF' }, { activation: 'LOADING' }, { activation: 'LEGACY_MISSING' }]) {
    assert.throws(() => parseInstrumentation(output({ ...receipt, ...changes }), expected));
  }
  for (const text of [output().replace('1 test', '0 tests'), output().replace('1 test', '2 tests'),
    output().replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'), output() + output(),
    `${output()}FAILURES!!!`, 'OK (1 test)\nINSTRUMENTATION_CODE: -1']) assert.throws(() => parseInstrumentation(text, expected));
});

test('STOPPED receipt cannot replace actual CLOSED completion for explicit stop', () => {
  const selected = { ...expected, phase: 'stop' };
  const stopped = { ...receipt, ...selected, ready: false, stopped: true, component: 'DEFAULT', activation: 'OFF', ownerPhase: 'CLOSED', notificationPresent: false };
  assert.deepEqual(parseInstrumentation(output(stopped), selected), stopped);
  assert.throws(() => parseInstrumentation(output({ ...stopped, ownerPhase: 'NONE' }), selected));
  assert.throws(() => parseInstrumentation(output({ ...stopped, notificationPresent: true }), selected));
  for (const activation of [undefined, 'ON', 'LOADING', 'LEGACY_MISSING', 'UNAVAILABLE']) {
    assert.throws(() => parseInstrumentation(output({ ...stopped, activation }), selected));
  }
  assert.throws(() => parseInstrumentation(output({ ...stopped, component: 'DISABLED' }), selected));
});

test('native actor readiness cannot replace actual local document readiness after launch or recreation', () => {
  for (const phase of ['initial', 'verify-enabled', 'start']) {
    const selected = { ...expected, phase };
    const value = { ...receipt, ...selected };
    assert.deepEqual(parseInstrumentation(output(value), selected), value);
    const required = ['initialWebViewReady', 'finalWebViewReady', ...(phase === 'initial' ? ['recreatedWebViewReady', 'relaunchedWebViewReady'] : [])];
    for (const key of required) {
      for (const incorrect of [undefined, false, 'true', 1]) {
        assert.throws(() => parseInstrumentation(output({ ...value, checks: { ...value.checks, [key]: incorrect } }), selected));
      }
    }
  }
});

test('initial lifecycle receipt requires real current/retired physical-origin comparisons', () => {
  for (const key of ['retiredNativeHttpReadRejected', 'sameCurrentNativeHttpReadSucceeded',
    'retiredPostMessagePreservedReadyOwner', 'sameCurrentPostMessageStoppedOwner', 'staleOriginProbeRestartReady']) {
    for (const value of [undefined, false, 'true']) assert.throws(() => parseInstrumentation(output({ ...receipt, checks: { ...receipt.checks, [key]: value } }), expected));
  }
});

test('instrumentation manifest must target real product, not renderer or other package', () => {
  const xml = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="${TEST_PACKAGE}"><instrumentation android:name="androidx.test.runner.AndroidJUnitRunner" android:targetPackage="${PACKAGE}"/></manifest>`;
  assert.equal(inspectTestManifest(xml).targetPackage, PACKAGE);
  assert.throws(() => inspectTestManifest(xml.replace(`android:targetPackage="${PACKAGE}"`, `android:targetPackage="${PACKAGE}.gallery"`)));
  assert.throws(() => inspectTestManifest(xml.replace('AndroidJUnitRunner', 'OtherRunner')));
  assert.throws(() => inspectTestManifest(xml.replace('</manifest>', '<instrumentation/></manifest>')));
  assert.throws(() => inspectTestManifest(`<!DOCTYPE manifest>${xml}`));
});

test('first-unlock extension preserves the original ceiling and reserves bounded failure diagnostics', () => {
  assert.deepEqual(extensionCommandLimits(272), { operational: 752, diagnostics: 784 });
  assert.deepEqual(extensionCommandLimits(400), { operational: 880, diagnostics: 912 });
  // Source-counted optional reveal, worst bounded boot polling and both
  // observation retry sets must fit without consuming diagnostic capacity.
  const maximumNominalOperations = 223 + 180 + (9 * 4 * 2);
  assert.ok(extensionCommandLimits(272).operational - 272 >= maximumNominalOperations);
  for (const start of [0, -1, 401, 1.5, NaN]) assert.throws(() => extensionCommandLimits(start));
  assert.doesNotThrow(() => requireFirstUnlockDevice('0\n', 'file\n'));
  for (const [user, fbe] of [['10', 'file'], ['current', 'file'], ['0', 'block'], ['0', 'emulated'], ['0', '']]) {
    assert.throws(() => requireFirstUnlockDevice(user, fbe));
  }
});

test('framework user parsing cannot substitute keyguard visibility, another user or unlocking for unlocked', () => {
  const dump = state => `Users:\n  UserInfo{0:Owner:c13}\n    State: ${state}\n  Started users state: [0=${state}]\n`;
  assert.equal(frameworkUserState(dump('RUNNING_LOCKED')), 'RUNNING_LOCKED');
  assert.equal(frameworkUserState(dump('RUNNING_UNLOCKED')), 'RUNNING_UNLOCKED');
  assert.equal(frameworkUserState(dump('RUNNING_UNLOCKING')), 'RUNNING_UNLOCKING');
  for (const value of ['', 'isKeyguardLocked=true', dump('UNKNOWN'), dump('RUNNING_LOCKED').replace('[0=', '[10='),
    dump('RUNNING_LOCKED').replace(']', ', 10=RUNNING_UNLOCKED]'), dump('RUNNING_LOCKED') + dump('RUNNING_UNLOCKED'),
    `${dump('RUNNING_LOCKED')}Permission Denial`]) assert.throws(() => frameworkUserState(value));
});

const lockedFields = { ...fields, user_unlock: 'LOCKED', owner_present: false, owner_phase: 'NONE', reported_state: 'WAITING_FOR_UNLOCK' };
test('locked phase needs the promoted real FGS with no attempted native owner', () => {
  assert.equal(isPassiveWaitingForUnlock(parsePassiveDump(dump(lockedFields))), true);
  assert.equal(isPassiveReady(lockedFields), false);
  for (const [key, value] of Object.entries(lockedFields)) {
    const bad = typeof value === 'boolean' ? !value : key === 'boot_component' ? 'DISABLED' : 'UNAVAILABLE';
    assert.equal(isPassiveWaitingForUnlock({ ...lockedFields, [key]: bad }), false, key);
  }
});

const uiNode = (id, extra = {}, children = '') => `<node ${Object.entries({
  'resource-id': `com.android.systemui:id/${id}`, package: 'com.android.systemui', bounds: '[0,0][1080,2400]',
  enabled: 'true', clickable: 'false', password: 'false', text: '', ...extra,
}).map(([key, value]) => `${key}="${value}"`).join(' ')}>${children}</node>`;
const keypad = () => [...'0123456789', 'enter'].map((digit, index) => {
  const x = 100 + (index % 3) * 200, y = 400 + Math.floor(index / 3) * 150;
  return uiNode(digit === 'enter' ? 'key_enter' : `key${digit}`, { bounds: `[${x},${y}][${x + 100},${y + 100}]`, clickable: 'true' });
}).join('');
const pinXml = () => `<hierarchy rotation="0">${uiNode('root', {}, uiNode('keyguard_pin_view', {},
  uiNode('pinEntry', { bounds: '[100,200][800,300]', password: 'true' }) + keypad()))}</hierarchy>`;
const lockXml = () => `<hierarchy rotation="0">${uiNode('root', {}, uiNode('notification_panel', {}, uiNode('keyguard_long_press')))}</hierarchy>`;

test('only the fixed source-defined SystemUI PIN controls and derived bounds may produce input', () => {
  const screen = parseSystemUiHierarchy(pinXml());
  assert.equal(screen.kind, 'pin'); assert.equal(screen.empty, true);
  assert.deepEqual(screen.controls['0'], [150, 450]);
  assert.deepEqual(parseSystemUiHierarchy(lockXml()).swipe, [540, 1800, 540, 600, 400]);
  for (const xml of [pinXml().replaceAll('com.android.systemui', 'other.package'),
    pinXml().replace('keyguard_pin_view', 'unsupported_compose_view'), pinXml().replace('pinEntry', 'passwordEntry'),
    pinXml().replace('key_enter', 'other_enter'), pinXml().replace('password="true"', 'password="false"'),
    pinXml().replace('clickable="true"', 'clickable="false"'), pinXml().replace('[100,400][200,500]', '[100,400][100,500]'),
    pinXml().replace('[100,400][200,500]', '[100,400][9000,9500]'),
    pinXml().replace('</hierarchy>', `${uiNode('extra')}</hierarchy>`),
    pinXml().replace('key1"', 'key0"'), `<bad>${pinXml()}</bad>`, `<!DOCTYPE hierarchy>${pinXml()}`,
    lockXml().replace('keyguard_long_press', 'notification_content'), '', '<hierarchy rotation="0"/>']) {
    assert.throws(() => parseSystemUiHierarchy(xml));
  }
});

test('fresh shell XML completion and <=5s post-guard age are mandatory even with process exit0', () => {
  const path = hierarchyPath('a'.repeat(32), 0);
  assert.doesNotThrow(() => requireHierarchyCompletion(`UI hierchary dumped to: ${path}\n`, '', path));
  for (const [out, err] of [['', 'ERROR: null root node'], ['', ''],
    [`UI hierchary dumped to: ${path}`, 'ERROR: failed'], ['UI hierchary dumped to: /sdcard/old.xml', '']]) {
    assert.throws(() => requireHierarchyCompletion(out, err, path));
  }
  for (const index of [-1, 7, 0.5]) assert.throws(() => hierarchyPath('a'.repeat(32), index));
  assert.throws(() => hierarchyPath('../foreign', 0));
  assert.doesNotThrow(() => requireHierarchyFresh(100, 5100));
  for (const [before, after] of [[100, 5101], [100, 99], [-1, 0], [NaN, 1], [0, Infinity]]) {
    assert.throws(() => requireHierarchyFresh(before, after));
  }
});

test('secure-lock instrumentation needs actual before/after framework observations', () => {
  for (const phase of FIRST_UNLOCK_PHASES) {
    const expectedPhase = { ...expected, phase }, secure = phase === 'verify-first-unlock';
    const value = { ...receipt, phase, checks: { ...receipt.checks, deviceSecureBefore: secure, deviceSecureAfter: secure, userUnlockedAfter: true } };
    assert.equal(parseInstrumentation(output(value), expectedPhase).phase, phase);
    for (const key of ['deviceSecureBefore', 'deviceSecureAfter', 'userUnlockedAfter']) {
      for (const bad of [undefined, 'true', !value.checks[key]]) {
        assert.throws(() => parseInstrumentation(output({ ...value, checks: { ...value.checks, [key]: bad } }), expectedPhase));
      }
    }
  }
});

function unlockEvidence() {
  const beforeBoot = '12345678-1234-1234-1234-123456789abc', bootId = '22345678-1234-1234-1234-123456789abc', nonce = 'a'.repeat(32);
  const nativePhase = (phase, secure, bootCount, nonce) => ({ ...receipt, phase, bootCount, nonce,
    checks: { ...receipt.checks, deviceSecureBefore: secure, deviceSecureAfter: secure, userUnlockedAfter: true } });
  return { scope: 'DISPOSABLE_API36_X86_64_FIRST_UNLOCK', beforeBoot, bootId, nonce, setupConfirmed: true,
    before: nativePhase(FIRST_UNLOCK_PHASES[0], false, 2, 'b'.repeat(32)), after: nativePhase(FIRST_UNLOCK_PHASES[1], true, 3, 'c'.repeat(32)),
    locked: [100, 900, 1700].map(observedAtMonotonicMs => ({ bootId, frameworkUserState: 'RUNNING_LOCKED', presence: 'foreground',
      beforeActivityOrInstrumentation: true, native: { ...lockedFields }, observedAtMonotonicMs })),
    ui: [...SYNTHETIC_CI_PIN, 'enter'].map((_, index) => ({ kind: 'pin', bootId, xmlSha256: 'd'.repeat(64),
      path: hierarchyPath(nonce, index), action: index === SYNTHETIC_CI_PIN.length ? 'enter' : `digit-${index}`,
      point: [150, 450], inputCompletedAtMonotonicMs: 2000 + index * 500 })),
    ready: { bootId, frameworkUserState: 'RUNNING_UNLOCKED', presence: 'foreground', beforeActivityOrInstrumentation: true,
      native: { ...fields }, observedAtMonotonicMs: 5000 } };
}

test('first-unlock coverage rejects crossed boots, partial locked observations, fake readiness and missing postcheck', () => {
  const good = unlockEvidence();
  assert.doesNotThrow(() => requireFirstUnlockEvidence(good, good.ready));
  for (const change of [value => { value.beforeBoot = value.bootId; }, value => { value.setupConfirmed = false; },
    value => { value.locked.pop(); }, value => { value.locked[1].native.owner_present = true; },
    value => { value.locked[1].observedAtMonotonicMs = value.locked[0].observedAtMonotonicMs; },
    value => { value.locked[1].frameworkUserState = 'RUNNING_UNLOCKED'; }, value => { value.ui.pop(); },
    value => { value.ui.reverse(); }, value => { value.ui[1].path = value.ui[0].path; },
    value => { value.ui[0].kind = 'unknown'; }, value => { value.after.checks.deviceSecureAfter = false; },
    value => { value.after.appSha256 = 'e'.repeat(64); }, value => { value.after.nonce = value.before.nonce; },
    value => { value.before.activation = 'OFF'; }, value => { value.after.activation = 'LEGACY_MISSING'; },
    value => { value.after.bootCount += 1; }, value => { value.ready.bootId = value.beforeBoot; },
    value => { value.ready.frameworkUserState = 'RUNNING_UNLOCKING'; }, value => { value.ready.beforeActivityOrInstrumentation = false; }]) {
    const changed = structuredClone(good); change(changed);
    assert.throws(() => requireFirstUnlockEvidence(changed, changed.ready));
  }
  for (const [key, current] of Object.entries(fields)) {
    const changed = structuredClone(good);
    changed.ready.native[key] = typeof current === 'boolean' ? !current : key === 'boot_component' ? 'DISABLED' : 'UNAVAILABLE';
    assert.throws(() => requireFirstUnlockEvidence(changed, changed.ready), key);
  }
});
