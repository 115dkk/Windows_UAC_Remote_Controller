// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic parser/guard contracts only; these never run adb or establish native lifecycle behavior.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { AVD, PACKAGE, TEST_PACKAGE, inspectTestManifest, isPassiveReady, parseInstrumentation, parsePassiveDump,
  requireCi, requireDevice, requireSameSource, servicePresence, requireSameBoot, commandEvidenceComplete,
  finalizeLifecycleResult } from './android-lifecycle-ci.mjs';

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
  const state = { passed: true, cancelled: false, cleanupIncomplete: false, deviceOperationMayContinue: false };
  assert.equal(finalizeLifecycleResult({ ...state }, false).passed, true);
  for (const [change, aborted] of [[{}, true], [{ cancelled: true }, false], [{ cleanupIncomplete: true }, false],
    [{ deviceOperationMayContinue: true }, false], [{ failure: '' }, false]]) {
    assert.equal(finalizeLifecycleResult({ ...state, ...change }, aborted).passed, false);
  }
});

const fields = {
  promoted: true, attached: true, destroyed: false, retiring: false, user_unlock: 'UNLOCKED', boot_component: 'ENABLED',
  owner_present: true, owner_phase: 'READY', wanted: true, start_pending: false, application_attached: true,
  construction_uncertain: false, start_rejected: false, reported_state: 'LOCAL_SETTINGS_READY',
};
const dump = (value = fields) => `SERVICE ${PACKAGE}/.background.ControllerForegroundService\n  UAC_LIFECYCLE_BEGIN_V1\n${Object.entries(value).map(([key, v]) => `  ${key}=${v}\n`).join('')}  UAC_LIFECYCLE_END_V1\n`;

test('passive readiness requires all actual owner and FGS facts, not launch acceptance', () => {
  assert.equal(isPassiveReady(parsePassiveDump(dump())), true);
  for (const changes of [{ promoted: false }, { owner_phase: 'STARTING' }, { start_pending: true },
    { owner_present: false }, { application_attached: false }, { user_unlock: 'LOCKED' }, { user_unlock: 'UNAVAILABLE' },
    { boot_component: 'DISABLED' }, { construction_uncertain: true }, { reported_state: 'CLEANUP_PENDING' }]) {
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

test('OS service result requires actual connected-device foreground state and fixed notification ID', () => {
  const header = 'ACTIVITY MANAGER SERVICES (dumpsys activity services)\n';
  const service = `${header}  * ServiceRecord{abc u0 ${PACKAGE}/.background.ControllerForegroundService}\n`;
  assert.equal(servicePresence(`${service}isForeground=true foregroundId=5587267 types=0x00000010 foregroundNoti=Notification\n`), 'foreground');
  assert.equal(servicePresence(`${service}isForeground=false foregroundId=5587267 types=0x00000010\n`), 'other');
  assert.equal(servicePresence(header), 'absent');
  const other = '  * ServiceRecord{other u0 other.package/.ForegroundService}\nisForeground=true foregroundId=5587267 types=0x00000010\n';
  assert.equal(servicePresence(`${service}isForeground=false foregroundId=0 types=0x00000000\n${other}`), 'other');
  assert.equal(servicePresence(`${header}${other}  * ServiceRecord{target u0 ${PACKAGE}/.background.ControllerForegroundService}\nisForeground=false foregroundId=0 types=0x00000000\n`), 'other');
  assert.equal(servicePresence(`${service.replace('u0', 'u10')}isForeground=true foregroundId=5587267 types=0x00000010\n`), 'other');
  assert.equal(servicePresence(`${service}isForeground=true foregroundId=5587267 types=0x00000010\nisForeground=false foregroundId=0 types=0x00000000\n`), 'other');
  assert.equal(servicePresence(`${service}isForeground=true foregroundId=5587267 types=0x00000010\n${service.slice(header.length)}isForeground=true foregroundId=5587267 types=0x00000010\n`), 'other');
  for (const text of ['', 'Permission Denial', `${header}Last ANR service: stale`, 'No arbitrary service result']) assert.throws(() => servicePresence(text));
});

const expected = { phase: 'initial', nonce: 'a'.repeat(32), appSha256: 'b'.repeat(64), testSha256: 'c'.repeat(64) };
const receipt = { ...expected, version: 1, package: PACKAGE, sdk: 36, abi: 'x86_64', bootCount: 1,
  ready: true, stopped: false, component: 'ENABLED', ownerPhase: 'READY', notificationPresent: true,
  checks: { initialWebViewReady: true, finalWebViewReady: true, recreatedWebViewReady: true, relaunchedWebViewReady: true,
    sameOwnerAfterRecreate: true, sameOwnerAfterRepeatedStart: true, oldOwnerClosed: true,
    manualRelaunchStayedDisabled: true, explicitStartCreatedOwnerAfterClose: true } };
const output = (value = receipt) => `INSTRUMENTATION_STATUS: uac_lifecycle_receipt=${Buffer.from(JSON.stringify(value)).toString('base64')}\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n`;

test('one passing test and fresh exact APK-bound receipt are both mandatory', () => {
  assert.deepEqual(parseInstrumentation(output(), expected), receipt);
  for (const changes of [{ nonce: 'd'.repeat(32) }, { appSha256: 'e'.repeat(64) }, { testSha256: 'f'.repeat(64) },
    { phase: 'stop' }, { ready: false }, { ownerPhase: 'STARTING' }, { sdk: 35 }, { checks: {} }, { bootCount: -1 }]) {
    assert.throws(() => parseInstrumentation(output({ ...receipt, ...changes }), expected));
  }
  for (const text of [output().replace('1 test', '0 tests'), output().replace('1 test', '2 tests'),
    output().replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'), output() + output(),
    `${output()}FAILURES!!!`, 'OK (1 test)\nINSTRUMENTATION_CODE: -1']) assert.throws(() => parseInstrumentation(text, expected));
});

test('STOPPED receipt cannot replace actual CLOSED completion for explicit stop', () => {
  const selected = { ...expected, phase: 'stop' };
  const stopped = { ...receipt, ...selected, ready: false, stopped: true, component: 'DISABLED', ownerPhase: 'CLOSED', notificationPresent: false };
  assert.deepEqual(parseInstrumentation(output(stopped), selected), stopped);
  assert.throws(() => parseInstrumentation(output({ ...stopped, ownerPhase: 'NONE' }), selected));
  assert.throws(() => parseInstrumentation(output({ ...stopped, notificationPresent: true }), selected));
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

test('instrumentation manifest must target real product, not renderer or other package', () => {
  const xml = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="${TEST_PACKAGE}"><instrumentation android:name="androidx.test.runner.AndroidJUnitRunner" android:targetPackage="${PACKAGE}"/></manifest>`;
  assert.equal(inspectTestManifest(xml).targetPackage, PACKAGE);
  assert.throws(() => inspectTestManifest(xml.replace(`android:targetPackage="${PACKAGE}"`, `android:targetPackage="${PACKAGE}.gallery"`)));
  assert.throws(() => inspectTestManifest(xml.replace('AndroidJUnitRunner', 'OtherRunner')));
  assert.throws(() => inspectTestManifest(xml.replace('</manifest>', '<instrumentation/></manifest>')));
  assert.throws(() => inspectTestManifest(`<!DOCTYPE manifest>${xml}`));
});
