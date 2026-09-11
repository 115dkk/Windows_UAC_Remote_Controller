// SPDX-License-Identifier: GPL-2.0-or-later
// Host parser/guard fixtures only; no ADB, device, camera or renderer execution.
import assert from 'node:assert/strict';
import test from 'node:test';
import { deflateSync } from 'node:zlib';
import { readFileSync } from 'node:fs';
import { SCANNER_CASES, SCANNER_STATES, SCANNER_IMAGES, scannerImagePath, parseScannerReceipt, requireScannerPrerequisite, checkScannerPng } from './android-pairing-scan-ci.mjs';
import { PACKAGE, TEST_PACKAGE } from './android-lifecycle-ci.mjs';
import { hierarchyPath } from './android-first-unlock.mjs';

const head = '1'.repeat(40), sourceHash = '2'.repeat(64), appHash = 'a'.repeat(64), testHash = 'b'.repeat(64);
const expected = name => ({ case: name, nonce: 'c'.repeat(32), appSha256: appHash, testSha256: testHash });
const receipt = name => ({ version: 1, ...expected(name), completed: true,
  checks: Object.fromEntries(SCANNER_CASES[name].checks.map(key => [key, true])) });
const output = value => `INSTRUMENTATION_STATUS: UAC_PAIRING_SCAN_RECEIPT_V1=${JSON.stringify(value)}\nOK (1 test)\nINSTRUMENTATION_CODE: -1\n`;

test('each real-scanner case requires exactly one completed test and its own complete bound receipt', () => {
  for (const name of Object.keys(SCANNER_CASES)) assert.deepEqual(parseScannerReceipt(output(receipt(name)), expected(name)), receipt(name));
  const text = output(receipt('native-dialog'));
  for (const invalid of [text + text, text.replace('1 test', '0 tests'), text.replace('1 test', '2 tests'),
    text.replace('INSTRUMENTATION_CODE: -1', 'INSTRUMENTATION_CODE: 0'), text + '\nFAILURES!!!',
    text + '\nNative entry deadline; completion unconfirmed', 'OK (1 test)\nINSTRUMENTATION_CODE: -1\n']) {
    assert.throws(() => parseScannerReceipt(invalid, expected('native-dialog')));
  }
});

test('crossed nonce, APK, case, version or additional/missing metadata cannot pass', () => {
  for (const change of [{ nonce: 'd'.repeat(32) }, { nonce: 'c' }, { appSha256: testHash }, { testSha256: appHash },
    { case: 'native-view-render' }, { version: 2 }, { completed: false }, { completed: 'true' }, { rawQr: 'forbidden' }]) {
    assert.throws(() => parseScannerReceipt(output({ ...receipt('native-dialog'), ...change }), expected('native-dialog')));
  }
  for (const key of Object.keys(receipt('native-dialog'))) {
    const value = receipt('native-dialog'); delete value[key];
    assert.throws(() => parseScannerReceipt(output(value), expected('native-dialog')));
  }
});

test('each native check is a real boolean; an unknown or duplicate-shadow check is rejected', () => {
  for (const name of Object.keys(SCANNER_CASES)) {
    for (const key of SCANNER_CASES[name].checks) for (const value of [false, null, 1, 'true', undefined]) {
      const changed = receipt(name); changed.checks[key] = value;
      assert.throws(() => parseScannerReceipt(output(changed), expected(name)));
    }
    const extra = receipt(name); extra.checks.unknown = true;
    assert.throws(() => parseScannerReceipt(output(extra), expected(name)));
  }
  const text = output(receipt('native-dialog'));
  assert.throws(() => parseScannerReceipt(text.replace('"completed":true', '"completed":false,"completed":true'), expected('native-dialog')));
  assert.throws(() => parseScannerReceipt(text.replace('"version":1', '"\\u0076ersion":1'), expected('native-dialog')));
});

test('fixture paths are only the fixed 68 native no-QR view states under one fresh nonce', () => {
  assert.equal(SCANNER_STATES.length, 17); assert.equal(SCANNER_IMAGES.length, 68);
  assert.equal(new Set(SCANNER_IMAGES).size, 68);
  assert.deepEqual(SCANNER_STATES.slice(9, 14), ['connecting', 'compare', 'waiting_pc', 'enrolled', 'failed']);
  for (const name of SCANNER_IMAGES) assert.equal(scannerImagePath('a'.repeat(32), name), `cache/pairing-scanner-fixtures/${'a'.repeat(32)}/${name}`);
  for (const name of ['../secret.png', '/tmp/secret.png', 'read-light-normal.png/../keys', 'unknown.png', 'READ-light-normal.png']) {
    assert.throws(() => scannerImagePath('a'.repeat(32), name));
  }
  for (const nonce of ['', '../', 'A'.repeat(32), 'a'.repeat(31)]) assert.throws(() => scannerImagePath(nonce, SCANNER_IMAGES[0]));
});

function native(ready) {
  return { promoted: true, attached: true, wanted: true, application_attached: true, owner_present: ready,
    destroyed: false, retiring: false, start_pending: false, construction_uncertain: false, start_rejected: false,
    activation_pending: false, activation_uncertain: false, owner_phase: ready ? 'READY' : 'NONE',
    reported_state: ready ? 'LOCAL_SETTINGS_READY' : 'WAITING_FOR_UNLOCK', user_unlock: ready ? 'UNLOCKED' : 'LOCKED',
    activation_state: 'ON', boot_component: 'DEFAULT' };
}
function prerequisite() {
  const bootId = '11111111-1111-1111-1111-111111111111', beforeBoot = '22222222-2222-2222-2222-222222222222';
  const phases = ['initial', 'stop', 'verify-stopped', 'verify-stopped', 'start', 'verify-no-secure-lock', 'verify-first-unlock']
    .map((phase, index) => ({ phase, nonce: String(index + 1).repeat(32), appSha256: appHash, testSha256: testHash,
      activation: 'ON', bootCount: index === 6 ? 2 : 1,
      checks: { deviceSecureBefore: index === 6, deviceSecureAfter: index === 6, userUnlockedAfter: true } }));
  const nonce = 'c'.repeat(32);
  const firstUnlock = { scope: 'DISPOSABLE_API36_X86_64_FIRST_UNLOCK', beforeBoot, bootId, nonce, setupConfirmed: true,
    before: phases[5], after: phases[6],
    locked: [0, 500, 1000].map(time => ({ bootId, frameworkUserState: 'RUNNING_LOCKED', presence: 'foreground',
      beforeActivityOrInstrumentation: true, observedAtMonotonicMs: time, native: native(false) })),
    ui: ['digit-0', 'digit-1', 'digit-2', 'digit-3', 'enter'].map((action, index) => ({ action, kind: 'pin', point: [15, 40],
      bootId, xmlSha256: 'f'.repeat(64), inputCompletedAtMonotonicMs: 2000 + index * 20, path: hierarchyPath(nonce, index) })),
    ready: { bootId, frameworkUserState: 'RUNNING_UNLOCKED', presence: 'foreground', beforeActivityOrInstrumentation: true,
      observedAtMonotonicMs: 3000, native: native(true) } };
  return { version: 1, classification: 'REAL_PRODUCT_EMULATOR_LIFECYCLE_AND_FIRST_UNLOCK', passed: true, firstUnlockVerified: true,
    physicalAuthenticationVerified: false, requestDeliveryVerified: false, cancelled: false, cleanupIncomplete: false,
    deviceOperationMayContinue: false, source: { commit: head, snapshotSha256: sourceHash }, phases, firstUnlock,
    apks: { [PACKAGE]: { path: '/fixture/product.apk', bytes: 123, sha256: appHash },
      [TEST_PACKAGE]: { path: '/fixture/test.apk', bytes: 456, sha256: testHash } } };
}

test('only the original same-source completed lifecycle admits the separate scanner extension', () => {
  assert.equal(requireScannerPrerequisite(prerequisite(), head, sourceHash), prerequisite().firstUnlock.bootId);
  for (const change of [{ passed: false }, { firstUnlockVerified: false }, { cancelled: true }, { cleanupIncomplete: true },
    { deviceOperationMayContinue: true }, { failure: 'old failure' }, { classification: 'SOURCE_INPUTS_ONLY' },
    { physicalAuthenticationVerified: true }, { phases: [] }, { firstUnlock: null }]) {
    assert.throws(() => requireScannerPrerequisite({ ...prerequisite(), ...change }, head, sourceHash));
  }
  assert.throws(() => requireScannerPrerequisite(prerequisite(), '0'.repeat(40), sourceHash));
  assert.throws(() => requireScannerPrerequisite(prerequisite(), head, '0'.repeat(64)));
});

test('old or incomplete original native facts cannot be replaced by a claimed passed flag', () => {
  for (const mutate of [value => { value.firstUnlock.ready.native.owner_phase = 'CLOSED'; },
    value => { value.firstUnlock.locked.pop(); }, value => { value.firstUnlock.ui.pop(); },
    value => { value.phases[0].appSha256 = 'e'.repeat(64); }, value => { value.apks[PACKAGE].bytes = 0; },
    value => { value.apks[PACKAGE].sha256 = 'e'.repeat(64); }, value => { value.apks.extra = value.apks[PACKAGE]; }]) {
    const value = prerequisite(); mutate(value);
    assert.throws(() => requireScannerPrerequisite(value, head, sourceHash));
  }
});

function crc(bytes) {
  let value = 0xffffffff;
  for (const byte of bytes) { value ^= byte; for (let bit = 0; bit < 8; bit++) value = (value >>> 1) ^ ((value & 1) ? 0xedb88320 : 0); }
  return (value ^ 0xffffffff) >>> 0;
}
function png() {
  const chunk = (name, data) => {
    const bytes = Buffer.alloc(data.length + 12); bytes.writeUInt32BE(data.length); bytes.write(name, 4, 'ascii'); data.copy(bytes, 8);
    bytes.writeUInt32BE(crc(bytes.subarray(4, -4)), bytes.length - 4); return bytes;
  };
  const header = Buffer.alloc(13); header.writeUInt32BE(390); header.writeUInt32BE(844, 4); header[8] = 8; header[9] = 6;
  return Buffer.concat([Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]), chunk('IHDR', header),
    chunk('IDAT', deflateSync(Buffer.alloc((390 * 4 + 1) * 844))), chunk('IEND', Buffer.alloc(0))]);
}
test('native PNG envelope checks exact bounds/dimensions but do not stand in for rendered pixel review', () => {
  const image = png(); assert.doesNotThrow(() => checkScannerPng(image));
  for (const bytes of [Buffer.alloc(0), Buffer.from('not a PNG'), image.subarray(0, image.length - 1), Buffer.concat([image, Buffer.from('extra')])]) {
    assert.throws(() => checkScannerPng(bytes));
  }
  for (const offset of [0, 8, 12, 16, 20]) { const changed = Buffer.from(image); changed[offset] ^= 1; assert.throws(() => checkScannerPng(changed)); }
});

test('scanner extension is separate and never repeats original credential setup or repairs device state', () => {
  const source = readFileSync(new URL('./android-pairing-scan-ci.mjs', import.meta.url), 'utf8');
  assert.ok(!source.includes("'set-pin'") && !source.includes("'reboot'") && !source.includes("'force-stop'") && !source.includes("'install'"));
  assert.ok(source.includes('requireScannerPrerequisite(prior'));
  assert.ok(source.includes('result.deviceOperationMayContinue = true'));
  assert.ok(source.includes('MAX_COMMANDS = 128'));
  assert.ok(source.includes('physicalCameraVerified: false'));
});
