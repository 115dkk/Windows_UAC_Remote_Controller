// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT dispatches this on a disposable GitHub emulator, never on a personal phone.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { setTimeout } from 'node:timers/promises';

assert.equal(process.env.GITHUB_ACTIONS, 'true');
assert.equal(process.env.CI, 'true');
assert.equal(process.env.RUNNER_OS, 'Linux');
const expected = process.env.STARTUP_EXPECTATION;
assert.ok(['current', 'alpha4-negative-control'].includes(expected));
const require = createRequire(resolve('product/package.json'));
const { JSDOM } = require('jsdom');
const adbPath = resolve(process.env.ANDROID_HOME, 'platform-tools/adb');
const serial = 'emulator-5554';
const pkg = 'dev.dkk115.uacremote';
const report = { source: expected, commit: readFileSync('evidence/product-commit.txt', 'utf8').trim(),
  release: true, minified: true, pregrantedCameraPermission: true,
  pairedPcCount: 0, physicalDeviceVerified: false, authenticationVerified: false, checks: [], passed: false };
let clicks = 0;
function adb(args, binary = false) {
  const value = spawnSync(adbPath, ['-s', serial, ...args], { encoding: binary ? undefined : 'utf8', timeout: 20000, maxBuffer: 8 * 1024 * 1024 });
  if (value.error || value.signal || value.status !== 0) throw new Error(`ADB command failed: ${args[0]}`);
  return value.stdout;
}
function dump() { return adb(['shell', 'dumpsys', 'activity', 'service', `${pkg}/.background.ControllerForegroundService`]); }
async function until(read, accept, description, attempts = 40) {
  for (let attempt = 0; attempt < attempts; attempt++) {
    const value = read();
    if (accept(value)) return value;
    await setTimeout(1000);
  }
  throw new Error(`Timed out: ${description}`);
}
function ui() {
  adb(['shell', 'uiautomator', 'dump', '/sdcard/uac-release-ui.xml']);
  const xml = adb(['shell', 'cat', '/sdcard/uac-release-ui.xml']);
  assert.ok(xml.length < 1024 * 1024);
  return { xml, document: new JSDOM(xml, { contentType: 'text/xml' }).window.document };
}
function nodeFor(view, label) {
  return [...view.document.querySelectorAll('node')].find(node => node.getAttribute('text') === label || node.getAttribute('content-desc') === label);
}
async function clickLabel(label) {
  const view = await until(ui, view => Boolean(nodeFor(view, label)), label, 15);
  const node = nodeFor(view, label);
  assert.equal(node.getAttribute('enabled'), 'true', label);
  assert.equal(node.getAttribute('clickable'), 'true', label);
  const bounds = /^\[(\d+),(\d+)\]\[(\d+),(\d+)\]$/.exec(node.getAttribute('bounds'));
  assert.ok(bounds, label);
  const [, left, top, right, bottom] = bounds.map(Number);
  assert.ok(right > left && bottom > top && right <= 4096 && bottom <= 4096);
  adb(['shell', 'input', 'keyevent', 'KEYCODE_WAKEUP']);
  const x = String(Math.floor((left + right) / 2)), y = String(Math.floor((top + bottom) / 2));
  // A short held touchscreen gesture, with the display awake, rather than a
  // zero-duration input that can be consumed merely waking the emulator.
  adb(['shell', 'input', 'touchscreen', 'swipe', x, y, x, y, '120']);
  clicks += 1;
  writeFileSync(`evidence/click-${clicks}-before.xml`, view.xml);
  writeFileSync(`evidence/click-${clicks}-after.xml`, ui().xml);
}
try {
  const manifest = readFileSync('evidence/manifest.xml', 'utf8');
  assert.match(manifest, /package="dev\.dkk115\.uacremote"/);
  assert.doesNotMatch(manifest, /android:debuggable="true"/);
  assert.ok(readFileSync('evidence/r8-mapping.txt', 'utf8').length > 1000);
  assert.equal(adb(['shell', 'getprop', 'ro.kernel.qemu']).trim(), '1');
  assert.match(adb(['emu', 'avd', 'name']), /^uac-release-startup-ci\r?\n/);
  assert.equal(adb(['shell', 'getprop', 'ro.product.cpu.abi']).trim(), 'x86_64');
  // Disposable emulator foreground-test preconditions. The configured secure
  // lock remains intact; no personal-device or product authentication setting.
  adb(['shell', 'svc', 'power', 'stayon', 'true']);
  adb(['shell', 'settings', 'put', 'system', 'screen_off_timeout', '1800000']);
  adb(['shell', 'input', 'keyevent', 'KEYCODE_WAKEUP']);
  // Public synthetic emulator lock, not a user credential or authentication test.
  adb(['shell', 'locksettings', 'set-pin', '2468']);
  adb(['install', resolve(process.env.RUNNER_TEMP, 'startup.apk')]);
  adb(['shell', 'pm', 'grant', pkg, 'android.permission.CAMERA']);
  adb(['shell', 'pm', 'grant', pkg, 'android.permission.POST_NOTIFICATIONS']);
  adb(['shell', 'am', 'start', '-W', '-n', `${pkg}/.MainActivity`]);
  writeFileSync('evidence/power.txt', adb(['shell', 'dumpsys', 'power']));
  writeFileSync('evidence/window-policy.txt', adb(['shell', 'dumpsys', 'window', 'policy']));
  const state = await until(dump, value => /owner_phase=(READY|FAILED|CLOSED)/.test(value), 'native owner startup');
  writeFileSync('evidence/owner.txt', state);
  if (expected === 'alpha4-negative-control') {
    assert.doesNotMatch(state, /owner_phase=READY/);
    const logs = adb(['logcat', '-d', '-s', 'UacBoot:I', 'UacScan:I', '*:S']);
    assert.match(logs, /OWNER_FIRST_FAILURE.*owner_step=(GENERATED_CONTRACT|BRIDGE_ABI).*owner_origin=INIT_EXCEPTION/);
    report.checks.push('old-minified-build-fails-native-abi-initialization');
  } else {
    assert.match(state, /owner_phase=READY/);
    report.checks.push('unpaired-native-owner-ready');
    const initial = await until(ui, view => Boolean(nodeFor(view, 'PC와 아직 연결하지 않았어요')), 'known-unpaired UI');
    assert.ok(nodeFor(initial, '기다리는 요청이 없어요'));
    writeFileSync('evidence/unpaired-ui.xml', initial.xml);
    await clickLabel('PC의 QR 코드 촬영');
    await until(ui, view => Boolean(nodeFor(view, 'PC 연결 QR 읽기')), 'native scanner opened');
    report.checks.push('actual-client-button-opens-native-scanner-before-pairing');
    await clickLabel('닫기');
    await clickLabel('알림 시간');
    await until(ui, view => Boolean(nodeFor(view, '휴대폰 승인 켜짐')), 'schedule owner panel');
    // The first policy choice can be below the connection and service cards on
    // this fixed Pixel 6 portrait emulator. Exercise scrolling, not DOM injection.
    adb(['shell', 'input', 'swipe', '540', '1800', '540', '850', '400']);
    const settings = await until(ui, view => Boolean(nodeFor(view, '항상')), 'default schedule before pairing');
    assert.ok(!settings.xml.includes('알림 시간 설정을 읽을 수 없어요'));
    writeFileSync('evidence/unpaired-settings-ui.xml', settings.xml);
    report.checks.push('notification-settings-available-before-pairing');
  }
  report.passed = true;
} finally {
  // Fixed-token diagnostics only; no general logcat or request/QR/key content.
  try { writeFileSync('evidence/owner-final.txt', dump()); } catch {}
  if (expected === 'current') try { writeFileSync('evidence/final-ui.xml', ui().xml); } catch {}
  try { writeFileSync('evidence/native-startup.log', adb(['logcat', '-d', '-s', 'UacBoot:I', 'UacScan:I', '*:S'])); } catch {}
  if (expected === 'current') try {
    const pid = adb(['shell', 'pidof', pkg]).trim();
    assert.match(pid, /^\d+$/);
    // This process is a fresh unpaired CI install; no request/QR/key is supplied.
    writeFileSync('evidence/client-errors.log', adb(['logcat', '-d', `--pid=${pid}`, '-s', 'chromium:E', 'AndroidRuntime:E', '*:S']));
  } catch {}
  writeFileSync('evidence/result.json', JSON.stringify(report, null, 2));
}
