// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { checkNotificationUi, matchesNativeReceipt, onlyIsolatedEmulator, requireBroadcastBarrier } from './android-notification-gallery.mjs';

test('native gallery rejects real, ambiguous, unauthorized and missing devices', () => {
  assert.equal(onlyIsolatedEmulator('List of devices attached\nemulator-5554\tdevice\n'), true);
  for (const list of ['List of devices attached\n', 'List of devices attached\nreal-phone\tdevice\n',
    'List of devices attached\nemulator-5554\tunauthorized\n',
    'List of devices attached\nemulator-5554\tdevice\nreal-phone\tdevice\n']) assert.equal(onlyIsolatedEmulator(list), false);
});
test('actual UI evidence cannot be absent or called withdrawn while still visible', () => {
  assert.doesNotThrow(() => checkNotificationUi('<hierarchy><node package="com.android.systemui" text="UAC 인증 요청 PowerShell"/></hierarchy>', 'sound'));
  assert.doesNotThrow(() => checkNotificationUi('<hierarchy><node package="com.android.systemui"/></hierarchy>', 'withdrawn'));
  assert.throws(() => checkNotificationUi('<hierarchy></hierarchy>', 'sound'));
  assert.throws(() => checkNotificationUi('<hierarchy><node text="UAC 인증 요청"/></hierarchy>', 'withdrawn'));
  assert.throws(() => checkNotificationUi('synthetic summary is not UI XML', 'sound'));
  assert.throws(() => checkNotificationUi('<hierarchy><node package="dev.dkk115.uacremote.gallery" text="UAC 인증 요청 PowerShell"/></hierarchy>', 'sound'));
  assert.throws(() => checkNotificationUi('<hierarchy><node package="dev.dkk115.uacremote.gallery"/></hierarchy>', 'withdrawn'));
});
test('same-case prior receipt cannot prove a fresh native launch', () => {
  const value = { case: 'sound', nonce: 'current', completed: true, scope: 'shared-renderer-only; no production owner/authentication' };
  assert.equal(matchesNativeReceipt(value, 'sound', 'current'), true);
  for (const invalid of [null, { ...value, nonce: 'previous' }, { ...value, completed: false },
    { ...value, case: 'restore' }, { ...value, scope: 'production authentication' }]) {
    assert.equal(matchesNativeReceipt(invalid, 'sound', 'current'), false);
  }
});
const completedBarrier = ['Loopers drained!', 'Test barrier passed', 'Finished application barriers!'];
test('cold launch requires all three actual ordered setup barrier completions', () => {
  assert.doesNotThrow(() => requireBroadcastBarrier(`${completedBarrier.join('\n')}\n`));
  assert.doesNotThrow(() => requireBroadcastBarrier('Waiting for 2 loopers to drain...\nLoopers drained!\nTest barrier failed due to synthetic-process queue\nTest barrier passed\nWaiting for application barriers, at 2 of 4...\nFinished application barriers!\n'));
  for (const value of ['', 'Unknown command: wait-for-broadcast-barrier', 'Permission denied',
    'All broadcast queues are idle!', 'Loopers drained!\nTest barrier passed',
    'Loopers drained!\nTest barrier passed\nGave up waiting for application barriers!',
    `${completedBarrier.join('\n')}\nError: later failure`]) {
    assert.throws(() => requireBroadcastBarrier(value));
  }
});

test('missing out-of-order duplicate or oversized barrier output cannot pass even with exit0', () => {
  for (let index = 0; index < completedBarrier.length; index += 1) {
    assert.throws(() => requireBroadcastBarrier(completedBarrier.filter((_, at) => at !== index).join('\n')));
    const duplicate = [...completedBarrier]; duplicate.splice(index, 0, completedBarrier[index]);
    assert.throws(() => requireBroadcastBarrier(duplicate.join('\n')));
  }
  assert.throws(() => requireBroadcastBarrier([...completedBarrier].reverse().join('\n')));
  assert.throws(() => requireBroadcastBarrier(`Test barrier passed\n${completedBarrier.join('\n')}`));
  assert.throws(() => requireBroadcastBarrier(`Error: rejected\n${completedBarrier.join('\n')}`));
  assert.throws(() => requireBroadcastBarrier(`${completedBarrier.join('\n')}\nWaiting for application barriers, at 1 of 2...`));
  assert.throws(() => requireBroadcastBarrier(`${'가'.repeat(32 * 1024)}\n${completedBarrier.join('\n')}`));
  assert.throws(() => requireBroadcastBarrier(null));
});

test('setup uses one fixedpoint barrier before first fixture launch with unchanged budget and UI gates', () => {
  const source = readFileSync(new URL('./android-notification-gallery.mjs', import.meta.url), 'utf8');
  const command = "run(['shell', 'am', 'wait-for-broadcast-barrier', '--flush-broadcast-loopers', '--flush-application-threads'], false, 60_000)";
  assert.equal(source.split(command).length - 1, 1);
  assert.ok(source.indexOf("run(['shell', 'pm', 'grant'") < source.indexOf(command));
  assert.ok(source.indexOf(command) < source.indexOf('for (const selected of cases)'));
  assert.ok(!source.includes("'wait-for-broadcast-idle'"));
  assert.ok(source.includes('if (consecutive < 2) throw'));
  assert.ok(source.includes('checkNotificationUi(after, selected)'));
  assert.ok(source.includes('matchesNativeReceipt(native, selected, nonce)'));
  const activity = readFileSync(new URL('./android-notification-gallery/src/main/java/dev/dkk115/uacremote/background/GalleryActivity.kt', import.meta.url), 'utf8');
  assert.ok(activity.includes('check(notification.timeoutAfter == 60_000L)'));
});
