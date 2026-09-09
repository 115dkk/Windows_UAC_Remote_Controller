// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { checkNotificationUi, matchesNativeReceipt, onlyIsolatedEmulator } from './android-notification-gallery.mjs';

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
