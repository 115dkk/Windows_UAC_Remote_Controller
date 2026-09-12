// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import { cases, statusCases, sharedRendererInputs, statusResourceExpectations, notificationActionsMatch,
  checkNotificationUi, checkStatusNativeReceipt, matchesNativeReceipt, matchesRendererSourceReceipt,
  onlyIsolatedEmulator, requireBroadcastBarrier } from './android-notification-gallery.mjs';

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
  assert.ok(source.includes('checkNotificationUi(after, selected, statusExpectations[selected])'));
  assert.ok(source.includes('matchesNativeReceipt(native, selected, nonce)'));
  const activity = readFileSync(new URL('./android-notification-gallery/src/main/java/dev/dkk115/uacremote/background/GalleryActivity.kt', import.meta.url), 'utf8');
  assert.ok(activity.includes('check(notification.timeoutAfter == 60_000L)'));
});

const productResources = readFileSync(new URL('../src-tauri/gen/android/app/src/main/res/values/strings.xml', import.meta.url), 'utf8');
const expectedStatus = statusResourceExpectations(productResources);
const ui = (title, body, actions = '') => `<hierarchy><node package="com.android.systemui"><node text="${title}"/><node text="${body}"/>${actions}</node></hierarchy>`;

test('status cases are appended after the five unchanged request cases and require exact action-free system-shade text', () => {
  assert.deepEqual(cases.slice(0, 5), ['sound', 'vibration', 'silent', 'restore', 'withdrawn']);
  assert.deepEqual(cases.slice(5), ['status-preparing', 'status-ready', 'status-stopping']);
  for (const selected of Object.keys(statusCases)) {
    const expected = expectedStatus[selected];
    assert.doesNotThrow(() => checkNotificationUi(ui(expected.title, expected.body), selected, expected));
    assert.equal(notificationActionsMatch(ui(expected.title, expected.body), selected), true);
    assert.throws(() => checkNotificationUi(ui(expected.title, '다른 상태'), selected, expected));
    assert.throws(() => checkNotificationUi(ui('다른 앱', expected.body), selected, expected));
    assert.throws(() => checkNotificationUi(ui(expected.title, expected.body), selected));
    assert.throws(() => checkNotificationUi(ui(expected.title, expected.body).replace('com.android.systemui', 'dev.dkk115.uacremote.gallery'), selected, expected));
    for (const action of ['승인', '거부', '자세히 보기']) {
      const withAction = ui(expected.title, expected.body, `<node text="${action}"/>`);
      assert.equal(notificationActionsMatch(withAction, selected), false);
      assert.throws(() => checkNotificationUi(withAction, selected, expected));
    }
    assert.throws(() => checkNotificationUi(ui(expected.title, expected.body, '<node text="UAC 인증 요청"/>'), selected, expected));
  }
  assert.throws(() => checkNotificationUi(ui('휴대폰 승인', '준비'), 'unknown'));
  assert.throws(() => notificationActionsMatch('', 'unknown'));
  assert.ok(expectedStatus['status-ready'].body.includes('설정'), 'local settings readiness is not remote approval readiness');
});

test('status text comes from bounded exact product resources, never native result-selected expected strings', () => {
  assert.equal(expectedStatus['status-preparing'].title, expectedStatus['status-ready'].title);
  assert.notEqual(expectedStatus['status-preparing'].body, expectedStatus['status-ready'].body);
  assert.notEqual(expectedStatus['status-ready'].body, expectedStatus['status-stopping'].body);
  for (const changed of [null, '', 'x'.repeat(1024 * 1024 + 1),
    productResources.replace('name="controller_service_ready"', 'name="missing_ready"'),
    productResources + '<string name="controller_service_ready">duplicate</string>',
    productResources.replace(expectedStatus['status-ready'].body, 'unsupported &amp; formatting'),
  ]) assert.throws(() => statusResourceExpectations(changed));
});

function statusNative(selected) {
  const expected = expectedStatus[selected];
  return { state: statusCases[selected].state, notificationId: 0x554143, channelId: 'controller_service_status_v1',
    title: expected.title, body: expected.body, actions: [], category: 'service', ongoing: true, onlyAlertOnce: true,
    localOnly: true, showWhen: false, timeoutAfter: 0, fullScreen: false, foregroundServicePromotionPerformed: false,
    contentIntentImmutable: true, channel: { name: expected.channelName, description: expected.channelDescription,
      importance: 2, sound: false, vibration: false, badge: false } };
}

test('native status receipt checks channel properties, flags, mapping and absence of action or foreground claims', () => {
  for (const selected of Object.keys(statusCases)) {
    const valid = statusNative(selected), expected = expectedStatus[selected];
    assert.doesNotThrow(() => checkStatusNativeReceipt(valid, selected, expected));
    for (const changed of [null, { ...valid, state: 'remote_ready' }, { ...valid, notificationId: 1 },
      { ...valid, channelId: 'uac_requests_sound_v1' }, { ...valid, body: 'wrong state' },
      { ...valid, actions: ['승인'] }, { ...valid, category: 'event' }, { ...valid, ongoing: false },
      { ...valid, onlyAlertOnce: false }, { ...valid, localOnly: false }, { ...valid, showWhen: true },
      { ...valid, timeoutAfter: 60_000 }, { ...valid, fullScreen: true },
      { ...valid, foregroundServicePromotionPerformed: true }, { ...valid, contentIntentImmutable: false },
      { ...valid, channel: { ...valid.channel, importance: 4 } }, { ...valid, channel: { ...valid.channel, sound: true } },
      { ...valid, channel: { ...valid.channel, vibration: true } }, { ...valid, channel: { ...valid.channel, badge: true } },
    ]) assert.throws(() => checkStatusNativeReceipt(changed, selected, expected));
  }
});

test('APK source receipt requires every exact renderer, lightweight type and resource hash without omissions or duplicates', () => {
  const expected = sharedRendererInputs.map((path, index) => ({ path, sha256: index.toString(16).padStart(64, '0') }));
  const value = { schema: 1, scope: 'exact-shared-renderer-inputs', files: expected };
  assert.equal(sharedRendererInputs.length, 26);
  assert.equal(matchesRendererSourceReceipt(value, expected), true);
  const changedHash = structuredClone(value); changedHash.files[1].sha256 = 'f'.repeat(64);
  const duplicate = structuredClone(value); duplicate.files[1] = duplicate.files[0];
  for (const invalid of [null, { ...value, schema: 2 }, { ...value, scope: 'production service' },
    { ...value, files: expected.slice(1) }, { ...value, files: [...expected, expected[0]] },
    { ...value, files: new Array(26) }, changedHash, duplicate,
  ]) assert.equal(matchesRendererSourceReceipt(invalid, expected), false);
});

test('production foreground service delegates only presentation with exact original IDs, flags and state mappings', () => {
  const base = new URL('../src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/', import.meta.url);
  const renderer = readFileSync(new URL('ControllerStatusNotificationRenderer.kt', base), 'utf8');
  const service = readFileSync(new URL('ControllerForegroundService.kt', base), 'utf8');
  assert.ok(renderer.includes('const val CHANNEL_ID = "controller_service_status_v1"'));
  assert.ok(renderer.includes('const val NOTIFICATION_ID = 0x554143'));
  for (const mapping of ['WAITING_FOR_UNLOCK -> R.string.controller_service_locked', 'PREPARING -> R.string.controller_service_preparing',
    'LOCAL_SETTINGS_READY -> R.string.controller_service_ready', 'CLEANUP_PENDING -> R.string.controller_service_cleanup',
    'UNAVAILABLE -> R.string.controller_service_unavailable', 'STOPPED -> R.string.controller_service_stopping']) assert.ok(renderer.includes(mapping));
  for (const field of ['.setSmallIcon(R.drawable.ic_controller_service)', '.setContentIntent(open)', '.setCategory(Notification.CATEGORY_SERVICE)',
    '.setOngoing(true)', '.setOnlyAlertOnce(true)', '.setShowWhen(false)', '.setLocalOnly(true)',
    'Notification.FOREGROUND_SERVICE_IMMEDIATE', 'NotificationManager.IMPORTANCE_LOW', 'channel.setSound(null, null)',
    'channel.enableVibration(false)', 'channel.setShowBadge(false)']) assert.ok(renderer.includes(field));
  assert.doesNotMatch(renderer, /startForeground\(|startService\(|addAction\(|setFullScreenIntent\(|DeviceKeyStore|MainActivity|nativecore/u);
  assert.doesNotMatch(service, /Notification\.Builder\(|NotificationChannel\(/u);
  assert.ok(service.includes('ControllerStatusNotificationRenderer(this).ensureChannel()'));
  assert.ok(service.includes('return ControllerStatusNotificationRenderer(this).build(state, pending)'));
  assert.ok(service.includes('Intent(this, MainActivity::class.java).addFlags(Intent.FLAG_ACTIVITY_CLEAR_TOP or Intent.FLAG_ACTIVITY_SINGLE_TOP)'));
  assert.ok(service.includes('PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE'));
  assert.ok(service.includes('startForeground(ControllerStatusNotificationRenderer.NOTIFICATION_ID, notification(initial), ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)'));
});

test('isolated APK includes exact shared renderers and hash asset but no production service, owner, JNI, boot or network component', () => {
  const build = readFileSync(new URL('./android-notification-gallery/build.gradle.kts', import.meta.url), 'utf8');
  const activity = readFileSync(new URL('./android-notification-gallery/src/main/java/dev/dkk115/uacremote/background/GalleryActivity.kt', import.meta.url), 'utf8');
  const manifest = readFileSync(new URL('./android-notification-gallery/src/main/AndroidManifest.xml', import.meta.url), 'utf8');
  for (const name of ['RequestNotificationRenderer.kt', 'ControllerStatusNotificationRenderer.kt', 'BootServicePolicy.kt', 'PolicyOwnerRules.kt', 'drawable/ic_controller_service.xml']) assert.ok(build.includes(`"${name}"`));
  assert.ok(build.includes('check(bytes.contentEquals(original.readBytes()))'));
  assert.ok(build.includes('gallery-source-receipt.json'));
  assert.ok(build.includes('MessageDigest.getInstance("SHA-256")'));
  assert.ok(build.includes('include(rendererSources)') && build.includes('include(rendererResources)'));
  assert.ok(activity.includes('ControllerStatusNotificationRenderer(this)'));
  assert.ok(activity.includes('manager.notify(ControllerStatusNotificationRenderer.NOTIFICATION_ID, notification)'));
  assert.ok(activity.includes('check(notification.category == Notification.CATEGORY_SERVICE && notification.actions.isNullOrEmpty())'));
  assert.doesNotMatch(activity, /startForeground\(|startService\(|System\.loadLibrary|nativecore|enum class ControllerServiceState/u);
  assert.doesNotMatch(build, /ControllerForegroundService\.kt|ControllerApplication\.kt|ApplicationPolicyActor\.kt|jna|\.so"/u);
  assert.doesNotMatch(manifest, /<service\b|<receiver\b|android\.permission\.INTERNET|android\.permission\.FOREGROUND_SERVICE/u);
  const runner = readFileSync(new URL('./android-notification-gallery.mjs', import.meta.url), 'utf8');
  assert.ok(runner.includes('matchesRendererSourceReceipt(native.sourceReceipt, receipt.sharedSources)'));
  assert.ok(runner.includes('checkStatusNativeReceipt(native.statusNotification, selected, statusExpectations[selected])'));
  assert.ok(runner.includes('if (!receipt.inputsUnchanged) throw'));
});
