// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { inspectBootManifest } from './verify-android-boot-manifest.mjs';
const xml = `<manifest xmlns:android="http://schemas.android.com/apk/res/android" package="dev.dkk115.uacremote">
${['RECEIVE_BOOT_COMPLETED','FOREGROUND_SERVICE','FOREGROUND_SERVICE_CONNECTED_DEVICE','CHANGE_NETWORK_STATE'].map((name) => `<uses-permission android:name="android.permission.${name}"/>`).join('')}
<application android:name=".ControllerApplication" android:allowBackup="false">
<receiver android:name=".background.ControllerBootReceiver" android:enabled="true" android:exported="false" android:directBootAware="true"><intent-filter>
${['LOCKED_BOOT_COMPLETED','BOOT_COMPLETED','MY_PACKAGE_REPLACED'].map((name) => `<action android:name="android.intent.action.${name}"/>`).join('')}
</intent-filter></receiver>
<service android:name=".background.ControllerForegroundService" android:exported="false" android:directBootAware="true" android:foregroundServiceType="connectedDevice" android:stopWithTask="false"/>
</application></manifest>`;
test('merged manifest enforces default-on private boot and same-process service declarations', () => {
  assert.equal(inspectBootManifest(xml).defaultBootEnabled, true);
  assert.equal(inspectBootManifest(xml.replace('connectedDevice', '0x00000010')).directBootAware, true);
});
test('disabled/exported/non-direct-boot/wrong-type components fail', () => {
  for (const bad of [xml.replace('android:enabled="true"', 'android:enabled="false"'), xml.replace('android:exported="false"','android:exported="true"'), xml.replace('android:directBootAware="true"','android:directBootAware="false"'), xml.replace('connectedDevice','dataSync'), xml.replace('android:stopWithTask="false"','android:stopWithTask="true"')]) assert.throws(() => inspectBootManifest(bad));
});
test('missing permissions/actions, another process and secret-backup enablement fail', () => {
  for (const bad of [xml.replace('android.permission.RECEIVE_BOOT_COMPLETED','wrong.permission'), xml.replace('android.intent.action.LOCKED_BOOT_COMPLETED','wrong.action'), xml.replace('<service ', '<service android:process=":other" '), xml.replace('<service ', '<service android:isolatedProcess="true" '), xml.replace('<application ', '<application android:enabled="false" '), xml.replace('android:allowBackup="false"','android:allowBackup="true"')]) assert.throws(() => inspectBootManifest(bad));
});
test('SDK-limited required permissions cannot satisfy the boot/foreground gate', () => {
  for (const permission of ['RECEIVE_BOOT_COMPLETED', 'FOREGROUND_SERVICE', 'FOREGROUND_SERVICE_CONNECTED_DEVICE', 'CHANGE_NETWORK_STATE']) {
    const original = `<uses-permission android:name="android.permission.${permission}"/>`;
    const limited = original.replace('/>', ' android:maxSdkVersion="28"/>');
    assert.throws(() => inspectBootManifest(xml.replace(original, limited)), /Missing unambiguous unbounded/);
    assert.throws(() => inspectBootManifest(xml.replace(original, limited + original)), /Missing unambiguous unbounded/);
    assert.throws(() => inspectBootManifest(xml.replace(original, original + original)), /Missing unambiguous unbounded/);
  }
});
test('malformed/DOCTYPE/oversized input cannot become a declaration pass', () => {
  for (const bad of ['', xml + '<broken>', '<!DOCTYPE manifest>' + xml, 'x'.repeat(1024 * 1024)]) assert.throws(() => inspectBootManifest(bad));
});
