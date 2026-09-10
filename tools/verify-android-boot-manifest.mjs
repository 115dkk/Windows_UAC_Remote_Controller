// SPDX-License-Identifier: GPL-2.0-or-later
// Inspect the decoded MERGED APK manifest, not just the source declaration.
import { JSDOM } from 'jsdom';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const ns = 'http://schemas.android.com/apk/res/android';
const packageName = 'dev.dkk115.uacremote';
const attr = (element, name) => element.getAttributeNS(ns, name);
const qualified = (name) => name?.startsWith('.') ? packageName + name : name;
const requireThat = (condition, message) => { if (!condition) throw new Error(message); };

export function inspectBootManifest(xml) {
  requireThat(typeof xml === 'string' && Buffer.byteLength(xml) < 1024 * 1024 && !/<!DOCTYPE/i.test(xml), 'Invalid bounded manifest XML.');
  const dom = new JSDOM(xml, { contentType: 'text/xml' });
  try {
    const document = dom.window.document;
    const manifest = document.documentElement;
    requireThat(manifest.tagName === 'manifest' && manifest.getAttribute('package') === packageName, 'Unexpected Android package.');
    const applications = [...manifest.children].filter((child) => child.tagName === 'application');
    requireThat(applications.length === 1, 'Expected one Application owner.');
    const application = applications[0];
    requireThat(qualified(attr(application, 'name')) === `${packageName}.ControllerApplication`, 'Missing actual Application owner.');
    requireThat(attr(application, 'enabled') === null || attr(application, 'enabled') === 'true', 'Application must default enabled.');
    requireThat(attr(application, 'allowBackup') === 'false', 'Private state backup must remain disabled.');
    const permissions = [...manifest.children].filter((child) => child.tagName === 'uses-permission');
    for (const permission of ['RECEIVE_BOOT_COMPLETED', 'FOREGROUND_SERVICE', 'FOREGROUND_SERVICE_CONNECTED_DEVICE', 'CHANGE_NETWORK_STATE']) {
      const matches = permissions.filter((declaration) => attr(declaration, 'name') === `android.permission.${permission}`);
      requireThat(matches.length === 1 && attr(matches[0], 'maxSdkVersion') === null, `Missing unambiguous unbounded boot/foreground requirement: ${permission}`);
    }
    function component(tag, suffix) {
      const matches = [...application.children].filter((child) => child.tagName === tag && qualified(attr(child, 'name')) === `${packageName}.background.${suffix}`);
      requireThat(matches.length === 1, `Missing/duplicate ${suffix}.`);
      const value = matches[0];
      requireThat(attr(value, 'exported') === 'false', `${suffix} must not be exported.`);
      requireThat(attr(value, 'directBootAware') === 'true', `${suffix} must handle locked boot explicitly.`);
      requireThat(!attr(value, 'process'), `${suffix} must share the single Application process.`);
      requireThat(attr(value, 'isolatedProcess') === null || attr(value, 'isolatedProcess') === 'false', `${suffix} must retain the app UID/key owner.`);
      requireThat(attr(value, 'enabled') === null || attr(value, 'enabled') === 'true', `${suffix} must default enabled.`);
      return value;
    }
    const receiver = component('receiver', 'ControllerBootWakeReceiver');
    const actions = new Set([...receiver.querySelectorAll('intent-filter > action')].map((action) => attr(action, 'name')));
    for (const action of ['LOCKED_BOOT_COMPLETED', 'BOOT_COMPLETED', 'MY_PACKAGE_REPLACED']) {
      requireThat(actions.has(`android.intent.action.${action}`), `Missing boot/update action ${action}.`);
    }
    const legacy = component('receiver', 'ControllerBootReceiver');
    requireThat(!legacy.querySelector('intent-filter'), 'Legacy component must be migration-only without automatic routes.');
    const service = component('service', 'ControllerForegroundService');
    requireThat(['connectedDevice', '16', '0x10', '0x00000010'].includes(attr(service, 'foregroundServiceType')), 'Expected only the connected-device foreground type.');
    requireThat(attr(service, 'stopWithTask') === null || attr(service, 'stopWithTask') === 'false', 'Removing the task must not stop the foreground service.');
    requireThat(!service.querySelector('intent-filter'), 'Service must have no generic external intent route.');
    return { packageName, defaultBootEnabled: true, privateComponents: true, directBootAware: true,
      scope: 'Merged APK declaration only; not actual boot, first unlock, OS permission, foreground promotion or native authentication execution.' };
  } finally { dom.window.close(); }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    requireThat(process.argv.length === 3, 'Pass one decoded APK manifest path.');
    process.stdout.write(`${JSON.stringify(inspectBootManifest(readFileSync(process.argv[2], 'utf8')), null, 2)}\n`);
  } catch (error) { process.stderr.write(`Android boot manifest gate: ${error.message}\n`); process.exitCode = 1; }
}
