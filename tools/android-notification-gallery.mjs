// SPDX-License-Identifier: GPL-2.0-or-later
import { execFileSync } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('../', import.meta.url));
const output = resolve(root, 'target/android-notification-gallery');
const application = 'dev.dkk115.uacremote.gallery';
const component = `${application}/dev.dkk115.uacremote.background.GalleryActivity`;
const serial = 'emulator-5554';
const source = 'src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/RequestNotificationRenderer.kt';
const background = 'src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background';
const resources = 'src-tauri/gen/android/app/src/main/res';
const productServiceSource = `${background}/ControllerForegroundService.kt`;
export const sharedRendererInputs = Object.freeze([
  ...['RequestNotificationRenderer.kt', 'ControllerStatusNotificationRenderer.kt', 'BootServicePolicy.kt', 'PolicyOwnerRules.kt', 'UntrustedDisplayText.kt'].map((name) => `${background}/${name}`),
  'src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/AppLanguage.kt',
  ...['values', 'values-ko', 'values-fr', 'values-de', 'values-ja', 'values-b+zh+Hans', 'values-b+zh+Hant',
    'values-es', 'values-pt', 'values-pt-rBR', 'values-pt-rPT', 'values-ar'].map((directory) => `${resources}/${directory}/strings.xml`),
  ...['xml/locale_config.xml', 'values/request_colors.xml', 'values-night/request_colors.xml', 'drawable/ic_request_notice.xml',
    'drawable/ic_request_approve.xml', 'drawable/ic_request_deny.xml', 'drawable/ic_request_details.xml', 'drawable/ic_controller_service.xml'].map((name) => `${resources}/${name}`),
]);
const apk = 'tools/android-notification-gallery/build/outputs/apk/debug/notification-renderer-gallery-only-debug.apk';
export const statusCases = Object.freeze({
  'status-preparing': Object.freeze({ state: 'preparing', resource: 'controller_service_preparing' }),
  'status-ready': Object.freeze({ state: 'local_settings_ready', resource: 'controller_service_ready' }),
  'status-stopping': Object.freeze({ state: 'stopped', resource: 'controller_service_stopping' }),
});
export const cases = Object.freeze(['sound', 'vibration', 'silent', 'restore', 'withdrawn', ...Object.keys(statusCases)]);
const actionLabels = ['승인', '거부', '자세히 보기'];
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const statusCase = (selected) => Object.hasOwn(statusCases, selected);
const xmlAttribute = (text) => text.replaceAll('&', '&amp;').replaceAll('"', '&quot;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll("'", '&apos;');
const hasUiText = (xml, text) => xml.includes(`text="${xmlAttribute(text)}"`);

export function statusResourceExpectations(xml) {
  if (typeof xml !== 'string' || Buffer.byteLength(xml) > 1024 * 1024) throw new Error('Missing bounded product resources.');
  const read = (name) => {
    const found = [...xml.matchAll(new RegExp(`<string name="${name}">([^<]*)</string>`, 'gu'))];
    if (found.length !== 1) throw new Error('Missing or duplicate status resource.');
    const text = found[0][1].trim();
    // These are fixed flat status labels. Refuse unsupported Android escaping
    // instead of guessing what getString would display after a future edit.
    if (!text || text.length > 512 || /[\\\r\n"]|&/u.test(text)) throw new Error('Unsupported status resource encoding.');
    return text;
  };
  const shared = { title: read('controller_service_title'), channelName: read('controller_service_channel'),
    channelDescription: read('controller_service_channel_description') };
  return Object.fromEntries(Object.entries(statusCases).map(([selected, value]) => [selected, { ...shared, body: read(value.resource) }]));
}

export function notificationActionsMatch(xml, selected) {
  if (!cases.includes(selected)) throw new Error('Unknown gallery case.');
  return statusCase(selected) ? !actionLabels.some((label) => hasUiText(xml, label))
    : selected === 'withdrawn' || actionLabels.every((label) => hasUiText(xml, label));
}

export function matchesRendererSourceReceipt(value, expected) {
  return value?.schema === 1 && value?.scope === 'exact-shared-renderer-inputs'
    && Array.isArray(value.files) && Array.isArray(expected) && value.files.length === sharedRendererInputs.length && expected.length === sharedRendererInputs.length
    && sharedRendererInputs.every((path, index) => {
      const file = value.files[index];
      return file?.path === path && expected[index]?.path === path
        && /^[0-9a-f]{64}$/u.test(file.sha256 ?? '') && file.sha256 === expected[index].sha256;
    });
}

export function checkStatusNativeReceipt(value, selected, expected) {
  if (!statusCase(selected) || !expected || !value || value.state !== statusCases[selected].state
      || value.notificationId !== 0x554143 || value.channelId !== 'controller_service_status_v1'
      || value.title !== expected.title || value.body !== expected.body || value.category !== 'service'
      || !Array.isArray(value.actions) || value.actions.length !== 0
      || value.ongoing !== true || value.onlyAlertOnce !== true || value.localOnly !== true || value.showWhen !== false
      || value.timeoutAfter !== 0 || value.fullScreen !== false || value.foregroundServicePromotionPerformed !== false
      || value.contentIntentImmutable !== true || value.channel?.importance !== 2 || value.channel?.sound !== false
      || value.channel?.vibration !== false || value.channel?.badge !== false
      || value.channel?.name !== expected.channelName || value.channel?.description !== expected.channelDescription) {
    throw new Error('Actual shared status renderer fields did not match the selected state.');
  }
}

export function onlyIsolatedEmulator(list) {
  const devices = list.trim().split(/\r?\n/u).slice(1).filter((line) => line.trim());
  return devices.length === 1 && devices[0].trim() === `${serial}\tdevice`;
}

export function checkNotificationUi(xml, selected, expectedStatus) {
  if (!cases.includes(selected) || typeof xml !== 'string' || xml.length > 1024 * 1024 || !xml.includes('<hierarchy')) throw new Error('Missing bounded actual UI dump.');
  const rootNode = xml.match(/<node\b[^>]*>/u)?.[0];
  if (!rootNode?.includes('package="com.android.systemui"')) throw new Error('The notification shade is not the observed UI.');
  const present = xml.includes('UAC 인증 요청');
  if (statusCase(selected)) {
    if (!expectedStatus || !hasUiText(xml, expectedStatus.title) || !hasUiText(xml, expectedStatus.body)
        || present || !notificationActionsMatch(xml, selected)) throw new Error('The selected action-free status notification is not visible.');
  } else if (selected === 'withdrawn') {
    if (present) throw new Error('Withdrawn test notification is still visible.');
  } else if (!present || !xml.includes('PowerShell')) {
    throw new Error('The actual system notification is not visible.');
  }
}

export function matchesNativeReceipt(value, selected, nonce) {
  return cases.includes(selected) && value?.case === selected && value?.nonce === nonce && value?.completed === true
    && value?.scope === 'shared-renderer-only; no production owner/authentication';
}

export function requireBroadcastBarrier(text) {
  if (typeof text !== 'string' || Buffer.byteLength(text, 'utf8') > 64 * 1024) {
    throw new Error('Missing bounded Android setup barrier output.');
  }
  // Android36: dispatch-looper barrier, pre-enqueued broadcast barrier, then
  // application-thread barrier. The final stage can give up and still return0;
  // only these exact ordered completion messages permit the FIRST launch.
  let stage = 0;
  for (const line of text.trim().split(/\r?\n/u)) {
    if (stage === 0 && /^Waiting for \d+ loopers to drain\.\.\.$/u.test(line)) continue;
    if (stage === 0 && line === 'Loopers drained!') { stage = 1; continue; }
    if (stage === 1 && /^Test barrier failed due to .+$/u.test(line)) continue;
    if (stage === 1 && line === 'Test barrier passed') { stage = 2; continue; }
    if (stage === 2 && /^Waiting for application barriers, at \d+ of \d+\.\.\.$/u.test(line)) continue;
    if (stage === 2 && line === 'Finished application barriers!') { stage = 3; continue; }
    throw new Error('Android did not confirm the exact setup barrier sequence.');
  }
  if (stage !== 3) throw new Error('Android did not finish the setup barriers.');
}

async function main() {
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.CI !== 'true') {
    throw new Error('This runner is restricted to the disposable GitHub CI emulator.');
  }
  let commandFailureSaved = false;
  const run = (args, binary = false, timeout = 15_000) => {
    try {
      return execFileSync('adb', ['-s', serial, ...args], {
        cwd: root, encoding: binary ? undefined : 'utf8', timeout, maxBuffer: 8 * 1024 * 1024,
        windowsHide: true,
      });
    } catch (error) {
      if (!commandFailureSaved) {
        commandFailureSaved = true;
        writeFileSync(resolve(output, 'command-failure.json'), JSON.stringify({ args, timeout,
          code: error.code ?? null, status: error.status ?? null, signal: error.signal ?? null,
          stdout: binary ? '[binary omitted]' : String(error.stdout ?? '').slice(0, 65536),
          stderr: String(error.stderr ?? '').slice(0, 65536) }, null, 2));
      }
      error.message = `adb ${args.slice(0, 4).join(' ')} failed: ${error.code ?? error.message}`;
      throw error;
    }
  };
  const inventory = execFileSync('adb', ['devices'], { encoding: 'utf8', timeout: 5000 });
  if (!onlyIsolatedEmulator(inventory)) throw new Error('Expected exactly the disposable emulator; refusing all other devices.');
  mkdirSync(output, { recursive: true });
  const receipt = { scope: 'actual Android renderer in isolated test APK; NOT production owner, auth, connection or UAC',
    commit: process.env.GITHUB_SHA, source, sourceSha256: null,
    sharedSources: [], productServiceSource, productServiceSourceSha256: null, productServiceLinked: false,
    apk, apkSha256: null, serial, sdk: null, abi: null, setupBarrier: null, captures: [], inputsUnchanged: false, completed: false, failure: null };
  const pause = () => new Promise((done) => setTimeout(done, 500));
  const diagnostics = (stage) => {
    // Read-only package-scoped OS state. Do not restart the Activity to observe
    // it: onCreate itself clears/posts and would change the cold-case behavior.
    writeFileSync(resolve(output, `${stage}-notifications.txt`), run(['shell', 'dumpsys', 'notification', '--package', application]));
    writeFileSync(resolve(output, `${stage}-trace.json`), run(['shell', 'run-as', application, 'cat', 'files/gallery-trace.json']));
  };
  try {
    receipt.sourceSha256 = hash(readFileSync(resolve(root, source)));
    receipt.sharedSources = sharedRendererInputs.map((path) => ({ path, sha256: hash(readFileSync(resolve(root, path))) }));
    receipt.productServiceSourceSha256 = hash(readFileSync(resolve(root, productServiceSource)));
    const statusExpectations = statusResourceExpectations(readFileSync(resolve(root, `${resources}/values-ko/strings.xml`), 'utf8'));
    receipt.apkSha256 = hash(readFileSync(resolve(root, apk)));
    receipt.sdk = run(['shell', 'getprop', 'ro.build.version.sdk']).trim();
    receipt.abi = run(['shell', 'getprop', 'ro.product.cpu.abi']).trim();
    run(['install', '-r', resolve(root, apk)]);
    // The gallery has intentionally Korean baseline assertions. Use the real
    // per-app OS preference rather than replacing production locale logic or
    // changing the whole emulator's language/SystemUI expansion controls.
    run(['shell', 'cmd', 'locale', 'set-app-locales', application, '--user', '0', '--locales', 'ko-KR']);
    receipt.appLanguage = { requested: 'ko-KR',
      osObservation: run(['shell', 'cmd', 'locale', 'get-app-locales', application, '--user', '0']).trim() };
    run(['shell', 'pm', 'grant', application, 'android.permission.POST_NOTIFICATIONS']);
    // Preserve the causal setup barrier against late PACKAGE_CHANGED reason5
    // cancellation, before the FIRST Activity/notification. Android36's fixed
    // barrier drains already-enqueued non-deferred work, unlike global idle
    // which can chase unrelated future Bluetooth/GMS/system broadcasts forever.
    // Flush dispatch loopers before taking that barrier and application threads
    // afterwards. No warmup, repost, fallback or notification lifetime change.
    const barrier = run(['shell', 'am', 'wait-for-broadcast-barrier', '--flush-broadcast-loopers', '--flush-application-threads'], false, 60_000);
    writeFileSync(resolve(output, 'setup-broadcast-barrier.txt'), barrier);
    requireBroadcastBarrier(barrier);
    receipt.setupBarrier = { kind: 'already-enqueued-broadcast-and-application-barriers',
      timeoutMs: 60_000, outputSha256: hash(barrier), completed: true };
    for (const selected of cases) {
      const nonce = randomUUID();
      run(['shell', 'cmd', 'statusbar', 'collapse']);
      run(['shell', 'am', 'start', '-W', '-n', component, '-f', '0x10008000', '--es', 'case', selected, '--es', 'nonce', nonce]);
      let native;
      for (let attempt = 0; attempt < 10; attempt += 1) {
        try {
          const text = run(['shell', 'run-as', application, 'cat', 'files/gallery-result.json']);
          native = JSON.parse(text);
        } catch { native = null; } // Activity may not have produced its receipt yet.
        if (matchesNativeReceipt(native, selected, nonce)) break;
        await pause();
      }
      if (!matchesNativeReceipt(native, selected, nonce)) throw new Error('Native renderer checks did not finish for this exact launch.');
      if (!matchesRendererSourceReceipt(native.sourceReceipt, receipt.sharedSources)) throw new Error('The installed gallery APK does not contain the exact current renderer/resource inputs.');
      if (statusCase(selected)) checkStatusNativeReceipt(native.statusNotification, selected, statusExpectations[selected]);
      diagnostics(`${selected}-posted`);
      run(['shell', 'cmd', 'statusbar', 'expand-notifications']);
      // App.onCreate/notify returning does not mean SystemUI finished its first
      // post-boot render. Await the actual shade/title/actions, not a fixed delay.
      const uiDeadline = Date.now() + 30_000;
      const observations = [];
      let xml = '';
      let consecutive = 0;
      for (let attempt = 0; attempt < 12 && Date.now() < uiDeadline; attempt += 1) {
        await pause();
        run(['shell', 'uiautomator', 'dump', '/sdcard/gallery-window.xml']);
        xml = run(['exec-out', 'cat', '/sdcard/gallery-window.xml']);
        let shown = false;
        try { checkNotificationUi(xml, selected, statusExpectations[selected]); shown = true; } catch { /* Retain actual failed observation. */ }
        const actionsMatch = notificationActionsMatch(xml, selected);
        consecutive = shown && actionsMatch ? consecutive + 1 : 0;
        observations.push({ attempt, shade: xml.includes('package="com.android.systemui"'), shown, actionsMatch,
          expectedActionCount: statusCase(selected) || selected === 'withdrawn' ? 0 : 3, xmlSha256: hash(xml) });
        diagnostics(`${selected}-observation-${attempt}`);
        if (consecutive >= 2) break;
        if (!xml.includes('package="com.android.systemui"')) {
          run(['shell', 'cmd', 'statusbar', 'expand-notifications']);
        } else if (shown && !actionsMatch && !statusCase(selected)) {
          // Expand only an observed system control; never guess a blind position.
          const controls = [...xml.matchAll(/<node\b[^>]*content-desc="Expand"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"[^>]*>/gu)];
          if (controls.length === 1) {
            const [, left, top, right, bottom] = controls[0];
            run(['shell', 'input', 'tap', String(Math.floor((Number(left) + Number(right)) / 2)), String(Math.floor((Number(top) + Number(bottom)) / 2))]);
          }
        }
      }
      const png = run(['exec-out', 'screencap', '-p'], true);
      if (!png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) throw new Error('Actual screenshot is not PNG.');
      writeFileSync(resolve(output, `${selected}.png`), png);
      writeFileSync(resolve(output, `${selected}.xml`), xml);
      diagnostics(`${selected}-captured`);
      receipt.captures.push({ case: selected, native, observations, pngSha256: hash(png), actualUiChecked: false });
      if (consecutive < 2) throw new Error('The actual notification did not remain visible across two observations.');
      checkNotificationUi(xml, selected, statusExpectations[selected]);
      if (!notificationActionsMatch(xml, selected)) {
        throw new Error('Actual notification actions did not match the selected case.');
      }
      // Accessibility can update before the compositor. Keep each image between
      // actual UI observations. ROOT must still inspect pixels independently.
      run(['shell', 'uiautomator', 'dump', '/sdcard/gallery-window.xml']);
      const after = run(['exec-out', 'cat', '/sdcard/gallery-window.xml']);
      writeFileSync(resolve(output, `${selected}-after.xml`), after);
      checkNotificationUi(after, selected, statusExpectations[selected]);
      if (!notificationActionsMatch(after, selected)) {
        throw new Error('Native action visibility changed during the actual screenshot capture.');
      }
      receipt.captures.at(-1).afterXmlSha256 = hash(after);
      receipt.captures.at(-1).actualUiChecked = true;
    }
    receipt.inputsUnchanged = receipt.sharedSources.every((file) => hash(readFileSync(resolve(root, file.path))) === file.sha256)
      && hash(readFileSync(resolve(root, productServiceSource))) === receipt.productServiceSourceSha256
      && hash(readFileSync(resolve(root, apk))) === receipt.apkSha256;
    if (!receipt.inputsUnchanged) throw new Error('Renderer, resource, service callsite or APK changed during capture.');
    receipt.completed = true;
  } catch (error) {
    receipt.failure = String(error.message).slice(0, 2000);
    // Diagnostic failure capture is separate and can never turn a failed case
    // into a success. No real device can reach this point past the inventory gate.
    try { writeFileSync(resolve(output, 'failure.png'), run(['exec-out', 'screencap', '-p'], true)); } catch { /* Preserve original failure. */ }
    try { writeFileSync(resolve(output, 'failure-logcat.txt'), run(['logcat', '-d', '-t', '200'])); } catch { /* Preserve original failure. */ }
    throw error;
  } finally {
    // Unlike the noisy tail of main/system buffers, these events carry actual
    // enqueue/cancellation reason/lifespan, visibility and alert observations.
    try { writeFileSync(resolve(output, 'notification-events.txt'), run(['logcat', '-b', 'events', '-d', '-v', 'threadtime', '-s',
      'notification_enqueue', 'notification_canceled', 'notification_visibility', 'notification_alert'])); } catch { /* Keep primary verdict. */ }
    writeFileSync(resolve(output, 'receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
