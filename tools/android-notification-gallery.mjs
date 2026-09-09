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
const apk = 'tools/android-notification-gallery/build/outputs/apk/debug/notification-renderer-gallery-only-debug.apk';
const cases = ['sound', 'vibration', 'silent', 'restore', 'withdrawn'];
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function onlyIsolatedEmulator(list) {
  const devices = list.trim().split(/\r?\n/u).slice(1).filter((line) => line.trim());
  return devices.length === 1 && devices[0].trim() === `${serial}\tdevice`;
}

export function checkNotificationUi(xml, selected) {
  if (xml.length > 1024 * 1024 || !xml.includes('<hierarchy')) throw new Error('Missing bounded actual UI dump.');
  const present = xml.includes('UAC 인증 요청');
  if (selected === 'withdrawn') {
    if (present) throw new Error('Withdrawn test notification is still visible.');
  } else if (!present || !xml.includes('PowerShell')) {
    throw new Error('The actual system notification is not visible.');
  }
}

export function matchesNativeReceipt(value, selected, nonce) {
  return value?.case === selected && value?.nonce === nonce && value?.completed === true
    && value?.scope === 'shared-renderer-only; no production owner/authentication';
}

async function main() {
  if (process.env.GITHUB_ACTIONS !== 'true' || process.env.CI !== 'true') {
    throw new Error('This runner is restricted to the disposable GitHub CI emulator.');
  }
  const run = (args, binary = false) => execFileSync('adb', ['-s', serial, ...args], {
    cwd: root, encoding: binary ? undefined : 'utf8', timeout: 15_000, maxBuffer: 8 * 1024 * 1024,
    windowsHide: true,
  });
  const inventory = execFileSync('adb', ['devices'], { encoding: 'utf8', timeout: 5000 });
  if (!onlyIsolatedEmulator(inventory)) throw new Error('Expected exactly the disposable emulator; refusing all other devices.');
  mkdirSync(output, { recursive: true });
  const receipt = { scope: 'actual Android renderer in isolated test APK; NOT production owner, auth, connection or UAC',
    commit: process.env.GITHUB_SHA, source, sourceSha256: null,
    apk, apkSha256: null, serial, sdk: null, abi: null, captures: [], completed: false, failure: null };
  const pause = () => new Promise((done) => setTimeout(done, 500));
  try {
    receipt.sourceSha256 = hash(readFileSync(resolve(root, source)));
    receipt.apkSha256 = hash(readFileSync(resolve(root, apk)));
    receipt.sdk = run(['shell', 'getprop', 'ro.build.version.sdk']).trim();
    receipt.abi = run(['shell', 'getprop', 'ro.product.cpu.abi']).trim();
    run(['install', '-r', resolve(root, apk)]);
    run(['shell', 'pm', 'grant', application, 'android.permission.POST_NOTIFICATIONS']);
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
      run(['shell', 'cmd', 'statusbar', 'expand-notifications']);
      // Wait only for the OS shade animation. Presence below is actually checked.
      await pause();
      run(['shell', 'uiautomator', 'dump', '/sdcard/gallery-window.xml']);
      let xml = run(['exec-out', 'cat', '/sdcard/gallery-window.xml']);
      if (selected !== 'withdrawn' && !['승인', '거부', '자세히 보기'].every((label) => xml.includes(`text="${label}"`))) {
        // Expand only an observed system control; never guess a blind position.
        const controls = [...xml.matchAll(/<node\b[^>]*content-desc="Expand"[^>]*bounds="\[(\d+),(\d+)\]\[(\d+),(\d+)\]"[^>]*>/gu)];
        if (controls.length === 1) {
          const [, left, top, right, bottom] = controls[0];
          run(['shell', 'input', 'tap', String(Math.floor((Number(left) + Number(right)) / 2)), String(Math.floor((Number(top) + Number(bottom)) / 2))]);
          await pause();
          run(['shell', 'uiautomator', 'dump', '/sdcard/gallery-window.xml']);
          xml = run(['exec-out', 'cat', '/sdcard/gallery-window.xml']);
        }
      }
      const png = run(['exec-out', 'screencap', '-p'], true);
      if (!png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]))) throw new Error('Actual screenshot is not PNG.');
      writeFileSync(resolve(output, `${selected}.png`), png);
      writeFileSync(resolve(output, `${selected}.xml`), xml);
      receipt.captures.push({ case: selected, native, pngSha256: hash(png), actualUiChecked: false });
      checkNotificationUi(xml, selected);
      if (selected !== 'withdrawn' && !['승인', '거부', '자세히 보기'].every((label) => xml.includes(`text="${label}"`))) {
        throw new Error('All three native notification actions were not visible in the actual UI.');
      }
      receipt.captures.at(-1).actualUiChecked = true;
    }
    receipt.completed = true;
  } catch (error) {
    receipt.failure = String(error.message).slice(0, 2000);
    // Diagnostic failure capture is separate and can never turn a failed case
    // into a success. No real device can reach this point past the inventory gate.
    try { writeFileSync(resolve(output, 'failure.png'), run(['exec-out', 'screencap', '-p'], true)); } catch { /* Preserve original failure. */ }
    try { writeFileSync(resolve(output, 'failure-logcat.txt'), run(['logcat', '-d', '-t', '200'])); } catch { /* Preserve original failure. */ }
    throw error;
  } finally {
    writeFileSync(resolve(output, 'receipt.json'), `${JSON.stringify(receipt, null, 2)}\n`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main().catch((error) => { console.error(error.message); process.exitCode = 1; });
}
