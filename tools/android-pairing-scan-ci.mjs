// SPDX-License-Identifier: GPL-2.0-or-later
// Additional real-product scanner checks AFTER the unchanged full lifecycle.
// No personal-device routing, credential input, QR injection or pairing claim.
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProver } from './prover-process.mjs';
import { PACKAGE, TEST_PACKAGE, SERIAL, SOURCE_ROOTS, requireCi, requireDevice, requireSameBoot, requireSameSource, commandEvidenceComplete } from './android-lifecycle-ci.mjs';
import { frameworkUserState, requireFirstUnlockDevice, requireFirstUnlockEvidence } from './android-first-unlock.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const CLASS = `${PACKAGE}.PairingScannerInstrumentationTest`;
const RUNNER = `${TEST_PACKAGE}/androidx.test.runner.AndroidJUnitRunner`;
const MAX_APK = 256 * 1024 * 1024;
const MAX_COMMANDS = 128;
const MAX_PNG = 8 * 1024 * 1024;
const requireThat = (value, message) => { if (!value) throw new Error(message); };
const sha = value => createHash('sha256').update(value).digest('hex');
const exactKeys = (value, keys) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).sort().join('|') === [...keys].sort().join('|');

export const SCANNER_CASES = Object.freeze({
  'native-dialog': {
    method: 'nativeDialogKeepsSecureFlagAndCancelsOnHostStop',
    checks: ['actualCurrentWebViewButtonOpened', 'secureWindow', 'cameraScanning', 'entryUnavailableWhileOpen',
      'closeReleased', 'entryRestoredAfterRelease', 'backgroundCancelled', 'originalActorPreserved'],
  },
  'native-view-render': {
    method: 'renderNativeViewsWithNoQrFixture',
    checks: ['ownedNativeViewOnly', 'noQrOrCameraFixture', 'normalAndLargeText', 'lightAndDark', 'allFixtureFilesWritten'],
  },
});
// Exact `PairingScannerState` order (PairingScanRules.kt): the enrollment ceremony states sit between
// `read` and `invalid`. The gallery multiplies these by light/dark and normal/large text: 17 x 4 = 68 PNGs.
export const SCANNER_STATES = Object.freeze(['preparing', 'permission_pending', 'permission_denied', 'permission_settings',
  'camera_unavailable', 'unavailable', 'scanning', 'reading', 'read', 'connecting', 'compare', 'waiting_pc', 'enrolled',
  'failed', 'invalid', 'expired', 'closed']);
export const SCANNER_IMAGES = Object.freeze(SCANNER_STATES.flatMap(state =>
  ['light', 'dark'].flatMap(theme => ['normal', 'large'].map(scale => `${state}-${theme}-${scale}.png`))));

export function scannerImagePath(nonce, name) {
  requireThat(/^[0-9a-f]{32}$/.test(nonce) && SCANNER_IMAGES.includes(name), 'Unknown scanner fixture path.');
  return `cache/pairing-scanner-fixtures/${nonce}/${name}`;
}

export function parseScannerReceipt(text, expected) {
  requireThat(typeof text === 'string' && Buffer.byteLength(text) <= 2 * 1024 * 1024 &&
    (text.match(/\bOK \(1 test\)/g) ?? []).length === 1 &&
    (text.match(/^INSTRUMENTATION_CODE: -1\s*$/gm) ?? []).length === 1 &&
    !/FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed|Native entry deadline; completion unconfirmed/.test(text),
  'Scanner instrumentation did not complete exactly one passing test.');
  const found = [...text.matchAll(/^INSTRUMENTATION_STATUS: UAC_PAIRING_SCAN_RECEIPT_V1=([^\r\n]+)\r?$/gm)];
  requireThat(found.length === 1 && Buffer.byteLength(found[0][1]) <= 8192, 'Missing, duplicate or oversized scanner receipt.');
  const value = JSON.parse(found[0][1]);
  // The fixed native JSONObject emits compact ASCII scalar/check fields. This
  // also rejects duplicate or escaped-shadow keys before their meaning is used.
  requireThat(JSON.stringify(value) === found[0][1], 'Noncanonical scanner receipt.');
  requireThat(SCANNER_CASES[expected.case] && exactKeys(value, ['version', 'case', 'nonce', 'appSha256', 'testSha256', 'completed', 'checks']) &&
    value.version === 1 && value.case === expected.case && value.nonce === expected.nonce && /^[0-9a-f]{32}$/.test(value.nonce) &&
    value.appSha256 === expected.appSha256 && /^[0-9a-f]{64}$/.test(value.appSha256) &&
    value.testSha256 === expected.testSha256 && /^[0-9a-f]{64}$/.test(value.testSha256) && value.completed === true,
  'Scanner receipt does not bind the exact original case and APKs.');
  const checks = SCANNER_CASES[value.case].checks;
  requireThat(exactKeys(value.checks, checks) && checks.every(key => value.checks[key] === true), 'Scanner native assertions are incomplete.');
  return value;
}

export function requireScannerPrerequisite(value, head, sourceSha256) {
  requireThat(value?.version === 1 && value.classification === 'REAL_PRODUCT_EMULATOR_LIFECYCLE_AND_FIRST_UNLOCK' &&
    value.passed === true && value.firstUnlockVerified === true && value.physicalAuthenticationVerified === false &&
    value.requestDeliveryVerified === false && value.cancelled === false && value.cleanupIncomplete === false &&
    value.deviceOperationMayContinue === false && !Object.hasOwn(value, 'failure') && /^[0-9a-f]{40}$/.test(head) &&
    value.source?.commit === head && value.source.snapshotSha256 === sourceSha256 && /^[0-9a-f]{64}$/.test(sourceSha256),
  'Scanner checks require the exact successful original lifecycle, without repair or new credentials.');
  requireThat(value.phases?.map(phase => phase.phase).join('|') ===
    'initial|stop|verify-stopped|verify-stopped|start|verify-no-secure-lock|verify-first-unlock', 'Original lifecycle phases are incomplete.');
  requireFirstUnlockEvidence(value.firstUnlock, value.firstUnlock?.ready);
  requireThat(exactKeys(value.apks, [PACKAGE, TEST_PACKAGE]), 'Original product and instrumentation APKs required.');
  for (const apk of Object.values(value.apks)) requireThat(typeof apk.path === 'string' && Number.isSafeInteger(apk.bytes) &&
    apk.bytes > 0 && apk.bytes <= MAX_APK && /^[0-9a-f]{64}$/.test(apk.sha256), 'Invalid original APK metadata.');
  requireThat(value.phases.every(phase => phase.appSha256 === value.apks[PACKAGE].sha256 &&
    phase.testSha256 === value.apks[TEST_PACKAGE].sha256 && /^[0-9a-f]{32}$/.test(phase.nonce)) &&
    JSON.stringify(value.firstUnlock.before) === JSON.stringify(value.phases[5]) &&
    JSON.stringify(value.firstUnlock.after) === JSON.stringify(value.phases[6]), 'Original native phases are not APK-bound.');
  return value.firstUnlock.bootId;
}

export function checkScannerPng(bytes) {
  requireThat(Buffer.isBuffer(bytes) && bytes.length >= 45 && bytes.length <= MAX_PNG &&
    bytes.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])) &&
    bytes.readUInt32BE(8) === 13 && bytes.toString('ascii', 12, 16) === 'IHDR' &&
    bytes.readUInt32BE(16) === 390 && bytes.readUInt32BE(20) === 844 &&
    bytes.subarray(-12).equals(Buffer.from([0, 0, 0, 0, 73, 69, 78, 68, 174, 66, 96, 130])),
  'Native fixture PNG envelope/dimensions are invalid; this does not replace pixel review.');
}

function regular(path, maximum, empty = false) {
  const stat = lstatSync(path);
  requireThat(stat.isFile() && !stat.isSymbolicLink() && stat.size >= (empty ? 0 : 1) && stat.size <= maximum,
    'Bounded regular source/evidence file required.');
  return stat;
}
function inside(path, parent) {
  const absolute = resolve(path), rel = relative(parent, absolute);
  requireThat(rel.length > 0 && !isAbsolute(rel) && rel !== '..' && !rel.startsWith(`..${sep}`) &&
    realpathSync(absolute) === absolute, 'Source or evidence path escapes its fixed owner.');
  return absolute;
}
async function fingerprint(path, maximum, empty = false) {
  const before = regular(path, maximum, empty), digest = createHash('sha256'); let bytes = 0;
  for await (const chunk of createReadStream(path)) { bytes += chunk.length; requireThat(bytes <= maximum, 'Input exceeded its bound.'); digest.update(chunk); }
  const after = regular(path, maximum, empty);
  requireThat(bytes === before.size && bytes === after.size && before.ino === after.ino && before.dev === after.dev &&
    before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs, 'Input changed during observation.');
  return { bytes, sha256: digest.digest('hex') };
}

export async function main(args = process.argv.slice(2)) {
  requireCi(process.env, process.platform, ROOT);
  requireThat(args.length === 0 && resolve(process.cwd()) === ROOT && Number(process.versions.node.split('.')[0]) === 24,
    'Use fixed Node24 checkout, with no device/path/case overrides.');
  const base = join(ROOT, 'target/android-lifecycle-ci');
  const runs = readdirSync(base, { withFileTypes: true }).filter(entry => /^run-[A-Za-z0-9]+$/.test(entry.name));
  requireThat(runs.length === 1 && runs[0].isDirectory() && !runs[0].isSymbolicLink(), 'One original completed lifecycle run required.');
  const priorPath = inside(join(base, runs[0].name, 'result.json'), base);
  regular(priorPath, 4 * 1024 * 1024);
  const sourcePath = inside(join(base, 'source-input.json'), base);
  regular(sourcePath, 4 * 1024 * 1024);
  const sourceBytes = readFileSync(sourcePath), source = JSON.parse(sourceBytes.toString('utf8'));
  const prior = JSON.parse(readFileSync(priorPath, 'utf8'));
  const boot = requireScannerPrerequisite(prior, process.env.GITHUB_SHA, sha(sourceBytes));
  const outRoot = join(ROOT, 'target/android-pairing-scan-ci');
  mkdirSync(outRoot, { recursive: true });
  requireThat(realpathSync(outRoot) === outRoot, 'Scanner evidence root must not redirect.');
  const directory = mkdtempSync(join(outRoot, 'run-'));
  const cancellation = new AbortController();
  const abort = () => cancellation.abort(new Error('Scanner CI cancelled.'));
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const result = { version: 1, classification: 'REAL_PRODUCT_NATIVE_SCANNER_AND_OWNED_VIEW_FIXTURES', passed: false,
    commit: process.env.GITHUB_SHA, priorResultSha256: sha(readFileSync(priorPath)), sourceSha256: sha(sourceBytes),
    bootId: boot, syntheticLockFromOriginalLifecycle: true, cameraGrantCommandCompleted: false, pregrantedCameraPermission: false,
    physicalCameraVerified: false, userPermissionFlowVerified: false, qrEnrollmentVerified: false,
    commands: [], cases: [], images: [], devices: [], cancelled: false, cleanupIncomplete: false, deviceOperationMayContinue: false };
  let index = 0;
  const deadline = performance.now() + 600_000;
  const command = async (binary, argv, timeoutMs = 15000, mutates = false, maximum = 512 * 1024, pngName = null) => {
    const remaining = deadline - performance.now();
    requireThat(!cancellation.signal.aborted && !result.deviceOperationMayContinue && index < MAX_COMMANDS && remaining > 0,
      'Stopped or exhausted scanner CI cannot continue.');
    const name = pngName ?? `${String(index + 1).padStart(3, '0')}.log`; index += 1;
    const path = join(directory, name);
    const value = await runProver(binary, argv, { cwd: ROOT, logPath: path, timeoutMs: Math.min(timeoutMs, Math.floor(remaining)),
      maxOutputBytes: maximum, signal: cancellation.signal });
    const record = await fingerprint(path, maximum, true).catch(() => ({ logUnavailable: true }));
    result.commands.push({ log: name, command: relative(ROOT, binary), args: argv, status: value.status, signal: value.signal,
      failed: Boolean(value.error), cancelled: value.cancelled, cleanupIncomplete: value.cleanupIncomplete, ...record });
    result.cancelled ||= value.cancelled; result.cleanupIncomplete ||= value.cleanupIncomplete;
    if (mutates && (value.error || value.cancelled || value.cleanupIncomplete || value.status !== 0)) result.deviceOperationMayContinue = true;
    requireThat(commandEvidenceComplete(value, record), 'Scanner command or its original transcript did not complete.');
    if (pngName !== null) {
      requireThat(value.stderr === '', 'Native PNG stream contains a diagnostic.');
      checkScannerPng(readFileSync(path));
      result.images.push({ name, ...record, width: 390, height: 844, scope: 'OWNED_NATIVE_VIEW_DUMMY_NO_CAMERA_NO_QR' });
    }
    return value.stdout;
  };
  let adbPath = null;
  // Bounded read-only failure context: which windows/activities exist and what the product and
  // the runtime logged. It never repeats the instrumentation, grants anything or mutates state.
  const captureFailureDiagnostics = async () => {
    if (adbPath === null || cancellation.signal.aborted) return;
    const captures = [
      ['dumpsys-window', ['shell', 'dumpsys', 'window', 'windows']],
      ['dumpsys-activity-top', ['shell', 'dumpsys', 'activity', 'top']],
      ['dumpsys-service', ['shell', 'dumpsys', 'activity', 'service', `${PACKAGE}/.background.ControllerForegroundService`]],
      ['dumpsys-package', ['shell', 'dumpsys', 'package', PACKAGE]],
      ['logcat-runtime', ['shell', 'logcat', '-d', '-v', 'threadtime', '-t', '4000', 'AndroidRuntime:E', 'System.err:W', 'RustStdoutStderr:I', 'UacBoot:I', 'chromium:W', 'cr_*:W', 'CameraX:W', 'Camera*:W', '*:S']],
      ['logcat-activity', ['shell', 'logcat', '-d', '-v', 'threadtime', '-t', '2000', 'ActivityManager:I', 'ActivityTaskManager:I', 'WindowManager:I', 'InputDispatcher:W', '*:S']],
    ];
    result.failureDiagnostics = [];
    for (const [name, argv] of captures) {
      const path = join(directory, `diag-${name}.log`);
      const value = await runProver(adbPath, ['-s', SERIAL, ...argv], { cwd: ROOT, logPath: path, timeoutMs: 20000,
        maxOutputBytes: 2 * 1024 * 1024, signal: cancellation.signal }).catch(() => null);
      const record = value ? await fingerprint(path, 2 * 1024 * 1024, true).catch(() => ({ logUnavailable: true })) : { logUnavailable: true };
      result.failureDiagnostics.push({ log: `diag-${name}.log`, args: argv, status: value?.status ?? null, failed: !value || Boolean(value.error), ...record });
    }
  };
  try {
    const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT;
    requireThat(sdk && isAbsolute(sdk) && (!process.env.ANDROID_HOME || !process.env.ANDROID_SDK_ROOT ||
      realpathSync(process.env.ANDROID_HOME) === realpathSync(process.env.ANDROID_SDK_ROOT)), 'One configured SDK required.');
    const adb = join(sdk, 'platform-tools/adb'); regular(adb, 64 * 1024 * 1024);
    adbPath = adb;
    const read = (argv, timeout, mutates = false, maximum, png) => command(adb, ['-s', SERIAL, ...argv], timeout, mutates, maximum, png);
    async function currentSources() {
      const commit = (await command('/usr/bin/git', ['rev-parse', 'HEAD'])).trim();
      requireThat(commit === process.env.GITHUB_SHA, 'Scanner source differs from Actions.');
      const paths = (await command('/usr/bin/git', ['ls-files', '-z', '--', ...SOURCE_ROOTS])).split('\0').filter(Boolean).sort();
      requireThat(paths.length > 0 && paths.length < 10000, 'Bounded scanner source inventory required.');
      const files = {};
      for (const path of paths) files[path] = await fingerprint(inside(join(ROOT, path), ROOT), 32 * 1024 * 1024, true);
      requireSameSource(source, { version: 1, commit, files });
    }
    async function guard() {
      const observed = { devices: await command(adb, ['devices']), qemu: await read(['shell', 'getprop', 'ro.kernel.qemu']),
        sdk: await read(['shell', 'getprop', 'ro.build.version.sdk']), abi: await read(['shell', 'getprop', 'ro.product.cpu.abi']),
        avd: await read(['emu', 'avd', 'name']) };
      requireDevice(observed);
      requireFirstUnlockDevice(await read(['shell', 'am', 'get-current-user']), await read(['shell', 'getprop', 'ro.crypto.type']));
      const actualBoot = (await read(['shell', 'cat', '/proc/sys/kernel/random/boot_id'])).trim();
      requireSameBoot(boot, actualBoot);
      requireThat(frameworkUserState(await read(['shell', 'dumpsys', 'user'])) === 'RUNNING_UNLOCKED', 'Original CI user is not unlocked.');
      result.devices.push({ ...observed, bootId: actualBoot, frameworkUserState: 'RUNNING_UNLOCKED' });
    }
    await currentSources();
    for (const apk of Object.values(prior.apks)) {
      const path = inside(apk.path, join(ROOT, 'src-tauri/gen/android/app/build/outputs/apk'));
      const actual = await fingerprint(path, MAX_APK);
      requireThat(actual.bytes === apk.bytes && actual.sha256 === apk.sha256, 'Original APK changed before scanner checks.');
    }
    await guard();
    const permission = await read(['shell', 'pm', 'grant', PACKAGE, 'android.permission.CAMERA'], 15000, true);
    requireThat(!/Exception|Failure|Permission Denial|Unknown command|Error:/i.test(permission), 'OS camera permission was not confirmed.');
    result.cameraGrantCommandCompleted = true; // Native test independently reads the real grant.
    for (const [name, scenario] of Object.entries(SCANNER_CASES)) {
      await guard();
      const expected = { case: name, nonce: randomBytes(16).toString('hex'),
        appSha256: prior.apks[PACKAGE].sha256, testSha256: prior.apks[TEST_PACKAGE].sha256 };
      const output = await read(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', `${CLASS}#${scenario.method}`,
        '-e', 'scan_nonce', expected.nonce, '-e', 'app_sha256', expected.appSha256, '-e', 'test_sha256', expected.testSha256,
        RUNNER], 180000, true, 2 * 1024 * 1024);
      if (output.includes('Native entry deadline; completion unconfirmed')) result.deviceOperationMayContinue = true;
      let receipt;
      try { receipt = parseScannerReceipt(output, expected); }
      catch (error) { result.deviceOperationMayContinue = true; throw error; }
      result.cases.push(receipt);
      if (name === 'native-dialog') result.pregrantedCameraPermission = true;
      await guard();
      if (name === 'native-view-render') for (const image of SCANNER_IMAGES) {
        await read(['exec-out', 'run-as', PACKAGE, 'cat', scannerImagePath(expected.nonce, image)], 15000, false, MAX_PNG, image);
      }
    }
    await currentSources();
    requireThat(result.cases.length === 2 && result.images.length === SCANNER_IMAGES.length, 'Scanner results are incomplete.');
    requireThat(!cancellation.signal.aborted && !result.cancelled && !result.cleanupIncomplete &&
      !result.deviceOperationMayContinue && performance.now() < deadline, 'Scanner completion crossed cancellation or its original budget.');
    result.passed = true;
  } catch (error) {
    result.failure = error instanceof Error ? error.message : 'Scanner CI failed.';
    await captureFailureDiagnostics().catch(() => { result.failureDiagnosticsIncomplete = true; });
    throw error;
  } finally {
    result.cancelled ||= cancellation.signal.aborted;
    if (result.cancelled || result.cleanupIncomplete || result.deviceOperationMayContinue || Object.hasOwn(result, 'failure')) result.passed = false;
    writeFileSync(join(directory, 'result.json'), `${JSON.stringify(result, null, 2)}\n`, { flag: 'wx' });
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(error => { console.error(`Android scanner CI: ${error.message}`); process.exitCode = 1; });
}
