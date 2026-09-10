// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only REAL PRODUCT lifecycle; not the isolated renderer and not authentication proof.
import { createHash, randomBytes } from 'node:crypto';
import { createReadStream, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { setTimeout as delay } from 'node:timers/promises';
import { JSDOM } from 'jsdom';
import { runProver as runBoundedProcess } from './prover-process.mjs';
import { onlyIsolatedEmulator, requireBroadcastBarrier } from './android-notification-gallery.mjs';
import { inspectApk } from './verify-android-apk.mjs';
import { inspectBootManifest } from './verify-android-boot-manifest.mjs';

export const PACKAGE = 'dev.dkk115.uacremote';
export const TEST_PACKAGE = `${PACKAGE}.test`;
export const SERVICE = `${PACKAGE}/.background.ControllerForegroundService`;
export const MAIN = `${PACKAGE}/.MainActivity`;
export const AVD = 'uac-lifecycle-ci-36-x86_64';
export const SERIAL = 'emulator-5554';
export const PHASES = ['initial', 'verify-enabled', 'stop', 'verify-stopped', 'start'];
const TEST_CLASS = `${PACKAGE}.ControllerLifecycleTest`;
const RUNNER = `${TEST_PACKAGE}/androidx.test.runner.AndroidJUnitRunner`;
const MAX_APK = 256 * 1024 * 1024;
export const SOURCE_ROOTS = Object.freeze(['Cargo.toml', 'Cargo.lock', 'rust-toolchain.toml', 'package.json', 'package-lock.json', '.node-version', 'crates', 'src-tauri', 'ui', 'tools', 'vendor', '.github/workflows/android-lifecycle.yml']);
const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const requireThat = (value, message) => { if (!value) throw new Error(message); };
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const json = (path, value) => writeFileSync(path, `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx' });

export function requireCi(env, platform, cwd) {
  requireThat(platform === 'linux' && env.CI === 'true' && env.GITHUB_ACTIONS === 'true', 'Disposable Linux Actions runner required.');
  requireThat(/^[0-9a-f]{40}$/.test(env.GITHUB_SHA ?? '') && env.GITHUB_WORKSPACE === cwd, 'Exact Actions checkout required.');
  requireThat(!env.ADB_SERVER_SOCKET && (!env.ANDROID_SERIAL || env.ANDROID_SERIAL === SERIAL), 'External ADB routing is forbidden.');
}

export function requireDevice({ devices, qemu, sdk, abi, avd }) {
  requireThat(onlyIsolatedEmulator(devices) && qemu.trim() === '1' && sdk.trim() === '36' && abi.trim() === 'x86_64' &&
    avd.trim().replaceAll('\r', '') === `${AVD}\nOK`, 'Expected the sole fixed API36 x86_64 CI AVD.');
}

export function requireSameSource(before, after) {
  for (const value of [before, after]) requireThat(value?.files && Object.entries(value.files).every(([path, entry]) =>
    typeof path === 'string' && !isAbsolute(path) && !path.split('/').includes('..') &&
    Number.isSafeInteger(entry?.bytes) && entry.bytes >= 0 && entry.bytes <= 32 * 1024 * 1024 && /^[0-9a-f]{64}$/.test(entry.sha256)),
  'Malformed source file binding.');
  requireThat(before?.version === 1 && after?.version === 1 && /^[0-9a-f]{40}$/.test(before.commit) &&
    before.commit === after.commit && Object.keys(before.files ?? {}).length > 0 &&
    JSON.stringify(before.files) === JSON.stringify(after.files), 'Build source changed or snapshot is incomplete.');
}

export function requireSameBoot(expected, actual) {
  requireThat(typeof expected === 'string' && /^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(expected) && actual === expected,
    'Lifecycle observation crossed a kernel boot boundary.');
}

export function commandEvidenceComplete(value, transcript) {
  return value?.status === 0 && !value.error && !value.signal && value.cancelled === false && value.cleanupIncomplete === false &&
    transcript?.logUnavailable !== true && Number.isSafeInteger(transcript?.bytes) && transcript.bytes >= 0 && /^[0-9a-f]{64}$/.test(transcript?.sha256 ?? '');
}

export function finalizeLifecycleResult(result, aborted) {
  result.cancelled ||= aborted;
  if (result.cancelled !== false || result.cleanupIncomplete !== false || result.deviceOperationMayContinue !== false ||
      Object.hasOwn(result, 'failure')) result.passed = false;
  return result;
}

export function inspectTestManifest(xml) {
  requireThat(Buffer.byteLength(xml) < 1024 * 1024 && !/<!DOCTYPE/i.test(xml), 'Invalid bounded test manifest.');
  const dom = new JSDOM(xml, { contentType: 'text/xml' });
  try {
    const root = dom.window.document.documentElement;
    const entries = [...root.children].filter((node) => node.tagName === 'instrumentation');
    const attr = (node, name) => node.getAttributeNS('http://schemas.android.com/apk/res/android', name);
    requireThat(root.tagName === 'manifest' && root.getAttribute('package') === TEST_PACKAGE && entries.length === 1 &&
      attr(entries[0], 'name') === 'androidx.test.runner.AndroidJUnitRunner' && attr(entries[0], 'targetPackage') === PACKAGE,
    'Test APK must instrument the exact real product.');
    return { package: TEST_PACKAGE, targetPackage: PACKAGE, runner: RUNNER };
  } finally { dom.window.close(); }
}

export function parsePassiveDump(text) {
  requireThat(Buffer.byteLength(text) <= 512 * 1024 && !text.includes('UAC_LIFECYCLE_UNAVAILABLE_V1'), 'Passive dump unavailable.');
  const matches = [...text.matchAll(/UAC_LIFECYCLE_BEGIN_V1\r?\n([\s\S]*?)UAC_LIFECYCLE_END_V1/g)];
  requireThat(matches.length === 1, 'Expected one exact live service diagnostic.');
  const fields = Object.create(null);
  const booleanFields = ['promoted', 'attached', 'destroyed', 'retiring', 'owner_present', 'wanted', 'start_pending', 'application_attached', 'construction_uncertain', 'start_rejected'];
  const enums = {
    user_unlock: ['UNLOCKED', 'LOCKED', 'UNAVAILABLE'], boot_component: ['DEFAULT', 'ENABLED', 'DISABLED', 'UNAVAILABLE'],
    owner_phase: ['NONE', 'NEW', 'STARTING', 'READY', 'FAILED', 'STOPPING', 'CLOSED'],
    reported_state: ['WAITING_FOR_UNLOCK', 'PREPARING', 'LOCAL_SETTINGS_READY', 'CLEANUP_PENDING', 'UNAVAILABLE', 'STOPPED'],
  };
  for (const line of matches[0][1].trim().split(/\r?\n/)) {
    const match = /^\s*([a-z_]+)=([A-Z_]+|true|false)\s*$/.exec(line);
    requireThat(match && !Object.hasOwn(fields, match[1]), 'Malformed/duplicate passive field.');
    const [, key, value] = match;
    requireThat(booleanFields.includes(key) ? ['true', 'false'].includes(value) : enums[key]?.includes(value), 'Unknown passive field/value.');
    fields[key] = booleanFields.includes(key) ? value === 'true' : value;
  }
  requireThat(Object.keys(fields).length === 14, 'Incomplete passive diagnostic.');
  return fields;
}

export function isPassiveReady(fields) {
  return ['promoted', 'attached', 'owner_present', 'wanted', 'application_attached'].every((key) => fields[key] === true) &&
    ['destroyed', 'retiring', 'start_pending', 'construction_uncertain', 'start_rejected'].every((key) => fields[key] === false) &&
    fields.owner_phase === 'READY' && fields.reported_state === 'LOCAL_SETTINGS_READY' && fields.user_unlock === 'UNLOCKED' &&
    ['DEFAULT', 'ENABLED'].includes(fields.boot_component);
}

export function servicePresence(text) {
  requireThat(text.startsWith('ACTIVITY MANAGER SERVICES (dumpsys activity services)') &&
    !/Permission Denial|Exception|DUMP TIMEOUT|Last ANR service:/.test(text), 'Missing/failed OS service dump.');
  if (!text.includes(`${PACKAGE}/.background.ControllerForegroundService`)) return 'absent';
  const records = [...text.matchAll(/^\s*\* ServiceRecord\{([^}\r\n]+)\}[^\r\n]*\r?\n([\s\S]*?)(?=^\s*\* ServiceRecord\{|$(?![\s\S]))/gm)];
  const target = records.filter((match) => match[1].split(/\s+/).includes('u0') &&
    match[1].split(/\s+/).includes(`${PACKAGE}/.background.ControllerForegroundService`));
  if (target.length !== 1) return 'other';
  const facts = [...target[0][2].matchAll(/\bisForeground=(true|false) foregroundId=(\d+) types=(0x[0-9a-fA-F]+)\b/g)];
  return facts.length === 1 && facts[0][1] === 'true' && facts[0][2] === '5587267' &&
    Number(facts[0][3]) === 0x10 ? 'foreground' : 'other';
}

export function parseInstrumentation(text, expected) {
  requireThat(Buffer.byteLength(text) <= 2 * 1024 * 1024 && /\bOK \(1 test\)/.test(text) &&
    /^INSTRUMENTATION_CODE: -1\s*$/m.test(text) && !/FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed/.test(text), 'Native test did not complete exactly one passing test.');
  const receipts = [...text.matchAll(/^INSTRUMENTATION_STATUS: uac_lifecycle_receipt=([A-Za-z0-9+/=]+)\s*$/gm)];
  requireThat(receipts.length === 1 && receipts[0][1].length <= 5500, 'Missing/duplicate/oversized native receipt.');
  const bytes = Buffer.from(receipts[0][1], 'base64');
  requireThat(bytes.length <= 4096 && bytes.toString('base64') === receipts[0][1], 'Invalid receipt encoding.');
  const receipt = JSON.parse(bytes.toString('utf8'));
  requireThat(receipt.version === 1 && receipt.phase === expected.phase && PHASES.includes(receipt.phase) &&
    receipt.nonce === expected.nonce && receipt.appSha256 === expected.appSha256 && receipt.testSha256 === expected.testSha256 &&
    receipt.package === PACKAGE && receipt.sdk === 36 && receipt.abi === 'x86_64' &&
    Number.isSafeInteger(receipt.bootCount) && receipt.bootCount >= 0, 'Stale/crossed native receipt.');
  const stopped = receipt.phase === 'stop' || receipt.phase === 'verify-stopped';
  requireThat(receipt.ready === !stopped && receipt.stopped === stopped && receipt.notificationPresent === !stopped &&
    (stopped ? receipt.component === 'DISABLED' && ['NONE', 'CLOSED'].includes(receipt.ownerPhase) :
      ['DEFAULT', 'ENABLED'].includes(receipt.component) && receipt.ownerPhase === 'READY'), 'Receipt contradicts lifecycle phase.');
  for (const key of ['initialWebViewReady', 'finalWebViewReady']) {
    requireThat(receipt.checks?.[key] === true, 'Actual local application document readiness missing.');
  }
  if (receipt.phase === 'initial') for (const key of ['sameOwnerAfterRecreate', 'sameOwnerAfterRepeatedStart', 'oldOwnerClosed', 'manualRelaunchStayedDisabled', 'explicitStartCreatedOwnerAfterClose', 'recreatedWebViewReady', 'relaunchedWebViewReady',
    'retiredNativeHttpReadRejected', 'sameCurrentNativeHttpReadSucceeded', 'retiredPostMessagePreservedReadyOwner', 'sameCurrentPostMessageStoppedOwner', 'staleOriginProbeRestartReady']) {
    requireThat(receipt.checks?.[key] === true, 'Initial lifecycle assertion missing.');
  }
  if (receipt.phase === 'stop') requireThat(receipt.checks?.oldOwnerClosed === true && receipt.ownerPhase === 'CLOSED', 'Stop lacks actual owner closure.');
  return receipt;
}

export function nativeOperationUnconfirmed(output) {
  return output.includes('Native entry deadline; completion unconfirmed');
}

function regular(path, limit, allowEmpty = false) {
  const info = lstatSync(path);
  requireThat(info.isFile() && !info.isSymbolicLink() && info.size >= (allowEmpty ? 0 : 1) && info.size <= limit, 'Expected bounded regular evidence/input file.');
  return info;
}
async function hashFile(path, limit, allowEmpty = false) {
  const before = regular(path, limit, allowEmpty), digest = createHash('sha256');
  let size = 0;
  for await (const chunk of createReadStream(path)) { size += chunk.length; requireThat(size <= limit, 'Input grew beyond bound.'); digest.update(chunk); }
  const after = regular(path, limit, allowEmpty);
  requireThat(size === before.size && size === after.size && before.mtimeMs === after.mtimeMs && before.ctimeMs === after.ctimeMs &&
    before.dev === after.dev && before.ino === after.ino, 'Input changed during read.');
  return { bytes: size, sha256: digest.digest('hex') };
}
function apkFiles(path, found = [], bounds = { entries: 0 }, depth = 0) {
  requireThat(found.length <= 16 && depth <= 8, 'Excess APK output tree.');
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    requireThat(!entry.isSymbolicLink() && ++bounds.entries <= 512, 'Symlink/excess entries in APK output tree.');
    const child = join(path, entry.name);
    if (entry.isDirectory()) apkFiles(child, found, bounds, depth + 1);
    else if (entry.isFile() && entry.name.endsWith('.apk')) found.push(child);
  }
  return found;
}

export async function main(args = process.argv.slice(2)) {
  requireCi(process.env, process.platform, ROOT);
  requireThat(resolve(process.cwd()) === ROOT && Number(process.versions.node.split('.')[0]) === 24 &&
    (args.length === 0 || (args.length === 1 && args[0] === '--prepare')), 'Use the fixed checkout with Node24 and no path/device overrides.');
  const evidence = join(ROOT, 'target/android-lifecycle-ci');
  mkdirSync(evidence, { recursive: true });
  const directory = mkdtempSync(join(evidence, args.length ? 'prepare-' : 'run-'));
  const controller = new AbortController();
  const abort = () => controller.abort(new Error('CI lifecycle cancelled.'));
  process.once('SIGINT', abort); process.once('SIGTERM', abort);
  const result = { version: 1, classification: 'REAL_PRODUCT_UNLOCKED_EMULATOR_LIFECYCLE', passed: false,
    firstUnlockVerified: false, physicalAuthenticationVerified: false, requestDeliveryVerified: false,
    phases: [], observations: [], commands: [], cancelled: false, cleanupIncomplete: false, deviceOperationMayContinue: false };
  let commandIndex = 0;
  let readFailureDiagnostics = null;
  async function command(command, argv, timeoutMs = 15_000, mutatesDevice = false, maxOutputBytes = 512 * 1024) {
    requireThat(!controller.signal.aborted && commandIndex < 400 && !result.deviceOperationMayContinue, 'Cancelled/uncertain/bounded command sequence cannot continue.');
    const name = `${String(++commandIndex).padStart(3, '0')}.log`;
    const value = await runBoundedProcess(command, argv, { cwd: ROOT, logPath: join(directory, name), timeoutMs, maxOutputBytes, signal: controller.signal });
    const transcript = await hashFile(join(directory, name), maxOutputBytes, true).catch(() => ({ logUnavailable: true }));
    result.commands.push({ log: name, command: relative(ROOT, command), args: argv, status: value.status, signal: value.signal,
      failed: Boolean(value.error), cancelled: value.cancelled, cleanupIncomplete: value.cleanupIncomplete,
      ...transcript });
    result.cancelled ||= value.cancelled; result.cleanupIncomplete ||= value.cleanupIncomplete;
    // Terminating the local adb process does NOT terminate/prove completion of its Android operation.
    if (mutatesDevice && (value.error || value.cancelled || value.cleanupIncomplete || value.status !== 0)) result.deviceOperationMayContinue = true;
    requireThat(commandEvidenceComplete(value, transcript), 'Bounded command or its retained transcript failed verification.');
    return value.stdout;
  }
  async function sources() {
    const commit = (await command('/usr/bin/git', ['rev-parse', 'HEAD'])).trim();
    requireThat(commit === process.env.GITHUB_SHA, 'Checkout differs from Actions SHA.');
    const paths = (await command('/usr/bin/git', ['ls-files', '-z', '--', ...SOURCE_ROOTS])).split('\0').filter(Boolean).sort();
    requireThat(paths.length > 0 && paths.length < 10000, 'Unexpected bounded source inventory.');
    const files = {};
    for (const path of paths) {
      requireThat(!isAbsolute(path) && !path.split('/').includes('..') && realpathSync(join(ROOT, path)).startsWith(`${ROOT}${sep}`), 'Source escapes checkout.');
      files[path] = await hashFile(join(ROOT, path), 32 * 1024 * 1024, true);
    }
    return { version: 1, commit, files };
  }
  try {
    const current = await sources();
    if (args[0] === '--prepare') {
      const output = join(ROOT, 'src-tauri/gen/android/app/build/outputs/apk');
      requireThat(!existsSync(output) || apkFiles(output).length === 0, 'Prebuild snapshot refuses pre-existing APK outputs.');
      json(join(evidence, 'source-input.json'), current);
      result.classification = 'SOURCE_INPUTS_ONLY'; result.sourcePrepared = true;
      return; // Operational preparation is not a passing lifecycle test.
    }
    const sourceFile = join(evidence, 'source-input.json'); regular(sourceFile, 4 * 1024 * 1024);
    requireSameSource(JSON.parse(readFileSync(sourceFile, 'utf8')), current);
    result.source = { commit: current.commit, snapshotSha256: sha(readFileSync(sourceFile)) };
    const sdk = process.env.ANDROID_HOME || process.env.ANDROID_SDK_ROOT;
    requireThat(sdk && isAbsolute(sdk) && (!process.env.ANDROID_HOME || !process.env.ANDROID_SDK_ROOT ||
      realpathSync(process.env.ANDROID_HOME) === realpathSync(process.env.ANDROID_SDK_ROOT)), 'One configured Android SDK required.');
    const adb = join(sdk, 'platform-tools/adb'), analyzer = join(sdk, 'cmdline-tools/latest/bin/apkanalyzer');
    regular(adb, 64 * 1024 * 1024); regular(analyzer, 1024 * 1024);
    async function read(argv, timeout) { return command(adb, ['-s', SERIAL, ...argv], timeout); }
    async function guard() {
      requireDevice({ devices: await command(adb, ['devices']), qemu: await read(['shell', 'getprop', 'ro.kernel.qemu']),
        sdk: await read(['shell', 'getprop', 'ro.build.version.sdk']), abi: await read(['shell', 'getprop', 'ro.product.cpu.abi']),
        avd: await read(['emu', 'avd', 'name']) });
    }
    async function mutate(argv, timeout = 30_000, limit) {
      await guard(); return command(adb, ['-s', SERIAL, ...argv], timeout, true, limit);
    }
    const selected = {};
    for (const path of apkFiles(join(ROOT, 'src-tauri/gen/android/app/build/outputs/apk'))) {
      const metadata = await hashFile(path, MAX_APK);
      const xml = await command(analyzer, ['manifest', 'print', path]);
      const dom = new JSDOM(xml, { contentType: 'text/xml' });
      const packageName = dom.window.document.documentElement.getAttribute('package'); dom.window.close();
      if (packageName === PACKAGE || packageName === TEST_PACKAGE) {
        requireThat(!selected[packageName], 'Ambiguous duplicate product/test APK.');
        const manifest = packageName === PACKAGE ? inspectBootManifest(xml) : inspectTestManifest(xml);
        if (packageName === PACKAGE) requireThat(/android:debuggable="true"/.test(xml), 'Only debug product APK permitted.');
        selected[packageName] = { path, ...metadata, manifest };
        writeFileSync(join(directory, packageName === PACKAGE ? 'app-manifest.xml' : 'test-manifest.xml'), xml, { flag: 'wx' });
      } else throw new Error('Unexpected APK package in fixed product build output.');
    }
    requireThat(selected[PACKAGE] && selected[TEST_PACKAGE], 'Both real product and instrumentation APKs required.');
    selected[PACKAGE].nativeInspection = await inspectApk(selected[PACKAGE].path, 'x86_64');
    result.apks = selected;
    await guard();
    readFailureDiagnostics = async () => {
      await guard();
      await read(['shell', 'dumpsys', 'activity', 'services', PACKAGE]);
      await read(['shell', 'dumpsys', 'activity', 'service', SERVICE]);
      await read(['shell', 'logcat', '-d', '-v', 'threadtime', '-t', '200', 'AndroidRuntime:E', 'System.err:W', '*:S']);
    };
    for (const packageName of [PACKAGE, TEST_PACKAGE]) {
      const installed = await read(['shell', 'pm', 'list', 'packages', packageName]);
      requireThat(!installed.split(/\r?\n/).includes(`package:${packageName}`), 'Initial run requires a fresh AVD; never clear/repair existing app data.');
    }
    for (const packageName of [PACKAGE, TEST_PACKAGE]) {
      requireThat(/\bSuccess\s*$/.test(await mutate(['install', '-t', selected[packageName].path])), 'APK install was not confirmed.');
    }
    await mutate(['shell', 'pm', 'grant', PACKAGE, 'android.permission.POST_NOTIFICATIONS']);
    async function barrier() {
      requireBroadcastBarrier(await read(['shell', 'am', 'wait-for-broadcast-barrier', '--flush-broadcast-loopers', '--flush-application-threads'], 60_000));
    }
    await barrier();
    async function phase(name) {
      requireThat(PHASES.includes(name), 'Unknown instrumentation phase.');
      const expected = { phase: name, nonce: randomBytes(16).toString('hex'), appSha256: selected[PACKAGE].sha256, testSha256: selected[TEST_PACKAGE].sha256 };
      const output = await mutate(['shell', 'am', 'instrument', '-w', '-r', '-e', 'class', TEST_CLASS,
        '-e', 'phase', name, '-e', 'nonce', expected.nonce, '-e', 'app_sha256', expected.appSha256,
        '-e', 'test_sha256', expected.testSha256, RUNNER], 180_000, 2 * 1024 * 1024);
      if (nativeOperationUnconfirmed(output)) {
        result.deviceOperationMayContinue = true;
        throw new Error('Native test operation completion remains unconfirmed.');
      }
      result.phases.push(parseInstrumentation(output, expected));
    }
    async function bootId() {
      const value = (await read(['shell', 'cat', '/proc/sys/kernel/random/boot_id'])).trim();
      requireThat(/^[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(value), 'Missing actual kernel boot identity.'); return value;
    }
    async function observe(label, ready, beforeLaunch, expectedBoot = null) {
      const startBoot = await bootId();
      if (expectedBoot !== null) requireSameBoot(expectedBoot, startBoot);
      const deadline = Date.now() + 45_000;
      let native;
      do {
        const os = await read(['shell', 'dumpsys', 'activity', 'services', PACKAGE]);
        const presence = servicePresence(os);
        if (ready && presence === 'foreground') {
          const dump = await read(['shell', 'dumpsys', 'activity', 'service', SERVICE]);
          if (dump.includes('UAC_LIFECYCLE_BEGIN_V1')) native = parsePassiveDump(dump);
          if (native && isPassiveReady(native)) break;
        } else if (!ready && presence === 'absent') break;
        requireThat(Date.now() < deadline, 'OS foreground/native owner observation deadline.');
        await delay(500, undefined, { signal: controller.signal });
      } while (true);
      const activities = await read(['shell', 'dumpsys', 'activity', 'activities']);
      if (beforeLaunch) requireThat(!/mResumedActivity:.*dev\.dkk115\.uacremote\//.test(activities), 'Target Activity resumed before passive boot/update observation.');
      const endBoot = await bootId(); requireSameBoot(startBoot, endBoot);
      if (expectedBoot !== null) requireSameBoot(expectedBoot, endBoot);
      result.observations.push({ label, ready, beforeActivityOrInstrumentation: beforeLaunch, bootId: endBoot, native: native ?? null });
    }
    async function normalLaunch() {
      const output = await mutate(['shell', 'am', 'start', '-W', '-n', MAIN]);
      requireThat(/Status: ok/.test(output) && !/Error:|Exception/.test(output), 'Actual MainActivity launch failed.');
      await mutate(['shell', 'input', 'keyevent', 'KEYCODE_HOME']);
    }
    async function reboot(label, ready) {
      const before = await bootId();
      await mutate(['reboot']);
      await read(['wait-for-device'], 90_000);
      const deadline = Date.now() + 90_000;
      while ((await read(['shell', 'getprop', 'sys.boot_completed'])).trim() !== '1') {
        requireThat(Date.now() < deadline, 'Reboot completion deadline.');
        await delay(500, undefined, { signal: controller.signal });
      }
      await guard();
      const after = await bootId(); requireThat(after !== before, 'Reboot did not change kernel boot identity.');
      await barrier(); await observe(label, ready, true, after);
    }
    async function update(label, ready) {
      const before = await bootId();
      requireThat((await hashFile(selected[PACKAGE].path, MAX_APK)).sha256 === selected[PACKAGE].sha256, 'Update APK changed.');
      requireThat(/\bSuccess\s*$/.test(await mutate(['install', '-r', '-t', selected[PACKAGE].path])), 'Same-source package replacement failed.');
      await barrier(); requireThat(await bootId() === before, 'Package update crossed a reboot.');
      await observe(label, ready, true, before);
    }
    await phase('initial');
    // Instrumentation may terminate/restart its target. Establish the baseline with a
    // declared ordinary launch, never silently use this recovery after a boot failure.
    await normalLaunch(); await observe('explicit-start-baseline', true, false);
    await reboot('enabled-real-reboot-before-launch', true);
    await update('enabled-real-package-replacement-before-launch', true);
    await phase('stop'); await observe('explicit-stop-closed', false, false);
    await normalLaunch(); await observe('manual-reopen-preserves-disabled', false, false);
    await reboot('disabled-real-reboot-before-launch', false);
    await phase('verify-stopped');
    await update('disabled-real-package-replacement-before-launch', false);
    await phase('verify-stopped');
    await phase('start'); await normalLaunch(); await observe('explicit-restart-ready', true, false);
    requireSameSource(current, await sources());
    controller.signal.throwIfAborted();
    requireThat(result.cancelled === false && result.cleanupIncomplete === false && result.deviceOperationMayContinue === false,
      'Cancelled or uncertain lifecycle cannot complete.');
    result.passed = true;
  } catch (error) {
    result.failure = error instanceof Error ? error.message : 'Unknown lifecycle failure.';
    if (readFailureDiagnostics && !controller.signal.aborted && !result.cleanupIncomplete && !result.deviceOperationMayContinue) {
      try { await readFailureDiagnostics(); result.failureDiagnosticsCaptured = true; }
      catch { result.failureDiagnosticsCaptured = false; }
    }
    throw error;
  } finally {
    finalizeLifecycleResult(result, controller.signal.aborted);
    json(join(directory, 'result.json'), result);
    process.removeListener('SIGINT', abort); process.removeListener('SIGTERM', abort);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch((error) => { process.stderr.write(`Android lifecycle CI: ${error.message}\n`); process.exitCode = 1; });
}
