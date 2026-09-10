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
import { SYNTHETIC_CI_PIN, FIRST_UNLOCK_PHASES, FIRST_UNLOCK_XML_LIMIT, MAX_LIFECYCLE_COMMANDS, extensionCommandLimits,
  requireFirstUnlockDevice, frameworkUserState, isPassiveWaitingForUnlock, hierarchyPath,
  requireHierarchyCompletion, requireHierarchyFresh, parseSystemUiHierarchy, requireFirstUnlockEvidence } from './android-first-unlock.mjs';

export const PACKAGE = 'dev.dkk115.uacremote';
export const TEST_PACKAGE = `${PACKAGE}.test`;
export const SERVICE = `${PACKAGE}/.background.ControllerForegroundService`;
export const MAIN = `${PACKAGE}/.MainActivity`;
export const AVD = 'uac-lifecycle-ci-36-x86_64';
export const SERIAL = 'emulator-5554';
export const PHASES = ['initial', 'verify-enabled', 'stop', 'verify-stopped', 'start', ...FIRST_UNLOCK_PHASES];
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
  if (result.passed !== true) result.firstUnlockVerified = false;
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
  const booleanFields = ['promoted', 'attached', 'destroyed', 'retiring', 'owner_present', 'wanted', 'start_pending', 'application_attached', 'construction_uncertain', 'start_rejected', 'activation_pending', 'activation_uncertain'];
  const enums = {
    user_unlock: ['UNLOCKED', 'LOCKED', 'UNAVAILABLE'], boot_component: ['DEFAULT', 'ENABLED', 'DISABLED', 'UNAVAILABLE'],
    activation_state: ['LOADING', 'ON', 'OFF', 'LEGACY_MISSING', 'UNAVAILABLE'],
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
  requireThat(Object.keys(fields).length === 17, 'Incomplete passive diagnostic.');
  return fields;
}

export function isPassiveReady(fields) {
  return ['promoted', 'attached', 'owner_present', 'wanted', 'application_attached'].every((key) => fields[key] === true) &&
    ['destroyed', 'retiring', 'start_pending', 'construction_uncertain', 'start_rejected', 'activation_pending', 'activation_uncertain'].every((key) => fields[key] === false) &&
    fields.owner_phase === 'READY' && fields.reported_state === 'LOCAL_SETTINGS_READY' && fields.user_unlock === 'UNLOCKED' &&
    fields.activation_state === 'ON' && ['DEFAULT', 'ENABLED'].includes(fields.boot_component);
}

export function servicePresence(text) {
  const header = 'ACTIVITY MANAGER SERVICES (dumpsys activity services)';
  requireThat(typeof text === 'string' && Buffer.byteLength(text) <= 512 * 1024 &&
    !/Permission Denial|Exception|DUMP TIMEOUT|Failure while dumping|Error dumping/.test(text), 'Missing/failed OS service dump.');
  const lines = text.replaceAll('\r\n', '\n').split('\n');
  requireThat(lines[0] === header && lines.at(-1) === '' && !text.includes('\0') &&
    !lines.some((line) => line.includes('\r')), 'Malformed/incomplete OS service dump.');
  const sections = [], users = new Set();
  let section = null, historical = false, nothing = false;
  for (const line of lines.slice(1)) {
    if (line.trim() === '') continue;
    requireThat(!nothing, 'Content after OS empty-service marker.');
    const active = /^  User (0|[1-9]\d*) active services:$/.exec(line);
    if (active) {
      requireThat(!users.has(active[1]), 'Duplicate active service user section.');
      users.add(active[1]);
      section = { kind: 'active', user: active[1], lines: [] };
      sections.push(section);
    } else if (line === '  Last ANR service:') {
      requireThat(!historical && sections.length === 0, 'Misplaced/duplicate historical service section.');
      historical = true;
      section = { kind: 'history', lines: [] };
    } else if (line === '  (nothing)') {
      // AOSP prints this explicit marker after a completed empty enumeration,
      // even when its independent Last ANR preamble contains an old record.
      requireThat(sections.length === 0, 'Empty-service marker conflicts with current sections.');
      nothing = true;
    } else if (/^(?:  User (?:0|[1-9]\d*) (?:delayed start services|starting in background)|  (?:Pending services|Restarting services|Destroying services|Connection bindings to services)|Active foreground apps - user (?:0|[1-9]\d*)|  Handler - user (?:0|[1-9]\d*)):$/.test(line)) {
      section = { kind: 'other', lines: [] };
      sections.push(section);
    } else {
      requireThat(section !== null && line !== header && !/^ {0,2}\S.*:\s*$/.test(line), 'Unscoped/malformed OS service section.');
      section.lines.push(line);
    }
  }
  if (nothing) return 'absent';
  requireThat(sections.length > 0, 'Missing active or explicit empty-service enumeration.');
  const records = [];
  for (const active of sections.filter((entry) => entry.kind === 'active')) {
    let record = null;
    for (const line of active.lines) {
      const start = /^  \* ServiceRecord\{([0-9a-fA-F]+) u(0|[1-9]\d*) ([A-Za-z0-9_.$]+\/[A-Za-z0-9_.$:]+)(?: c:[A-Za-z0-9_.$:-]+)?\}$/.exec(line);
      if (start) {
        requireThat(start[2] === active.user, 'Service record user differs from its active section.');
        record = { user: start[2], component: start[3], lines: [] };
        records.push(record);
      } else {
        requireThat(record !== null && /^\s+\S/.test(line) && !/^ {0,2}(?:\*|ServiceRecord\{)/.test(line), 'Malformed active service record.');
        record.lines.push(line);
      }
    }
    requireThat(record !== null, 'Empty/truncated active service section.');
  }
  // Non-active current sections (pending/restarting/destroying/bindings) cannot
  // supply active facts or turn an uncertain target lifetime into absence.
  if (sections.some((entry) => entry.kind === 'other' && entry.lines.some((line) => line.includes(SERVICE)))) return 'other';
  const target = records.filter((record) => record.component === SERVICE);
  if (!users.has('0') || target.some((record) => record.user !== '0') || target.length > 1) return 'other';
  if (target.length === 0) return 'absent';
  const body = target[0].lines.join('\n');
  const facts = [...body.matchAll(/^    isForeground=(true|false) foregroundId=(\d+) types=(0x[0-9a-fA-F]{1,8})(?: .*)?$/gm)];
  if (['isForeground=', 'foregroundId=', 'types='].some((field) => body.split(field).length !== 2)) return 'other';
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
    ['DEFAULT', 'ENABLED'].includes(receipt.component) &&
    (stopped ? receipt.activation === 'OFF' && ['NONE', 'CLOSED'].includes(receipt.ownerPhase) :
      receipt.activation === 'ON' && receipt.ownerPhase === 'READY'), 'Receipt contradicts lifecycle phase.');
  for (const key of ['initialWebViewReady', 'finalWebViewReady']) {
    requireThat(receipt.checks?.[key] === true, 'Actual local application document readiness missing.');
  }
  if (receipt.phase === 'initial') for (const key of ['sameOwnerAfterRecreate', 'sameOwnerAfterRepeatedStart', 'oldOwnerClosed', 'manualRelaunchStayedDisabled', 'explicitStartCreatedOwnerAfterClose', 'recreatedWebViewReady', 'relaunchedWebViewReady',
    'retiredNativeHttpReadRejected', 'sameCurrentNativeHttpReadSucceeded', 'retiredPostMessagePreservedReadyOwner', 'sameCurrentPostMessageStoppedOwner', 'staleOriginProbeRestartReady']) {
    requireThat(receipt.checks?.[key] === true, 'Initial lifecycle assertion missing.');
  }
  if (receipt.phase === 'stop') requireThat(receipt.checks?.oldOwnerClosed === true && receipt.ownerPhase === 'CLOSED', 'Stop lacks actual owner closure.');
  if (FIRST_UNLOCK_PHASES.includes(receipt.phase)) {
    const secure = receipt.phase === 'verify-first-unlock';
    requireThat(receipt.checks?.deviceSecureBefore === secure && receipt.checks?.deviceSecureAfter === secure &&
      receipt.checks?.userUnlockedAfter === true, 'Actual native secure-lock checks missing or contradictory.');
  }
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
  const result = { version: 1, classification: 'REAL_PRODUCT_EMULATOR_LIFECYCLE_AND_FIRST_UNLOCK', passed: false,
    firstUnlockVerified: false, physicalAuthenticationVerified: false, requestDeliveryVerified: false,
    phases: [], observations: [], commands: [], cancelled: false, cleanupIncomplete: false, deviceOperationMayContinue: false };
  let commandIndex = 0;
  let commandLimit = 400, diagnosticCommandLimit = 400;
  let firstUnlockDeviceRequired = false, protectedBoot = null;
  let readFailureDiagnostics = null;
  async function command(command, argv, timeoutMs = 15_000, mutatesDevice = false, maxOutputBytes = 512 * 1024, uiDumpPath = null) {
    requireThat(!controller.signal.aborted && commandIndex < commandLimit && commandLimit <= MAX_LIFECYCLE_COMMANDS && !result.deviceOperationMayContinue, 'Cancelled/uncertain/bounded command sequence cannot continue.');
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
    if (uiDumpPath !== null) requireHierarchyCompletion(value.stdout, value.stderr, uiDumpPath);
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
      if (firstUnlockDeviceRequired) requireFirstUnlockDevice(await read(['shell', 'am', 'get-current-user']), await read(['shell', 'getprop', 'ro.crypto.type']));
      if (protectedBoot !== null) requireSameBoot(protectedBoot, await bootId());
    }
    async function mutate(argv, timeout = 30_000, limit, uiDumpPath = null, deadline = null, uiCapturedAt = null) {
      await guard();
      if (deadline !== null) {
        const remaining = deadline - Date.now(); requireThat(remaining > 0, 'Device input deadline elapsed before dispatch.');
        timeout = Math.min(timeout, remaining);
      }
      if (uiCapturedAt !== null) requireHierarchyFresh(uiCapturedAt, performance.now());
      return command(adb, ['-s', SERIAL, ...argv], timeout, true, limit, uiDumpPath);
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
      await read(['shell', 'dumpsys', 'user']);
      await read(['shell', 'dumpsys', 'package', PACKAGE]);
      await read(['shell', 'dumpsys', 'activity', 'broadcasts', PACKAGE]);
      await read(['shell', 'logcat', '-d', '-b', 'all', '-v', 'threadtime', 'AndroidRuntime:E', 'System.err:W', 'RustStdoutStderr:I', '*:S']);
      await read(['shell', 'logcat', '-d', '-v', 'threadtime', 'ActivityManager:I', 'ActivityTaskManager:I', 'BroadcastQueue:I', 'BroadcastQueueModernImpl:I', 'UacBoot:I', '*:S']);
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
      const receipt = parseInstrumentation(output, expected);
      result.phases.push(receipt);
      return receipt;
    }
    async function bootId(timeout = 15_000) {
      const value = (await read(['shell', 'cat', '/proc/sys/kernel/random/boot_id'], timeout)).trim();
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
    async function rebootKernel() {
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
      return { before, after };
    }
    async function reboot(label, ready) {
      const { after } = await rebootKernel();
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
    // Preserve pre-reboot component/writer observations for any later lost-choice
    // diagnosis. Read-only evidence, not a sleep, retry or persistence receipt.
    await read(['shell', 'dumpsys', 'package', PACKAGE]);
    await read(['shell', 'logcat', '-d', '-v', 'threadtime', 'UacBoot:I', '*:S']);
    await reboot('disabled-real-reboot-before-launch', false);
    await phase('verify-stopped');
    await update('disabled-real-package-replacement-before-launch', false);
    await phase('verify-stopped');
    await phase('start'); await normalLaunch(); await observe('explicit-restart-ready', true, false);
    // Only after ALL original scenarios completed may the separately bounded
    // disposable first-unlock extension configure its public synthetic fixture.
    const extensionStart = commandIndex, extensionLimits = extensionCommandLimits(extensionStart);
    commandLimit = extensionLimits.operational; diagnosticCommandLimit = extensionLimits.diagnostics;
    firstUnlockDeviceRequired = true;
    const first = { scope: 'DISPOSABLE_API36_X86_64_FIRST_UNLOCK', nonce: randomBytes(16).toString('hex'),
      syntheticCredentialFixture: true, setupConfirmed: false, locked: [], ui: [],
      commandBudget: { start: extensionStart, operational: commandLimit, includingDiagnostics: diagnosticCommandLimit } };
    result.firstUnlock = first;
    await guard();
    first.beforeBoot = await bootId(); protectedBoot = first.beforeBoot;
    first.before = await phase('verify-no-secure-lock');
    requireSameBoot(first.beforeBoot, await bootId());
    requireThat((await mutate(['shell', 'locksettings', 'set-pin', '--user', '0', SYNTHETIC_CI_PIN])).trim() ===
      `Pin set to '${SYNTHETIC_CI_PIN}'`, 'Synthetic CI PIN setup was not confirmed.');
    first.setupConfirmed = true;
    protectedBoot = null; // Exactly the following real reboot may change it.
    const firstBoot = await rebootKernel();
    requireSameBoot(first.beforeBoot, firstBoot.before);
    first.bootId = firstBoot.after; protectedBoot = first.bootId;
    // No broadcast barrier here: unlock-dependent broadcasts may still be held.
    async function observeFirstUnlock(locked, stable = false) {
      const deadline = Date.now() + (stable ? 15_000 : 45_000);
      const boundedRead = async argv => {
        const remaining = deadline - Date.now(); requireThat(remaining > 0, 'First-unlock observation deadline.');
        return read(argv, Math.min(15_000, remaining));
      };
      const boundedBootId = async () => {
        const remaining = deadline - Date.now(); requireThat(remaining > 0, 'First-unlock observation deadline.');
        return bootId(Math.min(15_000, remaining));
      };
      for (let attempt = 0; attempt < (stable ? 1 : 10); attempt++) {
        requireSameBoot(first.bootId, await boundedBootId());
        const user = frameworkUserState(await boundedRead(['shell', 'dumpsys', 'user']));
        if (locked) requireThat(user !== 'RUNNING_UNLOCKED' && user !== 'RUNNING_UNLOCKING', 'User unlocked before ordinary credential input.');
        const presence = servicePresence(await boundedRead(['shell', 'dumpsys', 'activity', 'services', PACKAGE]));
        let native = null;
        if (presence === 'foreground') {
          const raw = await boundedRead(['shell', 'dumpsys', 'activity', 'service', SERVICE]);
          if (raw.includes('UAC_LIFECYCLE_BEGIN_V1')) native = parsePassiveDump(raw);
          if (locked && native) requireThat(native.owner_present === false && native.owner_phase === 'NONE' &&
            native.user_unlock === 'LOCKED' && native.construction_uncertain === false, 'Native owner was attempted before first unlock.');
        }
        if (native && user === (locked ? 'RUNNING_LOCKED' : 'RUNNING_UNLOCKED') &&
            (locked ? isPassiveWaitingForUnlock(native) : isPassiveReady(native))) {
          const activities = await boundedRead(['shell', 'dumpsys', 'activity', 'activities']);
          requireThat(!/mResumedActivity:.*dev\.dkk115\.uacremote\//.test(activities), 'Target Activity resumed before first-unlock observation.');
          requireSameBoot(first.bootId, await boundedBootId());
          requireThat(Date.now() < deadline, 'First-unlock observation completed after its deadline.');
          const sample = { label: locked ? 'first-unlock-locked-no-owner' : 'first-unlock-ready-before-launch',
            presence, frameworkUserState: user, native, bootId: first.bootId, beforeActivityOrInstrumentation: true,
            observedAtMonotonicMs: Math.floor(performance.now()) };
          result.observations.push(sample); return sample;
        }
        requireThat(!stable, 'Locked foreground state did not remain stable.');
        const remaining = deadline - Date.now(); requireThat(remaining > 0, 'First-unlock observation deadline.');
        await delay(Math.min(750, remaining), undefined, { signal: controller.signal });
      }
      throw new Error('Bounded first-unlock foreground observation did not complete.');
    }
    first.locked.push(await observeFirstUnlock(true));
    for (let index = 0; index < 2; index++) {
      await delay(750, undefined, { signal: controller.signal });
      first.locked.push(await observeFirstUnlock(true, true));
    }
    await mutate(['shell', 'input', 'keyevent', 'KEYCODE_WAKEUP']);
    const uiDeadline = Date.now() + 120_000;
    let hierarchyIndex = 0;
    async function currentCredentialUi() {
      requireThat(Date.now() < uiDeadline, 'SystemUI credential interaction deadline.');
      requireSameBoot(first.bootId, await bootId());
      requireThat(frameworkUserState(await read(['shell', 'dumpsys', 'user'])) === 'RUNNING_LOCKED', 'Credential input requires actual locked user0.');
      const path = hierarchyPath(first.nonce, hierarchyIndex++);
      await read(['shell', 'test', '!', '-e', path]); // Never reuse/overwrite an earlier hierarchy.
      await guard();
      const remaining = uiDeadline - Date.now(); requireThat(remaining > 0, 'SystemUI capture deadline elapsed.');
      // Conservative age begins BEFORE capture, after its device guard. The
      // later input guard must recheck this age immediately before dispatch.
      const capturedAt = performance.now();
      await command(adb, ['-s', SERIAL, 'shell', 'uiautomator', 'dump', path], Math.min(15_000, remaining), true, FIRST_UNLOCK_XML_LIMIT, path);
      const xml = await read(['shell', 'cat', path]);
      requireThat(Date.now() < uiDeadline, 'SystemUI hierarchy arrived after its interaction deadline.');
      const screen = parseSystemUiHierarchy(xml);
      return { ...screen, path, xmlSha256: sha(xml), bootId: first.bootId, capturedAt };
    }
    let screen = await currentCredentialUi();
    if (screen.kind === 'lockscreen') {
      await mutate(['shell', 'input', 'swipe', ...screen.swipe.map(String)], 15_000, undefined, null, uiDeadline, screen.capturedAt);
      first.ui.push({ kind: screen.kind, path: screen.path, xmlSha256: screen.xmlSha256, bootId: first.bootId,
        action: 'reveal', inputCompletedAtMonotonicMs: Math.floor(performance.now()) });
      screen = await currentCredentialUi();
    }
    requireThat(screen.kind === 'pin' && screen.empty, 'Expected an empty recognized PIN entry; no credential guessing or clearing.');
    const rotation = screen.rotation;
    for (let index = 0; index < SYNTHETIC_CI_PIN.length; index++) {
      if (index !== 0) screen = await currentCredentialUi();
      requireThat(screen.kind === 'pin' && screen.rotation === rotation && Date.now() < uiDeadline, 'PIN layout changed during the sole attempt.');
      const point = screen.controls[SYNTHETIC_CI_PIN[index]];
      await mutate(['shell', 'input', 'tap', ...point.map(String)], 15_000, undefined, null, uiDeadline, screen.capturedAt);
      first.ui.push({ kind: screen.kind, path: screen.path, xmlSha256: screen.xmlSha256, bootId: first.bootId,
        action: `digit-${index}`, point, inputCompletedAtMonotonicMs: Math.floor(performance.now()) });
    }
    screen = await currentCredentialUi();
    requireThat(screen.kind === 'pin' && screen.rotation === rotation && Date.now() < uiDeadline, 'PIN submit control unavailable.');
    await mutate(['shell', 'input', 'tap', ...screen.controls.enter.map(String)], 15_000, undefined, null, uiDeadline, screen.capturedAt);
    first.ui.push({ kind: screen.kind, path: screen.path, xmlSha256: screen.xmlSha256, bootId: first.bootId,
      action: 'enter', point: screen.controls.enter, inputCompletedAtMonotonicMs: Math.floor(performance.now()) });
    first.ready = await observeFirstUnlock(false);
    // Only now may instrumentation launch the product. It cannot establish the
    // preceding boot/unlock transition; it verifies the real PIN stayed configured.
    first.after = await phase('verify-first-unlock');
    requireSameBoot(first.bootId, await bootId());
    requireFirstUnlockEvidence(first, first.ready);
    requireSameSource(current, await sources());
    controller.signal.throwIfAborted();
    requireThat(result.cancelled === false && result.cleanupIncomplete === false && result.deviceOperationMayContinue === false,
      'Cancelled or uncertain lifecycle cannot complete.');
    result.firstUnlockVerified = true;
    result.passed = true;
  } catch (error) {
    result.failure = error instanceof Error ? error.message : 'Unknown lifecycle failure.';
    if (readFailureDiagnostics && !controller.signal.aborted && !result.cleanupIncomplete && !result.deviceOperationMayContinue) {
      commandLimit = diagnosticCommandLimit; // Reserved bounded read-only failure evidence.
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
