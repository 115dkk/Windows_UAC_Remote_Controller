// SPDX-License-Identifier: GPL-2.0-or-later
// Build/inspect only. Never executes an installer, service or prompt helper.
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { constants, copyFileSync, existsSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const TARGET = 'x86_64-pc-windows-msvc';
export const OUTPUT = 'target/windows-package';
export const MAX_BINARY_BYTES = 128 * 1024 * 1024;
export const MAX_INSTALLER_BYTES = 384 * 1024 * 1024;
export const MAX_REPAIR_MANIFEST_BYTES = 4096;
const MARKER = '.uac-windows-package-v1';
const MARKER_TEXT = 'Generated Windows package inputs v1; not enrollment or signature authority.\n';
const REPAIR_DIRECTORY = 'repair';
const REPAIR_MANIFEST = 'repair-manifest.json';
const LEAVES = ['uac-service.exe', 'uac-prompt-probe.exe'];
const ALL_LEAVES = ['controller-app.exe', ...LEAVES];
const REPAIR_ARCHIVE_PATHS = [...LEAVES.map((name) => `${REPAIR_DIRECTORY}/${name}`), `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`];
const BUNDLE_SOURCE_MARKER = Buffer.from('__TAURI_BUNDLE_TYPE_VAR_UNK', 'ascii');
const BUNDLE_NSIS_MARKER = Buffer.from('__TAURI_BUNDLE_TYPE_VAR_NSS', 'ascii');
const BUNDLE_TRANSFORM = 'tauri-bundler-2.9.4-nsis-marker-v1';
const root = fileURLToPath(new URL('../', import.meta.url));
const fail = (message) => { throw new Error(message); };
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function parseArguments(argv) {
  if (argv.length === 1 && ['--help', '-h'].includes(argv[0])) return { mode: 'help' };
  const mode = argv[0] ?? 'build';
  if (!['build', 'stage', 'inspect'].includes(mode)) fail('Use build, stage, inspect, or --help.');
  let target = TARGET, dryRun = false, targetSeen = false;
  for (let i = 1; i < argv.length; i += 1) {
    if (argv[i] === '--dry-run' && !dryRun) dryRun = true;
    else if (argv[i] === '--target' && argv[i + 1] === TARGET && !targetSeen) { targetSeen = true; target = argv[++i]; }
    else fail('Unsupported Windows packaging argument or target.');
  }
  return { mode, target, dryRun };
}

export function buildPlan(repository, env = process.env) {
  const targetRoot = env.CARGO_TARGET_DIR ? resolve(repository, env.CARGO_TARGET_DIR) : join(repository, 'target');
  return {
    output: join(repository, OUTPUT),
    inputs: join(repository, OUTPUT, 'inputs'),
    repair: join(repository, OUTPUT, REPAIR_DIRECTORY),
    release: join(targetRoot, TARGET, 'release'),
    cargo: ['build', '--locked', '--release', '--target', TARGET, '-p', 'windows-service-host', '--bin', 'uac-service', '-p', 'windows-prompt-probe', '--bin', 'uac-prompt-probe'],
    tauri: ['node_modules/@tauri-apps/cli/tauri.js', 'build', '--ci', '--bundles', 'nsis', '--target', TARGET, '--config', 'src-tauri/windows/package-config.json', '--', '--locked'],
  };
}

export function validateFileMetadata(info, limit, cargoSource = false) {
  // Cargo ordinarily hardlinks known build outputs to deps/. Copies in the
  // generated staging/output namespace must remain independent single links.
  if (!info.isFile() || info.isSymbolicLink() || (!cargoSource && info.nlink !== 1) || info.size < 1 || info.size > limit) fail('Package input is not a bounded regular file with the required link policy.');
}
function regular(path, limit, cargoSource = false) {
  const info = lstatSync(path);
  validateFileMetadata(info, limit, cargoSource);
  return readFileSync(path);
}
export function validateConfiguration(base, overlay) {
  if (base.productName !== 'UAC 원격 승인기' || base.identifier !== 'dev.dkk115.uacremote' || base.bundle?.windows?.nsis?.installMode !== 'perMachine' || base.bundle.windows.nsis.template !== 'windows/installer.nsi' || base.bundle.windows.nsis.installerHooks !== 'windows/packaging-hooks.nsh' || base.bundle.windows.allowDowngrades !== false || base.bundle.externalBin?.length || base.bundle.resources !== undefined || base.bundle.fileAssociations?.length || base.plugins?.['deep-link']) fail('Unsupported Windows package configuration.');
  if (JSON.stringify(overlay) !== JSON.stringify({ bundle: { windows: { webviewInstallMode: { type: 'skip' } }, externalBin: ['../target/windows-package/inputs/uac-service', '../target/windows-package/inputs/uac-prompt-probe'], resources: { '../target/windows-package/repair/uac-service.exe': 'repair/uac-service.exe', '../target/windows-package/repair/uac-prompt-probe.exe': 'repair/uac-prompt-probe.exe', '../target/windows-package/repair/repair-manifest.json': 'repair/repair-manifest.json' } } })) fail('Use the fixed Windows service and repair package overlay.');
  if (base.bundle.windows.signCommand != null || base.bundle.windows.certificateThumbprint != null) fail('Signing requires a separately reviewed post-signing payload capture; this profile predicts only the unsigned NSIS marker change.');
}
function noLinks(path) {
  let current = resolve(path);
  for (;;) {
    if (existsSync(current)) {
      const info = lstatSync(current);
      if (info.isSymbolicLink() || (current !== path && !info.isDirectory())) fail('Package path contains an unsupported link or ancestor.');
    }
    const parent = dirname(current);
    if (parent === current) return;
    current = parent;
  }
}
function writeKnown(path, bytes) {
  noLinks(path);
  if (existsSync(path)) regular(path, MAX_INSTALLER_BYTES);
  writeFileSync(path, bytes, { flag: existsSync(path) ? 'w' : 'wx' });
}
function prepareOutput(plan) {
  noLinks(plan.output);
  if (!existsSync(plan.output)) mkdirSync(plan.output, { recursive: true });
  const entries = readdirSync(plan.output);
  if (entries.length && !entries.includes(MARKER)) fail('Refusing an unowned package output directory.');
  if (entries.some((name) => ![MARKER, 'inputs', REPAIR_DIRECTORY, 'manifest.json', 'inspection.json', 'controller-setup.exe'].includes(name))) fail('Unknown package output entries are preserved.');
  const marker = join(plan.output, MARKER);
  if (existsSync(marker)) {
    if (regular(marker, 1024).toString('utf8') !== MARKER_TEXT) fail('Package ownership marker is invalid.');
  } else writeFileSync(marker, MARKER_TEXT, { flag: 'wx' });
  noLinks(plan.inputs);
  if (!existsSync(plan.inputs)) mkdirSync(plan.inputs);
  if (readdirSync(plan.inputs).some((name) => !LEAVES.map((leaf) => leaf.replace('.exe', `-${TARGET}.exe`)).includes(name))) fail('Unknown staged inputs are preserved.');
  noLinks(plan.repair);
  if (!existsSync(plan.repair)) mkdirSync(plan.repair);
  if (readdirSync(plan.repair).some((name) => ![...LEAVES, REPAIR_MANIFEST].includes(name))) fail('Unknown staged repair entries are preserved.');
}

function inspectPeShape(bytes, machines, limit) {
  if (bytes.length < 256 || bytes.length > limit || bytes.toString('ascii', 0, 2) !== 'MZ') fail('Expected a bounded Windows PE executable.');
  const offset = bytes.readUInt32LE(0x3c);
  if (offset < 64 || offset > 64 * 1024 || offset + 26 > bytes.length || bytes.readUInt32LE(offset) !== 0x00004550) fail('Windows executable architecture or PE shape is unsupported.');
  const machine = bytes.readUInt16LE(offset + 4), sections = bytes.readUInt16LE(offset + 6), optional = bytes.readUInt16LE(offset + 20), flags = bytes.readUInt16LE(offset + 22);
  const minimum = machine === 0x14c ? 96 : 112, magic = machine === 0x14c ? 0x10b : 0x20b;
  if (!machines.includes(machine) || sections < 1 || sections > 96 || optional < minimum || offset + 24 + optional + sections * 40 > bytes.length || bytes.readUInt16LE(offset + 24) !== magic || !(flags & 2) || (flags & 0x2000)) fail('Windows executable architecture or PE shape is unsupported.');
  return { bytes: bytes.length, sha256: digest(bytes) };
}
export function inspectPe(bytes) { return inspectPeShape(bytes, [0x8664], MAX_BINARY_BYTES); }
export function inspectInstallerPe(bytes) { return inspectPeShape(bytes, [0x14c, 0x8664], MAX_INSTALLER_BYTES); }
function unsignedPayload(bytes) {
  const info = inspectPe(bytes);
  const coff = bytes.readUInt32LE(0x3c), optional = coff + 24;
  const length = bytes.readUInt16LE(coff + 20), directories = bytes.readUInt32LE(optional + 108);
  if (directories > 16 || 112 + directories * 8 > length) fail('Payload PE data-directory shape is unsupported.');
  // The security directory is entry4 and uses a file offset, not an RVA. This
  // profile cannot predict Authenticode/checksum mutations after marker patching.
  if (directories >= 5 && (bytes.readUInt32LE(optional + 144) !== 0 || bytes.readUInt32LE(optional + 148) !== 0)) fail('Signed payloads need a separately reviewed packaging capture.');
  return info;
}
export function transformNsisMain(source) {
  // tauri-bundler 2.9.4 src/bundle.rs::patch_binary changes this same-length
  // marker before NSIS assembly; bundle_project restores its source afterwards.
  // Stricter than upstream's first-match search: ambiguity fails this profile.
  const original = unsignedPayload(source);
  const offset = source.indexOf(BUNDLE_SOURCE_MARKER);
  if (offset < 0 || source.indexOf(BUNDLE_SOURCE_MARKER, offset + 1) >= 0 || source.includes(BUNDLE_NSIS_MARKER) || BUNDLE_SOURCE_MARKER.length !== BUNDLE_NSIS_MARKER.length) fail('Expected exactly one unpatched Tauri bundle marker and no NSIS marker.');
  const packaged = Buffer.from(source);
  BUNDLE_NSIS_MARKER.copy(packaged, offset);
  const expected = unsignedPayload(packaged);
  return {
    packaged,
    metadata: {
      name: 'controller-app.exe', ...expected, sourceSha256: original.sha256,
      transformation: { kind: BUNDLE_TRANSFORM, offset, from: BUNDLE_SOURCE_MARKER.toString('ascii'), to: BUNDLE_NSIS_MARKER.toString('ascii') },
    },
  };
}
// ADR 0027: a binary built with the lab-only software key provider carries this
// profile marker (windows-identity IDENTITY_PROVIDER_PROFILE) and must never be packaged.
const LAB_PROFILE_MARKERS = ['lab-software-ksp-do-not-ship', 'uac-ci-startup-notes-do-not-ship']
  .map((marker) => Buffer.from(marker, 'ascii'));
export function expectedPayload(name, source) {
  if (LAB_PROFILE_MARKERS.some((marker) => source.includes(marker))) fail('A lab-profile binary cannot be packaged; build without lab-only features.');
  if (name === 'controller-app.exe') return transformNsisMain(source).metadata;
  if (!LEAVES.includes(name)) fail('Unexpected packaged executable name.');
  const original = unsignedPayload(source);
  return { name, ...original, sourceSha256: original.sha256, transformation: { kind: 'identity' } };
}
export function createRepairManifest(version, payload) {
  if (typeof version !== 'string' || !/^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$/u.test(version) || Buffer.byteLength(version, 'utf8') > 128 || !Array.isArray(payload) || payload.length !== LEAVES.length) fail('Repair manifest inputs are unsupported.');
  const files = LEAVES.map((name, index) => {
    const row = payload[index];
    if (row?.name !== name || !Number.isSafeInteger(row.bytes) || row.bytes < 1 || row.bytes > MAX_BINARY_BYTES || !/^[a-f0-9]{64}$/u.test(row.sha256)) fail('Repair manifest file metadata is invalid.');
    return { name, bytes: row.bytes, sha256: row.sha256 };
  });
  const bytes = Buffer.from(JSON.stringify({ schema: 1, product: 'uac-remote-controller', version, files }), 'utf8');
  if (bytes.length > MAX_REPAIR_MANIFEST_BYTES) fail('Repair manifest exceeded its bound.');
  return bytes;
}
export function validateRepairManifest(bytes, version, payload) {
  if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > MAX_REPAIR_MANIFEST_BYTES || bytes.subarray(0, 3).equals(Buffer.from([0xef, 0xbb, 0xbf])) || bytes.toString('utf8').includes('�')) fail('Repair manifest encoding or size is invalid.');
  const expected = createRepairManifest(version, payload);
  if (!bytes.equals(expected)) fail('Repair manifest content differs from the staged expectation.');
  return { name: `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`, bytes: bytes.length, sha256: digest(bytes) };
}
export function parseArchiveListing(text) {
  if (Buffer.byteLength(text) > 1024 * 1024) fail('Installer listing exceeded its bound.');
  const records = text.split(/\r?\n\r?\n/u).map((block) => {
    const row = Object.create(null);
    for (const line of block.split(/\r?\n/u).filter((value) => value.includes(' = '))) {
      const at = line.indexOf(' = '), key = line.slice(0, at);
      if (Object.hasOwn(row, key)) fail('Installer listing contains duplicate fields.');
      row[key] = line.slice(at + 3);
    }
    return row;
  });
  const outer = records.filter((row) => row.Type !== undefined);
  if (outer.length !== 1 || !['Nsis', 'NSIS'].includes(outer[0].Type) || !outer[0].Path) fail('The outer archive must be exactly one NSIS installer.');
  const rows = records.filter((row) => row.Path && row.Type === undefined);
  if (rows.length > 512) fail('Installer entry count exceeded its bound.');
  const normalized = rows.map((row) => ({ ...row, archivePath: row.Path, path: row.Path.replaceAll('\\', '/') }));
  if (new Set(normalized.map((row) => row.path.toLowerCase())).size !== rows.length) fail('Installer listing contains duplicate paths.');
  const required = [...ALL_LEAVES, ...REPAIR_ARCHIVE_PATHS];
  const resolved = required.map((name) => {
    const matches = normalized.filter((row) => row.path.toLowerCase() === name.toLowerCase());
    const limit = name.endsWith(`/${REPAIR_MANIFEST}`) ? MAX_REPAIR_MANIFEST_BYTES : MAX_BINARY_BYTES;
    if (matches.length !== 1 || matches[0].path !== name || !/^[0-9]+$/u.test(matches[0].Size ?? '') || Number(matches[0].Size) < 1 || Number(matches[0].Size) > limit) fail('Installer must contain each fixed payload at its exact normalized path.');
    return { name, archivePath: matches[0].archivePath, bytes: Number(matches[0].Size) };
  });
  const requiredLower = new Set(required.map((path) => path.toLowerCase()));
  const unexpectedPayload = normalized.some((row) => /^(?:controller-app|uac-service|uac-prompt-probe)\.exe$/iu.test(basename(row.path)) && !requiredLower.has(row.path.toLowerCase()));
  const expectedRepairManifestPath = `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`.toLowerCase();
  const unexpectedRepairManifest = normalized.some((row) => basename(row.path).toLowerCase() === REPAIR_MANIFEST.toLowerCase() && row.path.toLowerCase() !== expectedRepairManifestPath);
  if (unexpectedPayload || unexpectedRepairManifest) fail('Installer contains a fixed payload outside its exact path.');
  return resolved;
}
function validateManifestEnvelope(value, mode, expectedNames) {
  if (!Array.isArray(expectedNames) || expectedNames.some((name, index) => !name || expectedNames.indexOf(name) !== index)) fail('Package manifest schema is invalid.');
  if (!value || value.schemaVersion !== 2 || value.target !== TARGET || value.mode !== mode || value.signing !== 'not-attested' || !Array.isArray(value.payload) || value.payload.length !== expectedNames.length) fail('Package manifest is unsupported.');
  const keys = ['schemaVersion', 'target', 'mode', 'signing', 'payload', 'installer'];
  if (Object.keys(value).some((key) => !keys.includes(key))) fail('Package manifest has unknown fields.');
  for (const [index, row] of value.payload.entries()) {
    const expectedName = expectedNames[index];
    const repairManifest = expectedName === `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`;
    const expectedKeys = repairManifest ? 'bytes,name,sha256' : 'bytes,name,sha256,sourceSha256,transformation';
    const limit = repairManifest ? MAX_REPAIR_MANIFEST_BYTES : MAX_BINARY_BYTES;
    if (!row || Object.keys(row).sort().join() !== expectedKeys || row.name !== expectedName || !Number.isSafeInteger(row.bytes) || row.bytes < 1 || row.bytes > limit || !/^[a-f0-9]{64}$/u.test(row.sha256)) fail('Package payload metadata is invalid.');
    if (repairManifest) continue;
    if (!/^[a-f0-9]{64}$/u.test(row.sourceSha256)) fail('Package source metadata is invalid.');
    const transform = row.transformation;
    if (!transform || typeof transform !== 'object') fail('Missing bounded payload transformation metadata.');
    if (expectedName === 'controller-app.exe') {
      if (Object.keys(transform).sort().join() !== 'from,kind,offset,to' || transform.kind !== BUNDLE_TRANSFORM || transform.from !== BUNDLE_SOURCE_MARKER.toString('ascii') || transform.to !== BUNDLE_NSIS_MARKER.toString('ascii') || !Number.isSafeInteger(transform.offset) || transform.offset < 0 || transform.offset > row.bytes - BUNDLE_SOURCE_MARKER.length) fail('Unexpected main executable transformation.');
    } else if (Object.keys(transform).join() !== 'kind' || transform.kind !== 'identity' || row.sha256 !== row.sourceSha256) fail('Helper payload must be byte-identical to its build input.');
    if (expectedName.startsWith(`${REPAIR_DIRECTORY}/`) && expectedName !== `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`) {
      const original = value.payload.find((candidate) => candidate.name === basename(expectedName));
      if (!original || row.bytes !== original.bytes || row.sha256 !== original.sha256 || row.sourceSha256 !== original.sourceSha256) fail('Repair executable must be byte-identical to its top-level binary.');
    }
  }
  return value;
}
export function validateStagedManifest(value) {
  // Before Tauri builds controller-app.exe, provenance covers two top-level
  // helpers, their two repair copies and the repair manifest: exactly five rows.
  validateManifestEnvelope(value, 'staged', [...LEAVES, ...REPAIR_ARCHIVE_PATHS]);
  if (value.installer !== null) fail('Staged package manifest cannot claim installer metadata.');
  return value;
}
export function validateManifest(value) {
  // Assembly prepends controller-app.exe and binds installer metadata: six rows.
  validateManifestEnvelope(value, 'assembled', [...ALL_LEAVES, ...REPAIR_ARCHIVE_PATHS]);
  const installer = value.installer;
  if (!installer || Object.keys(installer).sort().join() !== 'bytes,name,sha256' || installer.name !== 'controller-setup.exe' || !Number.isSafeInteger(installer.bytes) || installer.bytes < 1 || installer.bytes > MAX_INSTALLER_BYTES || !/^[a-f0-9]{64}$/u.test(installer.sha256)) fail('Installer metadata is invalid.');
  return value;
}
export function createStagedManifest(version, payload, repairManifest) {
  if (!Array.isArray(payload) || payload.length !== LEAVES.length || payload.some((row, index) => row?.name !== LEAVES[index])) fail('Staged helper payload is unsupported.');
  const repairPayload = [
    ...payload.map((row) => ({ ...row, name: `${REPAIR_DIRECTORY}/${row.name}` })),
    validateRepairManifest(repairManifest, version, payload),
  ];
  return validateStagedManifest({ schemaVersion: 2, target: TARGET, mode: 'staged', signing: 'not-attested', payload: [...payload, ...repairPayload], installer: null });
}
export function verifyExtractedPayload(entry, data, expected) {
  const actual = unsignedPayload(data);
  if (entry.name !== expected.name || entry.bytes !== actual.bytes || expected.bytes !== actual.bytes || expected.sha256 !== actual.sha256) fail('Installer executable bytes differ from the expected build payload.');
  if (expected.name === 'controller-app.exe') {
    const offset = data.indexOf(BUNDLE_NSIS_MARKER);
    if (offset !== expected.transformation.offset || data.indexOf(BUNDLE_NSIS_MARKER, offset + 1) >= 0 || data.includes(BUNDLE_SOURCE_MARKER)) fail('Packaged main executable has an unexpected bundle marker.');
    // Validate the ALREADY recorded source attribution as well as the expected
    // packaged hash. This never learns or changes either expectation from data.
    const original = Buffer.from(data);
    BUNDLE_SOURCE_MARKER.copy(original, offset);
    if (digest(original) !== expected.sourceSha256) fail('Packaged main executable does not match the recorded build source.');
  }
  return actual;
}

function run(program, args, options = {}) {
  const result = spawnSync(program, args, { cwd: root, shell: false, timeout: 30 * 60_000, stdio: 'inherit', ...options });
  if (result.error || result.signal || result.status !== 0) fail('A checked packaging child process failed.');
  return result.stdout;
}
function rejectImplicitWindowsConfiguration() {
  if (process.env.TAURI_CONFIG !== undefined || ['tauri.windows.conf.json', 'tauri.windows.conf.json5', 'Tauri.windows.toml'].some((name) => existsSync(join(root, 'src-tauri', name)))) fail('Only the explicit packaging overlay may add generated Windows resources.');
}
function stage(plan) {
  prepareOutput(plan);
  invalidateInspection(plan, 'new-stage');
  rejectImplicitWindowsConfiguration();
  const base = JSON.parse(readFileSync(join(root, 'src-tauri/tauri.conf.json'), 'utf8'));
  validateConfiguration(base, JSON.parse(readFileSync(join(root, 'src-tauri/windows/package-config.json'), 'utf8')));
  run('cargo', plan.cargo);
  const payload = LEAVES.map((name) => {
    const source = join(plan.release, name);
    noLinks(source);
    const bytes = regular(source, MAX_BINARY_BYTES, true);
    const row = expectedPayload(name, bytes);
    writeKnown(join(plan.inputs, name.replace('.exe', `-${TARGET}.exe`)), bytes);
    writeKnown(join(plan.repair, name), bytes);
    return row;
  });
  const repairManifest = createRepairManifest(base.version, payload);
  writeKnown(join(plan.repair, REPAIR_MANIFEST), repairManifest);
  const stagedManifest = createStagedManifest(base.version, payload, repairManifest);
  writeKnown(join(plan.output, 'manifest.json'), `${JSON.stringify(stagedManifest, null, 2)}\n`);
}
export function invalidateInspection(plan, reason) {
  if (!['new-stage', 'inspection-started'].includes(reason)) fail('Unknown inspection state.');
  writeKnown(join(plan.output, 'inspection.json'), `${JSON.stringify({ schemaVersion: 1, passed: false, scope: 'passive-nsis-payload-only', reason }, null, 2)}\n`);
}
function inspect(plan) {
  noLinks(plan.output);
  if (regular(join(plan.output, MARKER), 1024).toString('utf8') !== MARKER_TEXT) fail('Package ownership marker is invalid.');
  invalidateInspection(plan, 'inspection-started');
  const manifestBytes = regular(join(plan.output, 'manifest.json'), 16 * 1024);
  const manifestText = manifestBytes.toString('utf8');
  if (manifestText.includes('�')) fail('Package manifest is not valid UTF-8.');
  const manifest = validateManifest(JSON.parse(manifestText));
  const installer = join(plan.output, 'controller-setup.exe');
  const bytes = regular(installer, MAX_INSTALLER_BYTES);
  inspectInstallerPe(bytes);
  if (bytes.length !== manifest.installer.bytes || digest(bytes) !== manifest.installer.sha256) fail('Assembled installer does not match its build manifest.');
  const listing = run('7z', ['l', '-slt', '--', installer], { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 60_000 });
  const entries = parseArchiveListing(listing);
  rejectImplicitWindowsConfiguration();
  const currentConfig = JSON.parse(readFileSync(join(root, 'src-tauri/tauri.conf.json'), 'utf8'));
  validateConfiguration(currentConfig, JSON.parse(readFileSync(join(root, 'src-tauri/windows/package-config.json'), 'utf8')));
  const version = currentConfig.version;
  const helpers = manifest.payload.slice(1, 3);
  createRepairManifest(version, helpers);
  const extracted = new Map();
  for (const entry of entries) {
    const limit = entry.name === `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}` ? MAX_REPAIR_MANIFEST_BYTES : MAX_BINARY_BYTES;
    const data = run('7z', ['e', '-so', '-bd', '--', installer, entry.archivePath], { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: limit, timeout: 60_000 });
    extracted.set(entry.name, data);
    const expected = manifest.payload.find((row) => row.name === entry.name);
    if (!expected) fail('Installer contains a payload absent from the package manifest.');
    if (entry.name === `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`) {
      const actual = validateRepairManifest(data, version, helpers);
      if (entry.bytes !== actual.bytes || expected.bytes !== actual.bytes || expected.sha256 !== actual.sha256) fail('Repair manifest bytes differ from package metadata.');
    } else {
      const extractedName = basename(entry.name);
      const expectedExecutable = { ...expected, name: basename(expected.name) };
      if (expectedExecutable.name === 'controller-app.exe') verifyExtractedPayload({ ...entry, name: extractedName }, data, expectedExecutable);
      else {
        const actual = unsignedPayload(data);
        if (extractedName !== expectedExecutable.name || entry.bytes !== actual.bytes || expected.bytes !== actual.bytes || expected.sha256 !== actual.sha256 || expected.sourceSha256 !== actual.sha256 || expected.transformation?.kind !== 'identity') fail('Installer executable bytes differ from package metadata.');
      }
    }
  }
  for (const name of LEAVES) {
    if (!extracted.get(name)?.equals(extracted.get(`${REPAIR_DIRECTORY}/${name}`))) fail('Repair executable differs from the installed top-level executable.');
  }
  const stagedRepairManifest = regular(join(plan.repair, REPAIR_MANIFEST), MAX_REPAIR_MANIFEST_BYTES);
  const stagedManifestMetadata = validateRepairManifest(stagedRepairManifest, version, helpers);
  const expectedManifestMetadata = manifest.payload.find((row) => row.name === `${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`);
  if (!expectedManifestMetadata || stagedManifestMetadata.bytes !== expectedManifestMetadata.bytes || stagedManifestMetadata.sha256 !== expectedManifestMetadata.sha256) fail('Staged repair manifest differs from package metadata.');
  if (!extracted.get(`${REPAIR_DIRECTORY}/${REPAIR_MANIFEST}`)?.equals(stagedRepairManifest)) fail('Packaged repair manifest differs from the staged file.');
  writeKnown(join(plan.output, 'inspection.json'), `${JSON.stringify({ schemaVersion: 1, passed: true, scope: 'passive-nsis-payload-only', manifestSha256: digest(manifestBytes), installer: manifest.installer, payload: manifest.payload, signing: 'not-attested', nativeInstallation: 'not-executed' }, null, 2)}\n`);
  process.stdout.write('Inspected six exact payloads, including the protected repair copies and manifest, without executing the installer. Signing and native installation are not verified.\n');
}
export function main(argv = process.argv.slice(2)) {
  const options = parseArguments(argv);
  if (options.mode === 'help') {
    process.stdout.write('Usage: node tools/windows-packaging.mjs [build|stage|inspect] [--target x86_64-pc-windows-msvc] [--dry-run]\nOutputs: target/windows-package/controller-setup.exe and manifest.json\nBuild and inspection only: no installer, helper, elevation or service is executed.\n');
    return;
  }
  const plan = buildPlan(root);
  if (options.dryRun) {
    process.stdout.write(`${JSON.stringify({ mode: options.mode, target: TARGET, output: OUTPUT, children: options.mode === 'inspect' ? ['7z list/extract-to-stdout only'] : [{ program: 'cargo', args: plan.cargo }, ...(options.mode === 'build' ? [{ program: 'node', args: plan.tauri }] : [])] }, null, 2)}\n`);
    return;
  }
  if (process.platform !== 'win32' || process.arch !== 'x64') fail('Use a native Windows x64 packaging host.');
  if (options.mode === 'inspect') { inspect(plan); return; }
  stage(plan);
  if (options.mode === 'stage') return;
  run(process.execPath, plan.tauri);
  const config = JSON.parse(readFileSync(join(root, 'src-tauri/tauri.conf.json'), 'utf8'));
  const installerName = `${config.productName}_${config.version}_x64-setup.exe`;
  const source = join(plan.release, 'bundle/nsis', installerName);
  noLinks(source);
  const installer = regular(source, MAX_INSTALLER_BYTES);
  // Tauri restores its unpatched Cargo main after bundling. Derive expected NSIS
  // bytes only from that build output, NEVER from extracted installer content.
  const payload = ALL_LEAVES.map((name) => expectedPayload(name, regular(name === 'controller-app.exe' ? join(plan.release, name) : join(plan.inputs, name.replace('.exe', `-${TARGET}.exe`)), MAX_BINARY_BYTES, name === 'controller-app.exe')));
  const helperPayload = payload.slice(1);
  const repairManifest = regular(join(plan.repair, REPAIR_MANIFEST), MAX_REPAIR_MANIFEST_BYTES);
  for (const [index, name] of LEAVES.entries()) {
    const staged = regular(join(plan.repair, name), MAX_BINARY_BYTES);
    const topLevel = regular(join(plan.inputs, name.replace('.exe', `-${TARGET}.exe`)), MAX_BINARY_BYTES);
    if (!staged.equals(topLevel) || staged.length !== helperPayload[index].bytes || digest(staged) !== helperPayload[index].sha256) fail('Staged repair executable differs from its top-level package input.');
  }
  const repairPayload = [
    ...helperPayload.map((row) => ({ ...row, name: `${REPAIR_DIRECTORY}/${row.name}` })),
    validateRepairManifest(repairManifest, config.version, helperPayload),
  ];
  const destination = join(plan.output, 'controller-setup.exe');
  noLinks(destination);
  if (existsSync(destination)) regular(destination, MAX_INSTALLER_BYTES);
  copyFileSync(source, destination, existsSync(destination) ? 0 : constants.COPYFILE_EXCL);
  const manifest = { schemaVersion: 2, target: TARGET, mode: 'assembled', signing: 'not-attested', payload: [...payload, ...repairPayload], installer: { name: 'controller-setup.exe', bytes: installer.length, sha256: digest(installer) } };
  validateManifest(manifest);
  writeKnown(join(plan.output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write('Assembled target/windows-package/controller-setup.exe; run inspect separately. No installer or service was executed.\n');
}
if (process.argv[1] && isAbsolute(process.argv[1]) && relative(resolve(process.argv[1]), fileURLToPath(import.meta.url)) === '') {
  try { main(); } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : 'Windows packaging failed.'}\n`); process.exitCode = 1; }
}
