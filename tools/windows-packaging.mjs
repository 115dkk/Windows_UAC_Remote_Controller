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
const MARKER = '.uac-windows-package-v1';
const MARKER_TEXT = 'Generated Windows package inputs v1; not enrollment or signature authority.\n';
const LEAVES = ['uac-service.exe', 'uac-prompt-probe.exe'];
const ALL_LEAVES = ['controller-app.exe', ...LEAVES];
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
  if (base.productName !== '휴대폰 승인' || base.identifier !== 'dev.dkk115.uacremote' || base.bundle?.windows?.nsis?.installMode !== 'perMachine' || base.bundle.windows.nsis.template !== 'windows/installer.nsi' || base.bundle.windows.nsis.installerHooks !== 'windows/packaging-hooks.nsh' || base.bundle.windows.allowDowngrades !== false || base.bundle.externalBin?.length || base.bundle.resources && Object.keys(base.bundle.resources).length || base.bundle.fileAssociations?.length || base.plugins?.['deep-link']) fail('Unsupported Windows package configuration.');
  if (JSON.stringify(overlay) !== JSON.stringify({ bundle: { windows: { webviewInstallMode: { type: 'skip' } }, externalBin: ['../target/windows-package/inputs/uac-service', '../target/windows-package/inputs/uac-prompt-probe'] } })) fail('Use the fixed Windows service package overlay.');
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
  if (entries.some((name) => ![MARKER, 'inputs', 'manifest.json', 'inspection.json', 'controller-setup.exe'].includes(name))) fail('Unknown package output entries are preserved.');
  const marker = join(plan.output, MARKER);
  if (existsSync(marker)) {
    if (regular(marker, 1024).toString('utf8') !== MARKER_TEXT) fail('Package ownership marker is invalid.');
  } else writeFileSync(marker, MARKER_TEXT, { flag: 'wx' });
  noLinks(plan.inputs);
  if (!existsSync(plan.inputs)) mkdirSync(plan.inputs);
  if (readdirSync(plan.inputs).some((name) => !LEAVES.map((leaf) => leaf.replace('.exe', `-${TARGET}.exe`)).includes(name))) fail('Unknown staged inputs are preserved.');
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
export function expectedPayload(name, source) {
  if (name === 'controller-app.exe') return transformNsisMain(source).metadata;
  if (!LEAVES.includes(name)) fail('Unexpected packaged executable name.');
  const original = unsignedPayload(source);
  return { name, ...original, sourceSha256: original.sha256, transformation: { kind: 'identity' } };
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
  if (new Set(rows.map((row) => row.Path.replaceAll('\\', '/').toLowerCase())).size !== rows.length) fail('Installer listing contains duplicate paths.');
  return ALL_LEAVES.map((leaf) => {
    const matches = rows.filter((row) => basename(row.Path.replaceAll('\\', '/')) === leaf);
    if (matches.length !== 1 || matches[0].Path !== leaf || !/^[0-9]+$/u.test(matches[0].Size ?? '') || Number(matches[0].Size) < 1 || Number(matches[0].Size) > MAX_BINARY_BYTES) fail('Installer must contain each fixed executable exactly once at its root.');
    return { name: leaf, bytes: Number(matches[0].Size) };
  });
}
export function validateManifest(value) {
  if (!value || value.schemaVersion !== 2 || value.target !== TARGET || value.mode !== 'assembled' || value.signing !== 'not-attested' || !Array.isArray(value.payload) || value.payload.length !== 3) fail('Package manifest is unsupported.');
  const keys = ['schemaVersion', 'target', 'mode', 'signing', 'payload', 'installer'];
  if (Object.keys(value).some((key) => !keys.includes(key))) fail('Package manifest has unknown fields.');
  for (const [index, row] of value.payload.entries()) {
    if (!row || Object.keys(row).sort().join() !== 'bytes,name,sha256,sourceSha256,transformation' || row.name !== ALL_LEAVES[index] || !Number.isSafeInteger(row.bytes) || row.bytes < 1 || row.bytes > MAX_BINARY_BYTES || !/^[a-f0-9]{64}$/u.test(row.sha256) || !/^[a-f0-9]{64}$/u.test(row.sourceSha256)) fail('Package payload metadata is invalid.');
    const transform = row.transformation;
    if (!transform || typeof transform !== 'object') fail('Missing bounded payload transformation metadata.');
    if (index === 0) {
      if (Object.keys(transform).sort().join() !== 'from,kind,offset,to' || transform.kind !== BUNDLE_TRANSFORM || transform.from !== BUNDLE_SOURCE_MARKER.toString('ascii') || transform.to !== BUNDLE_NSIS_MARKER.toString('ascii') || !Number.isSafeInteger(transform.offset) || transform.offset < 0 || transform.offset > row.bytes - BUNDLE_SOURCE_MARKER.length) fail('Unexpected main executable transformation.');
    } else if (Object.keys(transform).join() !== 'kind' || transform.kind !== 'identity' || row.sha256 !== row.sourceSha256) fail('Helper payload must be byte-identical to its build input.');
  }
  const installer = value.installer;
  if (!installer || Object.keys(installer).sort().join() !== 'bytes,name,sha256' || installer.name !== 'controller-setup.exe' || !Number.isSafeInteger(installer.bytes) || installer.bytes < 1 || installer.bytes > MAX_INSTALLER_BYTES || !/^[a-f0-9]{64}$/u.test(installer.sha256)) fail('Installer metadata is invalid.');
  return value;
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
function stage(plan) {
  prepareOutput(plan);
  invalidateInspection(plan, 'new-stage');
  if (process.env.TAURI_CONFIG !== undefined || ['tauri.windows.conf.json', 'tauri.windows.conf.json5', 'Tauri.windows.toml'].some((name) => existsSync(join(root, 'src-tauri', name)))) fail('Unreviewed Tauri configuration overrides are unsupported by the unsigned marker profile.');
  validateConfiguration(JSON.parse(readFileSync(join(root, 'src-tauri/tauri.conf.json'), 'utf8')), JSON.parse(readFileSync(join(root, 'src-tauri/windows/package-config.json'), 'utf8')));
  run('cargo', plan.cargo);
  const payload = LEAVES.map((name) => {
    const source = join(plan.release, name);
    noLinks(source);
    const bytes = regular(source, MAX_BINARY_BYTES, true);
    const row = expectedPayload(name, bytes);
    writeKnown(join(plan.inputs, name.replace('.exe', `-${TARGET}.exe`)), bytes);
    return row;
  });
  writeKnown(join(plan.output, 'manifest.json'), `${JSON.stringify({ schemaVersion: 2, target: TARGET, mode: 'staged', signing: 'not-attested', payload }, null, 2)}\n`);
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
  const manifest = validateManifest(JSON.parse(manifestBytes));
  const installer = join(plan.output, 'controller-setup.exe');
  const bytes = regular(installer, MAX_INSTALLER_BYTES);
  inspectInstallerPe(bytes);
  if (bytes.length !== manifest.installer.bytes || digest(bytes) !== manifest.installer.sha256) fail('Assembled installer does not match its build manifest.');
  const listing = run('7z', ['l', '-slt', '--', installer], { stdio: ['ignore', 'pipe', 'pipe'], encoding: 'utf8', maxBuffer: 1024 * 1024, timeout: 60_000 });
  const entries = parseArchiveListing(listing);
  for (const entry of entries) {
    const data = run('7z', ['e', '-so', '-bd', '--', installer, entry.name], { stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: MAX_BINARY_BYTES, timeout: 60_000 });
    const expected = manifest.payload.find((row) => row.name === entry.name);
    verifyExtractedPayload(entry, data, expected);
  }
  writeKnown(join(plan.output, 'inspection.json'), `${JSON.stringify({ schemaVersion: 1, passed: true, scope: 'passive-nsis-payload-only', manifestSha256: digest(manifestBytes), installer: manifest.installer, payload: manifest.payload, signing: 'not-attested', nativeInstallation: 'not-executed' }, null, 2)}\n`);
  process.stdout.write('Inspected three exact executable payloads without executing the installer. Signing and native installation are not verified.\n');
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
  const destination = join(plan.output, 'controller-setup.exe');
  noLinks(destination);
  if (existsSync(destination)) regular(destination, MAX_INSTALLER_BYTES);
  copyFileSync(source, destination, existsSync(destination) ? 0 : constants.COPYFILE_EXCL);
  const manifest = { schemaVersion: 2, target: TARGET, mode: 'assembled', signing: 'not-attested', payload, installer: { name: 'controller-setup.exe', bytes: installer.length, sha256: digest(installer) } };
  validateManifest(manifest);
  writeKnown(join(plan.output, 'manifest.json'), `${JSON.stringify(manifest, null, 2)}\n`);
  process.stdout.write('Assembled target/windows-package/controller-setup.exe; run inspect separately. No installer or service was executed.\n');
}
if (process.argv[1] && isAbsolute(process.argv[1]) && relative(resolve(process.argv[1]), fileURLToPath(import.meta.url)) === '') {
  try { main(); } catch (error) { process.stderr.write(`${error instanceof Error ? error.message : 'Windows packaging failed.'}\n`); process.exitCode = 1; }
}
