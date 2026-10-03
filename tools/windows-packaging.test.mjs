// SPDX-License-Identifier: GPL-2.0-or-later
// Root-run argv, artifact and source-contract tests. No installer/native service.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtempSync, readFileSync, writeFileSync, linkSync, lstatSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { buildPlan, createRepairManifest, createStagedManifest, expectedPayload, inspectPe, inspectInstallerPe, invalidateInspection, MAX_BINARY_BYTES, MAX_REPAIR_MANIFEST_BYTES, parseArchiveListing, parseArguments, TARGET, transformNsisMain, validateConfiguration, validateFileMetadata, validateManifest, validateRepairManifest, validateStagedManifest, verifyExtractedPayload } from './windows-packaging.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const base = JSON.parse(readFileSync(join(root, 'src-tauri/tauri.conf.json'), 'utf8'));
const overlay = JSON.parse(readFileSync(join(root, 'src-tauri/windows/package-config.json'), 'utf8'));
function pe(machine = 0x8664) {
  const bytes = Buffer.alloc(1024);
  bytes.write('MZ'); bytes.writeUInt32LE(128, 0x3c); bytes.writeUInt32LE(0x4550, 128);
  bytes.writeUInt16LE(machine, 132); bytes.writeUInt16LE(1, 134);
  bytes.writeUInt16LE(machine === 0x14c ? 224 : 240, 148); bytes.writeUInt16LE(2, 150);
  bytes.writeUInt16LE(machine === 0x14c ? 0x10b : 0x20b, 152);
  return bytes;
}
const leaves = ['controller-app.exe', 'uac-service.exe', 'uac-prompt-probe.exe'];
const repairLeaves = ['repair/uac-service.exe', 'repair/uac-prompt-probe.exe', 'repair/repair-manifest.json'];
const sourceMarker = '__TAURI_BUNDLE_TYPE_VAR_UNK';
const packagedMarker = '__TAURI_BUNDLE_TYPE_VAR_NSS';
const sha256 = (value) => createHash('sha256').update(value).digest('hex');
function mainPe() {
  const bytes = pe();
  bytes.write(sourceMarker, 600, 'ascii');
  return bytes;
}
function listing(type = 'Nsis', members = [...leaves, ...repairLeaves]) {
  return `7-Zip synthetic listing\n\nPath = controller-setup.exe\nType = ${type}\nPhysical Size = 10000\n\n${members.map((name) => `Path = ${name}\nSize = ${name.endsWith('.json') ? 256 : 1024}\nPacked Size = 400`).join('\n\n')}\n`;
}
function helperPayload() {
  return leaves.slice(1).map((name) => expectedPayload(name, pe()));
}
function manifest() {
  const helpers = helperPayload();
  const payload = [expectedPayload('controller-app.exe', mainPe()), ...helpers];
  const repairManifest = createRepairManifest(base.version, helpers);
  return { schemaVersion: 2, target: TARGET, mode: 'assembled', signing: 'not-attested', payload: [...payload, ...helpers.map((row) => ({ ...row, name: `repair/${row.name}` })), validateRepairManifest(repairManifest, base.version, helpers)], installer: { name: 'controller-setup.exe', bytes: 2048, sha256: 'b'.repeat(64) } };
}

test('fixed build/stage/inspect plans never execute packaged native binaries', () => {
  for (const mode of ['build', 'stage', 'inspect']) assert.equal(parseArguments([mode]).mode, mode);
  assert.equal(parseArguments(['--help']).mode, 'help');
  assert.equal(parseArguments(['build', '--target', TARGET, '--dry-run']).dryRun, true);
  const plan = buildPlan(root, { CARGO_TARGET_DIR: 'target/isolated-build' });
  assert.ok(plan.release.endsWith(join('target/isolated-build', TARGET, 'release')));
  assert.ok(plan.cargo.includes('--locked')); assert.ok(plan.tauri.includes('--locked'));
  assert.ok(plan.tauri.includes('src-tauri/windows/package-config.json'));
  assert.ok(!plan.cargo.includes('run'));
  for (const invalid of [['install'], ['build', '--target', 'i686-pc-windows-msvc'], ['inspect', '--run'], ['build', '--target', TARGET, '--target', TARGET], ['build', '--dry-run', '--dry-run']]) assert.throws(() => parseArguments(invalid));
});

test('packaging-only config fixes both helpers, repair resources, perMachine and prerequisite-only WebView', () => {
  assert.doesNotThrow(() => validateConfiguration(base, overlay));
  assert.equal(base.bundle.resources, undefined, 'ordinary cargo builds must not read generated repair paths');
  assert.deepEqual(overlay.bundle.resources, {
    '../target/windows-package/repair/uac-service.exe': 'repair/uac-service.exe',
    '../target/windows-package/repair/uac-prompt-probe.exe': 'repair/uac-prompt-probe.exe',
    '../target/windows-package/repair/repair-manifest.json': 'repair/repair-manifest.json',
  });
  for (const change of [(value) => { value.bundle.windows.nsis.installMode = 'currentUser'; }, (value) => { value.productName = 'Other'; }, (value) => { value.bundle.resources = {}; }, (value) => { value.bundle.fileAssociations = [{ ext: ['x'] }]; }]) {
    const other = structuredClone(base); change(other); assert.throws(() => validateConfiguration(other, overlay));
  }
  const extra = structuredClone(overlay); extra.bundle.externalBin.push('unexpected');
  assert.throws(() => validateConfiguration(base, extra));
  const wrongResource = structuredClone(overlay); wrongResource.bundle.resources['../target/windows-package/repair/uac-service.exe'] = 'uac-service.exe';
  assert.throws(() => validateConfiguration(base, wrongResource));
  const download = structuredClone(overlay); download.bundle.windows.webviewInstallMode.type = 'downloadBootstrapper';
  assert.throws(() => validateConfiguration(base, download));
  for (const field of ['certificateThumbprint', 'signCommand']) {
    const signed = structuredClone(base); signed.bundle.windows[field] = 'synthetic-not-a-credential';
    assert.throws(() => validateConfiguration(signed, overlay));
  }
});

test('PE payload has bounded complete executable header and correct architecture', () => {
  assert.equal(inspectPe(pe()).bytes, 1024);
  assert.throws(() => inspectPe(pe(0x14c)));
  for (const change of [(b) => { b.writeUInt32LE(0xffff, 0x3c); }, (b) => { b.writeUInt16LE(0x10b, 152); }, (b) => { b.writeUInt16LE(0, 150); }, (b) => { b.writeUInt16LE(0x2002, 150); }, (b) => { b.writeUInt16LE(1024, 148); }, (b) => { b.writeUInt16LE(97, 134); }]) {
    const bytes = pe(); change(bytes); assert.throws(() => inspectPe(bytes));
  }
  assert.throws(() => inspectPe(pe().subarray(0, 300)));
});

test('outer NSIS stub may be x86 independently of AMD64 payload, never renamed ZIP', () => {
  assert.equal(inspectInstallerPe(pe(0x14c)).bytes, 1024);
  assert.equal(inspectInstallerPe(pe()).bytes, 1024);
  const mismatch = pe(0x14c); mismatch.writeUInt16LE(0x20b, 152);
  assert.throws(() => inspectInstallerPe(mismatch));
  assert.throws(() => inspectInstallerPe(Buffer.from('PK synthetic renamed ZIP')));
  assert.throws(() => parseArchiveListing(listing('zip')));
});

test('archive requires one NSIS descriptor, three root payloads and three exact repair payloads', () => {
  assert.deepEqual(parseArchiveListing(listing()).map((row) => row.name), [...leaves, ...repairLeaves]);
  assert.equal(parseArchiveListing(listing().replace('Path = repair/uac-service.exe', 'Path = repair\\uac-service.exe'))[3].archivePath, 'repair\\uac-service.exe');
  assert.throws(() => parseArchiveListing(listing() + '\nPath = second.exe\nType = Nsis\n'));
  assert.throws(() => parseArchiveListing(listing().replace('Type = Nsis', 'Type = Nsis\nType = Nsis')));
  assert.throws(() => parseArchiveListing(listing().replace('Size = 1024', 'Size = 1024\nSize = 1024')));
  assert.throws(() => parseArchiveListing(listing('Nsis', [...leaves, ...repairLeaves, 'repair/uac-service.exe'])));
  assert.throws(() => parseArchiveListing(listing('Nsis', [...leaves, ...repairLeaves, 'nested/uac-service.exe'])));
  assert.throws(() => parseArchiveListing(listing('Nsis', [...leaves, ...repairLeaves, 'nested/repair-manifest.json'])));
  assert.throws(() => parseArchiveListing(listing('Nsis', [...leaves, ...repairLeaves, 'repair/REPAIR-MANIFEST.JSON'])));
  assert.throws(() => parseArchiveListing(listing('Nsis', ['controller-app.exe', 'nested/uac-service.exe', 'uac-prompt-probe.exe', ...repairLeaves])));
  assert.throws(() => parseArchiveListing(listing('Nsis', [...leaves, ...repairLeaves.slice(1)])));
  assert.doesNotThrow(() => parseArchiveListing(listing().replace('Path = repair/uac-service.exe', 'Path = repair\\uac-service.exe')));
  assert.throws(() => parseArchiveListing(listing().replace('Path = repair/uac-service.exe', 'Path = REPAIR/uac-service.exe')));
  assert.throws(() => parseArchiveListing(listing().replace('Path = repair/repair-manifest.json', 'Path = repair/REPAIR-MANIFEST.JSON')));
  assert.throws(() => parseArchiveListing(listing().replace('Size = 1024', `Size = ${MAX_BINARY_BYTES + 1}`)));
  assert.throws(() => parseArchiveListing(listing().replace('Size = 256', `Size = ${MAX_REPAIR_MANIFEST_BYTES + 1}`)));
});

test('staged and assembled package manifests have distinct exact schemas', () => {
  const helpers = helperPayload();
  // Use the same exported constructor stage() calls, with the same two-helper input.
  const staged = createStagedManifest(base.version, helpers, createRepairManifest(base.version, helpers));
  assert.deepEqual(staged.payload.map((row) => row.name), [
    'uac-service.exe', 'uac-prompt-probe.exe',
    'repair/uac-service.exe', 'repair/uac-prompt-probe.exe', 'repair/repair-manifest.json',
  ]);
  assert.equal(staged.installer, null);
  assert.equal(staged.payload[0].transformation.kind, 'identity');
  assert.equal(validateStagedManifest(staged).payload.length, 5);
  assert.doesNotMatch(JSON.stringify(staged), /controller-app\.exe|tauri-bundler/u);
  assert.equal(validateStagedManifest(structuredClone(staged)).payload[4].name, 'repair/repair-manifest.json');
  assert.deepEqual(staged.payload[2].sha256, staged.payload[0].sha256);
  assert.deepEqual(staged.payload[3].sha256, staged.payload[1].sha256);
  assert.deepEqual(staged.payload[2].bytes, staged.payload[0].bytes);
  assert.deepEqual(staged.payload[3].bytes, staged.payload[1].bytes);
  assert.equal(staged.payload[4].bytes, createRepairManifest(base.version, helpers).length);
  const reversedHelpers = helperPayload().reverse();
  const canonicalRepairManifest = createRepairManifest(base.version, helperPayload());
  assert.throws(() => createStagedManifest(base.version, reversedHelpers, canonicalRepairManifest));
  assert.throws(() => createStagedManifest(base.version, helpers.slice(0, 1), canonicalRepairManifest));
  assert.throws(() => validateManifest(staged));
  for (const change of [
    (m) => { m.mode = 'assembled'; },
    (m) => { m.payload.unshift(expectedPayload('controller-app.exe', mainPe())); },
    (m) => { m.payload.pop(); },
    (m) => { m.payload[0].transformation.kind = 'tauri-bundler-2.9.4-nsis-marker-v1'; },
    (m) => { m.payload[2].sha256 = '0'.repeat(64); },
    (m) => { m.payload[2].name = 'repair/uac-prompt-probe.exe'; },
    (m) => { m.payload[4].bytes = MAX_REPAIR_MANIFEST_BYTES + 1; },
    (m) => { m.installer = { name: 'controller-setup.exe', bytes: 1, sha256: 'b'.repeat(64) }; },
  ]) {
    const value = structuredClone(staged); change(value); assert.throws(() => validateStagedManifest(value));
  }

  assert.deepEqual(manifest().payload.map((row) => row.name), [
    'controller-app.exe', 'uac-service.exe', 'uac-prompt-probe.exe',
    'repair/uac-service.exe', 'repair/uac-prompt-probe.exe', 'repair/repair-manifest.json',
  ]);
  assert.equal(validateManifest(manifest()).signing, 'not-attested');
  for (const change of [(m) => { m.mode = 'staged'; }, (m) => { m.authenticated = true; }, (m) => { m.payload.pop(); }, (m) => { m.payload[0].sha256 = 'invalid'; }, (m) => { m.payload[1].name = 'other.exe'; }, (m) => { m.payload[3].sha256 = '0'.repeat(64); }, (m) => { m.payload[5].bytes = MAX_REPAIR_MANIFEST_BYTES + 1; }, (m) => { m.installer.bytes = Number.MAX_SAFE_INTEGER; }]) {
    const value = manifest(); change(value); assert.throws(() => validateManifest(value));
  }
});

test('repair manifest is exact compact UTF-8 from the staged helper metadata', () => {
  const helpers = helperPayload();
  const bytes = createRepairManifest('1.8.0', helpers);
  const exact = `{"schema":1,"product":"uac-remote-controller","version":"1.8.0","files":[{"name":"uac-service.exe","bytes":1024,"sha256":"${helpers[0].sha256}"},{"name":"uac-prompt-probe.exe","bytes":1024,"sha256":"${helpers[1].sha256}"}]}`;
  assert.deepEqual(bytes, Buffer.from(exact, 'utf8'));
  assert.ok(bytes.length <= MAX_REPAIR_MANIFEST_BYTES);
  assert.equal(validateRepairManifest(bytes, '1.8.0', helpers).sha256, sha256(bytes));
  assert.throws(() => validateRepairManifest(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), bytes]), '1.8.0', helpers));
  assert.throws(() => validateRepairManifest(Buffer.from([0xff]), '1.8.0', helpers));
  assert.throws(() => validateRepairManifest(Buffer.from(`${exact}\n`, 'utf8'), '1.8.0', helpers));
  assert.throws(() => validateRepairManifest(bytes, '1.8.1', helpers));
  assert.throws(() => createRepairManifest('1.8.0"}', helpers));
  assert.throws(() => createRepairManifest('01.8.0', helpers));
  const wrong = structuredClone(helpers); wrong[0].sha256 = '0'.repeat(64);
  assert.throws(() => validateRepairManifest(bytes, '1.8.0', wrong));
});

test('NSIS expected main is the exact one-marker transformation of immutable build source', () => {
  const source = mainPe(), original = Buffer.from(source);
  const { packaged, metadata } = transformNsisMain(source);
  const independentlyExpected = Buffer.from(original);
  independentlyExpected.write(packagedMarker, 600, 'ascii');
  assert.deepEqual(source, original, 'never mutate the restored Cargo/Tauri main');
  assert.equal(packaged.length, source.length);
  assert.deepEqual(packaged.subarray(0, 600), source.subarray(0, 600));
  assert.deepEqual(packaged.subarray(600 + sourceMarker.length), source.subarray(600 + sourceMarker.length));
  assert.deepEqual(packaged, independentlyExpected);
  assert.equal(metadata.sourceSha256, sha256(original));
  assert.equal(metadata.sha256, sha256(independentlyExpected));
  assert.notEqual(metadata.sourceSha256, metadata.sha256);
  assert.deepEqual(metadata.transformation, { kind: 'tauri-bundler-2.9.4-nsis-marker-v1', offset: 600, from: sourceMarker, to: packagedMarker });
});

test('missing, duplicate, already patched, or mixed bundle markers are not predicted', () => {
  assert.throws(() => transformNsisMain(pe()));
  const duplicate = mainPe(); duplicate.write(sourceMarker, 700, 'ascii');
  assert.throws(() => transformNsisMain(duplicate));
  const already = pe(); already.write(packagedMarker, 600, 'ascii');
  assert.throws(() => transformNsisMain(already));
  const mixed = mainPe(); mixed.write(packagedMarker, 700, 'ascii');
  assert.throws(() => transformNsisMain(mixed));
});

test('full extracted-byte hash remains mandatory outside and inside the marker', () => {
  const { packaged, metadata } = transformNsisMain(mainPe());
  const entry = { name: metadata.name, bytes: packaged.length };
  assert.equal(verifyExtractedPayload(entry, packaged, metadata).sha256, metadata.sha256);
  for (const offset of [500, 600, 900]) {
    const tampered = Buffer.from(packaged); tampered[offset] ^= 1;
    assert.throws(() => verifyExtractedPayload(entry, tampered, metadata));
  }
  assert.throws(() => verifyExtractedPayload(entry, mainPe(), metadata), 'the old unbundled hash is not accepted');
  for (const name of leaves.slice(1)) {
    const bytes = pe(), row = expectedPayload(name, bytes);
    assert.equal(row.sha256, sha256(bytes)); assert.equal(row.sourceSha256, row.sha256);
    assert.deepEqual(row.transformation, { kind: 'identity' });
    assert.doesNotThrow(() => verifyExtractedPayload({ name, bytes: bytes.length }, bytes, row));
  }
});

test('a source-hash-only substitution cannot pass packaged-byte inspection', () => {
  const { packaged, metadata } = transformNsisMain(mainPe());
  const wrong = { ...metadata, sourceSha256: '0'.repeat(64) };
  const syntacticallyValid = manifest();
  syntacticallyValid.payload[0] = wrong;
  assert.doesNotThrow(() => validateManifest(syntacticallyValid));
  assert.throws(() => verifyExtractedPayload(
    { name: metadata.name, bytes: packaged.length }, packaged, wrong,
  ), /recorded build source/u);
});

test('v2 manifest refuses old schemas and unsupported transformation descriptions', () => {
  assert.equal(validateManifest(manifest()).schemaVersion, 2);
  for (const change of [
    (m) => { m.schemaVersion = 1; },
    (m) => { m.payload[0].transformation.from = packagedMarker; },
    (m) => { m.payload[0].transformation.offset = 1024; },
    (m) => { m.payload[0].transformation.offset = -1; },
    (m) => { m.payload[0].transformation.to = '__TAURI_BUNDLE_TYPE_VAR_MSI'; },
    (m) => { m.payload[0].transformation.extra = true; },
    (m) => { m.payload[1].sourceSha256 = 'c'.repeat(64); },
    (m) => { m.payload[1].transformation.kind = 'sign'; },
    (m) => { m.payload[3].name = 'repair\\uac-service.exe'; },
    (m) => { m.payload[5].sourceSha256 = 'c'.repeat(64); },
  ]) {
    const value = manifest(); change(value); assert.throws(() => validateManifest(value));
  }
});

test('lab-profile binaries are refused for every packaged executable', () => {
  for (const name of leaves) {
    const bytes = name === 'controller-app.exe' ? mainPe() : pe();
    assert.doesNotThrow(() => expectedPayload(name, bytes));
    for (const marker of ['lab-software-ksp-do-not-ship', 'uac-ci-startup-notes-do-not-ship']) {
      const lab = Buffer.from(bytes);
      lab.write(marker, 800, 'ascii');
      assert.throws(() => expectedPayload(name, lab), /lab-profile/u);
    }
  }
});

test('marker-only prediction refuses signed or malformed PE security directories', () => {
  const signed = mainPe();
  signed.writeUInt32LE(5, 128 + 24 + 108);
  signed.writeUInt32LE(900, 128 + 24 + 144);
  signed.writeUInt32LE(64, 128 + 24 + 148);
  assert.throws(() => transformNsisMain(signed));
  assert.throws(() => expectedPayload('uac-service.exe', signed));
  const malformed = mainPe(); malformed.writeUInt32LE(17, 128 + 24 + 108);
  assert.throws(() => transformNsisMain(malformed));
});

test('Cargo hardlinked build source is allowed only before independent staging', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'uac-package-link-'));
  const source = join(dir, 'cargo.exe'), other = join(dir, 'deps.exe'), staged = join(dir, 'staged.exe');
  t.after(() => { for (const path of [source, other, staged]) unlinkSync(path); rmdirSync(dir); });
  writeFileSync(source, pe()); linkSync(source, other); writeFileSync(staged, readFileSync(source));
  assert.ok(lstatSync(source).nlink > 1);
  assert.doesNotThrow(() => validateFileMetadata(lstatSync(source), MAX_BINARY_BYTES, true));
  assert.throws(() => validateFileMetadata(lstatSync(source), MAX_BINARY_BYTES));
  assert.doesNotThrow(() => validateFileMetadata(lstatSync(staged), MAX_BINARY_BYTES));
  const link = { ...lstatSync(staged), isFile: () => true, isSymbolicLink: () => true };
  assert.throws(() => validateFileMetadata(link, MAX_BINARY_BYTES, true));
});

test('stage writes repair copies and inspect checks exact staged and packaged bytes', () => {
  const plan = buildPlan(root);
  assert.equal(plan.repair, join(root, 'target/windows-package/repair'));
  const source = readFileSync(join(root, 'tools/windows-packaging.mjs'), 'utf8');
  assert.match(source, /repair: join\(repository, OUTPUT, REPAIR_DIRECTORY\)/u);
  assert.match(source, /writeKnown\(join\(plan\.repair, name\), bytes\)/u);
  assert.match(source, /writeKnown\(join\(plan\.repair, REPAIR_MANIFEST\), repairManifest\)/u);
  assert.match(source, /createStagedManifest\(base\.version, payload, repairManifest\)/u);
  assert.match(source, /return validateStagedManifest\(\{ schemaVersion: 2,[\s\S]*payload: \[\.\.\.payload, \.\.\.repairPayload\]/u);
  assert.match(source, /createRepairManifest\(base\.version, payload\)/u);
  assert.match(source, /createRepairManifest\(version, helpers\)/u);
  assert.match(source, /validateConfiguration\(currentConfig/u);
  assert.equal(source.match(/Only the explicit packaging overlay may add generated Windows resources/gu)?.length, 1);
  assert.equal(source.match(/rejectImplicitWindowsConfiguration\(\)/gu)?.length, 3);
  assert.equal(source.match(/payload: \[\.\.\.payload, \.\.\.repairPayload\]/gu)?.length, 2);
  assert.match(source, /Staged repair executable differs from its top-level package input/u);
  assert.match(source, /extracted\.get\(name\)\?\.equals\(extracted\.get\(`\$\{REPAIR_DIRECTORY\}\/\$\{name\}`\)\)/u);
  assert.match(source, /Packaged repair manifest differs from the staged file/u);
  assert.match(source, /validateRepairManifest\(data, version, helpers\)/u);
  assert.match(source, /validateRepairManifest\(stagedRepairManifest, version, helpers\)/u);
  assert.match(source, /Staged repair manifest differs from package metadata/u);
});

test('fresh stage/inspection invalidate old successful receipt before child work', (t) => {
  const dir = mkdtempSync(join(tmpdir(), 'uac-package-receipt-'));
  const path = join(dir, 'inspection.json');
  t.after(() => { unlinkSync(path); rmdirSync(dir); });
  writeFileSync(path, JSON.stringify({ passed: true, stale: true }));
  invalidateInspection({ output: dir }, 'new-stage');
  assert.deepEqual(JSON.parse(readFileSync(path)), { schemaVersion: 1, passed: false, scope: 'passive-nsis-payload-only', reason: 'new-stage' });
  invalidateInspection({ output: dir }, 'inspection-started');
  assert.equal(JSON.parse(readFileSync(path)).passed, false);
  const source = readFileSync(join(root, 'tools/windows-packaging.mjs'), 'utf8');
  assert.ok(source.indexOf("invalidateInspection(plan, 'new-stage')") < source.indexOf("run('cargo', plan.cargo)"));
  assert.ok(!source.slice(source.indexOf('export function main')).includes('inspect(plan);\n}'));
});
