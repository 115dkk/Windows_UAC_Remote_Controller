// SPDX-License-Identifier: GPL-2.0-or-later
// Root-run argv, artifact and source-contract tests. No installer/native service.
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, writeFileSync, linkSync, lstatSync, unlinkSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { buildPlan, inspectPe, inspectInstallerPe, invalidateInspection, MAX_BINARY_BYTES, parseArchiveListing, parseArguments, TARGET, validateConfiguration, validateFileMetadata, validateManifest } from './windows-packaging.mjs';

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
function listing(type = 'Nsis', members = leaves) {
  return `7-Zip synthetic listing\n\nPath = controller-setup.exe\nType = ${type}\nPhysical Size = 10000\n\n${members.map((name) => `Path = ${name}\nSize = 1024\nPacked Size = 400`).join('\n\n')}\n`;
}
function manifest() {
  return { schemaVersion: 1, target: TARGET, mode: 'assembled', signing: 'not-attested', payload: leaves.map((name) => ({ name, bytes: 1024, sha256: 'a'.repeat(64) })), installer: { name: 'controller-setup.exe', bytes: 2048, sha256: 'b'.repeat(64) } };
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

test('actual package config fixes both helpers, perMachine and prerequisite-only WebView', () => {
  assert.doesNotThrow(() => validateConfiguration(base, overlay));
  for (const change of [(value) => { value.bundle.windows.nsis.installMode = 'currentUser'; }, (value) => { value.productName = 'Other'; }, (value) => { value.bundle.resources = ['unreviewed']; }, (value) => { value.bundle.fileAssociations = [{ ext: ['x'] }]; }]) {
    const other = structuredClone(base); change(other); assert.throws(() => validateConfiguration(other, overlay));
  }
  const extra = structuredClone(overlay); extra.bundle.externalBin.push('unexpected');
  assert.throws(() => validateConfiguration(base, extra));
  const download = structuredClone(overlay); download.bundle.windows.webviewInstallMode.type = 'downloadBootstrapper';
  assert.throws(() => validateConfiguration(base, download));
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

test('archive requires one NSIS outer descriptor and three unique root payloads', () => {
  assert.deepEqual(parseArchiveListing(listing()).map((row) => row.name), leaves);
  assert.throws(() => parseArchiveListing(listing() + '\nPath = second.exe\nType = Nsis\n'));
  assert.throws(() => parseArchiveListing(listing().replace('Type = Nsis', 'Type = Nsis\nType = Nsis')));
  assert.throws(() => parseArchiveListing(listing().replace('Size = 1024', 'Size = 1024\nSize = 1024')));
  assert.throws(() => parseArchiveListing(listing('Nsis', [...leaves, 'uac-service.exe'])));
  assert.throws(() => parseArchiveListing(listing('Nsis', ['controller-app.exe', 'nested/uac-service.exe', 'uac-prompt-probe.exe'])));
  assert.throws(() => parseArchiveListing(listing('Nsis', leaves.slice(1))));
  assert.throws(() => parseArchiveListing(listing().replace('Size = 1024', `Size = ${MAX_BINARY_BYTES + 1}`)));
});

test('manifest is exact bounded artifact metadata, not signing/native success', () => {
  assert.equal(validateManifest(manifest()).signing, 'not-attested');
  for (const change of [(m) => { m.mode = 'staged'; }, (m) => { m.authenticated = true; }, (m) => { m.payload[0].sha256 = 'invalid'; }, (m) => { m.payload[1].name = 'other.exe'; }, (m) => { m.installer.bytes = Number.MAX_SAFE_INTEGER; }]) {
    const value = manifest(); change(value); assert.throws(() => validateManifest(value));
  }
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
