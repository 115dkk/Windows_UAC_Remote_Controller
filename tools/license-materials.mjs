// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT/CI only. Bounded original Rust notice bytes, NOT compatibility clearance,
// all-language inventory or corresponding-source fulfillment. No fetch/sign/publish.
// REQUIRE quiescent, trusted ROOT/CI checkout, package/cache and output trees.
// Sampled lstat/realpath/bytes detect observed changes, NOT atomic directory-handle
// containment against adversarial ancestor swaps/ABA. This is not a runtime boundary.
import { createHash } from 'node:crypto';
import * as nativeFs from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep, win32 } from 'node:path';
import { fileURLToPath } from 'node:url';
import { TextDecoder } from 'node:util';
import { licenseInventoryFromMetadata, readLockedCargoMetadata } from './license-inventory.mjs';
import { ALLOC_STDLIB_SHARED_NOTICE, isReviewedSharedNoticeConsumer, isReviewedSharedNoticeProvider, matchesReviewedSharedNoticeBytes } from './license-material-supplements.mjs';
import { isApprovedUpstreamIndex, isUpstreamMaterialOrigin, matchesUpstreamMaterial, MAX_UPSTREAM_CONSUMERS, MAX_UPSTREAM_GROUP_FILES, upstreamNoticeGroup, upstreamPinForSourcePath, UPSTREAM_SOURCE_INDEX, UPSTREAM_SOURCE_PINS } from './license-upstream-policy.mjs';

const repositoryRoot = fileURLToPath(new URL('../', import.meta.url));
export const MATERIALS_OUTPUT = 'target/license-materials/rust';
export const MATERIAL_LIMITS = Object.freeze({ packages: 2048, perPackage: 32, fileBytes: 1024 * 1024, totalBytes: 32 * 1024 * 1024, rootEntries: 1024, pathBytes: 4096, manifestBytes: 16 * 1024 * 1024 });
const MARKER = '.rust-license-materials-v4';
const MARKER_BYTES = Buffer.from('Rust license-materials collection v4; incomplete until manifest.json is committed.\n');
const ROOT_NOTICES = ['LICENSE', 'LICENSE-NOTICE.md'];
const PATCH_NOTICE = 'vendor/ANDROID_LIFECYCLE_PATCHES.md';
const MAX_FIXED_ROOT_MATERIALS = ROOT_NOTICES.length + 1 + UPSTREAM_SOURCE_PINS.length;
const LIMITATIONS = Object.freeze(['license-compatibility-not-evaluated', 'legal-completeness-not-certified', 'g002-legal-completion-not-proven', 'collected-original-materials-not-full-terms-attestation', 'corresponding-source-not-produced', 'npm-maven-not-collected', 'fonts-remain-owned-by-tools/ui-fonts.mjs', 'stable-input-observations-not-upstream-archive-verification', 'quiescent-trusted-checkout-source-cache-output-required', 'anchor-stat-checks-not-adversarial-ancestor-swap-or-aba-containment']);
const LEGAL_NAME = /^(?:LICENSE|LICENCE|COPYING|NOTICE|COPYRIGHT|UNLICENSE)(?:[-_.][A-Za-z0-9._-]+)?$/iu;
const PRIVATE_SEGMENT = /^(?:\.git|\.ssh|\.aws|\.azure|\.gnupg|\.kube|\.config|\.codex|\.superloopy|\.env(?:\..*)?|credentials?|secrets?|config(?:\..*)?|id_rsa|id_ed25519)$/iu;
const ERRORS = new Set(['arguments', 'metadata_observation', 'metadata_shape', 'metadata_license', 'provenance', 'path', 'source_missing', 'source_type', 'source_changed', 'source_text', 'source_bounds', 'name_collision', 'material_missing', 'upstream_notice', 'output_exists', 'output_io', 'manifest']);
const compare = (left, right) => left < right ? -1 : left > right ? 1 : 0;
const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

export class LicenseMaterialsError extends Error {
  constructor(code, packageName = null) {
    super('Rust license material collection is incomplete.');
    this.name = 'LicenseMaterialsError';
    this.code = ERRORS.has(code) ? code : 'source_missing';
    this.packageName = typeof packageName === 'string' && /^[A-Za-z0-9_-]{1,128}$/u.test(packageName) ? packageName : null;
  }
}
function incomplete(code, packageName) { throw new LicenseMaterialsError(code, packageName); }
function record(value) { return value !== null && typeof value === 'object' && !Array.isArray(value); }
function keys(value, expected) { return record(value) && Object.keys(value).sort().join() === [...expected].sort().join(); }
function text(value, maximum) { return typeof value === 'string' && value.length > 0 && Buffer.byteLength(value) <= maximum && !/[\x00-\x1f\x7f]/u.test(value); }
function samePath(left, right) { return process.platform === 'win32' ? left.toLowerCase() === right.toLowerCase() : left === right; }

export function safeRelativePath(value) {
  if (!text(value, 512) || isAbsolute(value) || win32.isAbsolute(value) || value.includes('\\')) incomplete('path');
  const parts = value.split('/');
  if (parts.some((part) => !part || part === '.' || part === '..' || /[<>:"|?*]/u.test(part) || /[. ]$/u.test(part) || PRIVATE_SEGMENT.test(part) || /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)/iu.test(part))) incomplete('path');
  return value;
}
function absolutePath(value) {
  if (!text(value, MATERIAL_LIMITS.pathBytes) || !isAbsolute(value) || value.startsWith('\\\\') || value.startsWith('//')) incomplete('path');
  if (value.split(/[\\/]/u).some((part) => part === '.' || part === '..')) incomplete('path');
  const full = resolve(value), root = parse(full).root;
  if (samePath(full, root)) incomplete('path');
  // Validate every component without enumerating a drive/home/config directory.
  safeRelativePath(relative(root, full).split(sep).join('/'));
  return full;
}
function contained(root, path) {
  const part = relative(root, path).split(sep).join('/');
  if (!part || part === '..' || part.startsWith('../') || isAbsolute(part) || win32.isAbsolute(part)) incomplete('path');
  return safeRelativePath(part);
}
export function explicitLicensePath(packageRoot, declared) {
  if (!text(declared, MATERIAL_LIMITS.pathBytes)) incomplete('path');
  let path;
  if (isAbsolute(declared)) path = absolutePath(declared);
  else {
    if (win32.isAbsolute(declared) || declared.includes('\\')) incomplete('path');
    path = join(packageRoot, safeRelativePath(declared));
  }
  const part = contained(packageRoot, path);
  if (/(?:^|\/)(?:Cargo\.(?:toml|lock)|\.cargo|local\.properties|gradle\.properties|.*\.(?:jks|keystore|p12|pfx|pem|key))$/iu.test(part)) incomplete('path');
  return part;
}

export function publicCargoSource(value) {
  if (value === null) return null;
  if (!text(value, 2048)) incomplete('provenance');
  const match = /^(registry|sparse|git)\+(https:\/\/.*)$/u.exec(value);
  if (!match) incomplete('provenance');
  let url;
  try { url = new URL(match[2]); } catch { incomplete('provenance'); }
  if (url.protocol !== 'https:' || url.username || url.password || !url.hostname || url.href !== match[2]) incomplete('provenance');
  if (match[1] !== 'git' && (url.search || url.hash)) incomplete('provenance');
  if (match[1] === 'git') {
    if (!/^#[a-f0-9]{7,64}$/u.test(url.hash)) incomplete('provenance');
    const entries = [...url.searchParams];
    if (entries.length > 1 || entries.some(([key, value]) => !['branch', 'tag', 'rev'].includes(key) || !/^[A-Za-z0-9._/-]{1,256}$/u.test(value))) incomplete('provenance');
  }
  return value;
}

function lstat(io, path, missing = 'source_missing') {
  try { return io.lstatSync(path, { bigint: true }); } catch { incomplete(missing); }
}
function identity(stat) { return `${stat.dev}:${stat.ino}`; }
function stamp(stat) { return `${identity(stat)}:${stat.size}:${stat.mtimeNs}:${stat.ctimeNs}:${stat.nlink}`; }
function directoryAnchors(io, path) {
  const full = absolutePath(path), root = parse(full).root;
  let current = root;
  const anchors = [];
  for (const part of relative(root, full).split(sep)) {
    current = join(current, part);
    const stat = lstat(io, current);
    let actual;
    try { actual = io.realpathSync(current); } catch { incomplete('source_type'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || !samePath(resolve(actual), current)) incomplete('source_type');
    anchors.push({ path: current, identity: identity(stat) });
  }
  return anchors;
}
function checkAnchors(io, anchors) {
  for (const anchor of anchors) {
    const stat = lstat(io, anchor.path);
    let actual;
    try { actual = io.realpathSync(anchor.path); } catch { incomplete('source_changed'); }
    if (!stat.isDirectory() || stat.isSymbolicLink() || identity(stat) !== anchor.identity || !samePath(resolve(actual), anchor.path)) incomplete('source_changed');
  }
}
function readStable(io, path, maximum = MATERIAL_LIMITS.fileBytes) {
  const anchors = directoryAnchors(io, dirname(path));
  const before = lstat(io, path);
  if (!before.isFile() || before.isSymbolicLink() || before.nlink !== 1n) incomplete('source_type');
  if (before.size <= 0n || before.size > BigInt(maximum)) incomplete('source_bounds');
  let fd, bytes;
  try {
    fd = io.openSync(path, nativeFs.constants.O_RDONLY | (nativeFs.constants.O_NOFOLLOW ?? 0));
    if (stamp(io.fstatSync(fd, { bigint: true })) !== stamp(before)) incomplete('source_changed');
    const buffer = Buffer.alloc(Number(before.size) + 1);
    let used = 0;
    while (used < buffer.length) {
      const count = io.readSync(fd, buffer, used, buffer.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used !== Number(before.size) || stamp(io.fstatSync(fd, { bigint: true })) !== stamp(before)) incomplete('source_changed');
    bytes = buffer.subarray(0, used);
  } catch (error) {
    if (error instanceof LicenseMaterialsError) throw error;
    incomplete('source_missing');
  } finally { if (fd !== undefined) io.closeSync(fd); }
  if (stamp(lstat(io, path)) !== stamp(before)) incomplete('source_changed');
  checkAnchors(io, anchors);
  return { path, bytes, stamp: stamp(before), anchors };
}
function recheck(io, input) {
  checkAnchors(io, input.anchors);
  const current = readStable(io, input.path, Math.max(input.bytes.length, MATERIAL_LIMITS.fileBytes));
  if (current.stamp !== input.stamp || !current.bytes.equals(input.bytes)) incomplete('source_changed');
}
function originalText(bytes) {
  let decoded;
  try { decoded = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes); } catch { incomplete('source_text'); }
  if (!decoded.trim() || decoded.includes('\0')) incomplete('source_text');
  // Validation only. The original buffer, including a BOM/CRLF, is copied.
}
function directoryNames(io, root, maximum = MATERIAL_LIMITS.rootEntries) {
  const names = [];
  let handle;
  try {
    handle = io.opendirSync(root);
    for (let entry = handle.readSync(); entry !== null; entry = handle.readSync()) {
      if (names.length >= maximum) incomplete('source_bounds');
      names.push(entry.name);
    }
  } catch (error) {
    if (error instanceof LicenseMaterialsError) throw error;
    incomplete('source_missing');
  } finally { if (handle) handle.closeSync(); }
  return names;
}
export function legalCandidates(names) {
  if (!Array.isArray(names) || names.length > MATERIAL_LIMITS.rootEntries || names.some((name) => typeof name !== 'string')) incomplete('source_bounds');
  const selected = names.filter((name) => LEGAL_NAME.test(name)).sort(compare);
  if (selected.length > MATERIAL_LIMITS.perPackage) incomplete('source_bounds');
  const seen = new Set();
  for (const name of selected) {
    safeRelativePath(name);
    if (seen.has(name.toLowerCase())) incomplete('name_collision');
    seen.add(name.toLowerCase());
  }
  return selected;
}
export function inspectGeneratedMaterialNames(io, directory, expected) {
  if (!Array.isArray(expected) || expected.length > MATERIAL_LIMITS.packages * MATERIAL_LIMITS.perPackage + MAX_FIXED_ROOT_MATERIALS || expected.some((name, index) => name !== `m${String(index).padStart(6, '0')}.txt`)) incomplete('manifest');
  // The generated flat directory is not a package-root scan. Read only its
  // exact declared count plus one extra entry for bounded intrusion detection.
  const names = directoryNames(io, directory, expected.length + 1).sort(compare);
  if (JSON.stringify(names) !== JSON.stringify(expected)) incomplete('output_io');
}

function packageRecords(metadata, repository) {
  if (!record(metadata) || !Array.isArray(metadata.packages) || !Array.isArray(metadata.workspace_members) || metadata.packages.length === 0 || metadata.packages.length > MATERIAL_LIMITS.packages || metadata.workspace_members.length > metadata.packages.length || !samePath(absolutePath(metadata.workspace_root), repository)) incomplete('metadata_shape');
  const members = new Set(metadata.workspace_members);
  if (members.size !== metadata.workspace_members.length || [...members].some((id) => !text(id, 4096))) incomplete('metadata_shape');
  const ids = new Set(), roots = new Set(), labels = new Set();
  const entries = metadata.packages.map((pkg) => {
    if (!record(pkg) || !/^[A-Za-z0-9_-]{1,128}$/u.test(pkg.name ?? '') || !/^[A-Za-z0-9.+-]{1,128}$/u.test(pkg.version ?? '') || !text(pkg.id, 4096) || ![null, 'string'].includes(pkg.license === null ? null : typeof pkg.license) || pkg.license !== null && !text(pkg.license, 4096) || pkg.license_file !== null && !text(pkg.license_file, MATERIAL_LIMITS.pathBytes)) incomplete('metadata_shape');
    publicCargoSource(pkg.source);
    const manifest = absolutePath(pkg.manifest_path);
    if (basename(manifest) !== 'Cargo.toml') incomplete('path');
    const root = dirname(manifest), workspace = members.has(pkg.id);
    let provenance;
    if (pkg.source === null) {
      const path = contained(repository, root);
      if (/^(?:target|node_modules|dist)(?:\/|$)/iu.test(path)) incomplete('path');
      provenance = { kind: workspace ? 'workspace' : path.startsWith('vendor/') ? 'vendored' : 'path', root: path };
    } else {
      if (workspace) incomplete('provenance');
      const parts = root.split(sep);
      if (pkg.source.startsWith('git+')) {
        const at = parts.lastIndexOf('checkouts');
        if (at < 1 || parts[at - 1] !== 'git' || !/^[A-Za-z0-9._-]{1,128}$/u.test(parts[at + 1] ?? '') || !/^[a-f0-9]{7,40}$/u.test(parts[at + 2] ?? '')) incomplete('provenance');
        provenance = { kind: 'git', root: safeRelativePath(parts.slice(at + 1).join('/')) };
      } else {
        if (basename(root) !== `${pkg.name}-${pkg.version}` || basename(dirname(dirname(root))) !== 'src' || basename(dirname(dirname(dirname(root)))) !== 'registry') incomplete('provenance');
        provenance = { kind: 'registry', root: safeRelativePath(`${basename(dirname(root))}/${basename(root)}`) };
      }
    }
    const label = `${pkg.name}\0${pkg.version}\0${pkg.source ?? ''}\0${provenance.root}`;
    if (ids.has(pkg.id) || roots.has(root.toLowerCase()) || labels.has(label.toLowerCase())) incomplete('name_collision');
    ids.add(pkg.id); roots.add(root.toLowerCase()); labels.add(label.toLowerCase());
    return { pkg, root, manifest, provenance, workspace, label };
  });
  if ([...members].some((id) => !ids.has(id))) incomplete('metadata_shape');
  let inventory;
  try { inventory = licenseInventoryFromMetadata(metadata); } catch { incomplete('metadata_license'); }
  // Preserve the shared inventory row shape/checks. Only this separate manifest
  // canonicalizes order using a locale-independent public package identity.
  entries.sort((left, right) => compare(left.label, right.label));
  return { entries, inventory: entries.map(({ pkg, workspace }) => inventory.find((row) => row.name === pkg.name && row.version === pkg.version && row.license === pkg.license && row.source === pkg.source && row.workspace === workspace)) };
}

export function validateMaterialManifest(manifest) {
  if (!keys(manifest, ['schemaVersion', 'status', 'scope', 'lockfile', 'inventory', 'packages', 'materials', 'sharedNotices', 'upstreamIndex', 'upstreamNotices', 'limitations']) || manifest.schemaVersion !== 4 || manifest.status !== 'collected' || manifest.scope !== 'rust-declared-and-shallow-legal-materials' || !Array.isArray(manifest.inventory) || !Array.isArray(manifest.packages) || !Array.isArray(manifest.materials) || !Array.isArray(manifest.sharedNotices) || manifest.sharedNotices.length > 1 || !Array.isArray(manifest.upstreamNotices) || manifest.upstreamNotices.length > MAX_UPSTREAM_CONSUMERS || manifest.inventory.length === 0 || manifest.inventory.length > MATERIAL_LIMITS.packages || manifest.packages.length !== manifest.inventory.length || manifest.materials.length > MATERIAL_LIMITS.packages * MATERIAL_LIMITS.perPackage + MAX_FIXED_ROOT_MATERIALS) incomplete('manifest');
  const byteRecord = (value, maximum) => Number.isSafeInteger(value.bytes) && value.bytes > 0 && value.bytes <= maximum && /^[a-f0-9]{64}$/u.test(value.sha256);
  if (!keys(manifest.lockfile, ['sourcePath', 'bytes', 'sha256']) || manifest.lockfile.sourcePath !== 'Cargo.lock' || !byteRecord(manifest.lockfile, MATERIAL_LIMITS.fileBytes)) incomplete('manifest');
  if (manifest.upstreamNotices.length ? !keys(manifest.upstreamIndex, ['sourcePath', 'bytes', 'sha256']) || manifest.upstreamIndex.sourcePath !== UPSTREAM_SOURCE_INDEX || !byteRecord(manifest.upstreamIndex, MATERIAL_LIMITS.fileBytes) : manifest.upstreamIndex !== null) incomplete('manifest');
  const origins = new Set(), materialById = new Map();
  let total = 0;
  manifest.materials.forEach((item, index) => {
    const id = `m${String(index).padStart(6, '0')}`;
    if (!keys(item, ['id', 'origin', 'sourcePath', 'outputPath', 'kind', 'bytes', 'sha256']) || item.id !== id || item.outputPath !== `materials/${id}.txt` || !['text', 'spdx-metadata', 'attribution'].includes(item.kind) || !byteRecord(item, MATERIAL_LIMITS.fileBytes) || !/^(?:repository|upstream-repository|referenced-license-document|package:[0-9]{6})$/u.test(item.origin)) incomplete('manifest');
    safeRelativePath(item.sourcePath); safeRelativePath(item.outputPath);
    if (item.origin === 'repository' && ![...ROOT_NOTICES, PATCH_NOTICE].includes(item.sourcePath)) incomplete('manifest');
    if (isUpstreamMaterialOrigin(item.origin) && !matchesUpstreamMaterial(item, upstreamPinForSourcePath(item.sourcePath))) incomplete('manifest');
    if (item.origin.startsWith('package:') && Number(item.origin.slice(8)) >= manifest.packages.length) incomplete('manifest');
    const key = `${item.origin}/${item.sourcePath}`.toLowerCase();
    if (origins.has(key)) incomplete('name_collision');
    origins.add(key); materialById.set(item.id, item); total += item.bytes;
  });
  if (total > MATERIAL_LIMITS.totalBytes) incomplete('source_bounds');
  manifest.inventory.forEach((row) => {
    if (!keys(row, ['name', 'version', 'workspace', 'license', 'hasLicenseFile', 'source']) || !/^[A-Za-z0-9_-]{1,128}$/u.test(row.name) || !/^[A-Za-z0-9.+-]{1,128}$/u.test(row.version) || typeof row.workspace !== 'boolean' || typeof row.hasLicenseFile !== 'boolean' || row.license !== null && !text(row.license, 4096)) incomplete('manifest');
    publicCargoSource(row.source);
  });
  const reviewedShares = new Map();
  for (const share of manifest.sharedNotices) {
    if (!keys(share, ['id', 'consumerInventoryIndex', 'providerInventoryIndex', 'materialId', 'upstreamNoticeUrl', 'bytes', 'sha256']) || share.id !== ALLOC_STDLIB_SHARED_NOTICE.id || !Number.isSafeInteger(share.consumerInventoryIndex) || !Number.isSafeInteger(share.providerInventoryIndex) || share.consumerInventoryIndex < 0 || share.providerInventoryIndex < 0 || share.consumerInventoryIndex === share.providerInventoryIndex || share.consumerInventoryIndex >= manifest.inventory.length || share.providerInventoryIndex >= manifest.inventory.length || share.upstreamNoticeUrl !== ALLOC_STDLIB_SHARED_NOTICE.upstreamNoticeUrl || share.bytes !== ALLOC_STDLIB_SHARED_NOTICE.bytes || share.sha256 !== ALLOC_STDLIB_SHARED_NOTICE.sha256) incomplete('manifest');
    const consumer = manifest.packages[share.consumerInventoryIndex], provider = manifest.packages[share.providerInventoryIndex];
    const material = materialById.get(share.materialId);
    if (!isReviewedSharedNoticeConsumer(manifest.inventory[share.consumerInventoryIndex], consumer?.provenance?.kind) || !isReviewedSharedNoticeProvider(manifest.inventory[share.providerInventoryIndex], provider?.provenance?.kind) || !matchesReviewedSharedNoticeBytes(material) || material.origin !== `package:${String(share.providerInventoryIndex).padStart(6, '0')}` || !Array.isArray(consumer.materials) || !consumer.materials.includes(share.materialId) || !Array.isArray(provider.materials) || !provider.materials.includes(share.materialId)) incomplete('manifest');
    reviewedShares.set(share.consumerInventoryIndex, share.materialId);
  }
  const upstreamByConsumer = new Map(), referencedUpstream = new Set();
  for (const relation of manifest.upstreamNotices) {
    if (!keys(relation, ['consumerInventoryIndex', 'groupId', 'coverage', 'limitations', 'sources']) || !Number.isSafeInteger(relation.consumerInventoryIndex) || relation.consumerInventoryIndex < 0 || relation.consumerInventoryIndex >= manifest.inventory.length || upstreamByConsumer.has(relation.consumerInventoryIndex)) incomplete('manifest');
    const consumer = manifest.packages[relation.consumerInventoryIndex];
    const approved = upstreamNoticeGroup(manifest.inventory[relation.consumerInventoryIndex], consumer?.provenance?.kind);
    if (!approved || relation.groupId !== approved.id || relation.coverage !== approved.coverage || JSON.stringify(relation.limitations) !== JSON.stringify(approved.limitations) || !Array.isArray(relation.sources) || relation.sources.length !== approved.sources.length || !Array.isArray(consumer.materials)) incomplete('manifest');
    const refs = new Set();
    relation.sources.forEach((source, index) => {
      const pin = approved.sources[index], material = materialById.get(source?.materialId);
      if (!keys(source, ['sourceId', 'materialId', 'origin', 'upstreamSourcePath', 'upstreamUrl', 'documentVersion', 'referencedBySourceId', 'bytes', 'sha256']) || source.sourceId !== pin.id || source.origin !== pin.origin || source.upstreamSourcePath !== pin.upstreamSourcePath || source.upstreamUrl !== pin.upstreamUrl || source.documentVersion !== pin.documentVersion || source.referencedBySourceId !== pin.referencedBySourceId || source.bytes !== pin.bytes || source.sha256 !== pin.sha256 || !matchesUpstreamMaterial(material, pin) || !consumer.materials.includes(source.materialId) || refs.has(source.materialId)) incomplete('manifest');
      if (pin.referencedBySourceId !== null && !approved.sources.some((item) => item.id === pin.referencedBySourceId && item.origin === 'upstream-repository')) incomplete('manifest');
      refs.add(source.materialId); referencedUpstream.add(source.materialId);
    });
    upstreamByConsumer.set(relation.consumerInventoryIndex, refs);
  }
  if (manifest.materials.some((item) => isUpstreamMaterialOrigin(item.origin) && !referencedUpstream.has(item.id))) incomplete('manifest');
  manifest.packages.forEach((pkg, index) => {
    if (!keys(pkg, ['inventoryIndex', 'provenance', 'materials']) || pkg.inventoryIndex !== index || !keys(pkg.provenance, ['kind', 'root']) || !['workspace', 'vendored', 'path', 'registry', 'git'].includes(pkg.provenance.kind) || !Array.isArray(pkg.materials) || pkg.materials.length === 0 || pkg.materials.length > MATERIAL_LIMITS.perPackage + Math.max(3, MAX_UPSTREAM_GROUP_FILES) || new Set(pkg.materials).size !== pkg.materials.length) incomplete('manifest');
    safeRelativePath(pkg.provenance.root);
    const ownOrigin = `package:${String(index).padStart(6, '0')}`;
    const selected = pkg.materials.map((id) => materialById.get(id));
    const reviewedMaterial = reviewedShares.get(index);
    const upstreamMaterials = upstreamByConsumer.get(index) ?? new Set();
    if (selected.some((item) => !item || item.origin !== 'repository' && item.origin !== ownOrigin && item.id !== reviewedMaterial && !upstreamMaterials.has(item.id))) incomplete('manifest');
    if (selected.filter((item) => item.origin === ownOrigin).length > MATERIAL_LIMITS.perPackage) incomplete('source_bounds');
    const row = manifest.inventory[index];
    if (row.workspace !== (pkg.provenance.kind === 'workspace')) incomplete('manifest');
    const requiredUpstream = upstreamNoticeGroup(row, pkg.provenance.kind);
    if (requiredUpstream && upstreamMaterials.size !== requiredUpstream.sources.length) incomplete('material_missing');
    if (!row.workspace && !selected.some((item) => item.origin === ownOrigin && item.kind === 'text' || item.id === reviewedMaterial || upstreamMaterials.has(item.id))) incomplete('material_missing');
    if ((row.workspace || pkg.provenance.kind === 'vendored' && row.license?.includes('GPL-2.0-or-later')) && ROOT_NOTICES.some((name) => !selected.some((item) => item.origin === 'repository' && item.sourcePath === name))) incomplete('material_missing');
    if (pkg.provenance.kind === 'vendored' && !selected.some((item) => item.origin === 'repository' && item.sourcePath === PATCH_NOTICE)) incomplete('material_missing');
  });
  if (JSON.stringify(manifest.limitations) !== JSON.stringify(LIMITATIONS)) incomplete('manifest');
  if (Buffer.byteLength(JSON.stringify(manifest)) > MATERIAL_LIMITS.manifestBytes) incomplete('source_bounds');
  return manifest;
}
export function encodeMaterialManifest(manifest) {
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  if (bytes.length > MATERIAL_LIMITS.manifestBytes) incomplete('source_bounds');
  return bytes;
}

function ensureAbsent(io, path) {
  try { io.lstatSync(path); } catch (error) { if (error.code === 'ENOENT') return; incomplete('output_io'); }
  incomplete('output_exists');
}
function outputPreflight(io, root) {
  let parent = root;
  for (const leaf of ['target', 'license-materials', 'rust']) {
    directoryAnchors(io, parent);
    const matches = directoryNames(io, parent).filter((name) => name.toLowerCase() === leaf.toLowerCase());
    if (matches.length > 1 || matches.length === 1 && (matches[0] !== leaf || leaf === 'rust')) incomplete('output_exists');
    if (matches.length === 0) return;
    parent = join(parent, leaf);
    directoryAnchors(io, parent);
  }
}
function createChild(io, parent, leaf, mustBeNew) {
  directoryAnchors(io, parent);
  const matches = directoryNames(io, parent).filter((name) => name.toLowerCase() === leaf.toLowerCase());
  if (matches.length && (mustBeNew || matches.length !== 1 || matches[0] !== leaf)) incomplete('output_exists');
  const path = join(parent, leaf);
  if (!matches.length) {
    try { io.mkdirSync(path); } catch { incomplete('output_io'); }
  }
  directoryAnchors(io, path);
  return path;
}
function writeNew(io, path, bytes) {
  const anchors = directoryAnchors(io, dirname(path));
  ensureAbsent(io, path);
  let fd;
  try {
    fd = io.openSync(path, nativeFs.constants.O_WRONLY | nativeFs.constants.O_CREAT | nativeFs.constants.O_EXCL | (nativeFs.constants.O_NOFOLLOW ?? 0), 0o600);
    const stat = io.fstatSync(fd, { bigint: true });
    if (!stat.isFile() || stat.nlink !== 1n) incomplete('output_io');
    let used = 0;
    while (used < bytes.length) {
      const written = io.writeSync(fd, bytes, used, bytes.length - used, null);
      if (written <= 0) incomplete('output_io');
      used += written;
    }
    io.fsyncSync(fd);
    if (io.fstatSync(fd, { bigint: true }).size !== BigInt(bytes.length)) incomplete('output_io');
  } catch (error) {
    if (error instanceof LicenseMaterialsError) throw error;
    incomplete('output_io');
  } finally { if (fd !== undefined) io.closeSync(fd); }
  checkAnchors(io, anchors);
}

export function collectLicenseMaterials({ repository = repositoryRoot, metadataReader = readLockedCargoMetadata, io = nativeFs } = {}) {
  const root = absolutePath(repository);
  directoryAnchors(io, root);
  outputPreflight(io, root);
  const lock = readStable(io, join(root, 'Cargo.lock'));
  let metadata;
  try { metadata = metadataReader({ cwd: root, offline: true, stderr: { write() {} } }); } catch { incomplete('metadata_observation'); }
  recheck(io, lock);
  const { entries, inventory } = packageRecords(metadata, root);
  const inputs = [], materials = [], packages = [], byPath = new Map(), scans = [], missingText = [];
  let total = 0;
  const add = (anchor, sourcePath, origin, kind = 'text') => {
    safeRelativePath(sourcePath);
    const path = join(anchor, ...sourcePath.split('/'));
    contained(anchor, path);
    const existing = byPath.get(path.toLowerCase());
    if (existing) {
      if (existing.path !== path) incomplete('name_collision');
      return existing.id;
    }
    const input = readStable(io, path);
    originalText(input.bytes);
    total += input.bytes.length;
    if (total > MATERIAL_LIMITS.totalBytes) incomplete('source_bounds');
    const id = `m${String(materials.length).padStart(6, '0')}`;
    materials.push({ id, origin, sourcePath, outputPath: `materials/${id}.txt`, kind, bytes: input.bytes.length, sha256: digest(input.bytes) });
    inputs.push(input); byPath.set(path.toLowerCase(), { path, id });
    return id;
  };
  const rootRefs = ROOT_NOTICES.map((name) => add(root, name, 'repository'));
  entries.forEach((entry, index) => {
    const anchors = directoryAnchors(io, entry.root);
    const manifestStat = lstat(io, entry.manifest);
    if (!manifestStat.isFile() || manifestStat.isSymbolicLink() || manifestStat.nlink !== 1n || manifestStat.size <= 0n || manifestStat.size > BigInt(MATERIAL_LIMITS.fileBytes)) incomplete('source_type', entry.pkg.name);
    const names = legalCandidates(directoryNames(io, entry.root));
    const selected = [...names];
    if (entry.pkg.license_file !== null) {
      const explicit = explicitLicensePath(entry.root, entry.pkg.license_file);
      const other = selected.find((name) => name.toLowerCase() === explicit.toLowerCase());
      if (other && other !== explicit) incomplete('name_collision', entry.pkg.name);
      if (!other) selected.push(explicit);
    }
    if (selected.length > MATERIAL_LIMITS.perPackage) incomplete('source_bounds', entry.pkg.name);
    selected.sort(compare);
    if (!entry.workspace && !selected.some((name) => !name.toLowerCase().endsWith('.spdx'))) {
      if (isReviewedSharedNoticeConsumer(inventory[index], entry.provenance.kind)) missingText.push(index);
      else if (!upstreamNoticeGroup(inventory[index], entry.provenance.kind)) incomplete('material_missing', entry.pkg.name);
    }
    const refs = selected.map((name) => add(entry.root, name, `package:${String(index).padStart(6, '0')}`, name.toLowerCase().endsWith('.spdx') ? 'spdx-metadata' : 'text'));
    if (entry.workspace || entry.provenance.kind === 'vendored' && entry.pkg.license?.includes('GPL-2.0-or-later')) refs.push(...rootRefs);
    if (entry.provenance.kind === 'vendored') refs.push(add(root, PATCH_NOTICE, 'repository', 'attribution'));
    packages.push({ inventoryIndex: index, provenance: entry.provenance, materials: [...new Set(refs)].sort(compare) });
    scans.push({ root: entry.root, anchors, manifest: entry.manifest, manifestStamp: stamp(manifestStat), names });
  });
  const sharedNotices = missingText.map((consumerInventoryIndex) => {
    const providerInventoryIndex = inventory.findIndex((row, index) => isReviewedSharedNoticeProvider(row, packages[index].provenance.kind));
    const material = providerInventoryIndex < 0 ? null : materials.find((item) => item.origin === `package:${String(providerInventoryIndex).padStart(6, '0')}` && item.sourcePath === ALLOC_STDLIB_SHARED_NOTICE.sourcePath);
    if (!matchesReviewedSharedNoticeBytes(material)) incomplete('material_missing', inventory[consumerInventoryIndex].name);
    // Reference the actual provider-owned copy; never fabricate a LICENSE path
    // or material origin under alloc-stdlib, and never copy generic SPDX text.
    packages[consumerInventoryIndex].materials.push(material.id);
    packages[consumerInventoryIndex].materials.sort(compare);
    return { id: ALLOC_STDLIB_SHARED_NOTICE.id, consumerInventoryIndex, providerInventoryIndex, materialId: material.id, upstreamNoticeUrl: ALLOC_STDLIB_SHARED_NOTICE.upstreamNoticeUrl, bytes: material.bytes, sha256: material.sha256 };
  });
  let upstreamIndexInput = null;
  const imported = new Map(), upstreamNotices = [];
  inventory.forEach((row, consumerInventoryIndex) => {
    const approved = upstreamNoticeGroup(row, packages[consumerInventoryIndex].provenance.kind);
    if (!approved) return;
    if (!upstreamIndexInput) {
      upstreamIndexInput = readStable(io, join(root, ...UPSTREAM_SOURCE_INDEX.split('/')));
      let index;
      try { index = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(upstreamIndexInput.bytes)); } catch { incomplete('upstream_notice'); }
      if (!isApprovedUpstreamIndex(index)) incomplete('upstream_notice');
    }
    const sources = approved.sources.map((pin) => {
      let materialId = imported.get(pin.id);
      if (!materialId) {
        materialId = add(root, pin.sourcePath, pin.origin, pin.kind);
        const material = materials.find((item) => item.id === materialId);
        if (!matchesUpstreamMaterial(material, pin)) incomplete('upstream_notice', row.name);
        imported.set(pin.id, materialId);
      }
      packages[consumerInventoryIndex].materials.push(materialId);
      return { sourceId: pin.id, materialId, origin: pin.origin, upstreamSourcePath: pin.upstreamSourcePath, upstreamUrl: pin.upstreamUrl, documentVersion: pin.documentVersion, referencedBySourceId: pin.referencedBySourceId, bytes: pin.bytes, sha256: pin.sha256 };
    });
    packages[consumerInventoryIndex].materials.sort(compare);
    upstreamNotices.push({ consumerInventoryIndex, groupId: approved.id, coverage: approved.coverage, limitations: [...approved.limitations], sources });
  });
  const upstreamIndex = upstreamIndexInput ? { sourcePath: UPSTREAM_SOURCE_INDEX, bytes: upstreamIndexInput.bytes.length, sha256: digest(upstreamIndexInput.bytes) } : null;
  const manifest = validateMaterialManifest({ schemaVersion: 4, status: 'collected', scope: 'rust-declared-and-shallow-legal-materials', lockfile: { sourcePath: 'Cargo.lock', bytes: lock.bytes.length, sha256: digest(lock.bytes) }, inventory, packages, materials, sharedNotices, upstreamIndex, upstreamNotices, limitations: [...LIMITATIONS] });
  const manifestBytes = encodeMaterialManifest(manifest);
  const checkSources = () => {
    recheck(io, lock);
    if (upstreamIndexInput) recheck(io, upstreamIndexInput);
    for (const scan of scans) {
      checkAnchors(io, scan.anchors);
      if (stamp(lstat(io, scan.manifest)) !== scan.manifestStamp || JSON.stringify(legalCandidates(directoryNames(io, scan.root))) !== JSON.stringify(scan.names)) incomplete('source_changed');
    }
    for (const input of inputs) recheck(io, input);
  };
  checkSources();
  const target = createChild(io, root, 'target', false);
  const parent = createChild(io, target, 'license-materials', false);
  const output = createChild(io, parent, 'rust', true);
  writeNew(io, join(output, MARKER), MARKER_BYTES);
  const materialDirectory = createChild(io, output, 'materials', true);
  inputs.forEach((input, index) => writeNew(io, join(materialDirectory, `${materials[index].id}.txt`), input.bytes));
  checkSources(); // No final success manifest after an observed changed original.
  for (const item of materials) {
    const copy = readStable(io, join(output, ...item.outputPath.split('/')));
    if (copy.bytes.length !== item.bytes || digest(copy.bytes) !== item.sha256) incomplete('output_io');
  }
  if (JSON.stringify(directoryNames(io, output, 3).sort(compare)) !== JSON.stringify([MARKER, 'materials'].sort(compare))) incomplete('output_io');
  inspectGeneratedMaterialNames(io, materialDirectory, materials.map((item) => `${item.id}.txt`));
  checkSources();
  writeNew(io, join(output, 'manifest.json'), manifestBytes);
  return { status: 'collected', scope: manifest.scope, output: MATERIALS_OUTPUT, packages: packages.length, materials: materials.length, bytes: total, legalCompatibility: 'not-evaluated', legalCompletion: 'not-proven', correspondingSource: 'not-produced', filesystemScope: 'quiescent-trusted-root-ci-trees-required' };
}

export function runLicenseMaterials({ args = process.argv.slice(2), collect = collectLicenseMaterials, stdout = process.stdout, stderr = process.stderr } = {}) {
  try {
    if (args.length === 1 && args[0] === '--help') {
      stdout.write('Usage: node tools/license-materials.mjs\nFresh output: target/license-materials/rust. Original Rust legal material only; no overwrite, fetch, compatibility decision or source archive.\n');
      return 0;
    }
    if (args.length) incomplete('arguments');
    stdout.write(`${JSON.stringify(collect())}\n`);
    return 0;
  } catch (error) {
    const failure = error instanceof LicenseMaterialsError ? error : new LicenseMaterialsError('source_missing');
    stderr.write(`${JSON.stringify({ status: 'incomplete', code: failure.code, ...(failure.packageName ? { package: failure.packageName } : {}), legalCompatibility: 'not-evaluated', correspondingSource: 'not-produced' })}\n`);
    return 1;
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) process.exitCode = runLicenseMaterials();
