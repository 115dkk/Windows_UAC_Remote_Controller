// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT-run bounded temp/pure fixtures only. No Cargo, fetching, license clearance,
// source archive, native service/device, signing or publication is executed here.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import test from 'node:test';
import { licenseInventoryFromMetadata, readLockedCargoMetadata } from './license-inventory.mjs';
import { collectLicenseMaterials, encodeMaterialManifest, explicitLicensePath, inspectGeneratedMaterialNames, legalCandidates, LicenseMaterialsError, MATERIAL_LIMITS, MATERIALS_OUTPUT, publicCargoSource, runLicenseMaterials, safeRelativePath, validateMaterialManifest } from './license-materials.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const registrySource = 'registry+https://github.com/rust-lang/crates.io-index';
const rejected = (code) => (error) => error instanceof LicenseMaterialsError && error.code === code;
function fixture(t) {
  const fixtureParent = fs.realpathSync(tmpdir());
  const temporary = fs.mkdtempSync(join(fixtureParent, 'uac-license-materials-'));
  const repository = join(temporary, 'repository');
  const workspace = join(repository, 'crates/app');
  const dependency = join(temporary, 'cargo/registry/src/test-index/dep-1.0.0');
  const links = [];
  t.after(() => {
    // Only this exact newly created fixture root is recursively removed. Remove
    // known test links first; never follow them or target a home/drive/repo root.
    for (const path of links) if (fs.lstatSync(path, { throwIfNoEntry: false })?.isSymbolicLink()) fs.unlinkSync(path);
    assert.equal(dirname(resolve(temporary)), fixtureParent);
    assert.match(basename(temporary), /^uac-license-materials-/u);
    assert.ok(!fs.lstatSync(temporary).isSymbolicLink());
    fs.rmSync(temporary, { recursive: true });
  });
  for (const root of [workspace, dependency]) fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(join(repository, 'Cargo.lock'), '# Synthetic locked fixture; no actual Cargo invocation.\n');
  fs.writeFileSync(join(repository, 'LICENSE'), 'Synthetic original workspace license text.\r\n');
  fs.writeFileSync(join(repository, 'LICENSE-NOTICE.md'), 'Synthetic original workspace or-later notice.\n');
  for (const root of [workspace, dependency]) fs.writeFileSync(join(root, 'Cargo.toml'), '# Synthetic package manifest\n');
  const original = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from('Synthetic dependency original terms.\r\nCopyright fixture.\r\n')]);
  fs.writeFileSync(join(dependency, 'LICENSE-MIT'), original);
  fs.writeFileSync(join(dependency, 'NOTICE'), 'Synthetic separate attribution.\n');
  const app = { id: `path+file://${workspace}#app@1.0.0`, name: 'app', version: '1.0.0', license: 'GPL-2.0-or-later', license_file: null, source: null, manifest_path: join(workspace, 'Cargo.toml') };
  const dep = { id: 'registry+https://github.com/rust-lang/crates.io-index#dep@1.0.0', name: 'dep', version: '1.0.0', license: 'MIT', license_file: null, source: registrySource, manifest_path: join(dependency, 'Cargo.toml') };
  const metadata = { workspace_root: repository, workspace_members: [app.id], packages: [dep, app] };
  const output = join(repository, MATERIALS_OUTPUT);
  const run = (options = {}) => collectLicenseMaterials({ repository, metadataReader: ({ offline, stderr }) => { assert.equal(offline, true); stderr.write('suppressed synthetic observation'); return metadata; }, ...options });
  const manifest = () => JSON.parse(fs.readFileSync(join(output, 'manifest.json'), 'utf8'));
  return { temporary, repository, workspace, dependency, app, dep, metadata, original, output, run, manifest, links };
}

test('shared Cargo observation preserves standalone argv and collector-only offline seam', () => {
  for (const offline of [false, true]) {
    const calls = [];
    const result = readLockedCargoMetadata({ cwd: '/synthetic/repository', offline, spawn: (command, args, options) => { calls.push({ command, args, options }); return { status: 0, stdout: '{"packages":[],"workspace_members":[]}' }; } });
    assert.deepEqual(result, { packages: [], workspace_members: [] });
    assert.equal(calls[0].command, 'cargo');
    assert.deepEqual(calls[0].args, ['metadata', '--format-version', '1', '--locked', ...(offline ? ['--offline'] : [])]);
    assert.equal(calls[0].options.cwd, '/synthetic/repository');
    assert.equal(calls[0].options.timeout, 180_000);
    assert.equal(calls[0].options.maxBuffer, 16 * 1024 * 1024);
  }
  const stderr = [];
  assert.throws(() => readLockedCargoMetadata({ spawn: () => ({ status: 7, stderr: 'legacy standalone diagnostic' }), stderr: { write: (value) => stderr.push(value) } }));
  assert.deepEqual(stderr, ['legacy standalone diagnostic']);
});

test('shared inventory retains exact row fields and existing license metadata rejection', () => {
  const app = { id: 'a', name: 'app', version: '1.0.0', license: 'GPL-2.0-or-later', license_file: null, source: null };
  const dep = { id: 'b', name: 'dep', version: '1.0.0', license: null, license_file: 'COPYING', source: registrySource };
  const metadata = { workspace_members: ['a'], packages: [dep, app] };
  assert.deepEqual(licenseInventoryFromMetadata(metadata), [
    { name: 'app', version: '1.0.0', workspace: true, license: 'GPL-2.0-or-later', hasLicenseFile: false, source: null },
    { name: 'dep', version: '1.0.0', workspace: false, license: null, hasLicenseFile: true, source: registrySource },
  ]);
  assert.throws(() => licenseInventoryFromMetadata({ ...metadata, packages: [{ ...app, license: 'GPL-3.0-only' }, dep] }));
  assert.throws(() => licenseInventoryFromMetadata({ ...metadata, packages: [app, { ...dep, license_file: null }] }));
});

test('exact bytes, BOM, CRLF and original expressions survive deterministic public manifest collection', (t) => {
  const f = fixture(t), next = fixture(t);
  const result = f.run();
  next.metadata.packages.reverse();
  next.run();
  const manifest = f.manifest();
  assert.equal(result.status, 'collected');
  assert.equal(result.correspondingSource, 'not-produced');
  assert.deepEqual(manifest.inventory, licenseInventoryFromMetadata(f.metadata));
  assert.deepEqual(manifest, next.manifest(), 'machine roots, timestamps and metadata input ordering are not publication fields');
  assert.ok(!JSON.stringify(manifest).includes(f.temporary));
  assert.ok(!JSON.stringify(manifest).includes('path+file:'));
  const item = manifest.materials.find((value) => value.sourcePath === 'LICENSE-MIT');
  assert.equal(item.sha256, hash(f.original));
  assert.equal(item.bytes, f.original.length);
  assert.deepEqual(fs.readFileSync(join(f.output, item.outputPath)), f.original);
  assert.ok(manifest.limitations.includes('fonts-remain-owned-by-tools/ui-fonts.mjs'));
  assert.ok(manifest.limitations.includes('npm-maven-not-collected'));
  assert.equal(validateMaterialManifest(manifest), manifest);
});

test('contained explicit license_file is copied once, and automatic discovery remains shallow', (t) => {
  const f = fixture(t);
  fs.mkdirSync(join(f.dependency, 'terms'));
  fs.writeFileSync(join(f.dependency, 'terms/permission.txt'), 'Synthetic declared license text.\n');
  fs.writeFileSync(join(f.dependency, 'terms/UNLICENSE'), 'Nested undeclared material is intentionally not scanned.\n');
  f.dep.license_file = join(f.dependency, 'terms/permission.txt');
  f.run();
  const paths = f.manifest().materials.map((item) => item.sourcePath);
  assert.ok(paths.includes('terms/permission.txt'));
  assert.ok(!paths.includes('terms/UNLICENSE'));
  const second = fixture(t);
  second.dep.license_file = 'LICENSE-MIT';
  second.run();
  assert.equal(second.manifest().materials.filter((item) => item.sourcePath === 'LICENSE-MIT').length, 1);
});

test('vendored texts retain fixed patch attribution and shared original-source notices', (t) => {
  const f = fixture(t), vendor = join(f.repository, 'vendor/dep');
  fs.mkdirSync(vendor, { recursive: true });
  fs.writeFileSync(join(vendor, 'Cargo.toml'), '# Synthetic vendored metadata\n');
  fs.writeFileSync(join(vendor, 'LICENSE-APACHE'), 'Synthetic original upstream terms.\n');
  fs.writeFileSync(join(vendor, 'LICENSE.spdx'), 'Apache-2.0 AND GPL-2.0-or-later\n');
  fs.writeFileSync(join(f.repository, 'vendor/ANDROID_LIFECYCLE_PATCHES.md'), 'Synthetic retained upstream/local patch attribution.\n');
  Object.assign(f.dep, { id: 'vendored:dep', source: null, license: 'Apache-2.0 AND GPL-2.0-or-later', manifest_path: join(vendor, 'Cargo.toml') });
  f.run();
  const manifest = f.manifest(), pkg = manifest.packages[1];
  assert.equal(pkg.provenance.kind, 'vendored');
  const paths = pkg.materials.map((id) => manifest.materials.find((item) => item.id === id).sourcePath);
  assert.deepEqual(new Set(paths), new Set(['LICENSE-APACHE', 'LICENSE.spdx', 'LICENSE', 'LICENSE-NOTICE.md', 'vendor/ANDROID_LIFECYCLE_PATCHES.md']));
  assert.equal(manifest.inventory[1].license, 'Apache-2.0 AND GPL-2.0-or-later');
});

test('traversal, credential/config paths and candidate name collisions fail before file access', (t) => {
  const f = fixture(t);
  for (const path of ['../LICENSE', 'terms/../LICENSE', '/LICENSE', 'C:\\private\\LICENSE', 'terms\\LICENSE', '.ssh/LICENSE', '.env', 'terms/config.json', 'terms/license.key', 'LICENSE:stream', 'terms/CON', 'terms/notice.']) {
    assert.throws(() => explicitLicensePath(f.dependency, path));
  }
  assert.throws(() => explicitLicensePath(f.dependency, join(f.repository, 'LICENSE')), rejected('path'));
  for (const names of [['LICENSE', 'license'], ['COPYING', 'COPYING'], ['NOTICE.md', 'notice.MD']]) assert.throws(() => legalCandidates(names), rejected('name_collision'));
  assert.deepEqual(legalCandidates(['Cargo.toml', 'src', 'LICENSE-MIT', 'COPYING', 'UNLICENSE', '.env', 'LICENSES']), ['COPYING', 'LICENSE-MIT', 'UNLICENSE']);
  f.dep.license_file = '../LICENSE';
  assert.throws(() => f.run(), rejected('path'));
  assert.ok(!fs.existsSync(f.output));
});

test('missing trees, missing explicit material and metadata-only SPDX never become success', (t) => {
  for (const kind of ['tree', 'explicit', 'notices', 'spdx']) {
    const f = fixture(t);
    if (kind === 'tree') fs.renameSync(f.dependency, join(f.temporary, 'retained-missing-source'));
    else if (kind === 'explicit') f.dep.license_file = 'terms/missing.txt';
    else {
      fs.unlinkSync(join(f.dependency, 'LICENSE-MIT'));
      fs.unlinkSync(join(f.dependency, 'NOTICE'));
      if (kind === 'spdx') fs.writeFileSync(join(f.dependency, 'LICENSE.spdx'), 'MIT\n');
    }
    assert.throws(() => f.run(), (error) => error instanceof LicenseMaterialsError);
    assert.ok(!fs.existsSync(f.output));
  }
});

test('empty, whitespace, invalid UTF8, NUL and oversized source text are incomplete', (t) => {
  for (const bytes of [Buffer.alloc(0), Buffer.from(' \r\n'), Buffer.from([0xff]), Buffer.from('terms\0private'), Buffer.alloc(MATERIAL_LIMITS.fileBytes + 1, 65)]) {
    const f = fixture(t);
    fs.writeFileSync(join(f.dependency, 'LICENSE-MIT'), bytes);
    assert.throws(() => f.run(), (error) => error instanceof LicenseMaterialsError);
    assert.ok(!fs.existsSync(f.output));
  }
  assert.throws(() => legalCandidates(Array.from({ length: MATERIAL_LIMITS.perPackage + 1 }, (_, n) => `LICENSE-${n}`)), rejected('source_bounds'));
  assert.throws(() => legalCandidates(Array(MATERIAL_LIMITS.rootEntries + 1).fill('other')), rejected('source_bounds'));
});

test('generated material enumeration accepts more than1024 declared files and bounds unexpected extras', () => {
  const expected = Array.from({ length: 1025 }, (_, index) => `m${String(index).padStart(6, '0')}.txt`);
  const iterator = (names) => {
    let reads = 0, closed = false;
    return { io: { opendirSync() { return { readSync() { const name = names[reads++]; return name === undefined ? null : { name }; }, closeSync() { closed = true; } }; } }, reads: () => reads, closed: () => closed };
  };
  const good = iterator([...expected].reverse());
  assert.doesNotThrow(() => inspectGeneratedMaterialNames(good.io, '/synthetic/generated/materials', expected));
  assert.equal(good.reads(), expected.length + 1);
  assert.equal(good.closed(), true);
  const extra = iterator([...expected, 'unknown.txt']);
  assert.throws(() => inspectGeneratedMaterialNames(extra.io, '/synthetic/generated/materials', expected), rejected('output_io'));
  assert.equal(extra.closed(), true);
  const many = iterator([...expected, 'unknown.txt', 'another.txt', ...Array(100).fill('not-read.txt')]);
  assert.throws(() => inspectGeneratedMaterialNames(many.io, '/synthetic/generated/materials', expected), rejected('source_bounds'));
  assert.equal(many.reads(), expected.length + 2, 'never enumerate unbounded generated extras');
  assert.equal(many.closed(), true);
});

test('real directory link anchors and hard-linked notice candidates are rejected', (t) => {
  const f = fixture(t), moved = join(f.temporary, 'original-dependency');
  fs.renameSync(f.dependency, moved);
  fs.symlinkSync(moved, f.dependency, process.platform === 'win32' ? 'junction' : 'dir');
  f.links.push(f.dependency);
  assert.throws(() => f.run(), rejected('source_type'));
  const second = fixture(t);
  fs.linkSync(join(second.dependency, 'LICENSE-MIT'), join(second.temporary, 'same-original.txt'));
  assert.throws(() => second.run(), rejected('source_type'));
});

test('file symlink and parent canonical-alias observations reject without reading the candidate', (t) => {
  const f = fixture(t), original = join(f.dependency, 'LICENSE-MIT');
  const io = { ...fs, lstatSync(path, options) { const value = fs.lstatSync(path, options); return path === original ? new Proxy(value, { get(target, field) { if (field === 'isSymbolicLink') return () => true; const result = Reflect.get(target, field); return typeof result === 'function' ? result.bind(target) : result; } }) : value; }, openSync(path, ...args) { assert.notEqual(path, original); return fs.openSync(path, ...args); } };
  assert.throws(() => f.run({ io }), rejected('source_type'));
  assert.throws(() => f.run({ io: { ...fs, realpathSync(path) { return path === f.dependency ? f.repository : fs.realpathSync(path); } } }), rejected('source_type'));
});

test('changed source during reading and after staging leaves no final collected manifest', (t) => {
  const f = fixture(t), original = join(f.dependency, 'LICENSE-MIT');
  let changed = false, activeFd = null;
  const io = { ...fs, openSync(path, ...args) { const fd = fs.openSync(path, ...args); if (path === original) activeFd = fd; return fd; }, readSync(fd, ...args) { const read = fs.readSync(fd, ...args); if (fd === activeFd && !changed) { changed = true; fs.writeFileSync(original, 'Mutated synthetic original bytes.\n'); } return read; } };
  assert.throws(() => f.run({ io }), rejected('source_changed'));
  assert.ok(!fs.existsSync(f.output));
  const second = fixture(t);
  const duringOutput = { ...fs, mkdirSync(path, ...args) { const value = fs.mkdirSync(path, ...args); if (path === second.output) fs.writeFileSync(join(second.dependency, 'NOTICE'), 'Changed after staging began.\n'); return value; } };
  assert.throws(() => second.run({ io: duringOutput }), rejected('source_changed'));
  assert.ok(fs.existsSync(second.output), 'partial owned output is retained, never deleted');
  assert.ok(!fs.existsSync(join(second.output, 'manifest.json')));
});

test('locked metadata and exact copied output mutations are detected without a final manifest', (t) => {
  const f = fixture(t);
  assert.throws(() => f.run({ metadataReader: () => { fs.writeFileSync(join(f.repository, 'Cargo.lock'), 'Changed synthetic lock observation.\n'); return f.metadata; } }), rejected('source_changed'));
  assert.ok(!fs.existsSync(f.output));
  const second = fixture(t);
  const corruptCopy = { ...fs, writeSync(fd, buffer, ...args) { const changed = Buffer.from(buffer); if (changed.includes('Synthetic dependency original terms.')) changed[5] ^= 1; return fs.writeSync(fd, changed, ...args); } };
  assert.throws(() => second.run({ io: corruptCopy }), rejected('output_io'));
  assert.ok(!fs.existsSync(join(second.output, 'manifest.json')));
});

test('existing output, output parent links and concurrent output files are never adopted or overwritten', (t) => {
  const f = fixture(t);
  f.run();
  const before = fs.readFileSync(join(f.output, 'manifest.json'));
  assert.throws(() => f.run(), rejected('output_exists'));
  assert.deepEqual(fs.readFileSync(join(f.output, 'manifest.json')), before);
  const second = fixture(t), other = join(second.temporary, 'output-target');
  fs.mkdirSync(other);
  const target = join(second.repository, 'target');
  fs.symlinkSync(other, target, process.platform === 'win32' ? 'junction' : 'dir');
  second.links.push(target);
  assert.throws(() => second.run(), rejected('source_type'));
  assert.deepEqual(fs.readdirSync(other), []);
  const third = fixture(t);
  const race = { ...fs, mkdirSync(path, ...args) { const value = fs.mkdirSync(path, ...args); if (path === third.output) fs.writeFileSync(join(path, 'unknown.txt'), 'Preserve this synthetic concurrent file.'); return value; } };
  assert.throws(() => third.run({ io: race }), rejected('output_io'));
  assert.equal(fs.readFileSync(join(third.output, 'unknown.txt'), 'utf8'), 'Preserve this synthetic concurrent file.');
  assert.ok(!fs.existsSync(join(third.output, 'manifest.json')));
});

test('public provenance rejects credential-bearing URLs and duplicate or misplaced packages', (t) => {
  for (const value of ['registry+https://user:canary@example.com/index', 'registry+https://example.com/index?token=canary', 'git+ssh://git@example.com/repo', 'path+file:///private/home', 'registry+http://example.com/index']) assert.throws(() => publicCargoSource(value), rejected('provenance'));
  const f = fixture(t);
  f.metadata.packages.push({ ...f.dep });
  assert.throws(() => f.run(), rejected('name_collision'));
  const second = fixture(t);
  second.dep.source = null;
  assert.throws(() => second.run(), rejected('path'));
});

test('pure output-manifest validation rejects traversal, case aliases, cross-package references and changed bounds', (t) => {
  const f = fixture(t); f.run();
  for (const mutate of [
    (value) => { value.materials[0].outputPath = '../outside.txt'; },
    (value) => { value.materials[0].sourcePath = '/machine/home/LICENSE'; },
    (value) => { value.materials[0].sourcePath = '.ssh/LICENSE'; },
    (value) => { value.materials[1].sourcePath = value.materials[0].sourcePath.toLowerCase(); },
    (value) => { value.packages[1].materials = value.packages[0].materials; },
    (value) => { value.inventory[1].source = 'registry+https://user:canary@example.com/index'; },
    (value) => { value.materials[0].bytes = MATERIAL_LIMITS.fileBytes + 1; },
    (value) => { value.limitations = []; },
    (value) => { value.status = 'legally-complete'; },
  ]) {
    const manifest = f.manifest(); mutate(manifest);
    assert.throws(() => validateMaterialManifest(manifest));
  }
  assert.throws(() => safeRelativePath('target/../../private'), rejected('path'));
  const oversized = f.manifest();
  oversized.materials = Array.from({ length: 33 }, (_, index) => ({ id: `m${String(index).padStart(6, '0')}`, origin: 'package:000001', sourcePath: `LICENSE-${index}`, outputPath: `materials/m${String(index).padStart(6, '0')}.txt`, kind: 'text', bytes: MATERIAL_LIMITS.fileBytes, sha256: '0'.repeat(64) }));
  assert.throws(() => validateMaterialManifest(oversized), rejected('source_bounds'));
});

test('exact pretty-printed manifest bytes, not compact JSON size, enforce the16MiB output bound', () => {
  const compactOverhead = Buffer.byteLength(JSON.stringify({ a: { b: '' } }));
  const oversized = { a: { b: 'x'.repeat(MATERIAL_LIMITS.manifestBytes - compactOverhead - 1) } };
  assert.ok(Buffer.byteLength(JSON.stringify(oversized)) < MATERIAL_LIMITS.manifestBytes);
  assert.ok(Buffer.byteLength(`${JSON.stringify(oversized, null, 2)}\n`) > MATERIAL_LIMITS.manifestBytes);
  assert.throws(() => encodeMaterialManifest(oversized), rejected('source_bounds'));
  const small = { synthetic: true };
  assert.deepEqual(encodeMaterialManifest(small), Buffer.from(`${JSON.stringify(small, null, 2)}\n`));
});

test('collector metadata failures and arbitrary exceptions cannot escape fixed incomplete logs', (t) => {
  const f = fixture(t), stdout = [], stderr = [];
  const code = runLicenseMaterials({ args: [], collect: () => f.run({ metadataReader: ({ stderr }) => { stderr.write('RAW PRIVATE CARGO DIAGNOSTIC'); throw new Error('RAW PRIVATE ERROR'); } }), stdout: { write: (value) => stdout.push(value) }, stderr: { write: (value) => stderr.push(value) } });
  assert.equal(code, 1);
  assert.deepEqual(stdout, []);
  assert.equal(JSON.parse(stderr[0]).code, 'metadata_observation');
  assert.ok(!stderr[0].includes('RAW PRIVATE'));
  assert.ok(!stderr[0].includes(f.temporary));
  assert.ok(!fs.existsSync(f.output));
  for (const args of [['--output', '/outside'], ['--online'], ['--help', '--online']]) assert.equal(runLicenseMaterials({ args, collect: () => assert.fail('must not collect'), stdout: { write() {} }, stderr: { write() {} } }), 1);
  assert.equal(runLicenseMaterials({ args: ['--help'], collect: () => assert.fail('help must not collect'), stdout: { write() {} }, stderr: { write() {} } }), 0);
});
