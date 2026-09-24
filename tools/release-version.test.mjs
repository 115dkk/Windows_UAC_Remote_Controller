// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync, spawnSync } from 'node:child_process';
import test from 'node:test';
import { nextVersion, stableVersion, stampMetadata, verifyTaggedMetadata, VERSION_FILES } from './release-version.mjs';
import { mergeRunTestsExactTree, RELEASE_GATES, selectRun } from './release-gates.mjs';
import { shouldBeLatest, releaseTagsArguments } from './release-latest.mjs';

test('first stable is 1.0.0; later significance follows breaking, feat, then patch', () => {
  assert.equal(nextVersion(null, ['fix: cleanup']), '1.0.0');
  assert.equal(nextVersion('v0.9.0', ['feat: release']), '1.0.0');
  assert.equal(nextVersion('v1.2.3', ['fix(android): cleanup']), '1.2.4');
  assert.equal(nextVersion('v1.2.3', ['docs: explain logs']), '1.2.4');
  assert.equal(nextVersion('v1.2.3', ['docs: examples\n\nfeat: example text']), '1.2.4');
  assert.equal(nextVersion('v1.2.3', ['feat(logs): public diagnostics']), '1.3.0');
  assert.equal(nextVersion('v1.2.3', ['fix: repair\n\nBREAKING CHANGE: retire old format']), '2.0.0');
  assert.equal(nextVersion('v1.2.3', ['feat: minor', 'refactor(core)!: change protocol']), '2.0.0');
  for (const tag of ['v1.2.3-alpha.1', 'v01.2.3', 'v1.2.3\nmalicious', 'v65535.0.0']) assert.equal(stableVersion(tag), null);
  assert.throws(() => nextVersion('v1.2.3-alpha.1', []));
});

function fixture() {
  const root = mkdtempSync(join(tmpdir(), 'uac-semver-'));
  mkdirSync(join(root, 'src-tauri'));
  mkdirSync(join(root, 'crates', 'sample'), { recursive: true });
  writeFileSync(join(root, 'package.json'), JSON.stringify({ name: 'sample', version: '0.1.0-alpha.40' }));
  writeFileSync(join(root, 'package-lock.json'), JSON.stringify({ version: '0.1.0-alpha.40', packages: { '': { version: '0.1.0-alpha.40' }, external: { version: '0.1.0-alpha.40' } } }));
  writeFileSync(join(root, 'src-tauri', 'tauri.conf.json'), JSON.stringify({ version: '0.1.0-alpha.40', identifier: 'unchanged' }));
  writeFileSync(join(root, 'crates', 'sample', 'Cargo.toml'), '[package]\nname = "sample"\nversion.workspace = true\n');
  writeFileSync(join(root, 'Cargo.toml'), '[workspace]\nmembers = [\n "crates/sample",\n]\n[workspace.package]\nversion = "0.1.0-alpha.40"\n');
  writeFileSync(join(root, 'Cargo.lock'), '# fixture\nversion = 4\n\n[[package]]\nname = "sample"\nversion = "0.1.0-alpha.40"\n\n[[package]]\nname = "external"\nversion = "0.1.0-alpha.40"\n');
  return root;
}
test('stamping updates all owned metadata and never an external lock package', () => {
  const root = fixture();
  stampMetadata(root, '1.0.0');
  for (const name of ['package.json', 'package-lock.json', 'src-tauri/tauri.conf.json']) assert.equal(JSON.parse(readFileSync(join(root, name), 'utf8')).version, '1.0.0');
  const lock = JSON.parse(readFileSync(join(root, 'package-lock.json'), 'utf8'));
  assert.equal(lock.packages[''].version, '1.0.0');
  assert.equal(lock.packages.external.version, '0.1.0-alpha.40');
  const cargo = readFileSync(join(root, 'Cargo.lock'), 'utf8');
  assert.match(cargo, /name = "sample"\nversion = "1\.0\.0"/u);
  assert.match(cargo, /name = "external"\nversion = "0\.1\.0-alpha\.40"/u);
  assert.match(readFileSync(join(root, 'Cargo.toml'), 'utf8'), /version = "1\.0\.0"/u);
});
test('metadata disagreement rejects before any version file is written', () => {
  const root = fixture();
  writeFileSync(join(root, 'src-tauri', 'tauri.conf.json'), '{"version":"different"}');
  assert.throws(() => stampMetadata(root, '1.0.0'));
  assert.equal(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version, '0.1.0-alpha.40');
});

const metadataBytes = root => VERSION_FILES.map(name => readFileSync(join(root, name)));
test('tagged verification shares all metadata checks and leaves stable/prerelease bytes untouched', () => {
  const root = fixture();
  let before = metadataBytes(root);
  assert.equal(verifyTaggedMetadata(root, 'v0.1.0-alpha.40'), '0.1.0-alpha.40');
  assert.deepEqual(metadataBytes(root), before);
  stampMetadata(root, '1.0.0');
  before = metadataBytes(root);
  assert.equal(verifyTaggedMetadata(root, 'v1.0.0'), '1.0.0');
  assert.deepEqual(metadataBytes(root), before);
  assert.throws(() => verifyTaggedMetadata(root, 'v1.0.1'));
  assert.throws(() => stampMetadata(root, '1.0.1-alpha.1'), /Stable version required/u);
  assert.deepEqual(metadataBytes(root), before);
});

test('both callers reject metadata disagreement, absent/duplicate owned locks and non-workspace members before writing', () => {
  const changes = [
    ['package.json', text => text.replace('0.1.0-alpha.40', 'different')],
    ['package-lock.json', text => text.replace('0.1.0-alpha.40', 'different')],
    ['package-lock.json', text => text.replace('"packages":{"":{"version":"0.1.0-alpha.40"}', '"packages":{"":{"version":"different"}')],
    ['src-tauri/tauri.conf.json', text => text.replace('0.1.0-alpha.40', 'different')],
    ['Cargo.toml', text => text.replace('0.1.0-alpha.40', 'different')],
    ['Cargo.lock', text => text.replace('0.1.0-alpha.40', 'different')],
    ['Cargo.lock', text => text.replace('name = "sample"', 'name = "not-owned"')],
    ['Cargo.lock', text => text + '\n[[package]]\nname = "sample"\nversion = "0.1.0-alpha.40"\n'],
    ['crates/sample/Cargo.toml', text => text.replace('version.workspace = true', 'version = "0.1.0-alpha.40"')],
  ];
  for (const [name, change] of changes) {
    const root = fixture();
    const original = readFileSync(join(root, name), 'utf8');
    const changed = change(original);
    assert.notEqual(changed, original, `Negative control must change ${name}`);
    writeFileSync(join(root, name), changed);
    const before = metadataBytes(root);
    assert.throws(() => verifyTaggedMetadata(root, 'v0.1.0-alpha.40'), name);
    assert.throws(() => stampMetadata(root, '1.0.0'), name);
    assert.deepEqual(metadataBytes(root), before, `No write after rejecting ${name}`);
  }
});

test('tag grammar retains explicit prereleases and rejects payloads or trailing newlines', () => {
  const root = fixture();
  for (const tag of ['0.1.0-alpha.40', 'v0.1.0-', 'v0.1.0-alpha.40\n', 'v0.1.0-alpha.40\r', 'v0.1.0+build', '--prepare']) {
    assert.throws(() => verifyTaggedMetadata(root, tag), /Version tag required/u);
  }
});

function releaseCli(root, args) {
  return spawnSync(process.execPath, [fileURLToPath(new URL('./release-version.mjs', import.meta.url)), ...args], {
    cwd: root, encoding: 'utf8',
    env: { ...process.env, GITHUB_ACTIONS: 'true', GITHUB_REF: 'refs/heads/main', GITHUB_OUTPUT: join(root, 'cli-output') },
  });
}
test('read-only CLI verifies prerelease and stable metadata without Git or metadata writes', () => {
  const root = fixture();
  for (const tag of ['v0.1.0-alpha.40', 'v1.0.0']) {
    if (tag === 'v1.0.0') stampMetadata(root, '1.0.0');
    const before = metadataBytes(root);
    const result = releaseCli(root, ['--verify-tag', tag]);
    assert.equal(result.error, undefined);
    assert.equal(result.status, 0, result.stderr);
    assert.equal(result.stdout, tag.slice(1) + '\n');
    assert.deepEqual(metadataBytes(root), before);
    assert.equal(existsSync(join(root, 'cli-output')), false, 'Read-only mode never prepares main outputs');
  }
  writeFileSync(join(root, 'Cargo.lock'), readFileSync(join(root, 'Cargo.lock'), 'utf8').replace('version = "1.0.0"', 'version = "wrong"'));
  assert.notEqual(releaseCli(root, ['--verify-tag', 'v1.0.0']).status, 0);
});
test('unknown CLI mode or wrong arity rejects before entering mutating main preparation', () => {
  const root = fixture();
  const before = metadataBytes(root);
  for (const args of [['--verify-tag'], ['--verify-tags', 'v0.1.0-alpha.40'], ['--verify-tag', 'v0.1.0-alpha.40', 'extra'], ['--prepare'], ['v1.0.0']]) {
    const result = releaseCli(root, args);
    assert.equal(result.error, undefined);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /Usage: release-version\.mjs/u);
    assert.deepEqual(metadataBytes(root), before);
    assert.equal(existsSync(join(root, 'cli-output')), false);
  }
});
test('a fix after failed pre-tag CI reuses correct metadata and gates its new HEAD', () => {
  const root = fixture();
  const remote = mkdtempSync(join(tmpdir(), 'uac-semver-origin-'));
  const git = (...args) => execFileSync('git', args, { cwd: root, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim();
  git('init', '--initial-branch=main');
  git('config', 'user.name', 'Release test');
  git('config', 'user.email', 'release-test@example.invalid');
  git('config', 'commit.gpgsign', 'false');
  git('add', '.'); git('commit', '-m', 'feat: initial product');
  execFileSync('git', ['init', '--bare', remote], { stdio: 'ignore' });
  git('remote', 'add', 'origin', remote);
  git('push', 'origin', 'main');
  const evidence = join(mkdtempSync(join(tmpdir(), 'uac-semver-output-')), 'output');
  const prepare = () => execFileSync(process.execPath, [fileURLToPath(new URL('./release-version.mjs', import.meta.url))], {
    cwd: root, env: { ...process.env, GITHUB_ACTIONS: 'true', GITHUB_REF: 'refs/heads/main', GITHUB_OUTPUT: evidence },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  prepare();
  assert.equal(JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version, '1.0.0');
  writeFileSync(join(root, 'fix.txt'), 'synthetic follow-up fix');
  git('add', 'fix.txt'); git('commit', '-m', 'fix: failed CI'); git('push', 'origin', 'main');
  const fixed = git('rev-parse', 'HEAD');
  prepare();
  assert.equal(git('rev-parse', 'HEAD'), fixed);
  assert.match(readFileSync(evidence, 'utf8'), new RegExp(`sha=${fixed}`, 'u'));
  assert.equal(git('status', '--porcelain', '--untracked-files=no'), '');
});
test('gates require exact SHA and never select an older success instead of a newer failure', () => {
  const rows = [{ headSha: 'new', event: 'workflow_dispatch', conclusion: 'failure', databaseId: 2 },
    { headSha: 'new', event: 'push', conclusion: 'success', databaseId: 1 }];
  assert.equal(selectRun(rows, 'old', null), null);
  assert.equal(selectRun(rows, 'new', 'workflow_dispatch').databaseId, 2);
  assert.equal(selectRun(rows, 'new', null).conclusion, 'failure');
  assert.equal(selectRun(rows, 'new', 'workflow_dispatch', new Set([2])), null, 'Rerun must wait for its fresh dispatch registration');
  assert.equal(new Set(RELEASE_GATES).size, 10);
  for (const gate of ['quality.yml', 'android-release-startup.yml', 'windows-uac-lab.yml', 'windows-package.yml']) assert.ok(RELEASE_GATES.includes(gate));
});

test('a PR run counts for a tag only when its merge with main is the tagged tree', () => {
  assert.equal(mergeRunTestsExactTree('ahead'), true);
  assert.equal(mergeRunTestsExactTree('identical'), true);
  for (const status of ['behind', 'diverged', '', undefined]) assert.equal(mergeRunTestsExactTree(status), false);
});

test('every release gate runs on its own for each PR commit and main never runs it twice', () => {
  for (const gate of RELEASE_GATES) {
    const workflow = readFileSync(new URL(`../.github/workflows/${gate}`, import.meta.url), 'utf8');
    const triggers = /^on:\n((?:[ #].*\n|\n)*)/mu.exec(workflow)?.[1];
    assert.ok(triggers, gate);
    const events = [...triggers.matchAll(/^ {2}([a-z_]+):/gmu)].map(match => match[1]).sort();
    // main-release.yml dispatches every gate on the exact release commit, so a
    // push trigger would run it twice; a path filter would leave a PR commit
    // with no run at all and make a branch tag unpublishable.
    assert.deepEqual(events, ['pull_request', 'workflow_dispatch'], gate);
    assert.doesNotMatch(triggers, /^\s+(?:paths|paths-ignore|branches):/mu, gate);
  }
});

test('stable publication cannot overwrite assets or silently change the Android signer', () => {
  const workflow = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  assert.doesNotMatch(workflow, /--clobber/u);
  assert.match(workflow, /Stable releases require the complete persistent Android signer/u);
  assert.match(workflow, /security\/android-release-signer\.sha256/u);
  assert.match(workflow, /\[\[ "\$VERSION" == \*-\* \]\]/u);
  assert.match(workflow, /node tools\/release-gates\.mjs/u);
  assert.match(workflow, /group: release-publication/u);
  assert.match(workflow, /node tools\/release-latest\.mjs/u);
  assert.match(workflow, /node tools\/release-version\.mjs --verify-tag "\$tag"/u);
  assert.match(workflow, /test "\$\(git rev-parse HEAD\)" = "\$GITHUB_SHA"/u);
  const main = readFileSync(new URL('../.github/workflows/main-release.yml', import.meta.url), 'utf8');
  assert.match(main, /gh workflow run release\.yml --ref "\$tag"/u);
  assert.doesNotMatch(main, /--force|--no-verify/u);
});

test('late older release never replaces a higher stable release as latest', () => {
  const releases = [{ tag_name: 'v1.2.0', draft: false, prerelease: false },
    { tag_name: 'v9.0.0-beta.1', draft: false, prerelease: true }];
  assert.equal(shouldBeLatest('1.1.0', releases), false);
  assert.equal(shouldBeLatest('1.2.0', releases), false);
  assert.equal(shouldBeLatest('1.2.1', releases), true);
  assert.equal(shouldBeLatest('1.0.0', []), true);
  const args = releaseTagsArguments('owner/repo');
  assert.ok(args.includes('--paginate') && args.includes('--jq'));
  assert.ok(!args.includes('--slurp'), 'gh rejects slurp combined with jq');
});
