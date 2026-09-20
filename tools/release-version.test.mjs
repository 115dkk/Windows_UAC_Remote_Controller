// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { execFileSync } from 'node:child_process';
import test from 'node:test';
import { nextVersion, stableVersion, stampMetadata } from './release-version.mjs';
import { RELEASE_GATES, selectRun } from './release-gates.mjs';
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

test('stable publication cannot overwrite assets or silently change the Android signer', () => {
  const workflow = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  assert.doesNotMatch(workflow, /--clobber/u);
  assert.match(workflow, /Stable releases require the complete persistent Android signer/u);
  assert.match(workflow, /security\/android-release-signer\.sha256/u);
  assert.match(workflow, /\[\[ "\$VERSION" == \*-\* \]\]/u);
  assert.match(workflow, /node tools\/release-gates\.mjs/u);
  assert.match(workflow, /group: release-publication/u);
  assert.match(workflow, /node tools\/release-latest\.mjs/u);
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
