// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { fillTemplate, previousPublishedTag, publishedTagsArguments, readReleaseHistory, releaseValues, renderChanges } from './release-notes.mjs';

const sha = 'a'.repeat(40);
const env = { VERSION: '1.2.0-alpha.1', GITHUB_SHA: sha, GITHUB_REPOSITORY: 'owner/repo', SIGNER_SHA256: 'b'.repeat(64), SIGNER_SOURCE: 'repository-secret' };
const sums = 'c'.repeat(64) + '  example.apk';

test('published-release query includes all pages and prereleases but excludes drafts', () => {
  const args = publishedTagsArguments('owner/repo');
  assert.ok(args.includes('--paginate'));
  assert.ok(!args.includes('--slurp'));
  assert.match(args.at(-1), /draft == false/u);
  assert.doesNotMatch(args.at(-1), /prerelease/u);
  assert.throws(() => publishedTagsArguments('owner/repo?query=bad'));
});

test('nearest published ancestor wins over time, semantic version, duplicate or unrelated tags', () => {
  const distances = { 'v1.0.0': 5, 'v1.1.0-alpha.1': 2, 'v9.0.0': null };
  assert.equal(previousPublishedTag(['v9.0.0', 'v1.0.0', 'v1.1.0-alpha.1', 'v1.1.0-alpha.1', 'invalid', 'v1.1.0'], 'v1.1.0', tag => distances[tag]), 'v1.1.0-alpha.1');
  assert.equal(previousPublishedTag(['v9.0.0'], 'v1.1.0', () => null), null);
  assert.throws(() => previousPublishedTag(['v1.0.0'], 'v1.1.0', () => NaN));
});

test('successive real Git release ranges never repeat a prior release change', () => {
  const cwd = mkdtempSync(join(tmpdir(), 'uac-release-notes-'));
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8' }).trim();
  git('init', '--initial-branch=main');
  git('config', 'user.name', 'Release note fixture');
  git('config', 'user.email', 'release-note@example.invalid');
  git('config', 'commit.gpgsign', 'false');
  git('config', 'tag.gpgsign', 'false');
  git('commit', '--allow-empty', '-m', 'feat: original feature');
  git('tag', 'v1.0.0');
  git('commit', '--allow-empty', '-m', 'fix: first release fix');
  git('tag', 'v1.0.1');
  const first = readReleaseHistory(['v1.0.0'], 'v1.0.1', git('rev-parse', 'HEAD'), cwd);
  assert.deepEqual(first.commits.map(item => item.subject), ['fix: first release fix']);
  git('commit', '--allow-empty', '-m', 'fix: not yet published');
  git('tag', 'v1.0.2-alpha.1');
  git('commit', '--allow-empty', '-m', 'fix: second release fix');
  git('tag', 'v1.0.2');
  const head = git('rev-parse', 'HEAD');
  const second = readReleaseHistory(['v1.0.0', 'v1.0.1'], 'v1.0.2', head, cwd);
  assert.equal(second.previous, 'v1.0.1');
  assert.deepEqual(second.commits.map(item => item.subject), ['fix: second release fix', 'fix: not yet published']);
  assert.doesNotMatch(renderChanges(second.commits, 'owner/repo', second.previous, head), /original feature|first release fix/u);
  // Publishing that prerelease now advances the next boundary; an unpublished
  // tag did not. Reading an older tag at a newer checkout fails closed.
  const afterPublication = readReleaseHistory(['v1.0.0', 'v1.0.1', 'v1.0.2-alpha.1'], 'v1.0.2', head, cwd);
  assert.deepEqual(afterPublication.commits.map(item => item.subject), ['fix: second release fix']);
  assert.throws(() => readReleaseHistory(['v1.0.0'], 'v1.0.1', head, cwd));
  assert.throws(() => readReleaseHistory(['v7.0.0'], 'v1.0.2', head, cwd));
});

test('summary is capped at eight changes, hides metadata, and links the exact range', () => {
  const commits = [{ sha, subject: 'chore(release): 1.2.0' }, ...Array.from({ length: 12 }, (_, i) => ({ sha, subject: 'fix: change ' + i }))];
  const output = renderChanges(commits, 'owner/repo', 'v1.1.0', sha);
  assert.equal(output.split('\n').filter(line => line.startsWith('- ')).length, 8);
  assert.doesNotMatch(output, /chore|change 8/u);
  assert.ok(output.includes('/compare/v1.1.0...' + sha));
  assert.match(output, /총 12개/u);
  assert.ok(renderChanges([], 'owner/repo', null, sha).includes('/commits/' + sha));
});

test('untrusted commit subjects cannot introduce Markdown links or HTML', () => {
  const output = renderChanges([{ sha, subject: 'fix: [click](https://invalid.test) <img> **bold**' }], 'owner/repo', null, sha);
  assert.ok(output.includes('\\[click\\]\\(https://invalid.test\\)'));
  assert.ok(output.includes('&lt;img&gt;'));
  assert.ok(output.includes('\\*\\*bold\\*\\*'));
});

test('release template is compact, change-free until rendered, and links immutable verification', () => {
  const template = readFileSync(new URL('../docs/RELEASE_NOTES_TEMPLATE.md', import.meta.url), 'utf8');
  assert.match(template, /\{\{CHANGES\}\}/u);
  assert.doesNotMatch(template, /^- |CAPABILITY_TABLE|실기 미검증|alpha\.40/mu);
  const values = releaseValues(env, sums, '- 이번 판만의 변경');
  const output = fillTemplate(template, values);
  assert.ok(output.includes('/blob/' + sha + '/docs/release-verification.md'));
  assert.ok(output.includes('- 이번 판만의 변경'));
  assert.doesNotMatch(output, /\{\{[A-Z][A-Z0-9_]*\}\}/u);
  assert.ok(output.includes(env.SIGNER_SHA256), 'The numbered signer placeholder must be filled');
  assert.ok(output.includes(sums), 'The numbered checksum placeholder must be filled');
  assert.equal(fillTemplate('{{CHANGES}}', { CHANGES: '$& {{VERSION}}' }), '$& {{VERSION}}', 'Inserted commit text is never re-interpolated');
  assert.throws(() => fillTemplate('{{UNKNOWN}}', {}));
  assert.throws(() => fillTemplate('{{UNKNOWN_256}}', {}));
  assert.throws(() => releaseValues({ ...env, SIGNER_SHA256: 'bad' }, sums, ''));
  assert.throws(() => releaseValues({ ...env, GITHUB_SHA: 'main' }, sums, ''));
  assert.throws(() => releaseValues(env, 'bad checksum', ''));
});

test('verification retains historical evidence and deferred new-install acceptance', () => {
  const verification = readFileSync(new URL('../docs/release-verification.md', import.meta.url), 'utf8');
  for (const item of ['2026-09-19', 'alpha.40', '50ms', 'alpha.13', '2026-09-12', 'Tamarin', 'ERROR_CANCELLED', '새 설치본의 전체', '별도 사용자 시험']) assert.ok(verification.includes(item), item);
  const workflow = readFileSync(new URL('../.github/workflows/release.yml', import.meta.url), 'utf8');
  const publish = workflow.slice(workflow.indexOf('\n  publish:'));
  assert.match(publish, /fetch-depth: 0/u);
  assert.match(publish, /GH_TOKEN: \$\{\{ github.token \}\}/u);
  assert.match(publish, /docs\/release-verification.md assets\/release-verification.md > notes.md/u);
  assert.match(publish, /files=\([^\n]*assets\/release-verification.md\)/u);
});
