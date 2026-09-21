// SPDX-License-Identifier: GPL-2.0-or-later
// Generates bounded release notes and a separate version-bound verification asset.
// Usage: node tools/release-notes.mjs <template.md> <SHA256SUMS.txt> <verification.md> <verification-output.md>
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

const VERSION = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/u;
const SHA = /^[a-f0-9]{40}$/u;
const MAX_CHANGES = 8;

export function publishedTagsArguments(repository) {
  assert.match(repository, /^[\w.-]+\/[\w.-]+$/u);
  return ['api', '--paginate', 'repos/' + repository + '/releases?per_page=100', '--jq',
    '.[] | select(.draft == false) | .tag_name'];
}

// distance returns null for a tag on an unrelated/future branch. Publication time
// and semantic version ordering cannot define an older commit on this branch.
export function previousPublishedTag(tags, currentTag, distance) {
  const candidates = [...new Set(tags)].filter(tag => tag !== currentTag && tag.startsWith('v') && VERSION.test(tag.slice(1)))
    .map(tag => ({ tag, distance: distance(tag) }))
    .filter(item => item.distance !== null);
  for (const item of candidates) assert.ok(Number.isSafeInteger(item.distance) && item.distance >= 0, 'Invalid ancestor distance');
  candidates.sort((a, b) => a.distance - b.distance || a.tag.localeCompare(b.tag, 'en'));
  return candidates[0]?.tag ?? null;
}

function markdownText(value) {
  return value.replace(/[\r\n\t]/gu, ' ').replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replace(/[\\`*_{}\[\]()!|#]/gu, '\\$&');
}

export function renderChanges(commits, repository, previousTag, commit) {
  assert.match(repository, /^[\w.-]+\/[\w.-]+$/u);
  assert.match(commit, SHA);
  const base = 'https://github.com/' + repository;
  const relevant = commits.filter(item => !/^chore\(release\): /u.test(item.subject));
  const lines = relevant.slice(0, MAX_CHANGES).map(item => {
    assert.match(item.sha, SHA);
    return '- ' + markdownText(item.subject.slice(0, 180)) + ' ([' + item.sha.slice(0, 7) + '](' + base + '/commit/' + item.sha + '))';
  });
  if (lines.length === 0) lines.push('- 배포 메타데이터를 갱신했습니다.');
  const rangeLink = previousTag
    ? '[' + markdownText(previousTag) + ' 이후 전체 변경](' + base + '/compare/' + encodeURIComponent(previousTag) + '...' + commit + ')'
    : '[첫 릴리즈의 전체 기록](' + base + '/commits/' + commit + ')';
  return lines.join('\n') + '\n\n' + rangeLink + (relevant.length > MAX_CHANGES ? ' · 총 ' + relevant.length + '개 커밋 중 최근 ' + MAX_CHANGES + '개를 표시합니다.' : '');
}

export function fillTemplate(template, values) {
  return template.replace(/\{\{([A-Z_]+)\}\}/gu, (placeholder, key) => {
    if (!Object.hasOwn(values, key)) throw new Error('Unfilled placeholder ' + placeholder);
    return values[key];
  });
}

export function releaseValues(env, sums, changes) {
  for (const name of ['VERSION', 'SIGNER_SHA256', 'SIGNER_SOURCE', 'GITHUB_SHA', 'GITHUB_REPOSITORY']) {
    assert.ok(env[name] && env[name].length <= 256, name + ' is required for release notes');
  }
  assert.match(env.VERSION, VERSION);
  assert.match(env.GITHUB_SHA, SHA);
  assert.match(env.GITHUB_REPOSITORY, /^[\w.-]+\/[\w.-]+$/u);
  assert.match(env.SIGNER_SHA256, /^[a-f0-9]{64}$/u);
  assert.ok(['repository-secret', 'ephemeral-this-run-only'].includes(env.SIGNER_SOURCE), 'Unknown signer source');
  assert.ok(Buffer.byteLength(sums) <= 4096 && /^[a-f0-9]{64}  [\w.-]+(?:\n[a-f0-9]{64}  [\w.-]+)*$/u.test(sums), 'Unexpected SHA256SUMS shape');
  return {
    VERSION: env.VERSION,
    COMMIT: env.GITHUB_SHA,
    SIGNER_SHA256: env.SIGNER_SHA256,
    SIGNER_SOURCE: env.SIGNER_SOURCE,
    SHA256SUMS: sums,
    CHANGES: changes,
    VERIFICATION_URL: 'https://github.com/' + env.GITHUB_REPOSITORY + '/blob/' + env.GITHUB_SHA + '/docs/release-verification.md',
  };
}

export function readReleaseHistory(tags, currentTag, commit, cwd = process.cwd()) {
  assert.match(commit, SHA);
  assert.ok(currentTag.startsWith('v') && VERSION.test(currentTag.slice(1)), 'Version tag required');
  const git = (...args) => execFileSync('git', args, { cwd, encoding: 'utf8', maxBuffer: 8 * 1024 * 1024 }).trim();
  assert.equal(git('rev-parse', '--is-shallow-repository'), 'false', 'Full release history is required');
  assert.equal(git('rev-parse', 'HEAD'), commit, 'Release notes must match the checked-out commit');
  assert.equal(git('rev-parse', 'refs/tags/' + currentTag + '^{commit}'), commit);
  const previous = previousPublishedTag(tags, currentTag, tag => {
    const tagCommit = git('rev-parse', 'refs/tags/' + tag + '^{commit}');
    const result = spawnSync('git', ['merge-base', '--is-ancestor', tagCommit, commit], { cwd, encoding: 'utf8' });
    if (result.error) throw result.error;
    if (result.status === 1) return null;
    assert.equal(result.status, 0, result.stderr);
    return Number(git('rev-list', '--count', tagCommit + '..' + commit));
  });
  const range = previous ? git('rev-parse', 'refs/tags/' + previous + '^{commit}') + '..' + commit : commit;
  const log = git('log', '--no-merges', '--format=%H%x09%s', range, '--');
  const commits = log ? log.split('\n').map(line => ({ sha: line.slice(0, 40), subject: line.slice(41) })) : [];
  return { previous, commits };
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const [templatePath, sumsPath, verificationPath, verificationOutput, ...extra] = process.argv.slice(2);
  assert.ok(templatePath && sumsPath && verificationPath && verificationOutput && !extra.length,
    'Usage: node tools/release-notes.mjs <template.md> <SHA256SUMS.txt> <verification.md> <verification-output.md>');
  assert.equal(process.env.GITHUB_ACTIONS, 'true', 'Run inside the release publication job');
  const sums = readFileSync(sumsPath, 'utf8').trim();
  const values = releaseValues(process.env, sums, '');
  assert.equal(process.env.RELEASE_TAG, 'v' + values.VERSION);
  // Query all actually published releases (including prereleases), inside the
  // same publication lock. Unpublished tags and drafts never advance the base.
  const published = execFileSync('gh', publishedTagsArguments(process.env.GITHUB_REPOSITORY), { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  const { previous, commits } = readReleaseHistory(published.split(/\r?\n/u).filter(Boolean), process.env.RELEASE_TAG, values.COMMIT);
  values.CHANGES = renderChanges(commits, process.env.GITHUB_REPOSITORY, previous, values.COMMIT);
  const verification = '# ' + values.VERSION + ' 검증 기록\n\n빌드 커밋: ' + values.COMMIT + '  \n이전 공개 릴리즈: ' + (previous ?? '없음 (첫 릴리즈)') + '\n\n' + readFileSync(verificationPath, 'utf8');
  writeFileSync(verificationOutput, verification);
  process.stdout.write(fillTemplate(readFileSync(templatePath, 'utf8'), values));
}
