// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { stableVersion, compareVersions } from './release-version.mjs';

export function shouldBeLatest(version, releases) {
  const target = stableVersion(version);
  assert.ok(target, 'Stable semantic version required');
  return releases.every(release => {
    if (release.draft || release.prerelease) return true;
    const existing = stableVersion(release.tag_name);
    return existing === null || compareVersions(target, existing) > 0;
  });
}

export function releaseTagsArguments(repository) {
  return ['api', '--paginate', `repos/${repository}/releases?per_page=100`, '--jq',
    '.[] | select(.draft == false and .prerelease == false) | .tag_name'];
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  const repository = process.env.GITHUB_REPOSITORY;
  assert.match(repository ?? '', /^[\w.-]+\/[\w.-]+$/u);
  // Run ONLY inside the publication concurrency lock. Every page participates;
  // created-at ordering or many newer prereleases must not hide a higher stable.
  const tags = execFileSync('gh', releaseTagsArguments(repository), { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 });
  // gh's jq mode emits one raw string per result; Git refs cannot contain newlines.
  const records = tags.split(/\r?\n/u).filter(Boolean).map(tag => ({ tag_name: tag, draft: false, prerelease: false }));
  process.stdout.write(String(shouldBeLatest(process.argv[2], records)) + '\n');
}
