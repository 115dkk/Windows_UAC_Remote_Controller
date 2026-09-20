// SPDX-License-Identifier: GPL-2.0-or-later
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { FullConfig } from '@playwright/test';

const root = fileURLToPath(new URL('../../', import.meta.url));

export default function preflight(config: FullConfig): void {
  const directory = resolve(root, 'target/ui-gallery');
  mkdirSync(directory, { recursive: true });
  const entry = resolve(root, 'target/ui-qa/qa.html');
  if (statSync(entry).size > 1024 * 1024) throw new Error('QA entry exceeds the gallery input bound.');
  const bytes = readFileSync(entry);
  const html = bytes.toString('utf8');
  if (!/<script\b[^>]*src=["']\/assets\/[^"']+\.js["']/u.test(html)
    || /\/@vite\/client|\/src\/qa-preview|\/src\/main/u.test(html)) {
    throw new Error('Gallery requires the production-compiled QA entry, not a development server/input.');
  }
  const headSha = execFileSync('git', ['rev-parse', '--verify', 'HEAD'], {
    cwd: root, encoding: 'utf8', timeout: 5_000, windowsHide: true,
  }).trim();
  if (!/^[0-9a-f]{40,64}$/u.test(headSha)) throw new Error('Cannot identify the actual checked-out gallery commit.');
  const expected = process.env.GALLERY_COMMIT;
  if (expected && expected !== headSha) throw new Error('GALLERY_COMMIT does not match the actual checked-out HEAD.');
  writeFileSync(resolve(directory, 'build-input.json'), `${JSON.stringify({
    runId: config.metadata['galleryRunId'], headSha, expectedCommit: expected ?? null,
    githubSha: process.env.GITHUB_SHA ?? null, entry: 'target/ui-qa/qa.html',
    entrySha256: createHash('sha256').update(bytes).digest('hex'),
    builtEntryOnly: true, observedAt: new Date().toISOString(),
  }, null, 2)}\n`);
}
