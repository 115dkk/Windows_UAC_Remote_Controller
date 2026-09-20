// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { setTimeout } from 'node:timers/promises';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';

export const RELEASE_GATES = ['quality.yml', 'android-package.yml', 'android-release-startup.yml',
  'android-lifecycle.yml', 'windows-package.yml', 'windows-uac-lab.yml', 'ui-gallery.yml',
  'android-notification-gallery.yml', 'i18n.yml', 'attestation-status.yml'];
export function selectRun(rows, sha, event, excludedIds = new Set()) {
  return rows.find(row => row.headSha === sha && (!event || row.event === event) && !excludedIds.has(row.databaseId)) ?? null;
}
const output = (program, args) => execFileSync(program, args, { encoding: 'utf8', maxBuffer: 4 * 1024 * 1024 }).trim();
function run(program, args) {
  const result = spawnSync(program, args, { stdio: 'inherit', timeout: 75 * 60 * 1000 });
  assert.ok(!result.error && !result.signal && result.status === 0, `${program} failed (${result.status ?? result.signal ?? result.error?.code})`);
}

export async function requireReleaseGates(sha, dispatch = false) {
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.match(sha, /^[a-f0-9]{40}$/u);
  const repository = process.env.GITHUB_REPOSITORY;
  assert.match(repository ?? '', /^[\w.-]+\/[\w.-]+$/u);
  const rowsFor = workflow => JSON.parse(output('gh', ['run', 'list', '--repo', repository, '--workflow', workflow, '--commit', sha,
    '--limit', '20', '--json', 'databaseId,headSha,event,status,conclusion']));
  const prior = new Map();
  if (dispatch) {
    const remote = output('git', ['ls-remote', 'origin', 'refs/heads/main']).split(/\s/u)[0];
    assert.equal(remote, sha, 'Main changed before dispatch');
    // Dispatch all independent gates before watching any of them.
    for (const workflow of RELEASE_GATES) {
      prior.set(workflow, new Set(rowsFor(workflow).map(row => row.databaseId)));
      run('gh', ['workflow', 'run', workflow, '--repo', repository, '--ref', 'main']);
    }
  }
  for (const workflow of RELEASE_GATES) {
    let selected = null;
    const deadline = Date.now() + 60_000;
    do {
      selected = selectRun(rowsFor(workflow), sha, dispatch ? 'workflow_dispatch' : null, prior.get(workflow));
      if (selected) break;
      if (!dispatch) break;
      // Bounded registration only, after successful workflow_dispatch. Once an
      // ID exists, use gh's native event watcher and propagate its exit status.
      await setTimeout(2000);
    } while (Date.now() < deadline);
    assert.ok(selected && Number.isSafeInteger(selected.databaseId), `No exact-SHA run for ${workflow}`);
    process.stdout.write(`Gate ${workflow}: ${selected.databaseId} at ${sha}\n`);
    run('gh', ['run', 'watch', String(selected.databaseId), '--repo', repository, '--compact', '--exit-status', '--interval', '10']);
    const final = JSON.parse(output('gh', ['run', 'view', String(selected.databaseId), '--repo', repository, '--json', 'headSha,status,conclusion']));
    assert.equal(final.headSha, sha);
    assert.equal(final.status, 'completed');
    assert.equal(final.conclusion, 'success');
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const dispatch = process.argv[2] === '--dispatch-main';
  assert.ok(process.argv.length === (dispatch ? 4 : 3), 'Usage: release-gates.mjs [--dispatch-main] <sha>');
  await requireReleaseGates(process.argv.at(-1), dispatch);
}
