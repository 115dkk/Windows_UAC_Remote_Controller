// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { fileURLToPath } from 'node:url';

const script = fileURLToPath(new URL('./windows-uac-probe-observation.ps1', import.meta.url));

function observation(journal, startedUnixMs) {
  const result = spawnSync('pwsh', [
    '-NoLogo',
    '-NoProfile',
    '-File',
    script,
    '-JournalPath',
    journal,
    '-StartedUnixMs',
    String(startedUnixMs),
    '-RequestStarted',
    '-ConsentObserved',
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr || result.stdout);
  return result.stdout.trim();
}

test('probe observation rejects stale evidence and accepts evidence from this run', () => {
  const directory = mkdtempSync(join(tmpdir(), 'uac-probe-observation-'));
  const journal = join(directory, 'activity.jsonl');
  try {
    writeFileSync(journal, [
      JSON.stringify({ format_version: 1, last_observed_unix_ms: 1_999 }),
      JSON.stringify({
        timestamp_unix_ms: 1_999,
        event: { category: 'request', outcome: { state: 'observed' } },
      }),
      '',
    ].join('\n'));
    assert.equal(observation(journal, 2_000), 'probe_observed=false');

    writeFileSync(journal, [
      JSON.stringify({ format_version: 1, last_observed_unix_ms: 2_001 }),
      JSON.stringify({
        timestamp_unix_ms: 1_999,
        event: { category: 'request', outcome: { state: 'observed' } },
      }),
      JSON.stringify({
        timestamp_unix_ms: 2_001,
        event: { category: 'request', outcome: { state: 'observed' } },
      }),
      '',
    ].join('\n'));
    assert.equal(observation(journal, 2_000), 'probe_observed=true');
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
});
