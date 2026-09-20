// SPDX-License-Identifier: GPL-2.0-or-later
import test from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';

// Pure PowerShell parser fixtures only. No event-log query or service execution.
test('startup diagnostic parser accepts only bounded closed records', { skip: process.platform !== 'win32' }, () => {
  const script = String.raw`
    Import-Module './tools/service-startup-diagnostic.psm1' -Force
    $good = 'UAC_STARTUP_V1 version=0.1.0-alpha.37 pid=42 stage=7 phase=merge class=permissions code=00000000 policy=10'
    $valid = ConvertFrom-UacStartupDiagnostic $good
    $bad = @(
      ($good + "\nsecret"),
      ($good -replace 'phase=merge', 'phase=arbitrary'),
      ($good -replace 'policy=10', 'policy=20'),
      ($good -replace 'pid=42', 'pid=4294967296'),
      ($good -replace 'pid=42', 'pid=0'),
      ($good -replace 'code=00000000', 'code=FFFFFFFF'),
      ('x' * 257)
    )
    $rejected = @($bad | ForEach-Object { if ($null -eq (ConvertFrom-UacStartupDiagnostic $_)) { 1 } })
    $phases = @('scm_status','scm_state','scm_process','scm_controls') | ForEach-Object {
      (ConvertFrom-UacStartupDiagnostic ($good -replace 'phase=merge', ('phase=' + $_))).phase
    }
    @{ row=$valid; rejected=$rejected.Count; phases=@($phases) } | ConvertTo-Json -Depth 4 -Compress
  `;
  const result = JSON.parse(execFileSync('powershell.exe', ['-NoProfile', '-NonInteractive', '-Command', script], { encoding: 'utf8', windowsHide: true }));
  assert.equal(result.row.phase, 'merge');
  assert.equal(result.row.policyReason, 10);
  assert.equal(result.row.processId, 42);
  assert.equal(result.rejected, 7);
  assert.deepEqual(result.phases, ['scm_status', 'scm_state', 'scm_process', 'scm_controls']);
  assert.deepEqual(Object.keys(result.row).sort(), ['schema', 'version', 'processId', 'startupStage', 'phase', 'category', 'nativeCode', 'policyReason'].sort());
});
