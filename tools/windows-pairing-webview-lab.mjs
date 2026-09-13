// SPDX-License-Identifier: GPL-2.0-or-later
// Actual product QR button -> Windows-owned consent, then cancellation only.
import assert from 'node:assert/strict';
import { existsSync, lstatSync, readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect } from '@playwright/test';

export async function provePairingLaunch({ page, ps, profile, evidence, confirmService, clientPid }) {
  const consent = () => JSON.parse(ps(`$ErrorActionPreference='Stop';$session=(Get-Process -Id ${clientPid}).SessionId;$rows=@(Get-Process -Name consent -ErrorAction SilentlyContinue | Where-Object SessionId -eq $session);if($rows.Count -eq 0){'null';exit};if($rows.Count -ne 1){throw 'Ambiguous consent process'};$p=$rows[0];if($p.Path -ne (Join-Path $env:WINDIR 'System32/consent.exe')){throw 'Unexpected consent image'};@{pid=$p.Id;created=$p.StartTime.ToUniversalTime().Ticks.ToString()}|ConvertTo-Json -Compress`));
  assert.equal(consent(), null, 'No pre-existing consent prompt in this owned GUI session');
  let prompt;
  try {
    await page.locator('.navigation-item').nth(1).click();
    const button = page.locator('.pairing-entry button.primary');
    await expect(button).toBeEnabled({ timeout: 15000 });
    await button.click(); // One actual UI action; no mutation retry.
    await expect.poll(() => { prompt = consent(); return prompt !== null; },
      { timeout: 20000, intervals: [500, 1000] }).toBe(true);
    confirmService();
    writeFileSync(resolve(evidence, 'pairing-uac-launch.json'), JSON.stringify({
      commit: process.env.GITHUB_SHA, actualQrButton: true,
      newWindowsConsentInOriginalSession: true, approvalPerformed: false,
      scope: 'Actual GUI Starter and ShellExecute reach Windows consent; no QR disclosure or phone authentication',
    }, null, 2), { flag: 'wx' });
  } finally {
    const failure = resolve(profile, 'pairing-launch-failure.txt');
    if (existsSync(failure)) {
      const stat = lstatSync(failure);
      assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size < 4096);
      writeFileSync(resolve(evidence, 'pairing-launch-failure.txt'), readFileSync(failure), { flag: 'wx' });
    }
    // Cancel only the newly observed Windows prompt, never approve or kill a
    // product helper. The original PID/start-time/image are rechecked together.
    if (prompt) {
      ps(`$ErrorActionPreference='Stop';$p=Get-Process -Id ${prompt.pid} -ErrorAction SilentlyContinue;if($p){$held=$p.Handle;if($p.StartTime.ToUniversalTime().Ticks.ToString() -ne '${prompt.created}' -or $p.Path -ne (Join-Path $env:WINDIR 'System32/consent.exe')){throw 'Consent identity changed'};Stop-Process -InputObject $p -Force;$p.Dispose()}`);
    }
  }
}
