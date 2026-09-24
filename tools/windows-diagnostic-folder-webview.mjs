// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only actual product WebView action and observed native Explorer window.
import assert from 'node:assert/strict';
import { writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { expect } from '@playwright/test';

export async function proveDiagnosticFolder({ page, ps, evidence, replies, sameShellUser }) {
  await page.locator('nav .navigation-item', { hasText: /^(Activity history|활동 기록)$/u }).click();
  const button = page.getByRole('button', { name: /^(Open log folder|로그 폴더 열기)$/u });
  await expect(button).toBeEnabled();
  await page.screenshot({ path: resolve(evidence, 'diagnostic-folder-action.png') });
  const inventory = [
    'Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes',
    '$top=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,[Windows.Automation.Condition]::TrueCondition)',
    "$cabinets=@($top | Where-Object { $_.Current.ClassName -eq 'CabinetWClass' -and (Get-Process -Id $_.Current.ProcessId -ErrorAction Stop).ProcessName -eq 'explorer' })",
    "$owned=@($cabinets | Where-Object { $_.Current.Name.Contains('UACRemoteController-Logs') })",
  ].join(';');
  const count = () => Number(ps(inventory + ';$owned.Count'));
  assert.equal(count(), 0, 'A preexisting folder window cannot stand in for the click');
  const beforeHandles = JSON.parse(ps(inventory + ';ConvertTo-Json -InputObject @($cabinets | ForEach-Object { [long]$_.Current.NativeWindowHandle }) -Compress'));
  assert.ok(Array.isArray(beforeHandles) && beforeHandles.every(Number.isSafeInteger));
  let opened = false;
  await button.click();
  try {
    await expect.poll(() => replies.length, { timeout: 15000, intervals: [200, 500] }).toBe(1);
    if (replies[0] === 'UAC_DIAGNOSTIC_FOLDER_V1 outcome=accepted') {
      await expect.poll(count, { timeout: 15000, intervals: [500, 1000] }).toBe(1);
      opened = true;
      await expect(page.locator('.notice-box.error')).toHaveCount(0);
    } else {
      // Explorer is one interactive-user shell, not a supported cross-user
      // activation service. Preserve this real result, not a universal denial
      // assertion. The SAME-shell-user positive proof remains mandatory.
      assert.equal(sameShellUser, false, 'The actual shell-user GUI must open the folder');
      assert.equal(replies[0], 'UAC_DIAGNOSTIC_FOLDER_V1 outcome=failed category=unavailable stage=5 code=2147942405');
      assert.equal(count(), 0);
      await expect(button).toBeEnabled();
    }
  } finally {
    await page.screenshot({ path: resolve(evidence, 'diagnostic-folder-after.png') });
    writeFileSync(resolve(evidence, 'diagnostic-folder-result.json'), JSON.stringify({
      sameShellUser, opened, replies,
      errorVisible: await page.locator('.notice-box.error').count() > 0,
      buttonEnabled: await button.isEnabled(),
    }, null, 2), { flag: 'wx' });
    // Explorer may navigate an existing window/tab. Only a newly observed HWND
    // belongs to this click for cleanup; never close a preexisting shell window.
    if (opened) ps(inventory + ";if($owned.Count -ne 1){throw 'Folder window identity changed'};$before=@(" + beforeHandles.join(',') + ");if([long]$owned[0].Current.NativeWindowHandle -notin $before){([Windows.Automation.WindowPattern]$owned[0].GetCurrentPattern([Windows.Automation.WindowPattern]::Pattern)).Close()}");
  }
  return opened;
}
