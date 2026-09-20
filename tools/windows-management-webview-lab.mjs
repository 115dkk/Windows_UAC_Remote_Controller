// SPDX-License-Identifier: GPL-2.0-or-later
// Real protected GuiMedium app + original WebView. No fake bridge or mutation.
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, lstatSync } from 'node:fs';
import { resolve } from 'node:path';
import { chromium, expect } from '@playwright/test';
import { provePairingLaunch } from './windows-pairing-webview-lab.mjs';
import { proveFullPairing } from './windows-full-pairing-lab.mjs';
import { windowsPowerShell as ps } from './windows-ci-powershell.mjs';

if (process.platform !== 'win32' || process.env.CI !== 'true' || process.env.GITHUB_ACTIONS !== 'true'
    || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') throw new Error('Disposable hosted Windows only');
const evidence = resolve(process.env.LAB_EVIDENCE ?? '');
const launchFile = resolve(evidence, 'medium-client.json');
assert.ok(lstatSync(launchFile).isFile() && !lstatSync(launchFile).isSymbolicLink());
const launch = JSON.parse(readFileSync(launchFile, 'utf8'));
assert.ok(Number.isInteger(launch.clientPid) && launch.clientPid > 0 && launch.clientPid < 0xffffffff);
assert.equal(launch.debugPort, 19225);
assert.equal(launch.token.tokenType, 'Primary');
assert.equal(launch.token.integrityRid, 8192);
assert.equal(launch.token.elevation, 0);
assert.ok(['Default', 'Limited'].includes(launch.token.elevationType));
for (const name of ['adminEnabled', 'isSystem', 'isAppContainer', 'uiAccess']) assert.equal(launch.token[name], false);
assert.equal(launch.token.sessionNonzero, true);
const profile = resolve(launch.profileDirectory);
assert.ok(profile.startsWith(resolve(process.env.RUNNER_TEMP) + '\\'));
assert.ok(!profile.startsWith(evidence + '\\'));
function serviceState() {
  return JSON.parse(ps("$ErrorActionPreference='Stop'; $s=Get-CimInstance Win32_Service -Filter \"Name='UacRemoteController'\"; $ports=@(Get-NetTCPConnection -State Listen -LocalPort 7443 -ErrorAction SilentlyContinue); @{state=$s.State;pid=[long]$s.ProcessId;listening=[bool]($ports|Where-Object OwningProcess -eq $s.ProcessId)}|ConvertTo-Json -Compress"));
}
const original = serviceState();
assert.equal(original.state, 'Running');
assert.ok(original.pid > 0 && original.listening);
function confirmService() {
  const current = serviceState();
  assert.deepEqual(current, original, 'Management traffic must preserve original service and relay');
}
function debuggerOwnership() {
  const profileLiteral = profile.replaceAll("'", "''");
  // Inspect only this listener/ancestry; no command lines leave PowerShell.
  return JSON.parse(ps([
    "$ErrorActionPreference='Stop'",
    '$ports=@(Get-NetTCPConnection -State Listen -LocalPort 19225 -ErrorAction SilentlyContinue)',
    'if($ports.Count -eq 0){@{ready=$false}|ConvertTo-Json -Compress;exit}',
    "$loopback=@($ports|Where-Object LocalAddress -notin @('127.0.0.1','::1')).Count -eq 0",
    '$owners=@($ports.OwningProcess|Select-Object -Unique)',
    'if($owners.Count -ne 1){throw "Unexpected debugger listeners"}',
    '$all=@(Get-CimInstance Win32_Process);if($all.Count -gt 1024){throw "Process census bound"}',
    '$browser=$all|Where-Object ProcessId -eq $owners[0]',
    "$webview=$browser.Name -eq 'msedgewebview2.exe'",
    "$profile=[bool]($browser.CommandLine -and $browser.CommandLine.ToLowerInvariant().Contains('" + profileLiteral.toLowerCase() + "'))",
    '$at=[long]$owners[0];$owned=$false',
    'for($i=0;$i -lt 12;$i++){if($at -eq ' + launch.clientPid + '){$owned=$true;break};$row=$all|Where-Object ProcessId -eq $at;if(-not $row){break};$at=[long]$row.ParentProcessId}',
    '@{ready=$true;loopback=$loopback;owned=$owned;webview=$webview;profile=$profile}|ConvertTo-Json -Compress',
  ].join(';')));
}
const allowedUrl = value => {
  const url = new URL(value);
  return ['http:', 'https:'].includes(url.protocol) && url.hostname === 'tauri.localhost'
    && ['', '/', '/index.html'].includes(url.pathname) && !url.search && !url.hash;
};
let browser;
let snapshots = 0;
let refreshes = 0;
let rejected = 0;
let busyReads = 0;
try {
  await expect.poll(debuggerOwnership, { timeout: 45000, intervals: [500, 1000] })
    .toEqual({ ready: true, loopback: true, owned: true, webview: true, profile: true });
  browser = await chromium.connectOverCDP('http://127.0.0.1:19225', { timeout: 15000 });
  let targets = [];
  await expect.poll(() => {
    targets = browser.contexts().flatMap(context => context.pages()).filter(page => allowedUrl(page.url()));
    return targets.length;
  }, { timeout: 30000 }).toBe(1);
  const page = targets[0];
  const folderReplies = [];
  page.on('console', message => {
    const text = message.text();
    if (/^UAC_DIAGNOSTIC_FOLDER_V1 outcome=(accepted|failed category=(busy|unavailable|worker|other))$/u.test(text)) folderReplies.push(text);
  });
  const offerFile = resolve(profile, 'pairing-offer.txt');
  const offerStat = lstatSync(offerFile);
  assert.ok(offerStat.isFile() && !offerStat.isSymbolicLink() && offerStat.size < 4096);
  const offerProof = readFileSync(offerFile, 'utf8');
  writeFileSync(resolve(evidence, 'pairing-offer.txt'), offerProof, { flag: 'wx' });
  assert.match(offerProof, /starter_connected\r?\noffer_received_and_drained\r?\n$/,
    'Actual installed medium client must receive the service Offer before UAC');
  await expect(page.locator('.desktop-shell')).toBeVisible({ timeout: 30000 });
  assert.ok(['UAC 원격 승인기', 'UAC Remote Approval'].includes(await page.title()));
  async function snapshot() {
    // Existing read-only command through this exact product WebView's IPC.
    const state = await page.evaluate(async () => {
      let value;
      try {
        value = await window.__TAURI_INTERNALS__.invoke('app_snapshot');
      } catch (error) {
        // commands::with_runtime has one admission slot. A real UI Refresh
        // may still own it; only its exact busy reply permits a bounded retry.
        // Never serialize native error text or retry storage/worker failures.
        if (error && typeof error === 'object' && error.code === 'app_busy') return { busy: true };
        throw new Error('Native app_snapshot rejected with a non-busy error');
      }
      return { schema: value.schemaVersion, platform: value.platform,
        service: value.service?.state, mode: value.relayStatus?.mode,
        relay: value.relayStatus?.state, available: value.dataAvailability.devices,
        count: value.devices.length };
    });
    confirmService();
    if (state.busy === true) busyReads++;
    return state;
  }
  const expected = { schema: 4, platform: 'windows', service: 'running', mode: 'embedded', relay: 'listening', available: 'available', count: 0 };
  // Read-only refresh can wait for the original service's bounded rearm. It
  // never retries a mutation, claims a cancelled action succeeded, or restarts.
  for (let index = 0; index < 16; index++) {
    await page.locator('.refresh-button').click();
    refreshes++;
    await expect(page.locator('.refresh-button')).toBeEnabled({ timeout: 15000 });
    await expect.poll(snapshot, { timeout: 15000, intervals: [500, 1000] }).toEqual(expected);
    snapshots++;
  }
  for (let index = 0; index < 8; index++) {
    ps("$ErrorActionPreference='Stop';$p=[IO.Pipes.NamedPipeClientStream]::new('.','UacRemoteController.Management.v1',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::None);try{$p.Connect(3000);try{$p.Write([byte[]](66,65,68),0,3)}catch [IO.IOException]{}}finally{$p.Dispose()}");
    rejected++;
    confirmService();
    await expect.poll(snapshot, { timeout: 15000, intervals: [500, 1000] }).toEqual(expected);
    snapshots++;
  }
  assert.deepEqual(debuggerOwnership(), { ready: true, loopback: true, owned: true, webview: true, profile: true });
  confirmService();
  // Navigate only the real local client. Never invoke pairing/UAC to measure
  // its entry buttons; native owner, service and bridge admission stay intact.
  await expect(page.locator('.service-card')).toBeVisible();
  await expect(page.locator('.service-card .eyebrow')).toHaveCount(0);
  await expect(page.locator('.service-card .service-description')).toHaveCount(0);
  await page.evaluate(async () => { await document.fonts.ready; });
  await page.screenshot({ path: resolve(evidence, 'status-overview.png') });
  await page.locator('nav .navigation-item').nth(1).click();
  await page.evaluate(async () => { await document.fonts.ready; });
  const pairButtons = page.locator('section.pairing-entry').first().locator(':scope > button');
  await expect(pairButtons.nth(0)).toBeVisible();
  await expect(pairButtons.nth(1)).toBeVisible();
  const qr = await pairButtons.nth(0).boundingBox(), usb = await pairButtons.nth(1).boundingBox();
  assert.ok(qr && usb);
  const rootFontSize = await page.evaluate(() => Number.parseFloat(getComputedStyle(document.documentElement).fontSize));
  const clearGap = Math.max(usb.x - qr.x - qr.width, qr.x - usb.x - usb.width,
    usb.y - qr.y - qr.height, qr.y - usb.y - usb.height);
  assert.ok(clearGap >= rootFontSize - 0.5, 'Native PC WebView must retain its stacked1rem button gap');
  writeFileSync(resolve(evidence, 'pairing-action-bounds.json'), JSON.stringify({ qr, usb, clearGap, rootFontSize, engine: browser.version(), owner: 'actual Windows WebView2' }, null, 2), { flag: 'wx' });
  await page.screenshot({ path: resolve(evidence, 'pairing-actions.png') });
  await page.locator('nav .navigation-item').nth(2).click();
  const logFolder = page.getByRole('button', { name: /^(Open log folder|로그 폴더 열기)$/u });
  await expect(logFolder).toBeEnabled();
  await page.screenshot({ path: resolve(evidence, 'diagnostic-folder-action.png') });
  // Explorer can host several windows/tabs in one process. MainWindowTitle is
  // not a window inventory, so observe the actual accessible folder windows.
  const explorerWindows = [
    'Add-Type -AssemblyName UIAutomationClient,UIAutomationTypes',
    '$top=[Windows.Automation.AutomationElement]::RootElement.FindAll([Windows.Automation.TreeScope]::Children,[Windows.Automation.Condition]::TrueCondition)',
    "$owned=@($top | Where-Object { $_.Current.ClassName -eq 'CabinetWClass' -and $_.Current.Name.Contains('UACRemoteController-Logs') -and (Get-Process -Id $_.Current.ProcessId -ErrorAction Stop).ProcessName -eq 'explorer' })",
  ].join(';');
  const explorerCount = () => Number(ps(explorerWindows + ';$owned.Count'));
  assert.equal(explorerCount(), 0, 'No preexisting diagnostic Explorer window may stand in for this click');
  await logFolder.click();
  try {
    await expect.poll(() => folderReplies.length, { timeout: 15000, intervals: [200, 500] }).toBe(1);
    assert.equal(folderReplies[0], 'UAC_DIAGNOSTIC_FOLDER_V1 outcome=accepted', 'Native folder command must be accepted, not a lost/failed UI action');
    await expect.poll(explorerCount, { timeout: 15000, intervals: [500, 1000] }).toBe(1);
    await expect(page.locator('.notice-box.error')).toHaveCount(0);
  } finally {
    // Owned empty/history view only; no pairing/request body exists at this step.
    await page.screenshot({ path: resolve(evidence, 'diagnostic-folder-after.png') });
    writeFileSync(resolve(evidence, 'diagnostic-folder-result.json'), JSON.stringify({
      errorVisible: await page.locator('.notice-box.error').count() > 0,
      errorText: await page.locator('.notice-box.error').allTextContents(),
      buttonEnabled: await logFolder.isEnabled(),
      replies: folderReplies,
    }, null, 2), { flag: 'wx' });
  }
  ps(explorerWindows + ";if($owned.Count -ne 1){throw 'Diagnostic Explorer identity changed'};([Windows.Automation.WindowPattern]$owned[0].GetCurrentPattern([Windows.Automation.WindowPattern]::Pattern)).Close()");
  await page.locator('nav .navigation-item').nth(1).click();
  confirmService();
  writeFileSync(resolve(evidence, 'management-gui-proof.json'), JSON.stringify({
    commit: process.env.GITHUB_SHA, readOnly: true, actualGuiMedium: true,
    successfulSnapshotChecks: snapshots, refreshes, rejectedClients: rejected, busyReads, originalServicePid: original.pid,
    originalServicePidRetained: true,
    actualRelayListenerRetained: true, debuggerLoopbackAndOwned: true,
    publicDiagnosticFolderOpenedByNativeGui: true,
    scope: 'Real product GuiMedium reads/rejected-image clients; not CliElevated/UAC consent/phone authentication',
  }, null, 2), { flag: 'wx' });
  process.stdout.write('PASS: 24 real GuiMedium snapshot checks, 16 Refresh actions, 8 rejected pipe clients; original service PID and relay listener retained.\n');
  if (process.env.WUAC_CI_E2E === '1') await proveFullPairing({ page, ps, evidence, confirmService, clientPid: launch.clientPid });
  else await provePairingLaunch({ page, ps, profile, evidence, confirmService, clientPid: launch.clientPid });
} finally {
  await browser?.close();
}
