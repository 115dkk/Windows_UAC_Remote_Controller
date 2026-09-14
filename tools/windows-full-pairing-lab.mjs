// SPDX-License-Identifier: GPL-2.0-or-later
// Actual Windows pixels -> independent phone -> enrollment -> real UAC denial.
// All pixel/QR/comparison traffic stays in private process pipes, not artifacts.
import assert from 'node:assert/strict';
import { spawn, execFileSync } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { resolve } from 'node:path';
import { expect } from '@playwright/test';
import { PrivateChild } from './ci-private-child.mjs';
import { operatorStartupDiagnostic } from './ci-fixture-diagnostics.mjs';

const lab = 'C:\\ProgramData\\UacRemoteCiE2e';
const service = 'C:\\Program Files\\휴대폰 승인\\uac-service.exe';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function privateChild(exe, env = process.env) {
  return new PrivateChild(spawn(exe, [], { env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }));
}

export async function proveFullPairing({ page, ps, evidence, confirmService, clientPid }) {
  if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') throw new Error('Hosted Windows only');
  let phone, bridge;
  let stage = 'prepare';
  const proof = { commit: process.env.GITHUB_SHA, identity: 'software_ci_fixture', passed: false,
    physicalPhone: false, hardwareAttestation: false, checks: [] };
  function publishControl(name, bytes) {
    assert.ok(['phone-root.der', 'control.json'].includes(name));
    const final = `${lab}\\${name}`, pending = `${final}.pending`;
    assert.ok(!existsSync(final) && !existsSync(pending), 'CI control already exists');
    writeFileSync(pending, bytes, { flag: 'wx' });
    ps(`$p='${pending}';$a=Get-Acl -LiteralPath $p;$a.SetOwner([Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'));$a.SetAccessRuleProtection($true,$true);Set-Acl -LiteralPath $p -AclObject $a`);
    renameSync(pending, final);
  }
  try {
    const ip = ps("$s=[Net.Sockets.UdpClient]::new();try{$s.Connect('192.0.2.1',9);$s.Client.LocalEndPoint.Address.ToString()}finally{$s.Dispose()}").trim();
    assert.ok(Object.values(networkInterfaces()).flat().some(value => value?.address === ip && !value.internal), 'Relay must belong to this runner');
    phone = privateChild(resolve(process.env.CARGO_TARGET_DIR, 'x86_64-pc-windows-msvc/release/ci-phone-fixture.exe'), { ...process.env, WUAC_CI_PHONE_FIXTURE: '1' });
    const prepared = await phone.request({ command: 'prepare', expected_relay_ip: ip }, 'prepared');
    assert.ok(prepared.app_signer_sha256 === '08'.repeat(32), 'Fixture signer mismatch');
    const ca = Buffer.from(prepared.root_der_base64, 'base64');
    assert.ok(ca.length > 100 && ca.length <= 8192);
    publishControl('phone-root.der', ca);
    bridge = privateChild(`${lab}\\uac-ci-pipe-bridge.exe`);
    const session = Number(ps(`(Get-Process -Id ${clientPid}).SessionId`).trim());
    assert.ok(Number.isInteger(session) && session > 0);
    const metadata = { marker: 'uac-ci-e2e-do-not-ship', runNonce: randomBytes(16).toString('hex'),
      githubRunId: process.env.GITHUB_RUN_ID, githubRunAttempt: process.env.GITHUB_RUN_ATTEMPT,
      createdUtc: new Date().toISOString(), sessionId: session, clientPid: bridge.child.pid,
      serviceSha256: hash(readFileSync(service)), githubActions: 'true', runnerEnvironment: 'github-hosted' };
    publishControl('control.json', JSON.stringify(metadata));
    execFileSync(`${lab}\\PsExec64.exe`, ['-accepteula', '-nobanner', '-s', '-i', String(session), '-d', `${lab}\\uac-ci-windows-operator.exe`], { windowsHide: true, timeout: 30000, stdio: ['ignore', 'pipe', 'pipe'] });
    stage = 'initial-consent';
    await bridge.request({ command: 'arm' }, 'ready');
    await page.locator('.navigation-item').nth(1).click();
    const qr = page.locator('.pairing-entry button.primary[aria-describedby$="-qr-purpose"]');
    await expect(qr).toBeEnabled({ timeout: 15000 });
    await qr.click();
    stage = 'qr-pixels';
    const pixels = await bridge.request({ command: 'capture_qr' }, 'qr_pixels');
    assert.ok(typeof pixels.pngBase64 === 'string' && pixels.pngBase64.length < 12 * 1024 * 1024);
    await phone.send({ command: 'enroll_pixels', png_base64: pixels.pngBase64 });
    pixels.pngBase64 = null;
    const comparisonReady = await phone.next();
    assert.ok(comparisonReady.state === 'awaiting_comparison', 'Actual pixels did not start verified enrollment');
    proof.checks.push('actual-protected-qr-pixels-decoded');
    stage = 'comparison';
    const comparison = await bridge.request({ command: 'read_comparison' }, 'comparison_pixels');
    assert.ok(typeof comparison.code === 'string' && /^[0-9]{6}$/.test(comparison.code));
    await phone.request({ command: 'confirm_comparison', code: comparison.code }, 'phone_confirmation_queued');
    await bridge.request({ command: 'compare_confirm', code: comparison.code }, 'confirmed');
    comparison.code = null;
    const acceptance = await phone.next();
    assert.ok(acceptance.state === 'enrollment_accepted', 'Signed enrollment acceptance missing');
    proof.checks.push('both-actual-comparison-confirmations-and-signed-enrollment');
    await bridge.request({ command: 'finish' }, 'done');
    await bridge.complete();
    stage = 'service-registration';
    await expect.poll(async () => {
      try { return await page.evaluate(async () => {
        const s = await window.__TAURI_INTERNALS__.invoke('app_snapshot');
        return { available: s.dataAvailability.devices, count: s.devices.length, id: s.devices[0]?.id };
      }); } catch { return null; }
    }, { timeout: 20000 }).toEqual({ available: 'available', count: 1, id: acceptance.device_id });
    confirmService();
    proof.checks.push('actual-service-registry-row-matches-fixture');
    stage = 'request-roundtrip';
    await phone.send({ command: 'deny_next', expected_program_name: 'UacCiHarmlessRequest',
      expected_path: 'C:\\Program Files\\휴대폰 승인\\uac-ci-request.exe' });
    assert.ok((await phone.next()).state === 'session_ready', 'Pinned session not ready');
    // Only a nonsecret trigger is made readable to the owned medium requester.
    ps("$p='C:\\ProgramData\\UacRemoteCiE2e\\request.trigger';[IO.File]::WriteAllText($p,'trigger');$a=Get-Acl -LiteralPath $p;$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow));Set-Acl -LiteralPath $p -AclObject $a");
    const request = await phone.next();
    assert.ok(request.state === 'request_verified' && /^[a-f0-9]{64}$/.test(request.request_id) && /^[a-f0-9]{64}$/.test(request.content_digest), 'Bound native UAC request missing');
    assert.ok((await phone.next()).state === 'denial_queued');
    const result = await phone.next();
    assert.ok(result.state === 'pc_resolution' && result.outcome === 'denied' && result.request_id === request.request_id && result.content_digest === request.content_digest, 'PC did not verify/resolve the same denial');
    assert.ok((await phone.next()).state === 'completed');
    await phone.complete();
    proof.requestId = request.request_id; proof.contentDigest = request.content_digest;
    proof.checks.push('genuine-uac-request-and-matching-signed-denied-resolution');
    assert.ok(!existsSync(`${lab}\\unexpected-execution.txt`), 'Target must not execute');
    confirmService();
    proof.wirePassed = true; // Parent still must observe actual Windows cancellation/exit.
  } catch {
    const diagnostic = phone?.diagnostic ?? operatorStartupDiagnostic() ?? bridge?.diagnostic;
    if (diagnostic) proof.failure = diagnostic;
    proof.failedStage = stage;
    throw new Error(`Native pairing e2e failed at ${stage}`);
  } finally {
    phone?.abort(); bridge?.abort();
    writeFileSync(resolve(evidence, 'pairing-e2e-proof.json'), JSON.stringify(proof, null, 2), { flag: 'wx' });
  }
}
