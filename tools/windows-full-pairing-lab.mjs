// SPDX-License-Identifier: GPL-2.0-or-later
// Actual Windows pixels -> independent phone -> enrollment -> real UAC denial.
// All pixel/QR/comparison traffic stays in private process pipes, not artifacts.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { createHash, randomBytes } from 'node:crypto';
import { readFileSync, writeFileSync, existsSync, renameSync } from 'node:fs';
import { networkInterfaces } from 'node:os';
import { resolve } from 'node:path';
import { expect } from '@playwright/test';
import { PrivateChild } from './ci-private-child.mjs';
import { operatorStartupDiagnostic } from './ci-fixture-diagnostics.mjs';
import { OperatorProcess } from './ci-operator-process.mjs';
import { awaitQrEnrollment } from './ci-presentation-readiness.mjs';

const lab = 'C:\\ProgramData\\UacRemoteCiE2e';
const service = 'C:\\Program Files\\휴대폰 승인\\uac-service.exe';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
function privateChild(exe, env = process.env, options) {
  return new PrivateChild(spawn(exe, [], { env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] }), options);
}
// Shape-only client view for a failed stage: closed vocabulary words and counts.
// Never a device id, key, QR payload, comparison digit or free-text message.
async function clientShape(page) {
  try {
    return await page.evaluate(async () => {
      const closed = value => (typeof value === 'string' && /^[a-z_]{1,32}$/.test(value) ? value : null);
      const snapshot = await window.__TAURI_INTERNALS__.invoke('app_snapshot');
      return {
        serviceState: closed(snapshot.service?.state ?? null),
        devicesAvailability: closed(snapshot.dataAvailability?.devices ?? null),
        deviceCount: Array.isArray(snapshot.devices) ? snapshot.devices.length : null,
        pairingPhase: closed(snapshot.pairing?.phase ?? null),
        pairingFailure: closed(snapshot.pairing?.failure ?? null),
        issueCode: closed(snapshot.issue?.code ?? null),
      };
    });
  } catch { return null; }
}

export async function proveFullPairing({ page, ps, evidence, confirmService, clientPid }) {
  if (process.platform !== 'win32' || process.env.GITHUB_ACTIONS !== 'true' || process.env.RUNNER_ENVIRONMENT !== 'github-hosted') throw new Error('Hosted Windows only');
  let phone, bridge, operator;
  let stage = 'prepare-interface';
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
    stage = 'prepare-phone';
    // The real UAC hold is deliberately 115s; permit bounded scheduling slack
    // for its next payload-free observation, not longer protocol credentials.
    phone = privateChild(resolve(process.env.CARGO_TARGET_DIR, 'x86_64-pc-windows-msvc/release/ci-phone-fixture.exe'), { ...process.env, WUAC_CI_PHONE_FIXTURE: '1' }, { responseTimeoutMs: 150000 });
    const prepared = await phone.request({ command: 'prepare', expected_relay_ip: ip }, 'prepared');
    assert.ok(prepared.app_signer_sha256 === '08'.repeat(32), 'Fixture signer mismatch');
    const ca = Buffer.from(prepared.root_der_base64, 'base64');
    assert.ok(ca.length > 100 && ca.length <= 8192);
    stage = 'prepare-root';
    publishControl('phone-root.der', ca);
    stage = 'prepare-bridge';
    bridge = privateChild(`${lab}\\uac-ci-pipe-bridge.exe`);
    stage = 'prepare-session';
    const session = Number(ps(`(Get-Process -Id ${clientPid}).SessionId`).trim());
    assert.ok(Number.isInteger(session) && session > 0);
    stage = 'prepare-control';
    const metadata = { marker: 'uac-ci-e2e-do-not-ship', runNonce: randomBytes(16).toString('hex'),
      githubRunId: process.env.GITHUB_RUN_ID, githubRunAttempt: process.env.GITHUB_RUN_ATTEMPT,
      createdUtc: new Date().toISOString(), sessionId: session, clientPid: bridge.child.pid,
      serviceSha256: hash(readFileSync(service)), githubActions: 'true', runnerEnvironment: 'github-hosted' };
    publishControl('control.json', JSON.stringify(metadata));
    stage = 'prepare-operator';
    operator = new OperatorProcess(spawn(`${lab}\\PsExec64.exe`,
      ['-accepteula', '-nobanner', '-s', '-i', String(session), `${lab}\\uac-ci-windows-operator.exe`],
      { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] }));
    await operator.guardStartup(() => bridge.request({ command: 'arm' }, 'ready'));
    stage = 'initial-consent';
    await page.locator('.navigation-item').nth(1).click();
    const qr = page.locator('.pairing-entry button.primary[aria-describedby$="-qr-purpose"]');
    await expect(qr).toBeEnabled({ timeout: 15000 });
    await qr.click();
    stage = 'qr-pixels';
    await awaitQrEnrollment({
      capture: () => bridge.request({ command: 'capture_qr' }, 'qr_pixels'),
      onAttempt: count => { proof.qrCaptureAttempts = count; },
      enroll: async pixels => {
        assert.ok(typeof pixels.pngBase64 === 'string' && pixels.pngBase64.length < 12 * 1024 * 1024);
        try { await phone.send({ command: 'enroll_pixels', png_base64: pixels.pngBase64 }); }
        finally { pixels.pngBase64 = null; }
        return phone.next();
      },
    });
    proof.checks.push('actual-protected-qr-pixels-decoded');
    stage = 'comparison-read';
    const comparison = await bridge.request({ command: 'read_comparison' }, 'comparison_pixels');
    assert.ok(typeof comparison.code === 'string' && /^[0-9]{6}$/.test(comparison.code));
    stage = 'comparison-phone-confirm';
    await phone.request({ command: 'confirm_comparison', code: comparison.code }, 'phone_confirmation_queued');
    stage = 'comparison-pc-confirm';
    await bridge.request({ command: 'compare_confirm', code: comparison.code }, 'confirmed');
    comparison.code = null;
    stage = 'comparison-signed-acceptance';
    const acceptance = await phone.next();
    assert.ok(acceptance.state === 'enrollment_accepted', 'Signed enrollment acceptance missing');
    proof.checks.push('both-actual-comparison-confirmations-and-signed-enrollment');
    await bridge.request({ command: 'finish' }, 'done');
    await bridge.complete();
    stage = 'operator-completion';
    await operator.complete();
    proof.checks.push('operator-launcher-drained-zero-exit');
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
    // Windows names an unsigned program by its file name in the consent
    // dialog, and a collapsed dialog shows no location, so the fixture falls
    // back to requiring that name inside the actual observed details.
    await phone.send({ command: 'deny_next', expected_program_name: 'uac-ci-request.exe',
      expected_path: 'C:\\Program Files\\휴대폰 승인\\uac-ci-request.exe' });
    assert.ok((await phone.next()).state === 'session_ready', 'Pinned session not ready');
    // Only a nonsecret trigger is made readable to the owned medium requester.
    ps("$p='C:\\ProgramData\\UacRemoteCiE2e\\request.trigger';[IO.File]::WriteAllText($p,'trigger');$a=Get-Acl -LiteralPath $p;$a.AddAccessRule([Security.AccessControl.FileSystemAccessRule]::new([Security.Principal.SecurityIdentifier]::new('S-1-5-32-545'),[Security.AccessControl.FileSystemRights]::Read,[Security.AccessControl.AccessControlType]::Allow));Set-Acl -LiteralPath $p -AclObject $a");
    const request = await phone.next();
    assert.ok(request.state === 'request_verified' && /^[a-f0-9]{64}$/.test(request.request_id) && /^[a-f0-9]{64}$/.test(request.content_digest), 'Bound native UAC request missing');
    stage = 'request-native-lease-hold';
    const renewed = await phone.next();
    assert.ok(renewed.state === 'lease_renewed' && renewed.request_id === request.request_id &&
      renewed.content_digest === request.content_digest && Number.isInteger(renewed.held_millis) &&
      renewed.held_millis >= 115000 && renewed.held_millis <= 150000 &&
      Number.isInteger(renewed.renewals) && renewed.renewals >= 1 && renewed.renewals <= 4,
    'Verified renewal after native UAC hold missing');
    proof.nativeHoldMillis = renewed.held_millis;
    proof.leaseRenewals = renewed.renewals;
    proof.checks.push('native-uac-survives-original-lease-with-verified-fresh-renewal');
    stage = 'request-renewed-denial';
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
    proof.privateProcesses = { phone: phone?.snapshot() ?? null, bridge: bridge?.snapshot() ?? null };
    // Distinguishes a service that never registered the device from a client
    // that cannot yet read management while its pairing worker is still live.
    proof.clientView = await clientShape(page);
    proof.operatorProcess = operator?.snapshot() ?? null;
    throw new Error(`Native pairing e2e failed at ${stage}`);
  } finally {
    phone?.abort(); bridge?.abort();
    await operator?.abort();
    if (!proof.wirePassed && operator) proof.operatorProcess = operator.snapshot();
    writeFileSync(resolve(evidence, 'pairing-e2e-proof.json'), JSON.stringify(proof, null, 2), { flag: 'wx' });
  }
}
