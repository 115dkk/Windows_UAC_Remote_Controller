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

const lab = 'C:\\ProgramData\\UacRemoteCiE2e';
const service = 'C:\\Program Files\\휴대폰 승인\\uac-service.exe';
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
class PrivateChild {
  constructor(exe, env = process.env) {
    this.child = spawn(exe, [], { env, windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
    this.queue = []; this.waiters = []; this.buffer = ''; this.failure = null;
    this.child.stdout.setEncoding('utf8');
    this.child.stdout.on('data', chunk => {
      this.buffer += chunk;
      if (Buffer.byteLength(this.buffer) > 12 * 1024 * 1024) { this.fail(); return; }
      let end;
      while ((end = this.buffer.indexOf('\n')) >= 0) {
        const line = this.buffer.slice(0, end); this.buffer = this.buffer.slice(end + 1);
        let value; try { value = JSON.parse(line); } catch { this.fail(); return; }
        if (value.state === 'failed' || value.status === 'failed') { this.fail(); return; }
        const waiter = this.waiters.shift();
        if (waiter) waiter.resolve(value);
        else if (this.queue.length < 16) this.queue.push(value);
        else { this.fail(); return; }
      }
    });
    // Children deliberately expose fixed stage/reason text only, never traffic.
    this.child.stderr.on('data', data => {
      const text = data.toString('utf8');
      if (text.length < 512 && /^[A-Za-z0-9 :_.\-\r\n]+$/.test(text)) process.stderr.write(text);
    });
    this.child.on('error', () => this.fail());
    this.child.on('exit', code => { this.exited = true; this.code = code; if (code !== 0 || this.waiters.length) this.fail(); });
  }
  fail() { this.failure = new Error('Private CI fixture failed'); for (const waiter of this.waiters.splice(0)) waiter.reject(this.failure); }
  next() {
    if (this.queue.length) return Promise.resolve(this.queue.shift());
    if (this.failure || this.exited) return Promise.reject(this.failure ?? new Error('Fixture closed'));
    return new Promise((resolveValue, rejectValue) => {
      const timer = setTimeout(() => rejectValue(new Error('Private fixture response timeout')), 120000);
      this.waiters.push({ resolve: value => { clearTimeout(timer); resolveValue(value); }, reject: error => { clearTimeout(timer); rejectValue(error); } });
    });
  }
  send(value) { this.child.stdin.write(`${JSON.stringify(value)}\n`); }
  async request(value, state) { this.send(value); const reply = await this.next(); assert.ok((reply.state ?? reply.status) === state, 'Unexpected fixture protocol stage'); return reply; }
  close() { this.child.stdin.end(); if (!this.exited) this.child.kill(); }
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
    phone = new PrivateChild(resolve(process.env.CARGO_TARGET_DIR, 'x86_64-pc-windows-msvc/release/ci-phone-fixture.exe'), { ...process.env, WUAC_CI_PHONE_FIXTURE: '1' });
    const prepared = await phone.request({ command: 'prepare', expected_relay_ip: ip }, 'prepared');
    assert.ok(prepared.app_signer_sha256 === '08'.repeat(32), 'Fixture signer mismatch');
    const ca = Buffer.from(prepared.root_der_base64, 'base64');
    assert.ok(ca.length > 100 && ca.length <= 8192);
    publishControl('phone-root.der', ca);
    bridge = new PrivateChild(`${lab}\\uac-ci-pipe-bridge.exe`);
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
    phone.send({ command: 'enroll_pixels', png_base64: pixels.pngBase64 });
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
    phone.send({ command: 'deny_next', expected_program_name: 'UacCiHarmlessRequest',
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
    proof.requestId = request.request_id; proof.contentDigest = request.content_digest;
    proof.checks.push('genuine-uac-request-and-matching-signed-denied-resolution');
    assert.ok(!existsSync(`${lab}\\unexpected-execution.txt`), 'Target must not execute');
    confirmService();
    proof.wirePassed = true; // Parent still must observe actual Windows cancellation/exit.
  } catch {
    throw new Error(`Native pairing e2e failed at ${stage}`);
  } finally {
    phone?.close(); bridge?.close();
    writeFileSync(resolve(evidence, 'pairing-e2e-proof.json'), JSON.stringify(proof, null, 2), { flag: 'wx' });
  }
}
