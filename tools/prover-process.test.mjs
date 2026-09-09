// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, rmdirSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { runProver } from './prover-process.mjs';

function fixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'uac-prover-fixture-'));
  const logPath = join(root, 'transcript.log');
  t.after(() => { unlinkSync(logPath); rmdirSync(root); });
  return { cwd: root, logPath };
}

test('real bounded child output is retained before verdict parsing', async (t) => {
  const options = fixture(t);
  const result = await runProver(process.execPath, ['-e', 'process.stdout.write("out");process.stderr.write("err")'], options);
  assert.equal(result.status, 0);
  assert.equal(result.error, undefined);
  assert.equal(result.stdout, 'out');
  assert.equal(result.stderr, 'err');
  const log = readFileSync(options.logPath, 'utf8');
  assert.ok(log.includes('out') && log.includes('err'));
});

test('output overflow is an explicit failure and transcript stays bounded', async (t) => {
  const options = { ...fixture(t), maxOutputBytes: 64 };
  const result = await runProver(process.execPath, ['-e', 'process.stdout.write("x".repeat(10000));setInterval(()=>{},1000)'], options);
  assert.match(result.error.message, /output limit/);
  assert.equal(readFileSync(options.logPath).length, 64);
});

test('timeout kills the owned child and retains its partial output', async (t) => {
  const options = { ...fixture(t), timeoutMs: 500, killGraceMs: 100 };
  const result = await runProver(process.execPath, ['-e', 'process.stdout.write("partial");setInterval(()=>{},1000)'], options);
  assert.match(result.error.message, /timed out/);
  assert.equal(readFileSync(options.logPath, 'utf8'), 'partial');
});

test('missing executable cannot look like a completed proof', async (t) => {
  const result = await runProver('uac-fixture-no-such-prover', [], fixture(t));
  assert.ok(result.error);
  assert.notEqual(result.status, 0);
});

test('synchronous spawn rejection closes its transcript and returns explicit failure', async (t) => {
  const options = fixture(t);
  const result = await runProver(Symbol('invalid command'), [], options);
  assert.ok(result.error instanceof TypeError);
  assert.equal(result.status, null);
  assert.equal(result.cleanupIncomplete, false);
  assert.equal(readFileSync(options.logPath).length, 0);
});

test('already cancelled admission never tries to spawn even an invalid command', async (t) => {
  const cancellation = new AbortController();
  const reason = new Error('synthetic pre-admission cancellation');
  cancellation.abort(reason);
  const result = await runProver(Symbol('must not spawn'), [], { ...fixture(t), signal: cancellation.signal });
  assert.equal(result.error, reason);
  assert.equal(result.cancelled, true);
  assert.equal(result.cleanupIncomplete, false);
});

test('cancellation stops the current owned child instead of waiting for its work timeout', async (t) => {
  const cancellation = new AbortController();
  const reason = new Error('synthetic parent cancellation');
  const running = runProver(process.execPath, ['-e', 'setInterval(()=>{},1000)'],
    { ...fixture(t), signal: cancellation.signal, timeoutMs: 5000, killGraceMs: 100 });
  cancellation.abort(reason);
  const result = await running;
  assert.equal(result.error, reason);
  assert.equal(result.cancelled, true);
  assert.equal(result.cleanupIncomplete, false);
  assert.notEqual(result.status, 0);
});

test('leader exit terminates its POSIX descendant before inherited pipes hold close open',
  { skip: process.platform === 'win32' }, async (t) => {
    // The descendant stays in the created process group and inherits stderr.
    // The leader exits only after the descendant reports readiness; no sleeps
    // are used to guess process startup or ownership order.
    const program = `
      const { spawn } = require('node:child_process');
      const descendant = spawn(process.execPath, ['-e',
        'process.on("SIGTERM",()=>{});process.stdout.write("ready");setInterval(()=>{},1000)'],
        { stdio: ['ignore', 'pipe', 'inherit'] });
      descendant.stdout.once('data', () => {
        process.stdout.write('descendant=' + descendant.pid + '\\n');
        process.exit(0);
      });
    `;
    const result = await runProver(process.execPath, ['-e', program],
      { ...fixture(t), timeoutMs: 5000, killGraceMs: 100 });
    assert.equal(result.status, 0);
    assert.equal(result.error, undefined);
    assert.equal(result.cleanupIncomplete, false);
    assert.match(result.stdout, /^descendant=\d+\n$/);
  });
