// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic child-process lifecycle tests, not native pairing/UAC evidence.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import test from 'node:test';
import { PrivateChild } from './ci-private-child.mjs';

function fixture(t, source, options = {}) {
  const child = spawn(process.execPath, ['-e', source], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const owner = new PrivateChild(child, { responseTimeoutMs: 5000, completionTimeoutMs: 5000, ...options });
  t.after(() => owner.abort());
  return owner;
}

test('split/coalesced replies drain before successful completion', async t => {
  const owner = fixture(t, `process.stdout.write('{"status":'); setTimeout(() => {
    process.stdout.write('"ready"}\\n{"status":"done"}\\n');
  }, 20);`);
  assert.deepEqual(await owner.next(), { status: 'ready' });
  assert.deepEqual(await owner.next(), { status: 'done' });
  await owner.complete();
});

test('queued success cannot outlive a later terminal failure', async t => {
  const owner = fixture(t, `process.stdout.write('{"status":"done"}\\n' +
    '{"state":"failed","identity":"software_ci_fixture","reason":"fixture_panic"}\\n'); process.exitCode = 1;`);
  await once(owner.child, 'close');
  await assert.rejects(owner.next(), { reason: 'fixture_failed' });
  await assert.rejects(owner.complete(), { reason: 'fixture_failed' });
  assert.deepEqual(owner.diagnostic, { source: 'phone', stage: 'fixture', reason: 'fixture_panic' });
});

test('nonzero exit after final expected reply never completes successfully', async t => {
  const owner = fixture(t, `process.stdout.write('{"status":"done"}\\n'); setTimeout(() => { process.exitCode = 7; }, 40);`);
  assert.deepEqual(await owner.next(), { status: 'done' });
  await assert.rejects(owner.complete(), { reason: 'child_exit_failed' });
});

test('response timeout retires the wait and remains sticky', async t => {
  const owner = fixture(t, 'setTimeout(() => {}, 10000);', { responseTimeoutMs: 30 });
  await assert.rejects(owner.next(), { reason: 'response_timeout' });
  await assert.rejects(owner.next(), { reason: 'response_timeout' });
  await assert.rejects(owner.send({ command: 'finish' }), { reason: 'response_timeout' });
});

test('final reply without process exit fails bounded completion', async t => {
  const owner = fixture(t, `process.stdout.write('{"status":"done"}\\n'); setTimeout(() => {}, 10000);`, { completionTimeoutMs: 30 });
  assert.deepEqual(await owner.next(), { status: 'done' });
  await assert.rejects(owner.complete(), { reason: 'completion_timeout' });
});

test('closed input has a failure owner', async t => {
  const owner = fixture(t, 'setTimeout(() => {}, 10000);');
  owner.child.stdin.destroy();
  await assert.rejects(owner.send({ command: 'finish' }), { reason: 'input_closed' });
  await assert.rejects(owner.complete(), { reason: 'input_closed' });
});

test('owned stdin error rejects an outstanding response wait', async t => {
  const owner = fixture(t, 'setTimeout(() => {}, 10000);');
  const pending = owner.next();
  owner.child.stdin.emit('error', new Error('synthetic transport error'));
  await assert.rejects(pending, { reason: 'stdin_failed' });
});

test('a blocked private write has a bounded sticky failure', async t => {
  const owner = fixture(t, 'setTimeout(() => {}, 10000);', { responseTimeoutMs: 30 });
  await assert.rejects(owner.send({ synthetic: 'x'.repeat(2 * 1024 * 1024) }), { reason: 'stdin_timeout' });
  await assert.rejects(owner.next(), { reason: 'stdin_timeout' });
});

test('partial trailing output rejects already queued success', async t => {
  const owner = fixture(t, `process.stdout.write('{"status":"done"}\\n{');`);
  await once(owner.child, 'close');
  await assert.rejects(owner.next(), { reason: 'partial_response' });
});

test('unexpected extra final reply cannot be ignored', async t => {
  const owner = fixture(t, `process.stdout.write('{"status":"done"}\\n{"status":"extra"}\\n');`);
  await once(owner.child, 'close');
  assert.deepEqual(await owner.next(), { status: 'done' });
  await assert.rejects(owner.complete(), { reason: 'unfinished_protocol' });
});

test('request uses the same private interface and stdin closure permits clean exit', async t => {
  const owner = fixture(t, `process.stdin.setEncoding('utf8'); process.stdin.once('data', () => {
    process.stdout.write('{"status":"done"}\\n');
  }); process.stdin.resume();`);
  assert.deepEqual(await owner.request({ command: 'finish' }, 'done'), { status: 'done' });
  await owner.complete();
});

test('JSON primitives and CR lines fail without exposing input', async t => {
  for (const line of ['null\n', '[]\n', '{"status":"done"}\r\n']) {
    const owner = fixture(t, `process.stdout.write(${JSON.stringify(line)});`);
    await assert.rejects(owner.next(), { reason: 'invalid_response' });
  }
});
