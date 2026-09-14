// SPDX-License-Identifier: GPL-2.0-or-later
// Benign real ChildProcess fixtures only; never PsExec, UAC or native proof.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import test from 'node:test';
import { OperatorProcess } from './ci-operator-process.mjs';

function fixture(t, source, options = {}) {
  const child = spawn(process.execPath, ['-e', source], { windowsHide: true, stdio: ['pipe', 'pipe', 'pipe'] });
  const owner = new OperatorProcess(child, { startupTimeoutMs: 5000, wholeTimeoutMs: 10000, completionTimeoutMs: 5000, ...options });
  t.after(() => owner.abort());
  return owner;
}

const ready = owner => owner.guardStartup(async () => { await once(owner.child.stdout, 'data'); return 'authenticated-test-ready'; });

test('keeps running during arm, drains private streams, and requires zero exit', async t => {
  const owner = fixture(t, `process.stdout.write('synthetic-ready'); process.stderr.write('synthetic-private-no-log');
    process.stdin.resume(); process.stdin.on('end', () => { process.stdout.write('synthetic-tail'); });`);
  assert.equal(await ready(owner), 'authenticated-test-ready');
  assert.equal(owner.snapshot().closed, false);
  owner.child.stdin.end();
  await owner.complete();
  assert.deepEqual(owner.snapshot(), { closed: true, exitCode: 0, signal: 'none', spawnError: 'none', failure: 'none',
    stderrClassification: 'unclassified', stderrTruncated: false });
});

test('zero launcher exit before bridge readiness is not startup success', async t => {
  const owner = fixture(t, 'process.exitCode = 0;');
  await assert.rejects(owner.guardStartup(() => new Promise(() => {})), { reason: 'startup_exit' });
  await assert.rejects(owner.complete(), { reason: 'startup_exit' });
});

test('positive launcher exit is a failure, not a detached PID receipt', async t => {
  const owner = fixture(t, `process.stdout.write('synthetic-ready'); process.stdin.resume();
    process.stdin.on('end', () => { process.exitCode = 23; });`);
  await ready(owner);
  owner.child.stdin.end();
  await assert.rejects(owner.complete(), { reason: 'exit_failed' });
  await owner.abort();
  assert.equal(owner.snapshot().exitCode, 23);
  assert.equal(owner.snapshot().closed, true);
});

test('actual spawn error races a pending bridge arm with closed classification', async t => {
  const child = spawn(`${process.execPath}.missing-ci-operator-fixture`, [], { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
  const owner = new OperatorProcess(child, { startupTimeoutMs: 5000 });
  t.after(() => owner.abort());
  await assert.rejects(owner.guardStartup(() => new Promise(() => {})), { reason: 'spawn_failed' });
  await owner.abort();
  assert.equal(owner.snapshot().spawnError, 'ENOENT');
  assert.ok(!JSON.stringify(owner.snapshot()).includes(process.execPath));
});

test('startup timeout is bounded and rejects before any readiness substitution', async t => {
  const owner = fixture(t, 'setTimeout(() => {}, 10000);', { startupTimeoutMs: 30 });
  await assert.rejects(owner.guardStartup(() => new Promise(() => {})), { reason: 'startup_timeout' });
  await owner.abort();
  assert.equal(owner.snapshot().failure, 'startup_timeout');
});

test('whole timeout after startup remains sticky through completion and cleanup', async t => {
  const owner = fixture(t, `process.stdout.write('synthetic-ready'); setTimeout(() => {}, 10000);`, { wholeTimeoutMs: 1500 });
  await ready(owner);
  await assert.rejects(owner.complete(), { reason: 'whole_timeout' });
  await owner.abort();
  assert.equal(owner.snapshot().failure, 'whole_timeout');
});

test('completion timeout cannot stand in for drained exit', async t => {
  const owner = fixture(t, `process.stdout.write('synthetic-ready'); setTimeout(() => {}, 10000);`, { completionTimeoutMs: 30 });
  await ready(owner);
  await assert.rejects(owner.complete(), { reason: 'completion_timeout' });
});

test('failed bridge arm retains a fixed failure without exception contents', async t => {
  const owner = fixture(t, 'setTimeout(() => {}, 10000);');
  await assert.rejects(owner.guardStartup(() => Promise.reject(new Error('synthetic raw private details'))), { reason: 'bridge_arm_failed' });
  assert.ok(!JSON.stringify(owner.snapshot()).includes('synthetic'));
});

test('synchronous arm failure also retires the launcher failure watcher', async t => {
  const owner = fixture(t, 'setTimeout(() => {}, 10000);');
  await assert.rejects(owner.guardStartup(() => { throw new Error('synthetic private exception'); }), { reason: 'bridge_arm_failed' });
  await owner.abort();
});

test('drained zero close already observed after startup is accepted once', async t => {
  const owner = fixture(t, `process.stdout.write('synthetic-ready'); process.stdin.resume();`);
  await ready(owner);
  const closed = once(owner.child, 'close');
  owner.child.stdin.end();
  await closed;
  await owner.complete();
  await assert.rejects(owner.complete(), { reason: 'invalid_completion' });
});

test('owned forced termination cannot complete successfully', async t => {
  const owner = fixture(t, `process.stdout.write('synthetic-ready'); setTimeout(() => {}, 10000);`);
  await ready(owner);
  await owner.abort();
  await assert.rejects(owner.complete(), { reason: 'aborted' });
  const snapshot = owner.snapshot();
  assert.equal(snapshot.failure, 'aborted');
  assert.ok(['none', 'SIGTERM', 'SIGKILL', 'SIGINT', 'SIGABRT', 'SIGHUP', 'other'].includes(snapshot.signal));
});

test('private stderr retains only closed phrase classifications', async t => {
  for (const [phrase, expected] of [
    ['Access is denied.', 'access_denied'],
    ['The handle is invalid.', 'invalid_handle'],
    ['The system cannot find the file specified.', 'file_not_found'],
    ['unrecognized synthetic private detail', 'unclassified'],
    ['Access is denied. The handle is invalid.', 'unclassified'],
  ]) {
    const owner = fixture(t, `process.stderr.write(${JSON.stringify(phrase)}); process.stdout.write('synthetic-ready'); process.stdin.resume();`);
    await ready(owner);
    owner.child.stdin.end();
    await owner.complete();
    assert.equal(owner.snapshot().stderrClassification, expected);
    assert.ok(!JSON.stringify(owner.snapshot()).includes(phrase));
  }
});

test('stderr classification storage has an 8-KiB hard cap', async t => {
  const owner = fixture(t, `process.stderr.write('x'.repeat(9000) + 'Access is denied.');
    process.stdout.write('synthetic-ready'); process.stdin.resume();`);
  await ready(owner);
  owner.child.stdin.end();
  await owner.complete();
  assert.equal(owner.snapshot().stderrClassification, 'unclassified');
  assert.equal(owner.snapshot().stderrTruncated, true);
});
