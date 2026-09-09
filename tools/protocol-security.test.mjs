// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { mutateExactlyOnce, parseProofSummary, runProtocolSecurity } from './protocol-security.mjs';
const expected = { auth: { trace: 'all-traces', verdict: 'verified' }, executable: { trace: 'exists-trace', verdict: 'verified' } };
const text = 'summary of summaries:\n analyzed: Model.spthy\n auth (all-traces): verified (5 steps)\n executable (exists-trace): verified (3 steps)\n';
const result = (stdout) => ({ stdout, stderr: '', status: 0, signal: null });
const parse = (input, expected, known) => parseProofSummary(input, expected, known, 'Model.spthy');
test('actual summary needs every property and honest executable trace', () => {
  assert.equal(parse(result(text), expected).ok, true);
  assert.equal(parse(result(text.replace('executable (exists-trace): verified (3 steps)', '')), expected).ok, false);
});
test('exit zero does not turn falsified/incomplete/unknown into proof', () => {
  for (const status of ['falsified - found trace', 'analysis incomplete', 'unknown']) {
    assert.equal(parse(result(text.replace('auth (all-traces): verified', `auth (all-traces): ${status}`)), expected).ok, false);
  }
  assert.equal(parse({ ...result(text), status: 1 }, expected).ok, false);
  assert.equal(parse({ ...result(text), signal: 'SIGTERM' }, expected).ok, false);
  assert.equal(parse({ ...result(text), error: new Error('missing tool') }, expected).ok, false);
  assert.equal(parse({ ...result(text), cancelled: true }, expected).ok, false);
  assert.equal(parse({ ...result(text), cleanupIncomplete: true }, expected).ok, false);
  assert.equal(parse({ ...result(text), stderr: 'checking version: WARNING: returned unsupported version' }, expected).ok, false);
});
test('negative control requires a real counterexample to a named production lemma', () => {
  const wanted = { auth: { trace: 'all-traces', verdict: 'falsified' } };
  assert.equal(parse(result(text), wanted, Object.keys(expected)).ok, false);
  assert.equal(parse(result(text.replace('auth (all-traces): verified', 'auth (all-traces): falsified - found trace')), wanted, Object.keys(expected)).ok, true);
});
test('truncated, duplicate, unregistered and wrong trace summaries fail', () => {
  for (const broken of [text.replace('summary of summaries:', ''), text.replace('analyzed:', 'missing:'), text + ' auth (all-traces): verified (1 steps)\n', text + ' surprise (all-traces): verified (1 steps)\n', text.replace('auth (all-traces)', 'auth (exists-trace)')]) {
    assert.equal(parse(result(broken), expected).ok, false);
  }
  assert.equal(parse(result(text), {}).ok, false);
  assert.equal(parse(result(text.replace('verified (5 steps)', 'verified but incomplete')), expected).ok, false);
});
test('proof is tied to exactly one invoked model, not a neighboring or mixed summary', () => {
  assert.equal(parse(result(text.replace('Model.spthy', 'Other.spthy')), expected).ok, false);
  assert.equal(parse(result(text + ' analyzed: Other.spthy\n'), expected).ok, false);
  assert.equal(parse(result(text + text), expected).ok, false);
  assert.equal(parseProofSummary(result(text), expected).ok, false);
});
test('canary mutation must change exactly one current source marker', () => {
  assert.equal(mutateExactlyOnce('a GUARD b', { from: 'GUARD', to: 'BROKEN' }), 'a BROKEN b');
  for (const source of ['a b', 'GUARD GUARD']) assert.throws(() => mutateExactlyOnce(source, { from: 'GUARD', to: '' }));
  assert.throws(() => mutateExactlyOnce('GUARD', { from: '', to: 'x' }));
  assert.throws(() => mutateExactlyOnce('GUARD', { from: 'GUARD', to: 'GUARD' }));
});
test('early missing-manifest failure cannot leave a prior passing summary', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'uac-protocol-gate-test-'));
  try {
    const directory = join(temp, 'artifacts/protocol-security');
    mkdirSync(directory, { recursive: true });
    const path = join(directory, 'summary.json');
    writeFileSync(path, JSON.stringify({ passed: true, runs: [{ id: 'old-proof' }] }));
    await assert.rejects(() => runProtocolSecurity(temp));
    const current = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(current.passed, false);
    assert.equal(current.status, 'failed');
    assert.deepEqual(current.runs, []);
  } finally {
    // Only the exact newly-created isolated test fixture, never a user cache.
    assert.equal(resolve(temp).startsWith(resolve(tmpdir()) + sep + 'uac-protocol-gate-test-'), true);
    rmSync(temp, { recursive: true });
  }
});

// Synthetic runner fixture, NOT Tamarin or evidence of a security proof. The
// fake process reports controlled verdict text solely to test orchestration.
function runnerFixture(t) {
  const root = mkdtempSync(join(tmpdir(), 'uac-protocol-runner-test-'));
  const directory = join(root, 'artifacts/protocol-security');
  const manifestPath = join(root, 'security/tamarin/manifest.json');
  mkdirSync(directory, { recursive: true });
  mkdirSync(join(root, 'security/tamarin'), { recursive: true });
  writeFileSync(join(root, 'source.rs'), 'synthetic reviewed source\n');
  const model = (id) => ({ id, path: `security/tamarin/${id}.spthy`, expected,
    canaries: [{ id: `${id}-mutant`, expected: { auth: { trace: 'all-traces', verdict: 'falsified' } },
      mutation: { from: 'GUARD', to: 'MUTANT' } }] });
  const config = { version: 1, toolVersion: '1.12.0',
    sourceBindings: [{ path: 'source.rs', sha256: createHash('sha256').update('synthetic reviewed source\n').digest('hex') }],
    models: [model('alpha'), model('beta')] };
  for (const value of config.models) writeFileSync(join(root, value.path), 'synthetic GUARD input\n');
  const save = () => writeFileSync(manifestPath, JSON.stringify(config));
  save();
  const fake = join(root, 'fake-prover');
  writeFileSync(fake, `#!${process.execPath}
    const fs = require('node:fs');
    fs.appendFileSync('invocations.log', JSON.stringify(process.argv.slice(2)) + '\\n');
    if (process.argv.includes('--version')) { console.log('tamarin-prover 1.12.0'); process.exit(0); }
    const file = process.argv[2];
    const mutant = fs.readFileSync(file, 'utf8').includes('MUTANT');
    console.log('summary of summaries:\\n analyzed: ' + file);
    for (const arg of process.argv.filter(x => x.startsWith('--prove='))) {
      const name = arg.slice(8);
      const kind = name === 'executable' ? 'exists-trace' : 'all-traces';
      console.log(' ' + name + ' (' + kind + '): ' + (mutant ? 'falsified - found trace' : 'verified') + ' (1 steps)');
    }
  `);
  if (process.platform === 'linux') chmodSync(fake, 0o700);
  const previous = process.env.TAMARIN_BIN;
  process.env.TAMARIN_BIN = fake;
  t.after(() => {
    if (previous === undefined) delete process.env.TAMARIN_BIN;
    else process.env.TAMARIN_BIN = previous;
    assert.equal(resolve(root).startsWith(resolve(tmpdir()) + sep + 'uac-protocol-runner-test-'), true);
    rmSync(root, { recursive: true });
  });
  return { root, directory, config, save };
}

test('input identities are reserved before any baseline/canary can overwrite evidence', async (t) => {
  for (const collision of ['own-baseline', 'later-baseline', 'run-id']) {
    await t.test(collision, async (t) => {
      const f = runnerFixture(t);
      if (collision === 'own-baseline') f.config.models[0].canaries[0].id = 'alpha';
      if (collision === 'later-baseline') f.config.models[0].canaries[0].id = 'beta';
      if (collision === 'run-id') f.config.models[0].canaries[0].id = 'alpha-1';
      f.save();
      const retained = join(f.directory, 'alpha.spthy');
      writeFileSync(retained, 'existing evidence sentinel');
      await assert.rejects(() => runProtocolSecurity(f.root), /duplicate protocol evidence id/);
      assert.equal(readFileSync(retained, 'utf8'), 'existing evidence sentinel');
      assert.equal(existsSync(join(f.root, 'invocations.log')), false);
    });
  }
});

test('an input changed BETWEEN per-lemma runs cannot receive another attributed proof',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t);
    const originalWrite = process.stdout.write;
    let changed = false;
    process.stdout.write = function(chunk, ...rest) {
      if (!changed && String(chunk).startsWith('{"id":"alpha-1",')) {
        changed = true;
        writeFileSync(join(f.directory, 'alpha.spthy'), 'different model between runs');
      }
      return originalWrite.call(this, chunk, ...rest);
    };
    try {
      await assert.rejects(() => runProtocolSecurity(f.root), /snapshot changed before invocation/);
    } finally { process.stdout.write = originalWrite; }
    assert.equal(changed, true);
    assert.equal(existsSync(join(f.directory, 'alpha-2.log')), false);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, false);
    assert.equal(summary.status, 'failed');
    assert.equal(summary.runs.length, 1);
  });

test('a handled parent signal records cancellation and never starts remaining proofs',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t);
    const originalWrite = process.stdout.write;
    const previousHandlers = process.listeners('SIGTERM');
    let cancelled = false;
    process.stdout.write = function(chunk, ...rest) {
      if (!cancelled && String(chunk) === 'Protocol security: alpha-1\n') {
        cancelled = true;
        // Invoke only this wrapper's real registered handler; do not signal
        // the test runner PID or unrelated test-harness signal listeners.
        const ownedHandlers = process.listeners('SIGTERM').filter(handler => !previousHandlers.includes(handler));
        assert.equal(ownedHandlers.length, 1);
        ownedHandlers[0]();
      }
      return originalWrite.call(this, chunk, ...rest);
    };
    try {
      await assert.rejects(() => runProtocolSecurity(f.root), /interrupted by SIGTERM/);
    } finally { process.stdout.write = originalWrite; }
    assert.equal(cancelled, true);
    assert.equal(process.listenerCount('SIGTERM'), previousHandlers.length);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, false);
    assert.equal(summary.status, 'failed');
    assert.equal(summary.runs.length, 1);
    assert.equal(summary.runs[0].cancelled, true);
    assert.equal(summary.runs[0].ok, false);
    assert.equal(existsSync(join(f.directory, 'alpha-2.log')), false);
    const calls = readFileSync(join(f.root, 'invocations.log'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(calls, [['--version']]);
  });
