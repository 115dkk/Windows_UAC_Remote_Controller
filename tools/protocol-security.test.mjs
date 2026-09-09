// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
test('early missing-manifest failure cannot leave a prior passing summary', () => {
  const temp = mkdtempSync(join(tmpdir(), 'uac-protocol-gate-test-'));
  try {
    const directory = join(temp, 'artifacts/protocol-security');
    mkdirSync(directory, { recursive: true });
    const path = join(directory, 'summary.json');
    writeFileSync(path, JSON.stringify({ passed: true, runs: [{ id: 'old-proof' }] }));
    assert.throws(() => runProtocolSecurity(temp));
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
