// SPDX-License-Identifier: GPL-2.0-or-later
// Pure source/argv/result contracts; never starts Tamarin or any child process.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';
import { CANDIDATE, ORIGIN, admitCandidateEnvironment, admitCandidateSource, candidateArguments, candidateProcessResult } from './protocol-candidate.mjs';
import { DIAGNOSTIC_DEPTH, DIAGNOSTIC_OUTPUT_BYTES, DIAGNOSTIC_TIMEOUT_MS } from './protocol-diagnostic.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const production = readFileSync(resolve(root, ORIGIN), 'utf8');
const candidate = readFileSync(resolve(root, CANDIDATE), 'utf8');
const next = '\nlemma honest_deny_without_approval_auth_trace:';
const insert = (text) => candidate.replace(next, '\n' + text + next);

test('actual tracked candidate admits only its stored navigation proof region', () => {
  const result = admitCandidateSource(production, candidate);
  assert.ok(result.insertedScript.includes('solve( RegistrySlot('));
  assert.ok(result.insertedScript.includes('case CaptureEligibleDevice'));
  assert.ok(result.insertedScript.includes('by sorry'));
  assert.equal(result.normalizedProduction, production.replace(/\r\n?/gu, '\n').replace(/\n+$/u, '\n'));
});

test('line ending normalization does not permit other whitespace or source changes', () => {
  const windows = candidate.replace(/\r\n?/gu, '\n').replace(/\n/gu, '\r\n');
  assert.doesNotThrow(() => admitCandidateSource(production, windows + '\r\n'));
  assert.throws(() => admitCandidateSource(production, candidate.replace('builtins: signing', 'builtins:  signing')));
});

test('rule registry phase and signature-check drift outside the script reject', () => {
  for (const [from, to] of [
    ['rule CreatePc:', 'rule CreateAttackerPc:'],
    ['Fr(~pc)', 'Fr(~other_pc)'],
    ["RegistrySlot(~device, pc, ~revision, 'active')", "RegistrySlot(~device, pc, ~revision, 'retired')"],
    ['Eq(verify(signature, approval_message, approval_key), true)', "Eq('unchecked', 'unchecked')"],
    ['// CANARY_REPLAY_GUARD', ", RequestSlot(request_id, pc, binding, 'pending')"],
  ]) {
    assert.ok(candidate.includes(from));
    assert.throws(() => admitCandidateSource(production, candidate.replace(from, to)));
  }
});

test('honest formula and any other lemma formula or header must remain exact', () => {
  for (const [from, to] of [
    ['    & o < u & u < a"', '    & o < a"'],
    ['    & o < a\n', '    & a < o\n'],
    ['lemma no_accept_after_request_expired:', 'lemma renamed_expiry:'],
    ['    ==> #i = #j', '    ==> #i < #j'],
  ]) {
    assert.ok(candidate.includes(from));
    assert.throws(() => admitCandidateSource(production, candidate.replace(from, to)));
  }
});

test('restriction or production changes invalidate an older candidate', () => {
  assert.throws(() => admitCandidateSource(production.replace('left = right', 'left = left'), candidate));
  assert.throws(() => admitCandidateSource(production.replace('heuristic: i', 'heuristic: s'), candidate));
});

test('inserted preprocessor declarations new rules lemmas or oracle directives reject', () => {
  for (const text of ['#include "other.spthy"', '#define EXTRA', 'lemma added: "True"',
    'rule Added: [] --> []', 'restriction Extra: "True"', 'heuristic: o',
    'tactic: extra', 'functions: evil/0', 'equations: x = y', 'theory New begin',
    'qed lemma same_line: "True"', 'oracle "/untrusted/program"']) {
    assert.throws(() => admitCandidateSource(production, insert(text)), text);
  }
});

test('missing duplicate or misplaced witness delimiters and empty insertion reject', () => {
  assert.throws(() => admitCandidateSource(production, production));
  assert.throws(() => admitCandidateSource(production, candidate + '\nlemma honest_approve_trace:\n'));
  assert.throws(() => admitCandidateSource(production, candidate.replace(next, '\nlemma unrelated_next:')));
  assert.throws(() => admitCandidateSource(production, candidate + '\0'));
  assert.throws(() => admitCandidateSource('', candidate));
  assert.throws(() => admitCandidateSource(production, 'x'.repeat(1024 * 1024 + 1)));
});

test('admission does not pretend to validate a stored proof or certify syntax', () => {
  // Structurally inside the permitted region but intentionally not a real proof
  // method. Tamarin, not this text gate, must reject it during ROOT execution.
  const syntacticallyUnchecked = candidate.replace('by sorry', 'by not_a_tamarin_method');
  assert.doesNotThrow(() => admitCandidateSource(production, syntacticallyUnchecked));
});

test('actual runner admission is no-argument Linux GitHub CI with configured absolute binary', () => {
  const env = { CI: 'true', GITHUB_ACTIONS: 'true', TAMARIN_BIN: '/trusted/tamarin-prover' };
  assert.equal(admitCandidateEnvironment([], env, 'linux'), env.TAMARIN_BIN);
  for (const args of [['--help'], ['other.spthy'], ['--binary', '/other'], ['https://example.com']]) {
    assert.throws(() => admitCandidateEnvironment(args, env, 'linux'));
  }
  for (const platform of ['win32', 'darwin']) assert.throws(() => admitCandidateEnvironment([], env, platform));
  for (const change of [{ CI: 'false' }, { GITHUB_ACTIONS: undefined }, { TAMARIN_BIN: 'tamarin-prover' }, { TAMARIN_BIN: undefined }]) {
    assert.throws(() => admitCandidateEnvironment([], { ...env, ...change }, 'linux'));
  }
});

test('candidate argv uses the existing fixed diagnostic budgets and no output side file', () => {
  assert.deepEqual(candidateArguments('/fixed/candidate/request.input.spthy'), ['/fixed/candidate/request.input.spthy',
    '--quit-on-warning', '--prove=honest_approve_trace', '--heuristic=i', '--bound=12',
    '--stop-on-trace=NONE', '+RTS', '-N2', '-M2G', '-RTS']);
  assert.equal(DIAGNOSTIC_DEPTH, 12);
  assert.equal(DIAGNOSTIC_TIMEOUT_MS, 60_000);
  assert.equal(DIAGNOSTIC_OUTPUT_BYTES, 4 * 1024 * 1024);
  assert.equal(ORIGIN, 'security/tamarin/RequestAuthorization.spthy');
  assert.equal(CANDIDATE, 'security/tamarin/candidates/HonestApproveNavigation.spthy');
});

test('successful process and arbitrary printed verdicts can never become proof evidence', () => {
  const result = candidateProcessResult({ status: 0, signal: null, cancelled: false, cleanupIncomplete: false,
    stdout: 'honest_approve_trace (exists-trace): verified (1 steps)', stderr: '' });
  assert.equal(result.processCompleted, true);
  assert.equal(result.eligibleAsProof, false);
  assert.equal(result.classification, 'CANDIDATE_ONLY');
  assert.equal(Object.hasOwn(result, 'passed'), false);
  assert.equal(Object.hasOwn(result, 'verdicts'), false);
});

test('timeouts failed exits cancellation and uncertain cleanup retain their actual failure', () => {
  for (const failure of [{ status: 1 }, { status: null, signal: 'SIGTERM', error: new Error('Prover timed out.') },
    { status: 0, cancelled: true }, { status: 0, cleanupIncomplete: true }, { status: 0, error: new Error('output limited') }]) {
    const result = candidateProcessResult(failure);
    assert.equal(result.processCompleted, false);
    assert.equal(result.eligibleAsProof, false);
    assert.equal(result.process.status, failure.status);
    assert.equal(result.process.cancelled, failure.cancelled === true);
    assert.equal(result.process.cleanupIncomplete, failure.cleanupIncomplete === true);
  }
});
