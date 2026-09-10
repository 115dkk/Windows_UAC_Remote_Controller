// SPDX-License-Identifier: GPL-2.0-or-later
// Source/parser fixtures only; no Tamarin, build or native device execution.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { CHECKED_LEMMA, CURRENT_SOURCE_PATH, CURRENT_SOURCE_HASH, MAPPED_MAIN_COMMIT, CANDIDATE_PATH,
  ORIGINAL_TWO_APPROVERS, ORDERED_TWO_APPROVERS, admitTwoApproverCandidate, admitTwoApproverEnvironment,
  buildTwoApproverCandidate, twoApproverArguments, twoApproverSummary } from './protocol-two-approver-witness.mjs';

const source = readFileSync(new URL(`../${CURRENT_SOURCE_PATH}`, import.meta.url), 'utf8');
const candidate = readFileSync(new URL(`../${CANDIDATE_PATH}`, import.meta.url), 'utf8');

test('candidate comes only from pinned current42b source, with exact rule prefix and no supplied helpers/proofs', () => {
  const built = admitTwoApproverCandidate(source, candidate);
  assert.equal(built.sourceSha256, CURRENT_SOURCE_HASH);
  assert.equal(CURRENT_SOURCE_HASH, '42b467b376c93d3e237021e420798a67549a1aedd17ccde6a001eb73c3d7385d');
  assert.equal(MAPPED_MAIN_COMMIT, 'e5f1cf62185ec6016383b76b4f46ec86234982ec');
  assert.equal(built.candidate.slice(0, built.transitionSource.length), built.transitionSource);
  assert.equal((built.transitionSource.match(/^rule /gm) ?? []).length, 15);
  assert.equal((built.transitionSource.match(/^restriction /gm) ?? []).length, 1);
  assert.equal((built.candidate.match(/^lemma /gm) ?? []).length, 1);
  assert.doesNotMatch(built.candidate, /\[(?:[^\]]*reuse|[^\]]*sources)\]|^by\s|^simplify$/m);
  assert.equal(built.candidate, candidate.replace(/\r\n/g, '\n'));
  assert.deepEqual(buildTwoApproverCandidate(source.replace(/\r?\n/g, '\r\n')), built);
});

test('every original two-device/single-winner conjunct remains, with new binders and witness-local producer bounds', () => {
  const originalBody = ORIGINAL_TWO_APPROVERS.slice(ORIGINAL_TWO_APPROVERS.indexOf('.\n') + 2, -1);
  assert.ok(ORDERED_TWO_APPROVERS.includes(originalBody));
  assert.ok(ORDERED_TWO_APPROVERS.includes('& not (first_device = second_device)'));
  assert.ok(ORDERED_TWO_APPROVERS.includes('& not (Ex purpose #other.'));
  for (const expression of ['e1 < e2 & e2 < b & b < c1 & c1 < c2 & c2 < o',
    'o < u1 & u1 < s1 & s1 < u2 & u2 < s2 & s2 < a',
    'BuildingProduced(request_id, pc, binding) @b',
    '(#x = #b | #x = #c1 | #x = #c2)', '(#x = #e1 | #x = #c1 | #x = #a)', '(#x = #e2 | #x = #c2)',
    'purpose = \'approve\' & #x = #a']) assert.ok(ORDERED_TWO_APPROVERS.includes(expression));
  assert.doesNotMatch(ORDERED_TWO_APPROVERS, /RequestBuildingProduced|restriction|\[reuse\]|axiom/u);
  for (const who of ['first', 'second']) {
    assert.ok(ORDERED_TWO_APPROVERS.includes(`UserAuthenticated(${who}_device, binding)`));
    assert.ok(ORDERED_TWO_APPROVERS.includes(`ApprovalSigned(${who}_device, binding)`));
    assert.ok(ORDERED_TWO_APPROVERS.includes(`Enrolled(pc, ${who}_device, ${who}_revision, ${who}_approval_key, ${who}_denial_key)`));
  }
});

test('changed source, old7af model, weakened formula, altered observation and added global assumptions fail admission', () => {
  const old = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
  for (const text of [old, source.replace('builtins: signing', 'builtins: signing, hashing'),
    source.replace('ActiveRegistryProduced(pc, ~device, ~revision)', 'DifferentObservation(pc, ~device, ~revision)'),
    source + ORIGINAL_TWO_APPROVERS, 'x'.repeat(1024 * 1024 + 1)]) assert.throws(() => buildTwoApproverCandidate(text));
  for (const text of [candidate.replace('& not (first_device = second_device)', ''),
    candidate.replace('s2 < a', 's2 = a'), candidate.replace('first_revision', 'second_revision'),
    candidate.replace('exists-trace', 'all-traces'), candidate.replace('ActiveRegistryProduced', 'RequestBuildingProduced'),
    candidate.replace('rule CreatePc:', 'rule DifferentPc:'), `${candidate}\nrestriction Forced: "T"\n`,
    candidate.replace(`lemma ${CHECKED_LEMMA}:`, `lemma ${CHECKED_LEMMA} [reuse]:`), `${candidate}\nby sorry\n`]) {
    assert.throws(() => admitTwoApproverCandidate(source, text));
  }
});

test('runner admits only fixed Linux Node24 Actions environment and one bounded automatic BFS profile', () => {
  const env = { CI: 'true', GITHUB_ACTIONS: 'true', GITHUB_SHA: 'a'.repeat(40), TAMARIN_BIN: '/pinned/tamarin-prover' };
  assert.deepEqual(admitTwoApproverEnvironment([], env, 'linux', '24.17.0'), { commit: env.GITHUB_SHA, binary: env.TAMARIN_BIN });
  for (const args of [['--prove'], ['--bound=1'], ['--variant=other'], ['--model=/other'], ['--help'], null]) {
    assert.throws(() => admitTwoApproverEnvironment(args, env, 'linux', '24.17.0'));
  }
  for (const changed of [{ CI: 'false' }, { GITHUB_ACTIONS: '' }, { GITHUB_SHA: 'main' }, { TAMARIN_BIN: 'tamarin-prover' }]) {
    assert.throws(() => admitTwoApproverEnvironment([], { ...env, ...changed }, 'linux', '24.17.0'));
  }
  assert.throws(() => admitTwoApproverEnvironment([], env, 'win32', '24.17.0'));
  assert.throws(() => admitTwoApproverEnvironment([], env, 'linux', '22.0.0'));
  assert.deepEqual(twoApproverArguments('/isolated/request.input.spthy'), ['/isolated/request.input.spthy', '--quit-on-warning',
    `--prove=${CHECKED_LEMMA}`, '--stop-on-trace=DFS', '+RTS', '-N2', '-M2G', '-RTS']);
});

test('only actual selected complete existential verdict on the exact input can succeed', () => {
  const input = '/isolated/request.input.spthy';
  const complete = { status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${input}\n ${CHECKED_LEMMA} (exists-trace): verified (42 steps)\n` };
  assert.equal(twoApproverSummary(complete, input).ok, true);
  for (const change of [{ status: 1 }, { status: null }, { error: new Error('timeout') }, { signal: 'SIGTERM' },
    { cancelled: true }, { cleanupIncomplete: true }, { stderr: 'Warning: unsupported model' },
    { classification: 'OLD_RESULT' }, { stdout: complete.stdout.replace('verified', 'analysis incomplete') },
    { stdout: complete.stdout.replace(CHECKED_LEMMA, 'honest_two_approvers_single_winner_trace') },
    { stdout: complete.stdout.replace('exists-trace', 'all-traces') },
    { stdout: complete.stdout.replace(input, '/other/request.input.spthy') }, { stdout: complete.stdout + complete.stdout },
    { stdout: complete.stdout + ' extra_helper (all-traces): verified (1 steps)\n' }]) {
    assert.equal(twoApproverSummary({ ...complete, ...change }, input).ok, false);
  }
});

test('isolated workflow runs this one experiment and preserves separate always-upload evidence', () => {
  const workflow = readFileSync(new URL('../.github/workflows/protocol-two-approver-witness.yml', import.meta.url), 'utf8');
  assert.ok(workflow.includes('run: node tools/protocol-two-approver-witness.mjs'));
  assert.ok(workflow.includes('run: node tools/install-tamarin.mjs'));
  assert.ok(workflow.includes('if: ${{ always() }}'));
  assert.ok(workflow.includes('artifacts/protocol-two-approver-witness/'));
  assert.doesNotMatch(workflow, /continue-on-error|run: node tools\/protocol-security\.mjs|matrix:/u);
});
