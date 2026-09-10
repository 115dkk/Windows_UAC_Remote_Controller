// SPDX-License-Identifier: GPL-2.0-or-later
// Shape/parser tests only, not a symbolic attack or proof.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { CONTEXTS, SOURCE_PATH, VARIANTS, prepareAttack, selectAttack } from './protocol-attack-witness.mjs';
import { parseProofSummary } from './protocol-security.mjs';
const source = readFileSync(new URL(`../${SOURCE_PATH}`, import.meta.url), 'utf8');

test('only exact reviewed current source and fixed attack/context pairs are accepted', () => {
  for (const variant of VARIANTS) for (const context of CONTEXTS) {
    assert.deepEqual(selectAttack([`--variant=${variant}`, `--context=${context}`]), { variant, context });
    assert.doesNotThrow(() => prepareAttack(source, variant, context));
  }
  for (const args of [[], ['--variant=signature'], ['signature', 'baseline'], ['--variant=signature', '--context=unknown'],
    ['--variant=signature', '--context=mutant', '--depth=1'], ['--context=baseline', '--variant=replay']]) assert.throws(() => selectAttack(args));
  for (const changed of [source + '\n', source.replace('builtins: signing', 'builtins: hashing'),
    source.replace('u < a)', 'a < u)'), source.replace('#i = #j', '#i < #j')]) assert.throws(() => prepareAttack(changed, 'signature', 'mutant'));
});

test('mutations preserve the complete current transition prefix and add only a trace-local existential', () => {
  for (const variant of VARIANTS) {
    const baseline = prepareAttack(source, variant, 'baseline'), mutant = prepareAttack(source, variant, 'mutant');
    assert.equal(baseline.prefix, source.slice(0, source.indexOf('lemma enrolled_revision_unique [reuse]:')));
    assert.equal(baseline.mapping.mutation, null);
    assert.equal(mutant.prefix.replace(mutant.mapping.mutation.to, mutant.mapping.mutation.from), baseline.prefix);
    for (const value of [baseline, mutant]) {
      assert.equal((value.candidate.match(/^lemma /gm) ?? []).length, 1);
      assert.equal((value.candidate.match(/^restriction /gm) ?? []).length, 1);
      assert.deepEqual(value.mapping.assumedHelpers, []);
      assert.equal(value.mapping.allNonLemmaTransitionBytesPreserved, true);
      assert.doesNotMatch(value.candidate, /^lemma[^\n]*\[|^\s*#include|^\s*axiom/m);
    }
    assert.equal(baseline.expected[baseline.lemma].verdict, 'falsified');
    assert.equal(mutant.expected[mutant.lemma].verdict, 'verified');
  }
});

test('signature attack contains exact negated-auth implication and replay instantiates unequal acceptance times', () => {
  const signature = prepareAttack(source, 'signature', 'mutant').candidate.split('lemma attack_approval_without_auth:')[1];
  assert.ok(signature.includes("RequestAccepted(pc, device, revision, binding, 'approve') @a\n    & not (Ex #u. UserAuthenticated(device, binding) @u & u < a)"));
  const replay = prepareAttack(source, 'replay', 'mutant').candidate.split('lemma attack_replay_single_approval:')[1];
  for (const time of ['a1', 'a2']) assert.ok(replay.includes(`RequestAccepted(pc, device, revision, binding, 'approve') @${time}`));
  assert.ok(replay.includes('& a1 < a2'));
  assert.ok(replay.includes('All #x. ApprovalSigned(device, binding) @x ==> #x = #s'));
  assert.ok(replay.includes('All #x. UserAuthenticated(device, binding) @x ==> #x = #u'));
});

test('absence of an existential attack is distinct from finding a universal counterexample', () => {
  const input = '/actual/input.spthy';
  const result = (trace, label) => ({ status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false,
    stdout: `summary of summaries:\n analyzed: ${input}\n attack (${trace}): ${label} (21 steps)\n`, stderr: '' });
  for (const trace of ['exists-trace', 'all-traces']) {
    const correct = trace === 'exists-trace' ? 'falsified - no trace found' : 'falsified - found trace';
    const wrong = trace === 'exists-trace' ? 'falsified - found trace' : 'falsified - no trace found';
    const expected = { attack: { trace, verdict: 'falsified' } };
    assert.equal(parseProofSummary(result(trace, correct), expected, ['attack'], input).ok, true);
    assert.equal(parseProofSummary(result(trace, wrong), expected, ['attack'], input).ok, false);
    for (const label of ['analysis incomplete', 'unknown', `${correct} extra`]) assert.equal(parseProofSummary(result(trace, label), expected, ['attack'], input).ok, false);
    for (const changed of [{ status: 1 }, { signal: 'SIGTERM' }, { cancelled: true }, { cleanupIncomplete: true },
      { error: new Error('timeout') }, { stdout: result(trace, correct).stdout.replace(input, '/other.spthy') }]) {
      assert.equal(parseProofSummary({ ...result(trace, correct), ...changed }, expected, ['attack'], input).ok, false);
    }
  }
});
