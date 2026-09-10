// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  ORIGINAL, SHAPED, APPROVE_TIGHT_SHAPED, DENY_SHAPED, TWO_APPROVERS_SHAPED, WITNESS_VARIANTS,
  admitStoredProof, shapeWitness, selectWitnessArguments, selectedExpectation, selectedWitnessSummary,
} from './protocol-witness-shape.mjs';
import { proofArguments } from './protocol-security.mjs';

const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
test('only the original existential witness is strengthened; rules and all-trace properties stay byte-identical', () => {
  const { normalized, candidate } = shapeWitness(source);
  assert.equal(candidate.replace(SHAPED, ORIGINAL), normalized);
  assert.ok(candidate.includes("& o < u & u < a\n"));
  assert.ok(candidate.includes("& (All d r b #x. SnapshotCaptured(pc, d, r, b) @x ==> #x = #c)"));
  assert.ok(candidate.includes("& (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)"));
  assert.equal(candidate.split('lemma ').length, normalized.split('lemma ').length);
});
test('different rules, properties, duplicate witnesses and oversized inputs are rejected', () => {
  for (const invalid of [
    source.replace('builtins: signing', 'builtins: signing, hashing'),
    source.replace('==> #i = #j', '==> #i < #j'),
    source + ORIGINAL,
    'x'.repeat(1024 * 1024 + 1),
  ]) assert.throws(() => shapeWitness(invalid));
});
test('CRLF normalization changes no model text beyond line endings', () => {
  assert.deepEqual(shapeWitness(source.replace(/\r?\n/g, '\r\n')), shapeWitness(source));
});
test('actual stored proof can add methods only, never rules or property changes', () => {
  const base = shapeWitness(source).candidate;
  const stored = readFileSync(new URL('../security/tamarin/candidates/HonestApproveShapedProof.spthy', import.meta.url), 'utf8');
  assert.doesNotThrow(() => admitStoredProof(base, stored));
  assert.throws(() => admitStoredProof(base, stored.replace('builtins: signing', 'builtins: signing, hashing')));
  assert.throws(() => admitStoredProof(base, stored.replace('simplify\n', 'simplify\nrule injected:\n')));
});

for (const variant of ['approve-tight', 'deny', 'two-approvers']) {
  test(`${variant} changes only its existential formula and preserves every original conjunction`, () => {
    const { original, shaped } = WITNESS_VARIANTS[variant];
    const { normalized, candidate } = shapeWitness(source, variant);
    const at = normalized.indexOf(original);
    assert.ok(at > 0);
    assert.equal(candidate.slice(0, at), normalized.slice(0, at));
    assert.equal(candidate.slice(at + shaped.length), normalized.slice(at + original.length));
    assert.equal(candidate.replace(shaped, original), normalized);
    const originalConjunctions = original.slice(original.indexOf('.\n') + 2, -1);
    assert.ok(shaped.includes(originalConjunctions));
    for (const other of Object.values(WITNESS_VARIANTS).filter((entry) => entry.lemma !== WITNESS_VARIANTS[variant].lemma)) {
      assert.ok(candidate.includes(other.original), 'every unselected lemma remains its original formula');
    }
    assert.equal(candidate.split('lemma ').length, normalized.split('lemma ').length);
    assert.deepEqual(shapeWitness(source.replace(/\r?\n/g, '\r\n'), variant), shapeWitness(source, variant));
  });

  test(`${variant} rejects changed rules, universal properties, weakened originals and combined candidates`, () => {
    const invalid = [
      source.replace("RequestSlot(request_id, pc, binding, 'pending'),", "!RequestSlot(request_id, pc, binding, 'pending'),"),
      source.replace('==> #i = #j', '==> #i < #j'),
      source.replace('& not (Ex #u. UserAuthenticated(device, binding) @u)', ''),
      source.replace('& not (first_device = second_device)', ''),
      source + WITNESS_VARIANTS[variant].original,
      shapeWitness(source).candidate,
      shapeWitness(source, variant).candidate,
      'x'.repeat(1024 * 1024 + 1),
    ];
    for (const altered of invalid) {
      assert.notEqual(altered, source);
      assert.throws(() => shapeWitness(altered, variant));
    }
  });
}

test('approve-tight adds exactly the selected same-binding auth/sign timepoints to the old shape', () => {
  assert.ok(APPROVE_TIGHT_SHAPED.startsWith(SHAPED.slice(0, -1)));
  const suffix = APPROVE_TIGHT_SHAPED.slice(SHAPED.length - 1);
  assert.equal(suffix, `
    & (All #x. UserAuthenticated(device, binding) @x ==> #x = #u)
    & (All #x. ApprovalSigned(device, binding) @x ==> #x = #s)"`);
  assert.doesNotMatch(SHAPED, /All #x\. (?:UserAuthenticated|ApprovalSigned)/u);
  const stored = readFileSync(new URL('../security/tamarin/candidates/HonestApproveShapedProof.spthy', import.meta.url), 'utf8');
  assert.doesNotThrow(() => admitStoredProof(shapeWitness(source).candidate, stored));
  assert.throws(() => admitStoredProof(shapeWitness(source, 'approve-tight').candidate, stored));
});

test('deny retains no authentication and requires one explicit enrollment/capture/signing chain', () => {
  assert.ok(DENY_SHAPED.includes("& not (Ex #u. UserAuthenticated(device, binding) @u)"));
  assert.ok(DENY_SHAPED.includes('& DenialSigned(device, binding) @s'));
  assert.ok(DENY_SHAPED.includes('& e < c & c < o & o < s & s < a'));
  assert.ok(DENY_SHAPED.includes('SnapshotCaptured(pc, d, r, b) @x ==> #x = #c'));
  assert.ok(DENY_SHAPED.includes('Enrolled(pc, d, r, ak, dk) @x ==> #x = #e'));
  assert.ok(DENY_SHAPED.includes('(All #x. DenialSigned(device, binding) @x ==> #x = #s)'));
  assert.equal((DENY_SHAPED.match(/UserAuthenticated\(/gu) ?? []).length, 1, 'only the original negative auth condition is present');
});

test('two-device witness permits exactly two ordered enrollment/capture timepoints, not one owner', () => {
  assert.ok(TWO_APPROVERS_SHAPED.includes('& not (first_device = second_device)'));
  for (const who of ['first', 'second']) {
    assert.ok(TWO_APPROVERS_SHAPED.includes(`ApprovalSigned(${who}_device, binding) @s${who === 'first' ? '1' : '2'}`));
    assert.ok(TWO_APPROVERS_SHAPED.includes(`Enrolled(pc, ${who}_device, ${who}_revision, ${who}_approval_key, ${who}_denial_key)`));
  }
  assert.ok(TWO_APPROVERS_SHAPED.includes('& e1 < e2 & e2 < c1 & c1 < c2 & s1 < s2'));
  assert.ok(TWO_APPROVERS_SHAPED.includes("RequestAccepted(pc, first_device, first_revision, binding, 'approve') @a"));
  assert.ok(TWO_APPROVERS_SHAPED.includes('& not (Ex purpose #other.\n      RequestAccepted(pc, second_device, second_revision, binding, purpose) @other)'));
  assert.ok(TWO_APPROVERS_SHAPED.includes('SnapshotCaptured(pc, d, r, b) @x ==> (#x = #c1 | #x = #c2)'));
  assert.ok(TWO_APPROVERS_SHAPED.includes('Enrolled(pc, d, r, ak, dk) @x ==> (#x = #e1 | #x = #e2)'));
  assert.ok(TWO_APPROVERS_SHAPED.includes('#o #u1 #u2 #s1 #s2 #a.'));
  assert.ok(TWO_APPROVERS_SHAPED.includes('& o < u1 & u1 < s1 & s1 < u2 & u2 < s2 & s2 < a'));
  for (const [who, index] of [['first', 1], ['second', 2]]) {
    assert.ok(TWO_APPROVERS_SHAPED.includes(`& UserAuthenticated(${who}_device, binding) @u${index}`));
    assert.ok(TWO_APPROVERS_SHAPED.includes(`(All #x. UserAuthenticated(${who}_device, binding) @x ==> #x = #u${index})`));
    assert.ok(TWO_APPROVERS_SHAPED.includes(`(All #x. ApprovalSigned(${who}_device, binding) @x ==> #x = #s${index})`));
  }
});

test('CLI has only fixed independent variants and keeps approve replay intact', () => {
  assert.deepEqual(selectWitnessArguments([]), { variant: 'approve', replay: false });
  assert.deepEqual(selectWitnessArguments(['--replay']), { variant: 'approve', replay: true });
  for (const variant of ['approve-tight', 'deny', 'two-approvers']) {
    assert.deepEqual(selectWitnessArguments([`--variant=${variant}`]), { variant, replay: false });
    const expected = selectedExpectation(variant);
    assert.deepEqual(Object.keys(expected), [WITNESS_VARIANTS[variant].lemma]);
    assert.deepEqual(proofArguments('/isolated/request.input.spthy', expected), [
      '/isolated/request.input.spthy', '--quit-on-warning', `--prove=${WITNESS_VARIANTS[variant].lemma}`,
      '--stop-on-trace=BFS', '+RTS', '-N2', '-M2G', '-RTS',
    ]);
  }
  for (const args of [['--variant=unknown'], ['--variant=__proto__'], ['--variant=deny', '--replay'], ['--variant=approve-tight', '--replay'], ['--bound=1'], ['--model=elsewhere'], ['--variant=deny --replay']]) {
    assert.throws(() => selectWitnessArguments(args));
  }
  for (const variant of ['__proto__', 'constructor', 'unknown', null]) assert.throws(() => shapeWitness(source, variant));
  assert.ok(Object.isFrozen(WITNESS_VARIANTS) && Object.values(WITNESS_VARIANTS).every(Object.isFrozen));
});

test('summary accepts only the selected verified witness, never unselected or incomplete proofs', () => {
  const input = '/isolated/request.input.spthy';
  const known = Object.values(WITNESS_VARIANTS).map((entry) => entry.lemma);
  const rows = (selectedText = 'verified (42 steps)') => ({
    status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${input}\n honest_approve_trace (exists-trace): verified (500 steps)\n honest_deny_without_approval_auth_trace (exists-trace): ${selectedText}\n honest_two_approvers_single_winner_trace (exists-trace): analysis incomplete (0 steps)\n`,
  });
  const accepted = selectedWitnessSummary(rows(), 'deny', known, input);
  assert.equal(accepted.ok, true);
  assert.deepEqual(Object.keys(accepted.verdicts), ['honest_deny_without_approval_auth_trace']);
  assert.equal(selectedWitnessSummary(rows('analysis incomplete (9 steps)'), 'deny', known, input).ok, false);
  for (const partial of [{ status: 1 }, { cancelled: true }, { cleanupIncomplete: true }]) {
    assert.equal(selectedWitnessSummary({ ...rows(), ...partial }, 'deny', known, input).ok, false);
  }
});

test('CI runs only the three tight witnesses independently, while legacy replay remains a CLI choice', () => {
  const workflow = readFileSync(new URL('../.github/workflows/protocol-witness-shape.yml', import.meta.url), 'utf8');
  assert.match(workflow, /fail-fast: false/u);
  for (const name of ['approve-tight', 'deny', 'two-approvers']) assert.ok(workflow.includes(`variant: ${name}`));
  for (const argument of ['--variant=approve-tight', '--variant=deny', '--variant=two-approvers']) assert.ok(workflow.includes(`argument: ${argument}`));
  assert.doesNotMatch(workflow, /variant: approve-replay|argument: --replay/u);
  assert.ok(workflow.includes('protocol-witness-shape-${{ matrix.variant }}-${{ github.sha }}'));
  assert.doesNotMatch(workflow, /continue-on-error|protocol-security\.mjs\s*$/mu);
});
