// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import {
  ORIGINAL, SHAPED, APPROVE_TIGHT_SHAPED, DENY_ORIGINAL, DENY_SHAPED, DENY_STORED_SHAPED, DENY_STORED_SOURCE_HASH, TWO_APPROVERS_SHAPED, WITNESS_VARIANTS,
  admitStoredProof, shapeWitness, selectWitnessArguments, selectedExpectation, selectedWitnessSummary,
  STORED_CHECK_CONTEXTS, storedCheckInput, storedCheckArguments, storedCheckSummary,
  storedDenyCheckInput, storedDenyCheckSummary,
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

test('CI runs only three deny stored-proof contexts independently, while approve and legacy variants remain CLI choices', () => {
  const workflow = readFileSync(new URL('../.github/workflows/protocol-witness-shape.yml', import.meta.url), 'utf8');
  assert.match(workflow, /fail-fast: false/u);
  for (const context of STORED_CHECK_CONTEXTS) {
    assert.ok(workflow.includes(`context: ${context}`));
    assert.ok(workflow.includes(`argument: --check-deny-stored=${context}`));
  }
  assert.doesNotMatch(workflow, /argument: --replay|argument: --variant=/u);
  assert.ok(workflow.includes('protocol-deny-shape-check-${{ matrix.context }}-${{ github.sha }}'));
  assert.ok(workflow.includes('security/tamarin/candidates/HonestDenyShapedProof.spthy'));
  assert.doesNotMatch(workflow, /argument: --check-stored=/u);
  assert.ok(workflow.includes('if: ${{ always() }}'));
  assert.doesNotMatch(workflow, /continue-on-error|protocol-security\.mjs\s*$/mu);
});

test('stored check CLI is closed, separate from unchanged legacy replay, and strictly file-only', () => {
  assert.ok(Object.isFrozen(STORED_CHECK_CONTEXTS));
  assert.deepEqual(STORED_CHECK_CONTEXTS, ['good', 'sorry', 'contradiction']);
  for (const context of STORED_CHECK_CONTEXTS) {
    assert.deepEqual(selectWitnessArguments([`--check-stored=${context}`]), { variant: 'approve', replay: true, checkStored: context });
  }
  for (const args of [['--check-stored'], ['--check-stored='], ['--check-stored=SOLVED'], ['--check-stored=unknown'],
    ['--check-stored=constructor'], ['--check-stored=__proto__'], ['--check-stored=good\n'],
    ['--check-stored=good', '--replay'], ['--check-stored=sorry', '--variant=deny'],
    ['--check-stored=good', '--prove'], ['--check-stored=good', '--check-stored=contradiction']]) assert.throws(() => selectWitnessArguments(args));
  const input = '/isolated/request.input.spthy';
  assert.deepEqual(storedCheckArguments(input), [input, '--quit-on-warning', '+RTS', '-N2', '-M2G', '-RTS']);
  for (const argument of storedCheckArguments(input)) assert.doesNotMatch(argument, /^--(?:prove|lemma|parse-only|precompute-only|auto-sources|bound|output-module)/u);
  for (const input of ['relative/request.input.spthy', '/isolated/../request.input.spthy', '/isolated/other.spthy']) assert.throws(() => storedCheckArguments(input));
  assert.deepEqual(selectWitnessArguments(['--replay']), { variant: 'approve', replay: true });
});

test('stored checks alter only the entire target proof body and erase exactly to the unchanged shaped theory', () => {
  const stored = readFileSync(new URL('../security/tamarin/candidates/HonestApproveShapedProof.spthy', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const base = shapeWitness(source).candidate.trimEnd() + '\n';
  const marker = '\nlemma honest_deny_without_approval_auth_trace:', beginning = base.indexOf(marker);
  for (const context of STORED_CHECK_CONTEXTS) {
    const prepared = storedCheckInput(source, stored, context), ending = prepared.candidate.indexOf(marker);
    assert.equal(prepared.shaped, base);
    assert.equal(prepared.candidate.slice(0, beginning) + prepared.candidate.slice(ending), base);
    assert.equal(prepared.candidate.slice(0, beginning), base.slice(0, beginning));
    assert.equal(prepared.candidate.slice(ending), base.slice(beginning));
    assert.ok(prepared.candidate.includes(SHAPED));
    assert.equal(prepared.candidate.split('lemma ').length, base.split('lemma ').length);
    assert.doesNotMatch(prepared.candidate, /\[reuse\]|\[sources\]/u);
    if (context === 'good') assert.equal(prepared.candidate, admitStoredProof(base, stored));
    else assert.equal(prepared.candidate.slice(beginning, ending), `\nby ${context}\n`);
  }
  for (const context of [null, 'approve', 'replay', 'unknown', '__proto__']) assert.throws(() => storedCheckInput(source, stored, context));
  for (const altered of [stored.replace('builtins: signing', 'builtins: signing, hashing'),
    stored.replace(SHAPED, ORIGINAL), stored.replace('==> #i = #j', '==> #i < #j'),
    stored.replace('simplify\n', 'simplify\nlemma attacker [reuse]: "T"\n'),
    stored + '\nlemma injected: "T"\n', 'x'.repeat(1024 * 1024 + 1)]) {
    assert.throws(() => storedCheckInput(source, altered, 'sorry'));
  }
  assert.throws(() => storedCheckInput(source.replace('builtins: signing', 'builtins: signing, hashing'), stored, 'good'));
});

test('stored proof checks distinguish verified replay from exact incomplete negative controls', () => {
  const input = '/isolated/request.input.spthy', known = ['honest_approve_trace', 'honest_deny_without_approval_auth_trace'];
  const result = (verdict = 'verified (500 steps)') => ({ status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false,
    stderr: '', stdout: `summary of summaries:\n analyzed: ${input}\n honest_approve_trace (exists-trace): ${verdict}\n honest_deny_without_approval_auth_trace (exists-trace): analysis incomplete (1 steps)\n` });
  assert.equal(storedCheckSummary(result(), 'good', known, input).ok, true);
  assert.equal(storedCheckSummary(result('analysis incomplete (2 steps)'), 'good', known, input).ok, false);
  for (const context of ['sorry', 'contradiction']) {
    assert.equal(storedCheckSummary(result('analysis incomplete (2 steps)'), context, known, input).ok, true);
    for (const verdict of ['verified (500 steps)', 'analysis undetermined (2 steps)', 'unknown (2 steps)',
      'analysis incomplete', 'analysis incomplete (many steps)', 'analysis incomplete (2 steps) extra', 'falsified - found trace (2 steps)']) {
      assert.equal(storedCheckSummary(result(verdict), context, known, input).ok, false);
    }
  }
  for (const context of STORED_CHECK_CONTEXTS) {
    const complete = result(context === 'good' ? 'verified (500 steps)' : 'analysis incomplete (2 steps)');
    for (const changed of [{ status: 1 }, { status: null }, { signal: 'SIGTERM' }, { error: new Error('timeout') },
      { cancelled: true }, { cleanupIncomplete: true }, { stderr: 'WARNING model check failed' }, { stderr: 'Warning: detail' },
      { classification: 'WITNESS_SHAPE_EXPERIMENT_ONLY' },
      { stdout: complete.stdout.replace(input, '/old/request.input.spthy') },
      { stdout: complete.stdout + complete.stdout }, { stdout: complete.stdout + '\n analyzed: /other/model.spthy\n' },
      { stdout: complete.stdout.replace('(exists-trace)', '(all-traces)') },
      { stdout: complete.stdout.replace('honest_approve_trace', 'other_lemma') },
      { stdout: complete.stdout + '\n unknown_helper (all-traces): verified (1 steps)\n' }]) {
      assert.equal(storedCheckSummary({ ...complete, ...changed }, context, known, input).ok, false);
    }
  }
  assert.throws(() => storedCheckSummary(result(), 'replay', known, input));
});

test('deny check flags are distinct, fixed and never alias the newer automatic deny variant', () => {
  for (const context of STORED_CHECK_CONTEXTS) {
    assert.deepEqual(selectWitnessArguments([`--check-deny-stored=${context}`]), { variant: 'deny-be8a31b', replay: false, checkDenyStored: context });
    assert.deepEqual(selectWitnessArguments([`--check-stored=${context}`]), { variant: 'approve', replay: true, checkStored: context });
  }
  assert.deepEqual(selectWitnessArguments(['--variant=deny']), { variant: 'deny', replay: false });
  assert.deepEqual(selectWitnessArguments(['--replay']), { variant: 'approve', replay: true });
  for (const args of [['--check-deny-stored'], ['--check-deny-stored='], ['--check-deny-stored=unknown'],
    ['--check-deny-stored=constructor'], ['--check-deny-stored=good\n'], ['--check-deny-stored=SOLVED'],
    ['--check-deny-stored=good', '--check-stored=good'], ['--check-deny-stored=good', '--variant=deny'],
    ['--check-deny-stored=sorry', '--prove'], ['--check-deny-stored=good', '--replay']]) assert.throws(() => selectWitnessArguments(args));
});

test('deny candidate erases to exact be8 shape then original7af without importing later uniqueness or changing other lemmas', () => {
  const stored = readFileSync(new URL('../security/tamarin/candidates/HonestDenyShapedProof.spthy', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const original = shapeWitness(source).normalized, base = original.replace(DENY_ORIGINAL, DENY_STORED_SHAPED);
  const marker = '\nlemma honest_two_approvers_single_winner_trace:', beginning = base.indexOf(marker);
  assert.equal(DENY_STORED_SOURCE_HASH, '8cace48c3e4480400a984495dacb00601e31ea91462e2df247f220362d8a3012');
  assert.doesNotMatch(DENY_STORED_SHAPED, /All #x\. DenialSigned/u);
  assert.notEqual(DENY_STORED_SHAPED, DENY_SHAPED);
  for (const context of STORED_CHECK_CONTEXTS) {
    const prepared = storedDenyCheckInput(source, stored, context), ending = prepared.candidate.indexOf(marker);
    assert.equal(prepared.shaped, base);
    assert.equal(prepared.shaped.replace(DENY_STORED_SHAPED, DENY_ORIGINAL), original);
    assert.equal(prepared.candidate.slice(0, beginning) + prepared.candidate.slice(ending), base);
    assert.equal(prepared.candidate.slice(0, beginning), base.slice(0, beginning));
    assert.equal(prepared.candidate.slice(ending), base.slice(beginning));
    assert.ok(prepared.candidate.includes(ORIGINAL));
    if (context === 'good') {
      assert.equal(prepared.candidate, stored.trimEnd() + '\n');
      const body = prepared.candidate.slice(beginning, ending);
      assert.equal((body.match(/\bSOLVED\b/gu) ?? []).length, 1);
      assert.equal((body.match(/^\s*solve\(/gm) ?? []).length, (body.match(/^\s*qed\s*$/gm) ?? []).length);
      assert.doesNotMatch(body, /by contradiction|by solve\(/u);
      assert.ok(body.includes('case SignDenialWithoutApprovalAuthentication\n                                                  SOLVED'));
      for (const label of ['c_sign', 'SignExactApprovalOnce', 'PublishRequest_case_1', 'PublishRequest_case_2',
        'TrustedReenrollmentWithSameKeys', 'TrustedReplacementWithSameKeys']) {
        assert.match(body, new RegExp(`case ${label}\\n\\s+by sorry`, 'u'));
      }
    } else assert.equal(prepared.candidate.slice(beginning, ending), `\nby ${context}\n`);
  }
  for (const altered of [stored.replace(DENY_STORED_SHAPED, DENY_SHAPED), stored.replace(DENY_STORED_SHAPED, DENY_ORIGINAL),
    stored.replace('==> #i = #j', '==> #i < #j'), stored.replace('builtins: signing', 'builtins: signing, hashing'),
    stored.replace('simplify\n', 'simplify\nlemma injected [reuse]: "T"\n'), stored.replace('SOLVED', 'SOLVED\nSOLVED'),
    stored + '\nlemma extra: "T"\n']) assert.throws(() => storedDenyCheckInput(source, altered, 'good'));
  const approveStored = readFileSync(new URL('../security/tamarin/candidates/HonestApproveShapedProof.spthy', import.meta.url), 'utf8');
  assert.throws(() => storedDenyCheckInput(source, approveStored, 'good'));
  assert.throws(() => storedCheckInput(source, stored, 'good'));
});

test('deny selected summaries cannot borrow approve success or accept unknown negative rows', () => {
  const input = '/isolated/request.input.spthy', known = ['honest_approve_trace', 'honest_deny_without_approval_auth_trace'];
  const result = (verdict) => ({ status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${input}\n honest_approve_trace (exists-trace): verified (43 steps)\n honest_deny_without_approval_auth_trace (exists-trace): ${verdict}\n` });
  assert.equal(storedDenyCheckSummary(result('verified (42 steps)'), 'good', known, input).ok, true);
  assert.equal(storedDenyCheckSummary(result('analysis incomplete (1 steps)'), 'good', known, input).ok, false);
  assert.equal(storedCheckSummary(result('analysis incomplete (1 steps)'), 'good', known, input).ok, true, 'approve selection is unchanged');
  for (const context of ['sorry', 'contradiction']) {
    assert.equal(storedDenyCheckSummary(result('analysis incomplete (2 steps)'), context, known, input).ok, true);
    for (const verdict of ['verified (42 steps)', 'unknown (2 steps)', 'analysis undetermined (2 steps)', 'analysis incomplete', 'analysis incomplete (2 steps) extra']) {
      assert.equal(storedDenyCheckSummary(result(verdict), context, known, input).ok, false);
    }
    const complete = result('analysis incomplete (2 steps)');
    for (const changed of [{ status: 1 }, { error: new Error('timeout') }, { signal: 'SIGTERM' }, { cancelled: true },
      { cleanupIncomplete: true }, { stderr: 'Warning: unsupported output' }, { classification: 'WITNESS_SHAPE_EXPERIMENT_ONLY' },
      { stdout: complete.stdout + complete.stdout }, { stdout: complete.stdout.replace(input, '/other/request.input.spthy') },
      { stdout: complete.stdout.replace('honest_deny_without_approval_auth_trace (exists-trace)', 'honest_deny_without_approval_auth_trace (all-traces)') }]) {
      assert.equal(storedDenyCheckSummary({ ...complete, ...changed }, context, known, input).ok, false);
    }
  }
});
