// SPDX-License-Identifier: GPL-2.0-or-later
// Closed attack-existence implications. Both current-source contexts are freshly
// auto-proved; neither helpers nor retained proof text enter these inputs.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';

export const COUNTEREXAMPLE_CONTEXTS = Object.freeze(['mutant', 'baseline']);
export const COUNTEREXAMPLE_OUTPUT_LIMIT = 4 * 1024 * 1024;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const originalAuth = `lemma accepted_approval_requires_same_binding_auth:
  "All pc device revision binding #a.
    RequestAccepted(pc, device, revision, binding, 'approve') @a
    ==> (Ex #u. UserAuthenticated(device, binding) @u & u < a)"`;
const originalReplay = `lemma request_accepted_at_most_once:
  "All pc first_device second_device first_revision second_revision binding
      first_purpose second_purpose #i #j.
    RequestAccepted(pc, first_device, first_revision, binding, first_purpose) @i
    & RequestAccepted(pc, second_device, second_revision, binding, second_purpose) @j
    ==> #i = #j"`;
const attackAuth = `lemma attack_approval_without_auth:
  exists-trace
  "Ex pc device revision binding approval_key denial_key request_id #e #b #c #o #a.
    RequestAccepted(pc, device, revision, binding, 'approve') @a
    & not (Ex #u. UserAuthenticated(device, binding) @u & u < a)
    & Enrolled(pc, device, revision, approval_key, denial_key) @e
    & BuildingProduced(request_id, pc, binding) @b
    & SnapshotCaptured(pc, device, revision, binding) @c
    & RequestOpened(pc, binding) @o
    & e < b & b < c & c < o & o < a
    & not (Ex #u. UserAuthenticated(device, binding) @u)
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)
    & (All d r v #x. SnapshotCaptured(pc, d, r, v) @x ==> #x = #c)
    & (All r p v #x. BuildingProduced(r, p, v) @x ==> (#x = #b | #x = #c))
    & (All d r #x. ActiveRegistryProduced(pc, d, r) @x ==> (#x = #e | #x = #c | #x = #a))"`;
const attackReplay = `lemma attack_replay_single_approval:
  exists-trace
  "Ex pc device revision binding approval_key denial_key request_id #e #b #c #o #u #s #a1 #a2.
    RequestAccepted(pc, device, revision, binding, 'approve') @a1
    & RequestAccepted(pc, device, revision, binding, 'approve') @a2
    & a1 < a2
    & Enrolled(pc, device, revision, approval_key, denial_key) @e
    & BuildingProduced(request_id, pc, binding) @b
    & SnapshotCaptured(pc, device, revision, binding) @c
    & RequestOpened(pc, binding) @o
    & UserAuthenticated(device, binding) @u
    & ApprovalSigned(device, binding) @s
    & e < b & b < c & c < o & o < u & u < s & s < a1
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)
    & (All d r v #x. SnapshotCaptured(pc, d, r, v) @x ==> #x = #c)
    & (All r p v #x. BuildingProduced(r, p, v) @x ==> (#x = #b | #x = #c))
    & (All d r #x. ActiveRegistryProduced(pc, d, r) @x ==> (#x = #e | #x = #c | #x = #a1 | #x = #a2))
    & (All #x. UserAuthenticated(device, binding) @x ==> #x = #u)
    & (All #x. ApprovalSigned(device, binding) @x ==> #x = #s)"`;
const PROFILES = Object.freeze({
  'missing-approval-signature': Object.freeze({ profile: 'signature-attack-existence-v1',
    obligation: 'accepted_approval_requires_same_binding_auth', checkedLemma: 'attack_approval_without_auth', strategy: 'BFS',
    original: originalAuth, attack: attackAuth,
    mutation: Object.freeze({ from: 'Eq(verify(signature, approval_message, approval_key), true), // CANARY_APPROVAL_SIGNATURE',
      to: "Eq('unchecked-signature', 'unchecked-signature'), // CANARY_APPROVAL_SIGNATURE_DISABLED" }),
    implication: 'The accepted approval and negated earlier same-binding authentication are the exact negation of the original universal implication.' }),
  'missing-replay-consumption': Object.freeze({ profile: 'replay-attack-existence-v1',
    obligation: 'request_accepted_at_most_once', checkedLemma: 'attack_replay_single_approval', strategy: 'DFS',
    original: originalReplay, attack: attackReplay,
    mutation: Object.freeze({ from: '// CANARY_REPLAY_GUARD', to: ", RequestSlot(request_id, pc, binding, 'pending')" }),
    implication: 'Instantiate both device/revision/purpose tuples with device/revision/approve and i=a1,j=a2; a1<a2 refutes i=j.' }),
});
const withoutComments = text => text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g, '');

export function counterexampleProfile(canaryId) {
  assert.ok(typeof canaryId === 'string' && Object.hasOwn(PROFILES, canaryId));
  return PROFILES[canaryId];
}

export function counterexampleDischarge(model, canary) {
  if (canary.counterexampleDischarge === undefined) return null;
  assert.equal(model.id, 'request-authorization');
  assert.equal(model.path, 'security/tamarin/RequestAuthorization.spthy');
  const profile = counterexampleProfile(canary.id);
  assert.deepEqual(canary.counterexampleDischarge, { profile: profile.profile });
  assert.deepEqual(canary.mutation, profile.mutation);
  assert.deepEqual(canary.expected, { [profile.obligation]: { trace: 'all-traces', verdict: 'falsified' } });
  assert.deepEqual(model.expected[profile.obligation], { trace: 'all-traces', verdict: 'verified' });
  return profile;
}

export function counterexampleArguments(input, canaryId) {
  const profile = counterexampleProfile(canaryId);
  return [input, '--quit-on-warning', `--prove=${profile.checkedLemma}`, `--stop-on-trace=${profile.strategy}`,
    '+RTS', '-N2', '-M2G', '-RTS'];
}

export function counterexampleBindingPaths(model, bindings) {
  return [...new Set([model.path, 'security/tamarin/manifest.json', 'tools/protocol-security.mjs',
    'tools/protocol-counterexample-discharge.mjs', 'tools/protocol-witness-discharge.mjs', 'tools/prover-process.mjs',
    ...bindings.map(binding => binding.path)])];
}

export function deriveCounterexample(source, canaryId, context) {
  assert.ok(typeof source === 'string' && Buffer.byteLength(source) > 0 && Buffer.byteLength(source) <= 1024 * 1024);
  assert.ok(COUNTEREXAMPLE_CONTEXTS.includes(context));
  const profile = counterexampleProfile(canaryId), normalized = source.replace(/\r\n/g, '\n');
  const code = withoutComments(normalized);
  assert.doesNotMatch(code, /^\s*(?:by|axiom)\b|#\s*(?:include|define|ifdef|endif)\b/mu);
  const declarations = [...code.matchAll(/^lemma\s+([A-Za-z][A-Za-z0-9_]*)(?:\s*\[[^\]\r\n]*\])?\s*:/gm)];
  const selected = declarations.filter(match => match[1] === profile.obligation);
  assert.equal(selected.length, 1, 'Exactly one original universal declaration required.');
  const index = declarations.indexOf(selected[0]);
  const block = code.slice(selected[0].index, declarations[index + 1]?.index ?? code.lastIndexOf('\nend')).trim();
  assert.equal(block, profile.original, 'Original universal formula/binders changed.');
  const first = /^lemma\s+[A-Za-z][A-Za-z0-9_]*(?:\s*\[[^\]\r\n]*\])?\s*:/m.exec(source);
  assert.ok(first && /\nend\s*$/.test(source));
  const baseline = source.slice(0, first.index), transitionCode = withoutComments(baseline);
  assert.match(transitionCode, /^theory RequestAuthorization\s*\n/m);
  assert.doesNotMatch(transitionCode, /\b(?:lemma|axiom|tactic|configuration|oracle)\b|#\s*(?:include|define|ifdef|endif)\b/u);
  const { from, to } = profile.mutation, at = baseline.indexOf(from);
  assert.ok(at >= 0 && source.indexOf(from) === at && source.indexOf(from, at + from.length) < 0,
    'Registered mutation must occur exactly once inside the current transition prefix.');
  const mutant = baseline.slice(0, at) + to + baseline.slice(at + from.length);
  // The only rule difference is this exact registered edit; no global trace
  // restrictions, helpers, supplied proofs or source assumptions are introduced.
  const transitionSource = context === 'mutant' ? mutant : baseline;
  const input = `${transitionSource}${profile.attack}\n\nend\n`;
  assert.equal(input.slice(0, transitionSource.length), transitionSource);
  assert.equal((input.match(/^lemma\s/gm) ?? []).length, 1);
  return { input, transitionSource, checkedLemma: profile.checkedLemma,
    structural: { method: 'checked-existential-counterexample', canaryId, profile: profile.profile,
      obligation: profile.obligation, checkedLemma: profile.checkedLemma, implication: profile.implication,
      originalFormulaSha256: digest(profile.original), attackFormulaSha256: digest(profile.attack),
      sourceSha256: digest(source), baselineTransitionSha256: digest(baseline), mutantTransitionSha256: digest(mutant),
      mutation: profile.mutation, currentTransitionBytesPreservedExceptRegisteredMutation: true,
      assumedHelpers: [], suppliedProofs: [], originalUniversalDirectlyChecked: false,
      baselineNoTraceDoesNotProveOriginalUniversal: true } };
}

export function requireDerivedCounterexample(source, canaryId, context, input) {
  const derived = deriveCounterexample(source, canaryId, context);
  assert.equal(input, derived.input, 'Counterexample input differs from its exact current-source construction.');
  return derived;
}

export function counterexampleExpected(canaryId, context) {
  assert.ok(COUNTEREXAMPLE_CONTEXTS.includes(context));
  return { [counterexampleProfile(canaryId).checkedLemma]: { trace: 'exists-trace', verdict: context === 'mutant' ? 'verified' : 'falsified' } };
}

export function exactCounterexampleResult(parsed, result, canaryId, context) {
  assert.ok(COUNTEREXAMPLE_CONTEXTS.includes(context));
  const name = counterexampleProfile(canaryId).checkedLemma;
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  const summary = output.slice(Math.max(0, output.lastIndexOf('summary of summaries:')));
  const rows = [...summary.matchAll(new RegExp(`^\\s*${name}\\s+\\(exists-trace\\):\\s*([^\\r\\n]+)$`, 'gm'))];
  const expectedRow = context === 'mutant' ? 'verified' : 'falsified - no trace found';
  const exact = new RegExp(`^${expectedRow} \\(\\d+ steps\\)\\s*$`), reasons = [...parsed.reasons];
  if (rows.length !== 1 || !exact.test(rows[0][1])) reasons.push('counterexample context lacks its exact required existential verdict');
  if (Buffer.byteLength(output) > COUNTEREXAMPLE_OUTPUT_LIMIT + 1 || /\bwarn(?:ing|ings)?\b/i.test(output)) reasons.push('bounded warning-free counterexample output required');
  return { ...parsed, ok: reasons.length === 0, reasons, expectedRow, observedRow: rows.length === 1 ? rows[0][1].trim() : null };
}

export function counterexampleCoverage(structural, checks) {
  const profile = counterexampleProfile(structural.canaryId);
  assert.equal(structural.method, 'checked-existential-counterexample');
  assert.equal(structural.profile, profile.profile); assert.equal(structural.obligation, profile.obligation);
  assert.equal(structural.checkedLemma, profile.checkedLemma); assert.equal(structural.implication, profile.implication);
  assert.equal(structural.originalFormulaSha256, digest(profile.original)); assert.equal(structural.attackFormulaSha256, digest(profile.attack));
  for (const field of ['sourceSha256', 'baselineTransitionSha256', 'mutantTransitionSha256']) assert.match(structural[field], /^[0-9a-f]{64}$/);
  assert.deepEqual(structural.mutation, profile.mutation);
  assert.equal(structural.currentTransitionBytesPreservedExceptRegisteredMutation, true);
  assert.equal(structural.originalUniversalDirectlyChecked, false);
  assert.equal(structural.baselineNoTraceDoesNotProveOriginalUniversal, true);
  assert.deepEqual(structural.assumedHelpers, []); assert.deepEqual(structural.suppliedProofs, []);
  assert.deepEqual(checks.map(check => check.context), COUNTEREXAMPLE_CONTEXTS);
  assert.ok(checks.every(check => typeof check.ok === 'boolean'));
  const discharged = checks.every(check => check.ok === true && check.status === 0 && !check.signal && !check.processError &&
    check.cancelled === false && check.cleanupIncomplete === false &&
    Array.isArray(check.reasons) && check.reasons.length === 0 &&
    Object.keys(check.verdicts ?? {}).length === 1 &&
    check.verdicts[profile.checkedLemma]?.trace === 'exists-trace' &&
    check.verdicts[profile.checkedLemma]?.verdict === (check.context === 'mutant' ? 'verified' : 'falsified') &&
    check.expectedRow === (check.context === 'mutant' ? 'verified' : 'falsified - no trace found') &&
    (check.context === 'mutant' ? /^verified \(\d+ steps\)$/ : /^falsified - no trace found \(\d+ steps\)$/).test(check.observedRow ?? ''));
  return { ...structural, discharged, evidenceKind: 'checked-attack-existence-implication',
    requiredContexts: [...COUNTEREXAMPLE_CONTEXTS] };
}
