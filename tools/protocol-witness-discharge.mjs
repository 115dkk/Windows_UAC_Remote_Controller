// SPDX-License-Identifier: GPL-2.0-or-later
// Closed existential-conjunction discharge. Proof text remains untrusted input
// to a fresh Tamarin check; this module never manufactures an original verdict.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { dirname, isAbsolute, parse, relative, resolve, sep } from 'node:path';

export const WITNESS_CONTEXTS = Object.freeze(['good', 'sorry', 'contradiction']);
export const WITNESS_SOURCE_LIMIT = 1024 * 1024;
export const WITNESS_OUTPUT_LIMIT = 4 * 1024 * 1024;
const digest = bytes => createHash('sha256').update(bytes).digest('hex');
const originalApprove = `lemma honest_approve_trace:
  exists-trace
  "Ex pc device revision binding #o #u #a.
    RequestOpened(pc, binding) @o
    & UserAuthenticated(device, binding) @u
    & RequestAccepted(pc, device, revision, binding, 'approve') @a
    & o < u & u < a"`;
const originalDeny = `lemma honest_deny_without_approval_auth_trace:
  exists-trace
  "Ex pc device revision binding #o #a.
    RequestOpened(pc, binding) @o
    & RequestAccepted(pc, device, revision, binding, 'deny') @a
    & o < a
    & not (Ex #u. UserAuthenticated(device, binding) @u)"`;
const strongerApprove = `lemma checked_approval_witness:
  exists-trace
  "Ex pc device revision binding approval_key denial_key #e #c #o #u #s #a.
    RequestOpened(pc, binding) @o
    & UserAuthenticated(device, binding) @u
    & RequestAccepted(pc, device, revision, binding, 'approve') @a
    & o < u & u < a
    & Enrolled(pc, device, revision, approval_key, denial_key) @e
    & SnapshotCaptured(pc, device, revision, binding) @c
    & ApprovalSigned(device, binding) @s
    & e < c & c < o & u < s & s < a
    & (All d r b #x. SnapshotCaptured(pc, d, r, b) @x ==> #x = #c)
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)"`;
const strongerDeny = `lemma checked_denial_witness:
  exists-trace
  "Ex pc device revision binding approval_key denial_key #e #c #o #s #a.
    RequestOpened(pc, binding) @o
    & RequestAccepted(pc, device, revision, binding, 'deny') @a
    & o < a
    & not (Ex #u. UserAuthenticated(device, binding) @u)
    & Enrolled(pc, device, revision, approval_key, denial_key) @e
    & SnapshotCaptured(pc, device, revision, binding) @c
    & DenialSigned(device, binding) @s
    & e < c & c < o & o < s & s < a
    & (All d r b #x. SnapshotCaptured(pc, d, r, b) @x ==> #x = #c)
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)"`;

const originalTwoApprovers = `lemma honest_two_approvers_single_winner_trace:
  exists-trace
  "Ex pc first_device second_device first_revision second_revision binding
      #c1 #c2 #o #s1 #s2 #a.
    SnapshotCaptured(pc, first_device, first_revision, binding) @c1
    & SnapshotCaptured(pc, second_device, second_revision, binding) @c2
    & RequestOpened(pc, binding) @o
    & ApprovalSigned(first_device, binding) @s1
    & ApprovalSigned(second_device, binding) @s2
    & RequestAccepted(pc, first_device, first_revision, binding, 'approve') @a
    & not (first_device = second_device)
    & c1 < o & c2 < o & o < s1 & o < s2 & s1 < a & s2 < a
    & not (Ex purpose #other.
      RequestAccepted(pc, second_device, second_revision, binding, purpose) @other)"`;
const strongerTwoApprovers = `lemma two_approvers_ordered_observed_witness:
  exists-trace
  "Ex pc first_device second_device first_revision second_revision binding request_id
      first_approval_key first_denial_key second_approval_key second_denial_key
      #e1 #e2 #b #c1 #c2 #o #u1 #u2 #s1 #s2 #a.
    SnapshotCaptured(pc, first_device, first_revision, binding) @c1
    & SnapshotCaptured(pc, second_device, second_revision, binding) @c2
    & RequestOpened(pc, binding) @o
    & ApprovalSigned(first_device, binding) @s1
    & ApprovalSigned(second_device, binding) @s2
    & RequestAccepted(pc, first_device, first_revision, binding, 'approve') @a
    & not (first_device = second_device)
    & c1 < o & c2 < o & o < s1 & o < s2 & s1 < a & s2 < a
    & not (Ex purpose #other.
      RequestAccepted(pc, second_device, second_revision, binding, purpose) @other)
    & Enrolled(pc, first_device, first_revision, first_approval_key, first_denial_key) @e1
    & Enrolled(pc, second_device, second_revision, second_approval_key, second_denial_key) @e2
    & BuildingProduced(request_id, pc, binding) @b
    & UserAuthenticated(first_device, binding) @u1
    & UserAuthenticated(second_device, binding) @u2
    & e1 < e2 & e2 < b & b < c1 & c1 < c2 & c2 < o
    & o < u1 & u1 < s1 & s1 < u2 & u2 < s2 & s2 < a
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==>
      ((d = first_device & r = first_revision & ak = first_approval_key & dk = first_denial_key & #x = #e1)
       | (d = second_device & r = second_revision & ak = second_approval_key & dk = second_denial_key & #x = #e2)))
    & (All d r other_binding #x. SnapshotCaptured(pc, d, r, other_binding) @x ==>
      ((d = first_device & r = first_revision & other_binding = binding & #x = #c1)
       | (d = second_device & r = second_revision & other_binding = binding & #x = #c2)))
    & (All rid other_binding #x. BuildingProduced(rid, pc, other_binding) @x ==>
      (rid = request_id & other_binding = binding & (#x = #b | #x = #c1 | #x = #c2)))
    & (All d r #x. ActiveRegistryProduced(pc, d, r) @x ==>
      ((d = first_device & r = first_revision & (#x = #e1 | #x = #c1 | #x = #a))
       | (d = second_device & r = second_revision & (#x = #e2 | #x = #c2))))
    & (All other_binding #x. RequestOpened(pc, other_binding) @x ==> (other_binding = binding & #x = #o))
    & (All d r other_binding purpose #x. RequestAccepted(pc, d, r, other_binding, purpose) @x ==>
      (d = first_device & r = first_revision & other_binding = binding & purpose = 'approve' & #x = #a))
    & (All #x. UserAuthenticated(first_device, binding) @x ==> #x = #u1)
    & (All #x. UserAuthenticated(second_device, binding) @x ==> #x = #u2)
    & (All #x. ApprovalSigned(first_device, binding) @x ==> #x = #s1)
    & (All #x. ApprovalSigned(second_device, binding) @x ==> #x = #s2)"`;
const PROFILES = Object.freeze({
  honest_approve_trace: Object.freeze({ profile: 'approval-conjunction-v1', proof: 'security/tamarin/witnesses/Approve.proof',
    checkedLemma: 'checked_approval_witness', original: originalApprove, stronger: strongerApprove }),
  honest_deny_without_approval_auth_trace: Object.freeze({ profile: 'denial-be8-conjunction-v1', proof: 'security/tamarin/witnesses/Deny.proof',
    checkedLemma: 'checked_denial_witness', original: originalDeny, stronger: strongerDeny }),
  honest_two_approvers_single_winner_trace: Object.freeze({ profile: 'two-approver-observed-conjunction-v1', proof: 'security/tamarin/witnesses/TwoApprovers.proof',
    checkedLemma: 'two_approvers_ordered_observed_witness', original: originalTwoApprovers, stronger: strongerTwoApprovers }),
});
const dictionary = value => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));

export function witnessDischarges(model) {
  if (model.witnessDischarges === undefined) return {};
  assert.equal(model.id, 'request-authorization');
  assert.ok(dictionary(model.witnessDischarges));
  const entries = Object.entries(model.witnessDischarges);
  assert.ok(entries.length > 0 && entries.length <= 3 && Reflect.ownKeys(model.witnessDischarges).length === entries.length);
  return Object.fromEntries(entries.map(([name, value]) => {
    assert.ok(Object.hasOwn(PROFILES, name));
    const profile = PROFILES[name];
    assert.deepEqual(value, { profile: profile.profile, proof: profile.proof });
    assert.deepEqual(model.expected[name], { trace: 'exists-trace', verdict: 'verified' });
    return [name, profile];
  }));
}

export function witnessProfile(obligation) {
  assert.ok(typeof obligation === 'string' && Object.hasOwn(PROFILES, obligation));
  return PROFILES[obligation];
}

export function witnessArguments(input) {
  return [input, '--quit-on-warning', '+RTS', '-N2', '-M2G', '-RTS'];
}

export function witnessBindingPaths(model, profile, bindings) {
  return [...new Set([model.path, profile.proof, 'security/tamarin/manifest.json',
    'tools/protocol-security.mjs', 'tools/protocol-witness-discharge.mjs', 'tools/prover-process.mjs',
    ...bindings.map(binding => binding.path)])];
}

const withoutComments = text => text.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g, '');

export function deriveWitness(source, proof, obligation, context = 'good') {
  assert.ok(typeof source === 'string' && Buffer.byteLength(source) <= WITNESS_SOURCE_LIMIT);
  assert.ok(typeof proof === 'string' && Buffer.byteLength(proof) > 0 && Buffer.byteLength(proof) <= WITNESS_SOURCE_LIMIT);
  assert.ok(WITNESS_CONTEXTS.includes(context));
  const profile = witnessProfile(obligation), normalized = source.replace(/\r\n/g, '\n');
  const sourceCode = withoutComments(normalized);
  const declarations = [...sourceCode.matchAll(/^lemma\s+([A-Za-z][A-Za-z0-9_]*)(?:\s*\[[^\]\r\n]*\])?\s*:/gm)];
  const selected = declarations.filter(match => match[1] === obligation);
  assert.equal(selected.length, 1, 'Exactly one original existential declaration required.');
  const index = declarations.indexOf(selected[0]);
  const originalBlock = sourceCode.slice(selected[0].index, declarations[index + 1]?.index ?? sourceCode.lastIndexOf('\nend')).trim();
  assert.equal(originalBlock, profile.original, 'Original existential formula/binders changed.');
  const first = /^lemma\s+[A-Za-z][A-Za-z0-9_]*(?:\s*\[[^\]\r\n]*\])?\s*:/m.exec(source);
  assert.ok(first && /\nend\s*$/.test(source));
  const transitionSource = source.slice(0, first.index);
  // The entire non-lemma theory prefix is copied byte-for-byte, including all
  // current action observations. All lemma declarations are omitted: no reuse
  // or source assumptions can enter this independent witness system.
  const transitionCode = withoutComments(transitionSource);
  assert.doesNotMatch(transitionCode, /\b(?:lemma|axiom|tactic|configuration|oracle)\b|#\s*(?:include|define|ifdef|endif)\b/u);
  assert.match(transitionCode, /^theory RequestAuthorization\s*\n/m);
  const body = proof.replace(/\r\n/g, '\n').trim() + '\n', code = withoutComments(body).trim();
  assert.ok(code.startsWith('simplify\n') && code.endsWith('qed'));
  assert.equal((code.match(/\bSOLVED\b/gu) ?? []).length, 1);
  assert.doesNotMatch(code, /\b(?:lemma|rule|restriction|axiom|builtins|functions|equations|heuristic|tactic|configuration|theory|oracle|reuse|sources|typing)\b|#\s*(?:include|define|ifdef|endif)\b/u);
  const selectedBody = context === 'good' ? body : `by ${context}\n`;
  const declaration = `${profile.stronger}\n${selectedBody}\nend\n`;
  const input = transitionSource + declaration;
  assert.equal(input.slice(0, transitionSource.length), transitionSource);
  return { input, transitionSource, checkedLemma: profile.checkedLemma,
    structural: { method: 'existential-conjunction-elimination', obligation, profile: profile.profile,
      checkedLemma: profile.checkedLemma, originalFormulaSha256: digest(profile.original), strongerFormulaSha256: digest(profile.stronger),
      transitionSha256: digest(transitionSource), sourceSha256: digest(source), proofSha256: digest(proof),
      currentTransitionBytesUnchanged: true, assumedHelpers: [], originalDirectlyVerified: false } };
}

export function requireDerivedWitness(source, proof, obligation, context, input) {
  const derived = deriveWitness(source, proof, obligation, context);
  assert.equal(input, derived.input, 'Derived witness changed outside its exact approved construction.');
  return derived;
}

export function witnessExpected(obligation, context) {
  assert.ok(WITNESS_CONTEXTS.includes(context));
  return { [witnessProfile(obligation).checkedLemma]: { trace: 'exists-trace', verdict: context === 'good' ? 'verified' : 'inconclusive' } };
}

export function exactWitnessResult(parsed, result, obligation, context) {
  assert.ok(WITNESS_CONTEXTS.includes(context));
  const name = witnessProfile(obligation).checkedLemma;
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  const summary = output.slice(Math.max(0, output.lastIndexOf('summary of summaries:')));
  const rows = [...summary.matchAll(new RegExp(`^\\s*${name}\\s+\\(exists-trace\\):\\s*([^\\r\\n]+)$`, 'gm'))];
  const exact = context === 'good' ? /^verified \(\d+ steps\)\s*$/ : /^analysis incomplete \(\d+ steps\)\s*$/;
  const reasons = [...parsed.reasons];
  if (rows.length !== 1 || !exact.test(rows[0][1])) reasons.push('witness proof-integrity result lacks its exact required verdict');
  if (Buffer.byteLength(output) > WITNESS_OUTPUT_LIMIT + 1 || /\bwarn(?:ing|ings)?\b/i.test(output)) reasons.push('bounded warning-free witness output required');
  return { ...parsed, ok: reasons.length === 0, reasons,
    expectedRow: context === 'good' ? 'verified' : 'analysis incomplete', observedRow: rows.length === 1 ? rows[0][1].trim() : null };
}

export function witnessCoverage(structural, checks) {
  const profile = witnessProfile(structural.obligation);
  assert.equal(structural.method, 'existential-conjunction-elimination');
  assert.equal(structural.profile, profile.profile); assert.equal(structural.checkedLemma, profile.checkedLemma);
  assert.equal(structural.originalFormulaSha256, digest(profile.original));
  assert.equal(structural.strongerFormulaSha256, digest(profile.stronger));
  for (const field of ['transitionSha256', 'sourceSha256', 'proofSha256']) assert.match(structural[field], /^[0-9a-f]{64}$/);
  assert.equal(structural.currentTransitionBytesUnchanged, true);
  assert.equal(structural.originalDirectlyVerified, false); assert.deepEqual(structural.assumedHelpers, []);
  assert.deepEqual(checks.map(check => check.context), WITNESS_CONTEXTS);
  assert.ok(checks.every(check => typeof check.ok === 'boolean'));
  return { ...structural, discharged: checks.every(check => check.ok === true),
    evidenceKind: 'checked-stronger-existential', proofIntegrityControlsRequired: ['sorry', 'contradiction'] };
}

// Read bounded owned regular inputs/snapshots; the binary is digest-only.
export function readWitnessFile(path, maximum = WITNESS_SOURCE_LIMIT, capture = true) {
  assert.ok(isAbsolute(path));
  let cursor = parse(path).root;
  for (const part of relative(cursor, dirname(path)).split(sep).filter(Boolean)) {
    cursor = resolve(cursor, part); const item = lstatSync(cursor);
    assert.ok(item.isDirectory() && !item.isSymbolicLink());
  }
  const before = lstatSync(path);
  assert.ok(before.isFile() && !before.isSymbolicLink() && before.size > 0 && before.size <= maximum);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd), hash = createHash('sha256'), chunks = [], buffer = Buffer.alloc(Math.min(maximum + 1, 65536));
    assert.ok(opened.isFile() && opened.dev === before.dev && opened.ino === before.ino && opened.size === before.size);
    let size = 0;
    for (;;) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, maximum + 1 - size), null);
      if (!count) break;
      size += count; assert.ok(size <= maximum); hash.update(buffer.subarray(0, count));
      if (capture) chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    const after = fstatSync(fd), leaf = lstatSync(path);
    assert.ok(size === opened.size && after.size === size && after.mtimeMs === opened.mtimeMs && after.ctimeMs === opened.ctimeMs &&
      leaf.isFile() && !leaf.isSymbolicLink() && leaf.dev === opened.dev && leaf.ino === opened.ino);
    return { size, sha256: hash.digest('hex'), ...(capture ? { bytes: Buffer.concat(chunks, size) } : {}) };
  } finally { closeSync(fd); }
}
