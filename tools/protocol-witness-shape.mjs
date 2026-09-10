// SPDX-License-Identifier: GPL-2.0-or-later
// One selected isolated witness-search experiment. NEVER a normal security gate.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, parse, posix, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { mutateExactlyOnce, parseProofSummary, proofArguments } from './protocol-security.mjs';
import { runProver } from './prover-process.mjs';

const root = dirname(dirname(fileURLToPath(import.meta.url)));
export const ORIGIN_HASH = '7af08df4610de1d2eeac1f441339df76d5949b9c58be994fc272798559002460';
export const ORIGINAL = `lemma honest_approve_trace:
  exists-trace
  "Ex pc device revision binding #o #u #a.
    RequestOpened(pc, binding) @o
    & UserAuthenticated(device, binding) @u
    & RequestAccepted(pc, device, revision, binding, 'approve') @a
    & o < u & u < a"`;
export const SHAPED = `lemma honest_approve_trace:
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
// Only the new named variant gets these conjuncts. The original shape and its
// stored-proof admission remain byte-for-byte unchanged.
export const APPROVE_TIGHT_SHAPED = `${SHAPED.slice(0, -1)}
    & (All #x. UserAuthenticated(device, binding) @x ==> #x = #u)
    & (All #x. ApprovalSigned(device, binding) @x ==> #x = #s)"`;
export const DENY_ORIGINAL = `lemma honest_deny_without_approval_auth_trace:
  exists-trace
  "Ex pc device revision binding #o #a.
    RequestOpened(pc, binding) @o
    & RequestAccepted(pc, device, revision, binding, 'deny') @a
    & o < a
    & not (Ex #u. UserAuthenticated(device, binding) @u)"`;
export const DENY_SHAPED = `lemma honest_deny_without_approval_auth_trace:
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
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)
    & (All #x. DenialSigned(device, binding) @x ==> #x = #s)"`;
// Exact earlier be8a31b input, NOT the later deny variant above. Its actual
// transcript proved this formula without the added DenialSigned uniqueness.
export const DENY_STORED_SHAPED = `lemma honest_deny_without_approval_auth_trace:
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
export const DENY_STORED_SOURCE_HASH = '8cace48c3e4480400a984495dacb00601e31ea91462e2df247f220362d8a3012';
export const TWO_APPROVERS_ORIGINAL = `lemma honest_two_approvers_single_winner_trace:
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
export const TWO_APPROVERS_SHAPED = `lemma honest_two_approvers_single_winner_trace:
  exists-trace
  "Ex pc first_device second_device first_revision second_revision binding
      first_approval_key first_denial_key second_approval_key second_denial_key
      #e1 #e2 #c1 #c2 #o #u1 #u2 #s1 #s2 #a.
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
    & e1 < e2 & e2 < c1 & c1 < c2 & s1 < s2
    & (All d r b #x. SnapshotCaptured(pc, d, r, b) @x ==> (#x = #c1 | #x = #c2))
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> (#x = #e1 | #x = #e2))
    & UserAuthenticated(first_device, binding) @u1
    & UserAuthenticated(second_device, binding) @u2
    & o < u1 & u1 < s1 & s1 < u2 & u2 < s2 & s2 < a
    & (All #x. UserAuthenticated(first_device, binding) @x ==> #x = #u1)
    & (All #x. UserAuthenticated(second_device, binding) @x ==> #x = #u2)
    & (All #x. ApprovalSigned(first_device, binding) @x ==> #x = #s1)
    & (All #x. ApprovalSigned(second_device, binding) @x ==> #x = #s2)"`;
export const WITNESS_VARIANTS = Object.freeze({
  approve: Object.freeze({ lemma: 'honest_approve_trace', original: ORIGINAL, shaped: SHAPED }),
  'approve-tight': Object.freeze({ lemma: 'honest_approve_trace', original: ORIGINAL, shaped: APPROVE_TIGHT_SHAPED }),
  deny: Object.freeze({ lemma: 'honest_deny_without_approval_auth_trace', original: DENY_ORIGINAL, shaped: DENY_SHAPED }),
  'two-approvers': Object.freeze({ lemma: 'honest_two_approvers_single_winner_trace', original: TWO_APPROVERS_ORIGINAL, shaped: TWO_APPROVERS_SHAPED }),
});
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
export const STORED_CHECK_CONTEXTS = Object.freeze(['good', 'sorry', 'contradiction']);
const STORED_CLASSIFICATION = 'STORED_SHAPED_PROOF_CHECK_ONLY';
const STORED_LEMMA = 'honest_approve_trace';
const STORED_NEXT_LEMMA = '\nlemma honest_deny_without_approval_auth_trace:';
const MAX_SOURCE = 1024 * 1024;

function storedContext(context) {
  assert.ok(typeof context === 'string' && STORED_CHECK_CONTEXTS.includes(context), 'Unknown fixed stored-proof check context.');
  return context;
}

function variantDefinition(variant) {
  assert.ok(typeof variant === 'string' && Object.hasOwn(WITNESS_VARIANTS, variant), 'Unknown fixed witness variant.');
  return WITNESS_VARIANTS[variant];
}

export function selectWitnessArguments(args) {
  assert.ok(Array.isArray(args) && args.length <= 1, 'Select at most one fixed witness variant.');
  if (args.length === 0) return { variant: 'approve', replay: false };
  if (args[0] === '--replay') return { variant: 'approve', replay: true };
  if (args[0] === '--variant=approve-tight') return { variant: 'approve-tight', replay: false };
  if (args[0] === '--variant=deny') return { variant: 'deny', replay: false };
  if (args[0] === '--variant=two-approvers') return { variant: 'two-approvers', replay: false };
  for (const context of STORED_CHECK_CONTEXTS) if (args[0] === `--check-stored=${context}`) return { variant: 'approve', replay: true, checkStored: context };
  for (const context of STORED_CHECK_CONTEXTS) if (args[0] === `--check-deny-stored=${context}`) return { variant: 'deny-be8a31b', replay: false, checkDenyStored: context };
  throw new Error('usage: node tools/protocol-witness-shape.mjs [--replay|--variant=approve-tight|--variant=deny|--variant=two-approvers|--check-stored=good|--check-stored=sorry|--check-stored=contradiction|--check-deny-stored=good|--check-deny-stored=sorry|--check-deny-stored=contradiction]');
}

export function selectedExpectation(variant) {
  return { [variantDefinition(variant).lemma]: { trace: 'exists-trace', verdict: 'verified' } };
}

export function selectedWitnessSummary(result, variant, known, input) {
  const selected = variantDefinition(variant).lemma;
  const parsed = parseProofSummary(result, selectedExpectation(variant), known, input);
  return { ok: parsed.ok, reasons: parsed.reasons,
    verdicts: Object.fromEntries(Object.entries(parsed.verdicts).filter(([name]) => name === selected)) };
}

export function shapeWitness(source, variant = 'approve') {
  const definition = variantDefinition(variant);
  assert.equal(typeof source, 'string');
  assert.ok(Buffer.byteLength(source) <= 1024 * 1024);
  const normalized = source.replace(/\r\n/g, '\n');
  assert.equal(hash(normalized), ORIGIN_HASH, 'The reviewed original model changed.');
  const candidate = mutateExactlyOnce(normalized, { from: definition.original, to: definition.shaped });
  assert.equal(mutateExactlyOnce(candidate, { from: definition.shaped, to: definition.original }), normalized);
  return { normalized, candidate };
}

export function admitStoredProof(base, stored) {
  const normalize = (text) => text.replace(/\r\n/g, '\n').trimEnd() + '\n';
  base = normalize(base);
  stored = normalize(stored);
  assert.ok(Buffer.byteLength(stored) <= 1024 * 1024);
  const marker = '\nlemma honest_deny_without_approval_auth_trace:';
  const boundary = base.indexOf(marker);
  const next = stored.indexOf(marker);
  assert.ok(boundary > 0 && next > boundary);
  assert.equal(base.lastIndexOf(marker), boundary);
  assert.equal(stored.lastIndexOf(marker), next);
  assert.equal(stored.slice(0, boundary), base.slice(0, boundary));
  assert.equal(stored.slice(next), base.slice(boundary));
  const proof = stored.slice(boundary, next).trim();
  assert.ok(proof.startsWith('simplify\n') && proof.endsWith('qed'));
  assert.ok(/\bSOLVED\b/u.test(proof), 'The actual prover output must contain a solved witness branch.');
  assert.doesNotMatch(proof, /\b(?:lemma|rule|restriction|axiom|builtins|functions|equations|heuristic|tactic|configuration|theory|oracle)\b|#\s*(?:include|define|ifdef|endif)\b/iu);
  return stored;
}

export function storedCheckInput(source, stored, context) {
  storedContext(context);
  assert.equal(typeof stored, 'string');
  assert.ok(Buffer.byteLength(stored) <= MAX_SOURCE);
  const shaped = shapeWitness(source, 'approve');
  const base = shaped.candidate.trimEnd() + '\n';
  const admitted = admitStoredProof(base, stored);
  const beginning = base.indexOf(STORED_NEXT_LEMMA), ending = admitted.indexOf(STORED_NEXT_LEMMA);
  const originalBody = admitted.slice(beginning, ending);
  const replacement = context === 'good' ? originalBody : `\nby ${context}\n`;
  const candidate = admitted.slice(0, beginning) + replacement + admitted.slice(ending);
  // Exact body removal, not a formula/parser rewrite: every rule, restriction,
  // other lemma and the already-strengthened approve formula stays identical.
  assert.equal(candidate.slice(0, beginning) + candidate.slice(beginning + replacement.length), base);
  assert.doesNotMatch(base, /\[\s*(?:[^\]]*,\s*)?(?:reuse|sources)\b/u);
  return { ...shaped, shaped: base, admitted, candidate,
    originalBodySha256: hash(originalBody), replacementBodySha256: hash(replacement) };
}

export function storedDenyCheckInput(source, stored, context) {
  storedContext(context);
  assert.equal(typeof stored, 'string'); assert.ok(Buffer.byteLength(stored) <= MAX_SOURCE);
  const { normalized } = shapeWitness(source); // Existing exact original-source admission, not a new formula input.
  const base = mutateExactlyOnce(normalized, { from: DENY_ORIGINAL, to: DENY_STORED_SHAPED });
  assert.equal(hash(base), DENY_STORED_SOURCE_HASH, 'The exact be8a31b deny shape changed.');
  assert.equal(mutateExactlyOnce(base, { from: DENY_STORED_SHAPED, to: DENY_ORIGINAL }), normalized);
  const admitted = stored.replace(/\r\n/g, '\n').trimEnd() + '\n';
  const marker = '\nlemma honest_two_approvers_single_winner_trace:';
  const beginning = base.indexOf(marker), ending = admitted.indexOf(marker);
  assert.ok(beginning > 0 && ending > beginning && base.lastIndexOf(marker) === beginning && admitted.lastIndexOf(marker) === ending);
  assert.equal(admitted.slice(0, beginning), base.slice(0, beginning));
  assert.equal(admitted.slice(ending), base.slice(beginning));
  const originalBody = admitted.slice(beginning, ending), proof = originalBody.trim();
  assert.ok(proof.startsWith('simplify\n') && proof.endsWith('qed'));
  assert.equal((proof.match(/\bSOLVED\b/gu) ?? []).length, 1, 'Retain only the first solved deny spine.');
  assert.doesNotMatch(proof, /\b(?:lemma|rule|restriction|axiom|builtins|functions|equations|heuristic|tactic|configuration|theory|oracle)\b|#\s*(?:include|define|ifdef|endif)\b/iu);
  const replacement = context === 'good' ? originalBody : `\nby ${context}\n`;
  const candidate = admitted.slice(0, beginning) + replacement + admitted.slice(ending);
  assert.equal(candidate.slice(0, beginning) + candidate.slice(beginning + replacement.length), base);
  return { normalized, shaped: base, admitted, candidate,
    originalBodySha256: hash(originalBody), replacementBodySha256: hash(replacement) };
}

export function storedCheckArguments(input) {
  assert.ok(typeof input === 'string' && input.length <= 4096 && !/[\u0000-\u001f\u007f]/u.test(input) &&
    posix.isAbsolute(input) && posix.normalize(input) === input && posix.basename(input) === 'request.input.spthy');
  return [input, '--quit-on-warning', '+RTS', '-N2', '-M2G', '-RTS'];
}

export function storedCheckSummary(result, context, known, input) {
  return storedProofSummary(result, context, known, input, STORED_LEMMA);
}

export function storedDenyCheckSummary(result, context, known, input) {
  return storedProofSummary(result, context, known, input, 'honest_deny_without_approval_auth_trace');
}

function storedProofSummary(result, context, known, input, selectedLemma) {
  storedContext(context);
  const expected = { [selectedLemma]: { trace: 'exists-trace', verdict: context === 'good' ? 'verified' : 'inconclusive' } };
  // Reuse exact-input/single-summary/known-name/process ownership checks. For
  // negatives, the parser's broad inconclusive category is NEVER sufficient.
  const parsed = parseProofSummary(result, expected, known, input);
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  const reasons = [...parsed.reasons];
  if (Object.hasOwn(result, 'classification') || Object.hasOwn(result, 'selectedWitness')) reasons.push('stored result metadata is not a current raw prover result');
  if (Buffer.byteLength(output) > 4 * 1024 * 1024 + 1) reasons.push('stored-proof check output exceeds its bound');
  if (/\bwarn(?:ing|ings)?\b|returned unsupported version/i.test(output)) reasons.push('prover warning or unsupported dependency');
  const summary = output.slice(Math.max(0, output.lastIndexOf('summary of summaries:')));
  const rows = [...summary.matchAll(new RegExp(`^\\s*${selectedLemma}\\s+\\(exists-trace\\):\\s*([^\\r\\n]+)$`, 'gm'))];
  const exact = context === 'good' ? /^verified \(\d+ steps\)\s*$/ : /^analysis incomplete \(\d+ steps\)\s*$/;
  if (rows.length !== 1 || !exact.test(rows[0][1])) reasons.push('selected check did not produce its exact required verdict row');
  return { ok: reasons.length === 0, reasons, selectedLemma,
    expected: context === 'good' ? 'verified' : 'analysis incomplete', observedRow: rows.length === 1 ? rows[0][1].trim() : null };
}

function plainParents(path) {
  let cursor = parse(path).root;
  for (const part of relative(cursor, dirname(path)).split(sep).filter(Boolean)) {
    cursor = resolve(cursor, part);
    const metadata = lstatSync(cursor);
    assert.ok(metadata.isDirectory() && !metadata.isSymbolicLink(), 'Linked/non-directory evidence parent.');
  }
}

// Bounded open-handle snapshot. Binary mode retains only its digest/size, not
// the installed 150MiB executable in an uploaded artifact.
function storedFile(path, maximum = MAX_SOURCE, capture = true) {
  plainParents(path);
  const before = lstatSync(path);
  assert.ok(before.isFile() && !before.isSymbolicLink() && before.size > 0 && before.size <= maximum);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd);
    assert.ok(opened.isFile() && opened.dev === before.dev && opened.ino === before.ino && opened.size === before.size);
    const digest = createHash('sha256'), chunks = [], buffer = Buffer.alloc(Math.min(maximum + 1, 64 * 1024));
    let size = 0;
    for (;;) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, maximum + 1 - size), null);
      if (!count) break;
      size += count; assert.ok(size <= maximum);
      digest.update(buffer.subarray(0, count));
      if (capture) chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    const after = fstatSync(fd), leaf = lstatSync(path);
    assert.ok(size === opened.size && after.size === size && after.mtimeMs === opened.mtimeMs && after.ctimeMs === opened.ctimeMs &&
      leaf.isFile() && !leaf.isSymbolicLink() && leaf.dev === opened.dev && leaf.ino === opened.ino);
    return { size, sha256: digest.digest('hex'), ...(capture ? { bytes: Buffer.concat(chunks, size) } : {}) };
  } finally { closeSync(fd); }
}

async function runStoredCheck(context, variant = 'approve') {
  storedContext(context);
  assert.ok(variant === 'approve' || variant === 'deny-be8a31b');
  const deny = variant === 'deny-be8a31b';
  const selectedLemma = deny ? 'honest_deny_without_approval_auth_trace' : STORED_LEMMA;
  const commit = process.env.GITHUB_SHA, binary = process.env.TAMARIN_BIN;
  assert.ok(/^[0-9a-f]{40}$/.test(commit ?? '') && Number(process.versions.node.split('.')[0]) === 24);
  assert.ok(typeof binary === 'string' && isAbsolute(binary) && realpathSync(root) === root);
  for (const child of ['artifacts', 'artifacts/protocol-witness-shape']) {
    const path = resolve(root, child); plainParents(path);
    try { mkdirSync(path, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    assert.ok(lstatSync(path).isDirectory() && !lstatSync(path).isSymbolicLink());
  }
  const directory = mkdtempSync(resolve(root, 'artifacts/protocol-witness-shape', `${STORED_CLASSIFICATION}${deny ? '-deny-be8a31b' : ''}-${context}-`));
  const controller = new AbortController(), stop = () => controller.abort(new Error('Stored-proof check interrupted.'));
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  let report = { classification: STORED_CLASSIFICATION, eligibleAsNormalGate: false, normalGateStatus: 'not-run',
    commit, context, variant, selectedLemma, helpers: [],
    originalWeakerWitnessDirectlyVerified: false, storedProofReplayedAndVerified: false,
    expected: context === 'good' ? 'verified' : 'analysis incomplete',
    bounds: { invocations: 1, timeoutMs: 120000, outputBytes: 4 * 1024 * 1024, maxSourceFiles: 48, sourceBytesEach: MAX_SOURCE, heapGiB: 2, runtimeThreads: 2 },
    attempted: false, completed: false, inputsUnchanged: false, passed: false };
  const save = () => writeFileSync(resolve(directory, 'result.json'), JSON.stringify(report, null, 2));
  save();
  try {
    const snapshots = new Map();
    const capture = (name) => {
      assert.ok(typeof name === 'string' && /^[A-Za-z0-9_./-]+$/.test(name) && !isAbsolute(name) &&
        name.split('/').every((part) => part && part !== '.' && part !== '..'));
      if (snapshots.has(name)) return snapshots.get(name);
      assert.ok(snapshots.size < 48);
      const file = storedFile(resolve(root, name));
      const snapshot = `source-${String(snapshots.size).padStart(2, '0')}.txt`;
      writeFileSync(resolve(directory, snapshot), file.bytes, { flag: 'wx', mode: 0o400 });
      const entry = { path: name, snapshot, ...file }; snapshots.set(name, entry); return entry;
    };
    const original = capture('security/tamarin/RequestAuthorization.spthy');
    const stored = capture(deny ? 'security/tamarin/candidates/HonestDenyShapedProof.spthy' : 'security/tamarin/candidates/HonestApproveShapedProof.spthy');
    const manifest = JSON.parse(capture('security/tamarin/manifest.json').bytes.toString('utf8'));
    assert.equal(manifest.version, 1); assert.equal(manifest.toolVersion, '1.12.0');
    const models = manifest.models.filter((model) => model.id === 'request-authorization');
    assert.equal(models.length, 1); assert.ok(!Object.hasOwn(models[0], 'helpers'));
    assert.deepEqual(models[0].expected[selectedLemma], selectedExpectation(deny ? 'deny' : 'approve')[selectedLemma]);
    const known = Object.keys(models[0].expected);
    assert.deepEqual(known, [...original.bytes.toString('utf8').matchAll(/^lemma ([A-Za-z0-9_]+):/gm)].map((match) => match[1]));
    assert.ok(Array.isArray(manifest.sourceBindings) && manifest.sourceBindings.length > 0 && manifest.sourceBindings.length <= 32);
    const bound = new Set();
    for (const binding of manifest.sourceBindings) {
      assert.ok(/^crates\/[A-Za-z0-9_./-]+\.rs$/.test(binding?.path ?? '') && /^[0-9a-f]{64}$/.test(binding?.sha256 ?? '') && !bound.has(binding.path));
      bound.add(binding.path);
      assert.equal(hash(capture(binding.path).bytes.toString('utf8').replace(/\r\n/g, '\n')), binding.sha256);
    }
    for (const name of ['tools/protocol-witness-shape.mjs', 'tools/protocol-witness-shape.test.mjs', 'tools/protocol-security.mjs',
      'tools/prover-process.mjs', 'tools/install-tamarin.mjs', '.github/workflows/protocol-witness-shape.yml', '.node-version']) capture(name);
    const candidate = (deny ? storedDenyCheckInput : storedCheckInput)(original.bytes.toString('utf8'), stored.bytes.toString('utf8'), context);
    const input = resolve(directory, 'request.input.spthy'), args = storedCheckArguments(input);
    writeFileSync(input, candidate.candidate, { flag: 'wx', mode: 0o400 });
    writeFileSync(resolve(directory, 'shaped-without-proof.spthy'), candidate.shaped, { flag: 'wx', mode: 0o400 });
    const tool = storedFile(binary, 150 * 1024 * 1024, false), inputHash = hash(candidate.candidate);
    const unchanged = () => {
      for (const entry of snapshots.values()) {
        assert.equal(storedFile(resolve(root, entry.path), MAX_SOURCE, false).sha256, entry.sha256);
        assert.equal(storedFile(resolve(directory, entry.snapshot), MAX_SOURCE, false).sha256, entry.sha256);
      }
      assert.equal(storedFile(binary, 150 * 1024 * 1024, false).sha256, tool.sha256);
      assert.equal(storedFile(input).sha256, inputHash);
      assert.equal(storedFile(resolve(directory, 'shaped-without-proof.spthy')).sha256, hash(candidate.shaped));
      assert.equal(process.env.GITHUB_SHA, commit);
      return true;
    };
    report = { ...report, sources: [...snapshots.values()].map(({ path, snapshot, size, sha256 }) => ({ path, snapshot, size, sha256 })),
      binary, binaryMetadata: tool, sourceBindings: manifest.sourceBindings, arguments: args,
      originSha256: hash(candidate.normalized), shapedWithoutProofSha256: hash(candidate.shaped),
      storedProofSha256: stored.sha256, inputSha256: inputHash, originalBodySha256: candidate.originalBodySha256,
      replacementBodySha256: candidate.replacementBodySha256, exactProofBodyErasureMatchesShapedSource: true,
      originalRulesRestrictionsAndOtherLemmasUnchanged: true, originalShapedFormulaUnchanged: true,
      ...(deny ? { retainedShapedSourceSha256: DENY_STORED_SOURCE_HASH, shapedFormulaSha256: hash(DENY_STORED_SHAPED),
        originalFormulaSha256: hash(DENY_ORIGINAL), proofExtraction: { sourceCommit: 'be8a31b', sourceBodyLines: [419, 2424],
          retainedSolvedLine: 515, transform: 'first-SOLVED-ancestor-spine; sibling subtrees become by sorry', previouslyCheckedAsStoredProof: false } } : {}),
      unselectedLemmas: known.filter((name) => name !== selectedLemma).map((name) => ({ name, status: 'not-required-by-this-experiment' })) };
    unchanged(); controller.signal.throwIfAborted();
    writeFileSync(resolve(directory, 'invocation.json'), JSON.stringify(report, null, 2), { flag: 'wx' });
    report.attempted = true; save();
    const result = await runProver(binary, args, { cwd: directory, logPath: resolve(directory, 'prover.log'),
      timeoutMs: 120000, maxOutputBytes: 4 * 1024 * 1024, signal: controller.signal });
    const selectedCheck = (deny ? storedDenyCheckSummary : storedCheckSummary)(result, context, known, input);
    report = { ...report, selectedCheck,
      completed: !result.error && !result.signal && result.status === 0 && !result.cancelled && !result.cleanupIncomplete,
      process: { status: result.status, signal: result.signal, error: result.error?.message ?? null,
        cancelled: result.cancelled, cleanupIncomplete: result.cleanupIncomplete } };
    report.inputsUnchanged = unchanged(); controller.signal.throwIfAborted();
    report.passed = report.completed && report.inputsUnchanged && selectedCheck.ok;
    report.storedProofReplayedAndVerified = context === 'good' && report.passed;
    if (!report.passed) process.exitCode = 1;
  } catch {
    report.passed = false; report.failure = 'Stored shaped-proof check or input validation failed.'; process.exitCode = 1;
  } finally {
    if (controller.signal.aborted) { report.passed = false; report.storedProofReplayedAndVerified = false; process.exitCode = 1; }
    report.cancelled = controller.signal.aborted;
    save(); process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}

async function main() {
  assert.equal(process.platform, 'linux');
  assert.equal(process.env.CI, 'true');
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  const { variant, replay, checkStored, checkDenyStored } = selectWitnessArguments(process.argv.slice(2));
  if (checkStored !== undefined) return runStoredCheck(checkStored);
  if (checkDenyStored !== undefined) return runStoredCheck(checkDenyStored, 'deny-be8a31b');
  const expected = selectedExpectation(variant);
  const binary = process.env.TAMARIN_BIN;
  assert.ok(typeof binary === 'string' && isAbsolute(binary));
  assert.ok(lstatSync(binary).isFile() && !lstatSync(binary).isSymbolicLink());
  const origin = resolve(root, 'security/tamarin/RequestAuthorization.spthy');
  assert.ok(lstatSync(origin).isFile() && !lstatSync(origin).isSymbolicLink());
  const shaped = shapeWitness(readFileSync(origin, 'utf8'), variant);
  const normalized = shaped.normalized;
  const storedPath = resolve(root, 'security/tamarin/candidates/HonestApproveShapedProof.spthy');
  if (replay) assert.ok(lstatSync(storedPath).isFile() && !lstatSync(storedPath).isSymbolicLink());
  const candidate = replay ? admitStoredProof(shaped.candidate, readFileSync(storedPath, 'utf8')) : shaped.candidate;
  const manifest = JSON.parse(readFileSync(resolve(root, 'security/tamarin/manifest.json'), 'utf8'));
  assert.equal(manifest.toolVersion, '1.12.0');
  const model = manifest.models.find((entry) => entry.id === 'request-authorization');
  assert.ok(model);
  const known = Object.keys(model.expected);
  const selectedLemma = variantDefinition(variant).lemma;
  assert.deepEqual(model.expected[selectedLemma], expected[selectedLemma], 'The selected original lemma must remain registered.');
  const base = resolve(root, 'artifacts/protocol-witness-shape');
  mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(resolve(base, `witness-${variant}${replay ? '-replay' : ''}-`));
  const input = resolve(directory, 'request.input.spthy');
  writeFileSync(input, candidate, { flag: 'wx' });
  const args = proofArguments(input, expected);
  const controller = new AbortController();
  const stop = () => controller.abort(new Error('Witness experiment interrupted.'));
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let report = {
    classification: 'WITNESS_SHAPE_EXPERIMENT_ONLY', eligibleAsNormalGate: false,
    variant, selectedLemma, unselectedLemmas: known.filter((name) => name !== selectedLemma).map((name) => ({ name, status: 'not-selected' })),
    storedProofIncludedInInput: replay, storedProofUsageEstablished: false,
    originSha256: hash(normalized), candidateSha256: hash(candidate),
    originalRulesRestrictionsAndOtherLemmasUnchanged: true,
    bounds: { invocations: 1, timeoutMs: 120000, outputBytes: 4 * 1024 * 1024, heapGiB: 2, runtimeThreads: 2 },
    arguments: args, attempted: false, completed: false,
  };
  const save = () => writeFileSync(resolve(directory, 'result.json'), JSON.stringify(report, null, 2));
  save();
  try {
    report.attempted = true;
    save();
    const result = await runProver(binary, args, {
      cwd: directory, logPath: resolve(directory, 'prover.log'),
      timeoutMs: 120000, maxOutputBytes: 4 * 1024 * 1024, signal: controller.signal,
    });
    const verdict = selectedWitnessSummary(result, variant, known, input);
    const unchanged = hash(readFileSync(input)) === hash(candidate)
      && hash(readFileSync(origin, 'utf8').replace(/\r\n/g, '\n')) === ORIGIN_HASH;
    report = { ...report, completed: !result.error && !result.signal && result.status === 0 && !result.cancelled && !result.cleanupIncomplete,
      process: { status: result.status, signal: result.signal, error: result.error?.message ?? null,
        cancelled: result.cancelled, cleanupIncomplete: result.cleanupIncomplete },
      inputsUnchanged: unchanged, selectedWitness: verdict };
    if (!unchanged || !verdict.ok) process.exitCode = 1;
  } finally {
    save();
    process.removeListener('SIGINT', stop);
    process.removeListener('SIGTERM', stop);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
