// SPDX-License-Identifier: GPL-2.0-or-later
// One selected isolated witness-search experiment. NEVER a normal security gate.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve } from 'node:path';
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
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)"`;
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
      #e1 #e2 #c1 #c2 #o #s1 #s2 #a.
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
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> (#x = #e1 | #x = #e2))"`;
export const WITNESS_VARIANTS = Object.freeze({
  approve: Object.freeze({ lemma: 'honest_approve_trace', original: ORIGINAL, shaped: SHAPED }),
  deny: Object.freeze({ lemma: 'honest_deny_without_approval_auth_trace', original: DENY_ORIGINAL, shaped: DENY_SHAPED }),
  'two-approvers': Object.freeze({ lemma: 'honest_two_approvers_single_winner_trace', original: TWO_APPROVERS_ORIGINAL, shaped: TWO_APPROVERS_SHAPED }),
});
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

function variantDefinition(variant) {
  assert.ok(typeof variant === 'string' && Object.hasOwn(WITNESS_VARIANTS, variant), 'Unknown fixed witness variant.');
  return WITNESS_VARIANTS[variant];
}

export function selectWitnessArguments(args) {
  assert.ok(Array.isArray(args) && args.length <= 1, 'Select at most one fixed witness variant.');
  if (args.length === 0) return { variant: 'approve', replay: false };
  if (args[0] === '--replay') return { variant: 'approve', replay: true };
  if (args[0] === '--variant=deny') return { variant: 'deny', replay: false };
  if (args[0] === '--variant=two-approvers') return { variant: 'two-approvers', replay: false };
  throw new Error('usage: node tools/protocol-witness-shape.mjs [--replay|--variant=deny|--variant=two-approvers]');
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

async function main() {
  assert.equal(process.platform, 'linux');
  assert.equal(process.env.CI, 'true');
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  const { variant, replay } = selectWitnessArguments(process.argv.slice(2));
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
    replayOfActualProverOutput: replay,
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
