// SPDX-License-Identifier: GPL-2.0-or-later
// Isolated attack existence experiments; never a replacement normal-gate verdict.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, isAbsolute, resolve, sep } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { mutateExactlyOnce, parseProofSummary, proofArguments } from './protocol-security.mjs';
import { runProver } from './prover-process.mjs';

export const SOURCE_PATH = 'security/tamarin/candidates/CurrentRequestAuthorization42b.spthy';
export const SOURCE_SHA256 = '42b467b376c93d3e237021e420798a67549a1aedd17ccde6a001eb73c3d7385d';
export const VARIANTS = Object.freeze(['signature', 'replay']);
export const CONTEXTS = Object.freeze(['mutant', 'baseline']);
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
const PREFIX_END = 'lemma enrolled_revision_unique [reuse]:';
const AUTH_ORIGINAL = `lemma accepted_approval_requires_same_binding_auth:
  "All pc device revision binding #a.
    RequestAccepted(pc, device, revision, binding, 'approve') @a
    ==> (Ex #u. UserAuthenticated(device, binding) @u & u < a)"`;
const REPLAY_ORIGINAL = `lemma request_accepted_at_most_once:
  "All pc first_device second_device first_revision second_revision binding
      first_purpose second_purpose #i #j.
    RequestAccepted(pc, first_device, first_revision, binding, first_purpose) @i
    & RequestAccepted(pc, second_device, second_revision, binding, second_purpose) @j
    ==> #i = #j"`;
const AUTH_SHAPE = `lemma attack_approval_without_auth:
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
const REPLAY_SHAPE = `lemma attack_replay_single_approval:
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
  signature: Object.freeze({ lemma: 'attack_approval_without_auth', obligation: 'accepted_approval_requires_same_binding_auth',
    original: AUTH_ORIGINAL, shape: AUTH_SHAPE,
    mutation: Object.freeze({ from: 'Eq(verify(signature, approval_message, approval_key), true), // CANARY_APPROVAL_SIGNATURE',
      to: "Eq('unchecked-signature', 'unchecked-signature'), // CANARY_APPROVAL_SIGNATURE_DISABLED" }),
    implication: 'A same-binding accepted approval with no earlier authentication negates the exact original universal implication.' }),
  replay: Object.freeze({ lemma: 'attack_replay_single_approval', obligation: 'request_accepted_at_most_once',
    original: REPLAY_ORIGINAL, shape: REPLAY_SHAPE,
    mutation: Object.freeze({ from: '// CANARY_REPLAY_GUARD', to: ", RequestSlot(request_id, pc, binding, 'pending')" }),
    implication: 'Instantiate both device/revision/purpose binders with the same device/revision/approve and i=a1,j=a2; a1<a2 contradicts i=j.' }),
});

export function prepareAttack(source, variant, context) {
  assert.ok(VARIANTS.includes(variant) && CONTEXTS.includes(context));
  assert.equal(hash(source), SOURCE_SHA256, 'Only the exact current reviewed theory is admitted.');
  const profile = PROFILES[variant];
  assert.equal(source.split(profile.original).length, 2);
  assert.equal(source.split(PREFIX_END).length, 2);
  const mutated = context === 'mutant' ? mutateExactlyOnce(source, profile.mutation) : source;
  const prefix = mutated.slice(0, mutated.indexOf(PREFIX_END));
  const candidate = `${prefix}${profile.shape}\n\nend\n`;
  assert.equal(candidate.slice(0, prefix.length), prefix);
  assert.equal((candidate.match(/^lemma /gm) ?? []).length, 1);
  assert.doesNotMatch(candidate, /^lemma[^\n]*\[(?:[^\]]*reuse|[^\]]*sources)/m);
  return { candidate, prefix, lemma: profile.lemma, obligation: profile.obligation,
    expected: { [profile.lemma]: { trace: 'exists-trace', verdict: context === 'mutant' ? 'verified' : 'falsified' } },
    mapping: { sourceSha256: SOURCE_SHA256, mutatedSourceSha256: hash(mutated), prefixSha256: hash(prefix),
      originalFormulaSha256: hash(profile.original), attackFormulaSha256: hash(profile.shape),
      mutation: context === 'mutant' ? profile.mutation : null, implication: profile.implication,
      allNonLemmaTransitionBytesPreserved: true, assumedHelpers: [] } };
}

export function selectAttack(args) {
  assert.equal(args.length, 2, 'Expected one fixed variant and context.');
  const variant = args[0].replace(/^--variant=/, ''), context = args[1].replace(/^--context=/, '');
  assert.equal(args[0], `--variant=${variant}`); assert.equal(args[1], `--context=${context}`);
  assert.ok(VARIANTS.includes(variant) && CONTEXTS.includes(context));
  return { variant, context };
}

export function attackArguments(input, expected, variant) {
  assert.ok(VARIANTS.includes(variant));
  const args = proofArguments(input, expected);
  // Producer/timepoint bounds already make this one trace finite; try its
  // branches depth-first after the unchanged replay shape exhausted BFS.
  return variant === 'replay' ? args.map(arg => arg === '--stop-on-trace=BFS' ? '--stop-on-trace=DFS' : arg) : args;
}

function capture(path, limit = 1024 * 1024) {
  const info = lstatSync(path);
  assert.ok(info.isFile() && !info.isSymbolicLink() && info.size > 0 && info.size <= limit);
  assert.equal(realpathSync(path), path);
  const bytes = readFileSync(path), after = lstatSync(path);
  assert.ok(bytes.length === info.size && after.size === info.size && after.dev === info.dev && after.ino === info.ino &&
    after.mtimeMs === info.mtimeMs && after.ctimeMs === info.ctimeMs);
  return { path, sha256: hash(bytes), size: bytes.length, bytes };
}

async function main() {
  const { variant, context } = selectAttack(process.argv.slice(2));
  assert.equal(process.platform, 'linux'); assert.equal(process.env.CI, 'true'); assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(Number(process.versions.node.split('.')[0]), 24);
  assert.match(process.env.GITHUB_SHA ?? '', /^[0-9a-f]{40}$/);
  assert.equal(realpathSync(root), root);
  const binary = process.env.TAMARIN_BIN; assert.ok(typeof binary === 'string' && isAbsolute(binary));
  const tool = capture(binary, 150 * 1024 * 1024);
  const snapshots = [SOURCE_PATH, 'tools/protocol-attack-witness.mjs', 'tools/protocol-attack-witness.test.mjs',
    'tools/protocol-security.mjs', 'tools/prover-process.mjs', 'tools/install-tamarin.mjs',
    '.github/workflows/protocol-attack-witness.yml', '.node-version'].map(name => {
    const path = resolve(root, name); assert.ok(path.startsWith(`${root}${sep}`)); return { name, ...capture(path) };
  });
  const source = snapshots[0].bytes.toString('utf8'); assert.ok(Buffer.from(source).equals(snapshots[0].bytes));
  const prepared = prepareAttack(source, variant, context);
  const base = resolve(root, 'artifacts/protocol-attack-witness'); mkdirSync(base, { recursive: true });
  assert.equal(realpathSync(base), base);
  const directory = mkdtempSync(resolve(base, `${variant}-${context}-`));
  const input = resolve(directory, 'input.spthy'); writeFileSync(input, prepared.candidate, { flag: 'wx' });
  for (const [index, file] of snapshots.entries()) writeFileSync(resolve(directory, `source-${index}.txt`), file.bytes, { flag: 'wx' });
  const inputHash = hash(prepared.candidate), args = attackArguments(input, prepared.expected, variant);
  const controller = new AbortController(), stop = () => controller.abort(new Error('Experiment interrupted.'));
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  let report = { classification: 'ATTACK_WITNESS_EXPERIMENT_ONLY', normalGateEligible: false, commit: process.env.GITHUB_SHA,
    variant, context, originalObligation: prepared.obligation, originalUniversalDirectlyChecked: false,
    strongerCounterexampleChecked: false, passed: false, input, inputSha256: inputHash, arguments: args, mapping: prepared.mapping,
    binary: { path: binary, sha256: tool.sha256, size: tool.size },
    bounds: { proofInvocations: 1, proofTimeoutMs: 120000, proofOutputBytes: 4 * 1024 * 1024, heapGiB: 2, threads: 2 },
    snapshots: snapshots.map(({ name, sha256, size }, index) => ({ source: name, sha256, size, retained: `source-${index}.txt` })) };
  const save = () => writeFileSync(resolve(directory, 'result.json'), JSON.stringify(report, null, 2));
  const unchanged = () => {
    assert.equal(capture(binary, 150 * 1024 * 1024).sha256, tool.sha256);
    for (const item of snapshots) assert.equal(capture(item.path).sha256, item.sha256);
    assert.equal(capture(input).sha256, inputHash);
  };
  save();
  try {
    unchanged(); controller.signal.throwIfAborted();
    const version = await runProver(binary, ['--version'], { cwd: root, logPath: resolve(directory, 'version.log'),
      timeoutMs: 15_000, maxOutputBytes: 64 * 1024, signal: controller.signal });
    assert.ok(version.status === 0 && !version.error && !version.signal && !version.cleanupIncomplete && !version.cancelled);
    assert.match(version.stdout + version.stderr, /tamarin[- ]prover\s+1\.12\.0\b/i);
    assert.doesNotMatch(version.stdout + version.stderr, /warn|unsupported/i);
    unchanged(); controller.signal.throwIfAborted();
    const result = await runProver(binary, args, { cwd: root, logPath: resolve(directory, 'prover.log'),
      timeoutMs: 120_000, maxOutputBytes: 4 * 1024 * 1024, signal: controller.signal });
    const verdict = parseProofSummary(result, prepared.expected, [prepared.lemma], input);
    report = { ...report, verdict, process: { status: result.status, error: result.error?.message ?? null, signal: result.signal,
      cancelled: result.cancelled, cleanupIncomplete: result.cleanupIncomplete } };
    unchanged(); controller.signal.throwIfAborted();
    report.passed = verdict.ok; report.strongerCounterexampleChecked = context === 'mutant' && verdict.ok;
    save(); assert.ok(report.passed, 'Required experimental witness verdict was not established.');
  } catch (error) { report.passed = false; report.strongerCounterexampleChecked = false; report.failure = error.message; save(); throw error; }
  finally { process.off('SIGINT', stop); process.off('SIGTERM', stop); }
}

if (process.argv[1] && pathToFileURL(resolve(process.argv[1])).href === import.meta.url) {
  main().catch(error => { process.stderr.write(`${error.message}\n`); process.exitCode = 1; });
}
