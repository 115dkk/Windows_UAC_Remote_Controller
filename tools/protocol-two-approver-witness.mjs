// SPDX-License-Identifier: GPL-2.0-or-later
// One isolated automatic search. Never a normal-gate or native-behavior receipt.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readSync, realpathSync, writeFileSync } from 'node:fs';
import { dirname, parse, posix, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { parseProofSummary, proofArguments } from './protocol-security.mjs';
import { runProver } from './prover-process.mjs';

const ROOT = dirname(dirname(fileURLToPath(import.meta.url)));
export const CURRENT_SOURCE_PATH = 'security/tamarin/candidates/CurrentRequestAuthorization42b.spthy';
export const CURRENT_SOURCE_HASH = '42b467b376c93d3e237021e420798a67549a1aedd17ccde6a001eb73c3d7385d';
export const MAPPED_MAIN_COMMIT = 'e5f1cf62185ec6016383b76b4f46ec86234982ec';
export const CANDIDATE_PATH = 'security/tamarin/candidates/TwoApproverObservedWitness.spthy';
export const CHECKED_LEMMA = 'two_approvers_ordered_observed_witness';
const CLASSIFICATION = 'TWO_APPROVER_OBSERVATION_WITNESS_EXPERIMENT_ONLY';
const MAX_SOURCE = 1024 * 1024, MAX_OUTPUT = 4 * 1024 * 1024;
const hash = bytes => createHash('sha256').update(bytes).digest('hex');
export const ORIGINAL_TWO_APPROVERS = `lemma honest_two_approvers_single_winner_trace:
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
const ORIGINAL_CONJUNCTS = ORIGINAL_TWO_APPROVERS.slice(ORIGINAL_TWO_APPROVERS.indexOf('.\n') + 2, -1);
export const ORDERED_TWO_APPROVERS = `lemma ${CHECKED_LEMMA}:
  exists-trace
  "Ex pc first_device second_device first_revision second_revision binding request_id
      first_approval_key first_denial_key second_approval_key second_denial_key
      #e1 #e2 #b #c1 #c2 #o #u1 #u2 #s1 #s2 #a.
${ORIGINAL_CONJUNCTS}
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

export function buildTwoApproverCandidate(source) {
  assert.ok(typeof source === 'string' && Buffer.byteLength(source) <= MAX_SOURCE);
  const normalized = source.replace(/\r\n/g, '\n');
  assert.equal(hash(normalized), CURRENT_SOURCE_HASH, 'The pinned current-main theory changed.');
  assert.equal(normalized.split(ORIGINAL_TWO_APPROVERS).length, 2);
  const marker = '\n// REQUEST_SECURITY_PROBE_ONLY:';
  const boundary = normalized.indexOf(marker);
  assert.ok(boundary > 0 && normalized.lastIndexOf(marker) === boundary);
  const transitionSource = normalized.slice(0, boundary);
  assert.doesNotMatch(transitionSource, /^lemma\b/m);
  const candidate = `${transitionSource}\n${ORDERED_TWO_APPROVERS}\n\nend\n`;
  return { candidate, transitionSource, sourceSha256: hash(normalized), transitionSha256: hash(transitionSource),
    originalFormulaSha256: hash(ORIGINAL_TWO_APPROVERS), strongerFormulaSha256: hash(ORDERED_TWO_APPROVERS) };
}

export function admitTwoApproverCandidate(source, candidate) {
  const derived = buildTwoApproverCandidate(source);
  assert.equal(candidate.replace(/\r\n/g, '\n'), derived.candidate, 'Only the exact approved current-source-derived witness is admitted.');
  return derived;
}

export function admitTwoApproverEnvironment(args, env, platform, version) {
  assert.ok(Array.isArray(args) && args.length === 0, 'No profile, path, bound or proof override is accepted.');
  assert.equal(platform, 'linux'); assert.equal(env.CI, 'true'); assert.equal(env.GITHUB_ACTIONS, 'true');
  assert.ok(/^[0-9a-f]{40}$/.test(env.GITHUB_SHA ?? '') && /^24\./.test(version));
  assert.ok(typeof env.TAMARIN_BIN === 'string' && posix.isAbsolute(env.TAMARIN_BIN));
  return { commit: env.GITHUB_SHA, binary: env.TAMARIN_BIN };
}

export function twoApproverArguments(input) {
  assert.ok(typeof input === 'string' && posix.isAbsolute(input) && posix.normalize(input) === input && posix.basename(input) === 'request.input.spthy');
  return proofArguments(input, { [CHECKED_LEMMA]: { trace: 'exists-trace', verdict: 'verified' } })
    .map(arg => arg === '--stop-on-trace=BFS' ? '--stop-on-trace=DFS' : arg);
}

export function twoApproverSummary(result, input) {
  const parsed = parseProofSummary(result, { [CHECKED_LEMMA]: { trace: 'exists-trace', verdict: 'verified' } }, [CHECKED_LEMMA], input);
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  if (/\bwarn(?:ing|ings)?\b|returned unsupported version/i.test(output) || Buffer.byteLength(output) > MAX_OUTPUT + 1) {
    parsed.ok = false; parsed.reasons.push('bounded warning-free output required');
  }
  if (Object.hasOwn(result, 'classification')) { parsed.ok = false; parsed.reasons.push('prior experiment metadata is not a current prover result'); }
  return parsed;
}

function parents(path) {
  let cursor = parse(path).root;
  for (const part of relative(cursor, dirname(path)).split(sep).filter(Boolean)) {
    cursor = resolve(cursor, part); const item = lstatSync(cursor);
    assert.ok(item.isDirectory() && !item.isSymbolicLink());
  }
}
function readBounded(path, maximum = MAX_SOURCE, capture = true) {
  parents(path);
  const before = lstatSync(path);
  assert.ok(before.isFile() && !before.isSymbolicLink() && before.size > 0 && before.size <= maximum);
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd), digest = createHash('sha256'), chunks = [], buffer = Buffer.alloc(Math.min(maximum + 1, 65536));
    assert.ok(opened.isFile() && opened.dev === before.dev && opened.ino === before.ino && opened.size === before.size);
    let size = 0;
    for (;;) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, maximum + 1 - size), null);
      if (!count) break;
      size += count; assert.ok(size <= maximum); digest.update(buffer.subarray(0, count));
      if (capture) chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    const after = fstatSync(fd), leaf = lstatSync(path);
    assert.ok(size === opened.size && after.size === size && after.mtimeMs === opened.mtimeMs && after.ctimeMs === opened.ctimeMs &&
      leaf.isFile() && !leaf.isSymbolicLink() && leaf.dev === opened.dev && leaf.ino === opened.ino);
    return { size, sha256: digest.digest('hex'), ...(capture ? { bytes: Buffer.concat(chunks, size) } : {}) };
  } finally { closeSync(fd); }
}

async function main() {
  const { commit, binary } = admitTwoApproverEnvironment(process.argv.slice(2), process.env, process.platform, process.versions.node);
  assert.equal(realpathSync(ROOT), ROOT);
  for (const child of ['artifacts', 'artifacts/protocol-two-approver-witness']) {
    const path = resolve(ROOT, child); parents(path);
    try { mkdirSync(path, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    assert.ok(lstatSync(path).isDirectory() && !lstatSync(path).isSymbolicLink());
  }
  const directory = mkdtempSync(resolve(ROOT, 'artifacts/protocol-two-approver-witness', 'TWO_APPROVER_ONLY-'));
  const controller = new AbortController(), stop = () => controller.abort(new Error('Two-approver experiment cancelled.'));
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  let report = { classification: CLASSIFICATION, eligibleAsNormalGate: false, normalGateStatus: 'not-run', commit,
    profile: 'ordered-observed-producers-dfs-v1', selectedLemma: CHECKED_LEMMA,
    mappedMainCommit: MAPPED_MAIN_COMMIT, mappedMainTheory: 'security/tamarin/RequestAuthorization.spthy', mappedMainTheorySha256: CURRENT_SOURCE_HASH,
    helpers: [], originalConjunctsPreserved: false, originalDirectlyVerified: false, implementationRefinementVerified: false,
    bounds: { invocations: 1, timeoutMs: 120000, outputBytes: MAX_OUTPUT, sourceBytesEach: MAX_SOURCE, heapGiB: 2, runtimeThreads: 2 },
    attempted: false, completed: false, inputsUnchanged: false, passed: false };
  const save = () => writeFileSync(resolve(directory, 'result.json'), JSON.stringify(report, null, 2));
  save();
  try {
    const paths = [CURRENT_SOURCE_PATH, CANDIDATE_PATH, 'tools/protocol-two-approver-witness.mjs', 'tools/protocol-two-approver-witness.test.mjs',
      '.github/workflows/protocol-two-approver-witness.yml', 'tools/protocol-security.mjs', 'tools/prover-process.mjs', 'tools/install-tamarin.mjs', '.node-version'];
    const snapshots = paths.map((path, index) => {
      const file = readBounded(resolve(ROOT, path)), snapshot = `source-${index}.txt`;
      writeFileSync(resolve(directory, snapshot), file.bytes, { flag: 'wx', mode: 0o400 }); return { path, snapshot, ...file };
    });
    const candidate = admitTwoApproverCandidate(snapshots[0].bytes.toString('utf8'), snapshots[1].bytes.toString('utf8'));
    const input = resolve(directory, 'request.input.spthy'), args = twoApproverArguments(input), inputSha256 = hash(candidate.candidate);
    writeFileSync(input, candidate.candidate, { flag: 'wx', mode: 0o400 });
    const tool = readBounded(binary, 150 * 1024 * 1024, false);
    const unchanged = () => {
      for (const file of snapshots) {
        assert.equal(readBounded(resolve(ROOT, file.path), MAX_SOURCE, false).sha256, file.sha256);
        assert.equal(readBounded(resolve(directory, file.snapshot), MAX_SOURCE, false).sha256, file.sha256);
      }
      assert.equal(readBounded(binary, 150 * 1024 * 1024, false).sha256, tool.sha256);
      assert.equal(readBounded(input).sha256, inputSha256); assert.equal(process.env.GITHUB_SHA, commit); return true;
    };
    report = { ...report, binary, binaryMetadata: tool, arguments: args, inputSha256,
      transitionSha256: candidate.transitionSha256, originalFormulaSha256: candidate.originalFormulaSha256, strongerFormulaSha256: candidate.strongerFormulaSha256,
      transitionBytesUnchanged: true, originalConjunctsPreserved: true,
      sourceSnapshots: snapshots.map(({ path, snapshot, size, sha256 }) => ({ path, snapshot, size, sha256 })) };
    unchanged(); controller.signal.throwIfAborted();
    writeFileSync(resolve(directory, 'invocation.json'), JSON.stringify(report, null, 2), { flag: 'wx' });
    report.attempted = true; save();
    const result = await runProver(binary, args, { cwd: directory, logPath: resolve(directory, 'prover.log'),
      timeoutMs: 120000, maxOutputBytes: MAX_OUTPUT, signal: controller.signal });
    report.selectedWitness = twoApproverSummary(result, input);
    report.process = { status: result.status, signal: result.signal, error: result.error?.message ?? null,
      cancelled: result.cancelled, cleanupIncomplete: result.cleanupIncomplete };
    report.completed = result.status === 0 && !result.error && !result.signal && !result.cancelled && !result.cleanupIncomplete;
    report.inputsUnchanged = unchanged(); controller.signal.throwIfAborted();
    report.passed = report.completed && report.inputsUnchanged && report.selectedWitness.ok;
    if (!report.passed) process.exitCode = 1;
  } catch {
    report.failure = 'Two-approver witness admission, checking or input identity failed.'; report.passed = false; process.exitCode = 1;
  } finally {
    report.cancelled = controller.signal.aborted;
    if (report.cancelled) { report.passed = false; process.exitCode = 1; }
    save(); process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
    process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
  }
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
