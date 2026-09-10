// SPDX-License-Identifier: GPL-2.0-or-later
// Independent baseline helper feasibility only. NEVER the normal security gate.
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { mutateExactlyOnce, parseProofSummary, proofArguments } from './protocol-security.mjs';
import { runProver } from './prover-process.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const ORIGIN_PATH = 'security/tamarin/RequestAuthorization.spthy';
export const ORIGIN_HASH = '7af08df4610de1d2eeac1f441339df76d5949b9c58be994fc272798559002460';
export const PROBE_TIMEOUT_MS = 120_000;
export const PROBE_OUTPUT_BYTES = 4 * 1024 * 1024;
const MAX_SOURCE_BYTES = 1024 * 1024;
const MANIFEST_PATH = 'security/tamarin/manifest.json';
const ANCHOR = '\nlemma honest_approve_trace:\n';
const CLASSIFICATION = 'BASELINE_INVARIANT_PROBE_ONLY';
export const HELPER_NAMES = Object.freeze(['enrolled_revision_unique', 'request_opened_unique']);
export const ORIGINAL_NAMES = Object.freeze([
  'honest_approve_trace', 'honest_deny_without_approval_auth_trace', 'honest_two_approvers_single_winner_trace',
  'accepted_approval_requires_same_binding_auth', 'accepted_decision_matches_opened_request',
  'request_accepted_at_most_once', 'no_accept_after_revision_revoked',
  'no_accept_after_request_cancelled', 'no_accept_after_request_expired',
]);
const KNOWN_NAMES = Object.freeze([...HELPER_NAMES, ...ORIGINAL_NAMES]);
export const HELPER_INSERTION = `
// INVARIANT_PROBE_ONLY: two independent direct helpers, no proof reuse.
lemma enrolled_revision_unique:
  all-traces
  "All pc device revision ak1 dk1 ak2 dk2 #i #j.
     Enrolled(pc,device,revision,ak1,dk1)@i
     & Enrolled(pc,device,revision,ak2,dk2)@j
     ==> #i = #j"

lemma request_opened_unique:
  all-traces
  "All pc binding #i #j.
     RequestOpened(pc,binding)@i
     & RequestOpened(pc,binding)@j
     ==> #i = #j"
`;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const reject = () => { throw new Error('Invariant probe source, selection or evidence admission rejected.'); };
const same = (left, right) => { if (!isDeepStrictEqual(left, right)) reject(); };

function normalize(source) {
  if (typeof source !== 'string' || !source || source.includes('\0') || Buffer.byteLength(source) > MAX_SOURCE_BYTES) reject();
  // Normalize CRLF only: no trimming, lone-CR acceptance or other source edits.
  return source.replace(/\r\n/g, '\n');
}

function helper(name) {
  if (typeof name !== 'string' || !HELPER_NAMES.includes(name)) reject();
  return name;
}

/** Text admission, not a substitute Tamarin parser or a proved invariant. */
export function insertInvariantHelpers(source) {
  const normalized = normalize(source);
  if (hash(normalized) !== ORIGIN_HASH) reject();
  const candidate = mutateExactlyOnce(normalized, { from: ANCHOR, to: HELPER_INSERTION + ANCHOR });
  if (mutateExactlyOnce(candidate, { from: HELPER_INSERTION + ANCHOR, to: ANCHOR }) !== normalized) reject();
  const names = [...candidate.matchAll(/^lemma ([A-Za-z][A-Za-z0-9_]*):$/gm)].map((match) => match[1]);
  same(names, KNOWN_NAMES);
  // Exact insertion above is the primary guard. These checks document that this
  // experiment supplies no reuse/sources/induction attribute or stored proof.
  if (/^lemma\s+\w+\s*\[/m.test(candidate) || /\b(?:BuildingProduced|use_induction)\b/.test(candidate)) reject();
  return { normalized, candidate };
}

export function admitInvariantCandidate(source, candidate) {
  const expected = insertInvariantHelpers(source);
  if (typeof candidate !== 'string' || candidate !== expected.candidate ||
      mutateExactlyOnce(candidate, { from: HELPER_INSERTION + ANCHOR, to: ANCHOR }) !== expected.normalized) reject();
  return expected;
}

export function selectInvariantArguments(args) {
  if (!Array.isArray(args) || args.length !== 1 || typeof args[0] !== 'string' || !args[0].startsWith('--helper=')) reject();
  return helper(args[0].slice('--helper='.length));
}

export function admitInvariantEnvironment(args, env, platform) {
  const selected = selectInvariantArguments(args);
  if (platform !== 'linux' || env.CI !== 'true' || env.GITHUB_ACTIONS !== 'true' ||
      typeof env.TAMARIN_BIN !== 'string' || !isAbsolute(env.TAMARIN_BIN) ||
      !/^[0-9a-f]{40}$/.test(env.GITHUB_SHA ?? '')) reject();
  return { selected, binary: env.TAMARIN_BIN, commit: env.GITHUB_SHA };
}

export function invariantArguments(input, selected) {
  if (typeof input !== 'string' || !isAbsolute(input) || resolve(input) !== input || basename(input) !== 'request.input.spthy') reject();
  return proofArguments(input, { [helper(selected)]: { trace: 'all-traces', verdict: 'verified' } });
}

export function selectedInvariantSummary(result, selected, input) {
  const parsed = parseProofSummary(result, { [helper(selected)]: { trace: 'all-traces', verdict: 'verified' } }, KNOWN_NAMES, input);
  // --quit-on-warning must be honored; an exit-zero fixture cannot turn a
  // dependency/wellformedness warning into successful experiment evidence.
  if (/\bWARNING\b|returned unsupported version/i.test(`${result.stdout ?? ''}\n${result.stderr ?? ''}`)) {
    parsed.ok = false;
    parsed.reasons.push('prover reported a warning or unsupported dependency');
  }
  return { ok: parsed.ok, reasons: parsed.reasons.slice(0, 32), reasonsTruncated: parsed.reasons.length > 32,
    verdict: parsed.verdicts[selected] ?? null };
}

export function invariantRunSummary(result, selected, input, inputsUnchanged) {
  const selectedProof = selectedInvariantSummary(result, selected, input);
  if (inputsUnchanged !== true) {
    selectedProof.ok = false;
    selectedProof.reasons.push('input, mapped source or binary identity could not be preserved');
  }
  return {
    completed: result.status === 0 && !result.signal && !result.error && !result.cancelled && !result.cleanupIncomplete,
    inputsUnchanged: inputsUnchanged === true,
    status: result.cancelled ? 'cancelled' : result.cleanupIncomplete ? 'cleanup-incomplete' : 'attempt-finished',
    process: { status: result.status ?? null, signal: result.signal ?? null,
      error: result.error ? String(result.error.message ?? result.error).slice(0, 2000) : null,
      cancelled: result.cancelled === true, cleanupIncomplete: result.cleanupIncomplete === true },
    selectedProof,
  };
}

export function validateInvariantManifest(manifest) {
  if (manifest?.version !== 1 || manifest.toolVersion !== '1.12.0' || !Array.isArray(manifest.models) ||
      manifest.models.length < 2 || manifest.models.length > 8 ||
      !Array.isArray(manifest.sourceBindings) || !manifest.sourceBindings.length || manifest.sourceBindings.length > 32) reject();
  const matches = manifest.models.filter((model) => model?.id === 'request-authorization');
  if (matches.length !== 1 || matches[0].path !== ORIGIN_PATH) reject();
  const expected = Object.fromEntries(ORIGINAL_NAMES.map((name, index) => [name, {
    trace: index < 3 ? 'exists-trace' : 'all-traces', verdict: 'verified',
  }]));
  same(matches[0].expected, expected);
  const seen = new Set();
  for (const binding of manifest.sourceBindings) {
    if (!binding || typeof binding.path !== 'string' || !/^crates\/[A-Za-z0-9_./-]+\.rs$/.test(binding.path) ||
        binding.path.split('/').some((part) => !part || part === '.' || part === '..') ||
        !/^[0-9a-f]{64}$/.test(binding.sha256 ?? '') || seen.has(binding.path)) reject();
    seen.add(binding.path);
  }
  return manifest.sourceBindings.map(({ path, sha256 }) => ({ path, sha256 }));
}

function plainAncestors(path) {
  let cursor = parse(path).root;
  for (const part of relative(cursor, dirname(path)).split(sep).filter(Boolean)) {
    cursor = join(cursor, part);
    const stat = lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) reject();
  }
}

function owned(root, child) {
  const path = resolve(root, child), rel = relative(root, path);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) reject();
  return path;
}

// Snapshot the opened bounded regular file, not a followed symlink/FIFO. The
// digest-only mode keeps the installed binary out of uploaded source artifacts.
function regular(path, maximum = MAX_SOURCE_BYTES, capture = true) {
  plainAncestors(path);
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > maximum) reject();
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) reject();
    const digest = createHash('sha256'), chunks = [], buffer = Buffer.alloc(Math.min(maximum + 1, 64 * 1024));
    let size = 0;
    for (;;) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, maximum + 1 - size), null);
      if (!count) break;
      size += count;
      if (size > maximum) reject();
      digest.update(buffer.subarray(0, count));
      if (capture) chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    const after = fstatSync(fd), leaf = lstatSync(path);
    if (size !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
        leaf.isSymbolicLink() || !leaf.isFile() || leaf.dev !== opened.dev || leaf.ino !== opened.ino) reject();
    return { sha256: digest.digest('hex'), size, ...(capture ? { bytes: Buffer.concat(chunks, size) } : {}) };
  } finally { closeSync(fd); }
}

function utf8(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(bytes);
  if (!Buffer.from(text).equals(bytes)) reject();
  return text;
}

function freshDirectory(root, selected) {
  for (const child of ['artifacts', 'artifacts/protocol-invariant-probe']) {
    const path = owned(root, child);
    plainAncestors(path);
    try { mkdirSync(path, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) reject();
  }
  return mkdtempSync(join(owned(root, 'artifacts/protocol-invariant-probe'), `INVARIANT_PROBE_ONLY-${selected}-`));
}

export async function runInvariantProbe(args = process.argv.slice(2), root = ROOT) {
  const { selected, binary, commit } = admitInvariantEnvironment(args, process.env, process.platform);
  root = realpathSync(root);
  const directory = freshDirectory(root, selected);
  const cancellation = new AbortController();
  const stop = () => cancellation.abort(new Error('Invariant experiment interrupted.'));
  // Keep repeated parent signals handled until the owned prover group has
  // completed its bounded cleanup; cancellation itself is irreversible.
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  let report = {
    classification: CLASSIFICATION, eligibleAsNormalGate: false, baselineOnly: true,
    normalGateStatus: 'not-run', helperReuse: false, observationalEventsAdded: false,
    selectedHelper: selected, commit, toolVersion: '1.12.0',
    unselectedLemmas: KNOWN_NAMES.filter((name) => name !== selected).map((name) => ({ name, status: 'not-selected' })),
    negativeControls: ['missing-approval-signature', 'missing-replay-consumption'].map((name) => ({ name, status: 'not-selected' })),
    bounds: { proofInvocations: 1, timeoutMs: PROBE_TIMEOUT_MS, combinedOutputBytes: PROBE_OUTPUT_BYTES, heapGiB: 2, runtimeThreads: 2 },
    attempted: false, completed: false, inputsUnchanged: false, selectedProof: null, status: 'not-started',
  };
  const write = (name, value) => writeFileSync(join(directory, name), `${JSON.stringify(value, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  try {
    write('started.json', report);
    const files = new Map();
    const read = (path) => {
      if (!files.has(path)) files.set(path, regular(owned(root, path)));
      return files.get(path);
    };
    const origin = read(ORIGIN_PATH), manifestFile = read(MANIFEST_PATH);
    const manifest = JSON.parse(utf8(manifestFile.bytes));
    const bindings = validateInvariantManifest(manifest);
    const { normalized, candidate } = insertInvariantHelpers(utf8(origin.bytes));
    admitInvariantCandidate(utf8(origin.bytes), candidate);
    for (const binding of bindings) {
      if (hash(utf8(read(binding.path).bytes).replace(/\r\n/g, '\n')) !== binding.sha256) reject();
    }
    for (const path of ['tools/protocol-invariant-probe.mjs', 'tools/protocol-security.mjs', 'tools/prover-process.mjs',
      'tools/install-tamarin.mjs', '.github/workflows/protocol-invariant-probe.yml']) read(path);
    const sources = [...files].map(([path, file], index) => {
      const snapshot = `source-${String(index).padStart(2, '0')}.txt`;
      writeFileSync(join(directory, snapshot), file.bytes, { flag: 'wx', mode: 0o400 });
      return { path, snapshot, size: file.size, sha256: file.sha256 };
    });
    const input = join(directory, 'request.input.spthy');
    writeFileSync(input, candidate, { flag: 'wx', mode: 0o400 });
    const candidateHash = hash(candidate), tool = regular(binary, 150 * 1024 * 1024, false);
    const argv = invariantArguments(input, selected);
    const unchanged = () => regular(input).sha256 === candidateHash &&
      regular(binary, 150 * 1024 * 1024, false).sha256 === tool.sha256 &&
      sources.every((file) => regular(owned(root, file.path)).sha256 === file.sha256 && regular(join(directory, file.snapshot)).sha256 === file.sha256);
    report = { ...report, origin: { path: ORIGIN_PATH, rawSha256: origin.sha256, normalizedSha256: hash(normalized) },
      candidateSha256: candidateHash, insertionSha256: hash(HELPER_INSERTION), reverseErasureSha256: ORIGIN_HASH,
      originalRulesRestrictionsAndLemmasUnchanged: true, manifestSha256: manifestFile.sha256, sourceBindings: bindings,
      sources, binary, binaryMetadata: tool, arguments: argv,
      toolchainAuthority: 'fixed workflow install-tamarin.mjs validates pinned Tamarin and Maude distributions; this run retains the binary digest',
      scope: 'Independent symbolic helper feasibility on this baseline only, not mutant proofs, reuse approval, implementation refinement or native security.' };
    if (!unchanged()) reject();
    cancellation.signal.throwIfAborted();
    report = { ...report, attempted: true, status: 'running' };
    write('invocation.json', report);
    const result = await runProver(binary, argv, { cwd: directory, logPath: join(directory, 'prover.log'),
      timeoutMs: PROBE_TIMEOUT_MS, maxOutputBytes: PROBE_OUTPUT_BYTES, signal: cancellation.signal });
    let inputsUnchanged = false;
    try { inputsUnchanged = unchanged(); } catch { /* No attribution to changed/unreadable inputs. */ }
    report = { ...report, ...invariantRunSummary(result, selected, input, inputsUnchanged) };
  } catch {
    report = { ...report, status: cancellation.signal.aborted ? 'cancelled' : 'rejected-or-unavailable', error: 'invariant_probe_failed' };
  } finally {
    process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop);
    write('result.json', report);
  }
  return { directory, ...report };
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const report = await runInvariantProbe();
    process.stdout.write(`${JSON.stringify(report)}\n`);
    if (!report.completed || !report.inputsUnchanged || report.selectedProof?.ok !== true || report.status !== 'attempt-finished') process.exitCode = 1;
  } catch {
    process.stderr.write(`${JSON.stringify({ classification: CLASSIFICATION, eligibleAsNormalGate: false, status: 'rejected-or-unavailable' })}\n`);
    process.exitCode = 1;
  }
}
