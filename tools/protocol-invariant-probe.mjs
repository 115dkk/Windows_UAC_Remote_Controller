// SPDX-License-Identifier: GPL-2.0-or-later
// Isolated helper feasibility on fixed contexts. NEVER the normal security gate.
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
export const DIRECT_HELPER_NAMES = Object.freeze(['enrolled_revision_unique', 'request_opened_unique']);
export const BUILDING_HELPER = 'building_precedes_open';
export const HELPER_NAMES = Object.freeze([...DIRECT_HELPER_NAMES, BUILDING_HELPER]);
export const DEPENDENT_PROFILE = 'request-opened-with-building';
export const REQUEST_SECURITY_PROFILE = 'request-security-with-helpers';
export const CONTEXT_NAMES = Object.freeze(['baseline', 'missing-approval-signature', 'missing-replay-consumption']);
// Closed copies of the EXISTING manifest mutations. Runtime must match the
// actual manifest entries exactly; no caller-provided mutation is accepted.
export const CONTEXT_MUTATIONS = Object.freeze({
  'missing-approval-signature': Object.freeze({
    from: 'Eq(verify(signature, approval_message, approval_key), true), // CANARY_APPROVAL_SIGNATURE',
    to: "Eq('unchecked-signature', 'unchecked-signature'), // CANARY_APPROVAL_SIGNATURE_DISABLED",
  }),
  'missing-replay-consumption': Object.freeze({
    from: '// CANARY_REPLAY_GUARD', to: ", RequestSlot(request_id, pc, binding, 'pending')",
  }),
});
export const ORIGINAL_NAMES = Object.freeze([
  'honest_approve_trace', 'honest_deny_without_approval_auth_trace', 'honest_two_approvers_single_winner_trace',
  'accepted_approval_requires_same_binding_auth', 'accepted_decision_matches_opened_request',
  'request_accepted_at_most_once', 'no_accept_after_revision_revoked',
  'no_accept_after_request_cancelled', 'no_accept_after_request_expired',
]);
export const REQUEST_SECURITY_NAMES = Object.freeze(ORIGINAL_NAMES.slice(3));
export const REQUEST_WITNESS_NAMES = Object.freeze(ORIGINAL_NAMES.slice(0, 3));
export const REQUEST_SECURITY_HELPERS = Object.freeze([DIRECT_HELPER_NAMES[0], BUILDING_HELPER, DIRECT_HELPER_NAMES[1]]);
export const REQUIRED_COUNTEREXAMPLES = Object.freeze({
  'missing-approval-signature': 'accepted_approval_requires_same_binding_auth',
  'missing-replay-consumption': 'request_accepted_at_most_once',
});
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
export const BUILDING_HELPER_INSERTION = `
// BUILDING_INVARIANT_PROBE_ONLY: observational production points, no proof reuse.
lemma building_precedes_open [use_induction]:
  all-traces
  "All request_id pc binding #b #o.
     BuildingProduced(request_id,pc,binding)@b
     & RequestOpened(pc,binding)@o
     ==> b < o"
`;
export const REUSED_BUILDING_INSERTION = BUILDING_HELPER_INSERTION
  .replace('// BUILDING_INVARIANT_PROBE_ONLY: observational production points, no proof reuse.',
    '// DEPENDENT_INVARIANT_PROBE_ONLY: this helper MUST verify here before its dependent result counts.')
  .replace('lemma building_precedes_open [use_induction]:', 'lemma building_precedes_open [use_induction,reuse]:');
export const DEPENDENT_HELPER_INSERTION = mutateExactlyOnce(
  HELPER_INSERTION.replace('// INVARIANT_PROBE_ONLY: two independent direct helpers, no proof reuse.',
    '// DEPENDENT_INVARIANT_PROBE_ONLY: required helper precedes its consumer; no imported proof.'),
  { from: '\nlemma request_opened_unique:\n', to: REUSED_BUILDING_INSERTION + '\nlemma request_opened_unique:\n' },
);
export const REQUEST_SECURITY_HELPER_INSERTION = DEPENDENT_HELPER_INSERTION
  .replace('// DEPENDENT_INVARIANT_PROBE_ONLY: required helper precedes its consumer; no imported proof.',
    '// REQUEST_SECURITY_PROBE_ONLY: ALL reused helpers must verify in this same context/invocation; no imported proof.')
  .replace('lemma enrolled_revision_unique:', 'lemma enrolled_revision_unique [reuse]:')
  .replace('lemma request_opened_unique:', 'lemma request_opened_unique [reuse]:');
const OPEN_PRODUCER = `rule OpenActualRequest:
  let binding = <pc, epoch, session_id, logon_luid, ~request_id, ~nonce,
        ~content_digest, ~expiry>
  in
  [ !HostContext(pc, epoch, session_id, logon_luid),
    Fr(~request_id), Fr(~nonce), Fr(~content_digest), Fr(~expiry) ]
  -->
  [ RequestSlot(~request_id, pc, binding, 'building'), !RequestOrigin(~request_id, pc, binding) ]`;
const CAPTURE_PRODUCER = `rule CaptureEligibleDevice:
  [ RequestSlot(request_id, pc, binding, 'building'), !RequestOrigin(request_id, pc, binding)[+],
    RegistrySlot(device, pc, revision, 'active'),
    !EnrollmentKeys(pc, device, approval_key, denial_key) ]
  --[ SnapshotCaptured(pc, device, revision, binding) ]->
  [ RequestSlot(request_id, pc, binding, 'building'),
    RegistrySlot(device, pc, revision, 'active'),
    !Snapshot(pc, device, revision, approval_key, denial_key, binding) ]`;
export const BUILDING_ACTION_EDITS = Object.freeze([
  Object.freeze({ rule: 'OpenActualRequest', from: OPEN_PRODUCER,
    to: OPEN_PRODUCER.replace('\n  -->\n', '\n  --[ BuildingProduced(~request_id, pc, binding) ]->\n') }),
  Object.freeze({ rule: 'CaptureEligibleDevice', from: CAPTURE_PRODUCER,
    to: CAPTURE_PRODUCER.replace('SnapshotCaptured(pc, device, revision, binding) ]->',
      'SnapshotCaptured(pc, device, revision, binding),\n       BuildingProduced(request_id, pc, binding) ]->') }),
]);
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

export function invariantProfile(selected, context = 'baseline') {
  if (typeof context !== 'string' || !CONTEXT_NAMES.includes(context)) reject();
  if (selected === REQUEST_SECURITY_PROFILE) {
    return {
      observationalEventsAdded: true, inductionHelpers: [BUILDING_HELPER], helperReuse: true,
      requiredLemmas: [...REQUEST_SECURITY_HELPERS, ...(context === 'baseline' ? REQUEST_SECURITY_NAMES : [REQUIRED_COUNTEREXAMPLES[context]])],
      reusedHelpers: [...REQUEST_SECURITY_HELPERS],
      candidateLemmas: [...REQUEST_SECURITY_HELPERS, ...ORIGINAL_NAMES],
    };
  }
  const dependent = selected === DEPENDENT_PROFILE;
  if (!dependent) {
    helper(selected);
    if (context !== 'baseline') reject(); // Legacy independent profiles are unchanged.
  }
  const observationalEventsAdded = dependent || selected === BUILDING_HELPER;
  return {
    observationalEventsAdded,
    inductionHelpers: observationalEventsAdded ? [BUILDING_HELPER] : [],
    helperReuse: dependent,
    requiredLemmas: dependent ? [BUILDING_HELPER, 'request_opened_unique'] : [selected],
    reusedHelpers: dependent ? [BUILDING_HELPER] : [],
    candidateLemmas: dependent ? [DIRECT_HELPER_NAMES[0], BUILDING_HELPER, DIRECT_HELPER_NAMES[1], ...ORIGINAL_NAMES]
      : [...DIRECT_HELPER_NAMES, ...(observationalEventsAdded ? [BUILDING_HELPER] : []), ...ORIGINAL_NAMES],
  };
}

function insertion(selected) {
  if (selected === REQUEST_SECURITY_PROFILE) return REQUEST_SECURITY_HELPER_INSERTION;
  if (selected === DEPENDENT_PROFILE) return DEPENDENT_HELPER_INSERTION;
  return HELPER_INSERTION + (helper(selected) === BUILDING_HELPER ? BUILDING_HELPER_INSERTION : '');
}

function contextMutation(context, manifest) {
  if (!CONTEXT_NAMES.includes(context)) reject();
  if (manifest !== undefined || context !== 'baseline') validateInvariantManifest(manifest);
  if (context === 'baseline') return null;
  return CONTEXT_MUTATIONS[context];
}

export function invariantContextSource(source, selected, context = 'baseline', manifest) {
  invariantProfile(selected, context);
  const normalized = normalize(source);
  if (hash(normalized) !== ORIGIN_HASH) reject();
  const mutation = contextMutation(context, manifest);
  return mutation ? mutateExactlyOnce(normalized, mutation) : normalized;
}

/** Erase ONLY this profile's exact additions; any unrelated change rejects. */
export function eraseInvariantCandidate(candidate, selected = DIRECT_HELPER_NAMES[0], context = 'baseline', manifest) {
  const profile = invariantProfile(selected, context), mutation = contextMutation(context, manifest);
  if (typeof candidate !== 'string' || Buffer.byteLength(candidate) > MAX_SOURCE_BYTES) reject();
  let restored = mutateExactlyOnce(candidate, { from: insertion(selected) + ANCHOR, to: ANCHOR });
  if (profile.observationalEventsAdded) {
    for (const edit of [...BUILDING_ACTION_EDITS].reverse()) {
      restored = mutateExactlyOnce(restored, { from: edit.to, to: edit.from });
    }
  }
  if (mutation) restored = mutateExactlyOnce(restored, { from: mutation.to, to: mutation.from });
  if (hash(restored) !== ORIGIN_HASH) reject();
  return restored;
}

/** Text admission, not a substitute Tamarin parser or a proved invariant. */
export function insertInvariantHelpers(source, selected = DIRECT_HELPER_NAMES[0], context = 'baseline', manifest) {
  const profile = invariantProfile(selected, context);
  const normalized = normalize(source);
  if (hash(normalized) !== ORIGIN_HASH) reject();
  let candidate = invariantContextSource(normalized, selected, context, manifest);
  if (profile.observationalEventsAdded) {
    for (const edit of BUILDING_ACTION_EDITS) candidate = mutateExactlyOnce(candidate, edit);
  }
  candidate = mutateExactlyOnce(candidate, { from: ANCHOR, to: insertion(selected) + ANCHOR });
  if (eraseInvariantCandidate(candidate, selected, context, manifest) !== normalized) reject();
  const names = [...candidate.matchAll(/^lemma ([A-Za-z][A-Za-z0-9_]*)(?: \[(?:reuse|use_induction(?:,reuse)?)\])?:$/gm)].map((match) => match[1]);
  same(names, profile.candidateLemmas);
  const attributes = [...candidate.matchAll(/^lemma\s+\w+\s*\[[^\r\n]*\]:$/gm)].map((match) => match[0]);
  same(attributes, selected === REQUEST_SECURITY_PROFILE ? [
    'lemma enrolled_revision_unique [reuse]:', 'lemma building_precedes_open [use_induction,reuse]:', 'lemma request_opened_unique [reuse]:',
  ] : profile.helperReuse ? ['lemma building_precedes_open [use_induction,reuse]:']
    : profile.observationalEventsAdded ? ['lemma building_precedes_open [use_induction]:'] : []);
  const observations = candidate.match(/\bBuildingProduced\(/g) ?? [];
  if (observations.length !== (profile.observationalEventsAdded ? 3 : 0)) reject(); // two actions + one helper premise
  if (/^lemma[^\r\n]*\bsources\b/m.test(candidate)) reject();
  const reused = [...candidate.matchAll(/^lemma\s+(\w+)[^\r\n]*\breuse\b[^\r\n]*:$/gm)].map((match) => match[1]);
  same(reused, profile.reusedHelpers);
  for (const name of reused) {
    if (!profile.requiredLemmas.includes(name) || profile.candidateLemmas.indexOf(name) >= profile.candidateLemmas.indexOf(ORIGINAL_NAMES[0])) reject();
  }
  if (profile.helperReuse && profile.candidateLemmas.indexOf(BUILDING_HELPER) >= profile.candidateLemmas.indexOf('request_opened_unique')) reject();
  return { normalized, candidate };
}

export function admitInvariantCandidate(source, candidate, selected = DIRECT_HELPER_NAMES[0], context = 'baseline', manifest) {
  const expected = insertInvariantHelpers(source, selected, context, manifest);
  if (typeof candidate !== 'string' || candidate !== expected.candidate ||
      eraseInvariantCandidate(candidate, selected, context, manifest) !== expected.normalized) reject();
  return expected;
}

export function selectInvariantArguments(args) {
  if (!Array.isArray(args) || args.length !== 1 || typeof args[0] !== 'string' || !args[0].startsWith('--helper=')) reject();
  return helper(args[0].slice('--helper='.length));
}

export function selectInvariantRunArguments(args) {
  if (Array.isArray(args) && args.length === 2 && [DEPENDENT_PROFILE, REQUEST_SECURITY_PROFILE].some((name) => args[0] === `--profile=${name}`) &&
      typeof args[1] === 'string' && args[1].startsWith('--context=')) {
    const selected = args[0].slice('--profile='.length);
    const context = args[1].slice('--context='.length);
    invariantProfile(selected, context);
    return { selected, context };
  }
  return { selected: selectInvariantArguments(args), context: 'baseline' };
}

export function admitInvariantEnvironment(args, env, platform) {
  const selection = selectInvariantRunArguments(args);
  if (platform !== 'linux' || env.CI !== 'true' || env.GITHUB_ACTIONS !== 'true' ||
      typeof env.TAMARIN_BIN !== 'string' || !isAbsolute(env.TAMARIN_BIN) ||
      !/^[0-9a-f]{40}$/.test(env.GITHUB_SHA ?? '')) reject();
  return { ...selection, binary: env.TAMARIN_BIN, commit: env.GITHUB_SHA };
}

function directoryPrefix(selected, context) {
  invariantProfile(selected, context);
  return `INVARIANT_PROBE_ONLY-${selected}-${context}-`;
}

export function requiredInvariantVerdicts(selected, context = 'baseline') {
  const profile = invariantProfile(selected, context);
  return Object.fromEntries(profile.requiredLemmas.map((name) => [name, { trace: 'all-traces',
    verdict: selected === REQUEST_SECURITY_PROFILE && context !== 'baseline' && name === REQUIRED_COUNTEREXAMPLES[context] ? 'falsified' : 'verified',
  }]));
}

export function invariantArguments(input, selected, context = 'baseline') {
  const expected = requiredInvariantVerdicts(selected, context);
  if (typeof input !== 'string' || !isAbsolute(input) || resolve(input) !== input || basename(input) !== 'request.input.spthy') reject();
  if ([DEPENDENT_PROFILE, REQUEST_SECURITY_PROFILE].includes(selected) && !basename(dirname(input)).startsWith(directoryPrefix(selected, context))) reject();
  return proofArguments(input, expected);
}

export function selectedInvariantSummary(result, selected, input, context = 'baseline') {
  invariantArguments(input, selected, context);
  const profile = invariantProfile(selected, context);
  const expected = requiredInvariantVerdicts(selected, context);
  const parsed = parseProofSummary(result, expected, profile.candidateLemmas, input);
  // --quit-on-warning must be honored; an exit-zero fixture cannot turn a
  // dependency/wellformedness warning into successful experiment evidence.
  const diagnosticOutput = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  if (/\bWARNING\b|returned unsupported version/i.test(diagnosticOutput)) {
    parsed.ok = false;
    parsed.reasons.push('prover reported a warning or unsupported dependency');
  }
  return { ok: parsed.ok, reasons: parsed.reasons.slice(0, 32), reasonsTruncated: parsed.reasons.length > 32,
    verdict: parsed.verdicts[profile.requiredLemmas.at(-1)] ?? null,
    requiredVerdicts: Object.fromEntries(profile.requiredLemmas.map((name) => [name, parsed.verdicts[name] ?? null])) };
}

export function invariantRunSummary(result, selected, input, inputsUnchanged, context = 'baseline') {
  const selectedProof = selectedInvariantSummary(result, selected, input, context);
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
  const canaries = matches[0].canaries;
  if (!Array.isArray(canaries) || canaries.length !== 2) reject();
  for (const context of CONTEXT_NAMES.slice(1)) {
    const matching = canaries.filter((canary) => canary?.id === context);
    if (matching.length !== 1) reject();
    same(matching[0].mutation, CONTEXT_MUTATIONS[context]);
    same(matching[0].expected, { [REQUIRED_COUNTEREXAMPLES[context]]:
      { trace: 'all-traces', verdict: 'falsified' } });
  }
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

function freshDirectory(root, selected, context) {
  for (const child of ['artifacts', 'artifacts/protocol-invariant-probe']) {
    const path = owned(root, child);
    plainAncestors(path);
    try { mkdirSync(path, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.isSymbolicLink()) reject();
  }
  return mkdtempSync(join(owned(root, 'artifacts/protocol-invariant-probe'), directoryPrefix(selected, context)));
}

export async function runInvariantProbe(args = process.argv.slice(2), root = ROOT) {
  const { selected, context, binary, commit } = admitInvariantEnvironment(args, process.env, process.platform);
  const profile = invariantProfile(selected, context);
  const securityProfile = selected === REQUEST_SECURITY_PROFILE;
  root = realpathSync(root);
  const directory = freshDirectory(root, selected, context);
  const cancellation = new AbortController();
  const stop = () => cancellation.abort(new Error('Invariant experiment interrupted.'));
  // Keep repeated parent signals handled until the owned prover group has
  // completed its bounded cleanup; cancellation itself is irreversible.
  process.on('SIGINT', stop); process.on('SIGTERM', stop);
  let report = {
    classification: securityProfile ? (context === 'baseline' ? 'BASELINE_REQUEST_SECURITY_PROBE_ONLY' : 'MUTANT_REQUEST_SECURITY_PROBE_ONLY')
      : context === 'baseline' ? CLASSIFICATION : 'MUTANT_INVARIANT_PROBE_ONLY', eligibleAsNormalGate: false, baselineOnly: context === 'baseline',
    normalGateStatus: 'not-run', ...profile,
    selectedProfile: selected, selectedHelper: securityProfile ? null : profile.requiredLemmas.at(-1), context, commit, toolVersion: '1.12.0',
    selectedSecurityProperties: securityProfile ? profile.requiredLemmas.filter((name) => REQUEST_SECURITY_NAMES.includes(name)) : [],
    requiredExpected: requiredInvariantVerdicts(selected, context),
    helperProofScope: 'same-invocation-same-context-only', importedProofs: false,
    unselectedLemmas: profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name)).map((name) => ({ name, status: 'not-selected' })),
    negativeControls: CONTEXT_NAMES.slice(1).map((name) => ({ name,
      status: name === context ? (securityProfile ? 'required-counterexample-selected' : 'mutated-context-only-counterexample-not-selected') : 'not-selected' })),
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
    const { normalized, candidate } = insertInvariantHelpers(utf8(origin.bytes), selected, context, manifest);
    admitInvariantCandidate(utf8(origin.bytes), candidate, selected, context, manifest);
    const contextual = invariantContextSource(normalized, selected, context, manifest);
    const mutation = contextMutation(context, manifest);
    for (const binding of bindings) {
      if (hash(utf8(read(binding.path).bytes).replace(/\r\n/g, '\n')) !== binding.sha256) reject();
    }
    for (const path of ['tools/protocol-invariant-probe.mjs', 'tools/protocol-invariant-probe.test.mjs', 'tools/protocol-security.mjs', 'tools/prover-process.mjs',
      'tools/install-tamarin.mjs', '.github/workflows/protocol-invariant-probe.yml']) read(path);
    const sources = [...files].map(([path, file], index) => {
      const snapshot = `source-${String(index).padStart(2, '0')}.txt`;
      writeFileSync(join(directory, snapshot), file.bytes, { flag: 'wx', mode: 0o400 });
      return { path, snapshot, size: file.size, sha256: file.sha256 };
    });
    const input = join(directory, 'request.input.spthy');
    const contextInput = join(directory, 'context.input.spthy');
    writeFileSync(contextInput, contextual, { flag: 'wx', mode: 0o400 });
    writeFileSync(input, candidate, { flag: 'wx', mode: 0o400 });
    const candidateHash = hash(candidate), contextHash = hash(contextual), tool = regular(binary, 150 * 1024 * 1024, false);
    const argv = invariantArguments(input, selected, context);
    const unchanged = () => regular(input).sha256 === candidateHash &&
      regular(contextInput).sha256 === contextHash &&
      regular(binary, 150 * 1024 * 1024, false).sha256 === tool.sha256 &&
      sources.every((file) => regular(owned(root, file.path)).sha256 === file.sha256 && regular(join(directory, file.snapshot)).sha256 === file.sha256);
    report = { ...report, origin: { path: ORIGIN_PATH, rawSha256: origin.sha256, normalizedSha256: hash(normalized) },
      candidateSha256: candidateHash, insertionSha256: hash(insertion(selected)), reverseErasureSha256: ORIGIN_HASH,
      contextSourceSha256: contextHash,
      contextMutation: mutation ? { id: context, ...mutation, beforeSha256: ORIGIN_HASH, afterSha256: contextHash } : null,
      observationalEdits: profile.observationalEventsAdded ? BUILDING_ACTION_EDITS.map((edit) => ({
        rule: edit.rule, event: 'BuildingProduced', beforeSha256: hash(edit.from), afterSha256: hash(edit.to),
      })) : [],
      originalRulesRestrictionsAndLemmasUnchanged: !profile.observationalEventsAdded && context === 'baseline',
      originalPremisesConclusionsAndPublicMessagesUnchanged: context === 'baseline', originalRestrictionsAndLemmasUnchanged: true,
      changesBeyondExactManifestMutationAndObservations: false,
      traceScope: context !== 'baseline' ? 'The exact manifest mutant intentionally changes traces. Undo it and erase BuildingProduced labels to recover the original rules; no baseline security verdict is inferred.'
        : profile.observationalEventsAdded ? 'Erase only BuildingProduced action labels to recover the original transition traces; no new restrictions.' : 'Original transition/action traces unchanged.',
      manifestSha256: manifestFile.sha256, sourceBindings: bindings,
      sources, binary, binaryMetadata: tool, arguments: argv,
      toolchainAuthority: 'fixed workflow install-tamarin.mjs validates pinned Tamarin and Maude distributions; this run retains the binary digest',
      scope: securityProfile
        ? 'Only the original six all-traces properties in baseline, or the exact manifest-required counterexample in its mutant, conditional on ALL reused helpers verifying in this SAME invocation/context. Original existential witnesses remain unselected. No normal gate, implementation or native-security approval.'
        : 'Only the fixed required helper proofs in this exact context. Original security properties and required counterexamples are not selected; no normal gate, implementation or native-security approval.' };
    if (!unchanged()) reject();
    cancellation.signal.throwIfAborted();
    report = { ...report, attempted: true, status: 'running' };
    write('invocation.json', report);
    const result = await runProver(binary, argv, { cwd: directory, logPath: join(directory, 'prover.log'),
      timeoutMs: PROBE_TIMEOUT_MS, maxOutputBytes: PROBE_OUTPUT_BYTES, signal: cancellation.signal });
    let inputsUnchanged = false;
    try { inputsUnchanged = unchanged(); } catch { /* No attribution to changed/unreadable inputs. */ }
    report = { ...report, ...invariantRunSummary(result, selected, input, inputsUnchanged, context) };
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
