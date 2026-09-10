// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only partial-proof investigation. NEVER normal proof evidence or a fallback.
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { mutateExactlyOnce, proofArguments, proofRequirements, validateTheoryRequirements } from './protocol-security.mjs';
import { runProver } from './prover-process.mjs';
import { WITNESS_CONTEXTS, deriveWitness, witnessArguments, witnessBindingPaths, witnessCoverage, witnessDischarges } from './protocol-witness-discharge.mjs';
import { COUNTEREXAMPLE_CONTEXTS, counterexampleArguments, counterexampleBindingPaths, counterexampleCoverage,
  counterexampleDischarge, deriveCounterexample } from './protocol-counterexample-discharge.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const NORMAL = 'artifacts/protocol-security';
const DIAGNOSTIC = 'artifacts/protocol-diagnostic';
const REQUEST_MODEL = 'request-authorization';
const ROWS = 16;
export const DIAGNOSTIC_OUTPUT_BYTES = 4 * 1024 * 1024;
export const DIAGNOSTIC_TIMEOUT_MS = 60_000;
// Depth8 produced a skeleton, but b5b3b19 depth16 exhausted the fixed60s cap.
// Observe their midpoint once; no normal proof bound/model/verdict changes.
export const DIAGNOSTIC_DEPTH = 12;
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const reject = () => { throw new Error('Diagnostic admission rejected inconsistent or unavailable evidence.'); };
const hash = (value) => typeof value === 'string' && /^[0-9a-f]{64}$/.test(value);
const id = (value) => typeof value === 'string' && /^[a-z][a-z0-9-]{0,47}$/.test(value);
const lemma = (value) => typeof value === 'string' && /^[A-Za-z][A-Za-z0-9_]*$/.test(value);
const same = (actual, expected) => { if (!isDeepStrictEqual(actual, expected)) reject(); };

function owned(root, child) {
  if (typeof child !== 'string' || !child.split('/').every((part) => /^[A-Za-z0-9_.-]+$/.test(part) && part !== '.' && part !== '..')) reject();
  const path = resolve(root, child);
  if (!relative(root, path) || relative(root, path).startsWith('..') || isAbsolute(relative(root, path))) reject();
  return path;
}

function plainAncestors(path) {
  let cursor = parse(path).root;
  for (const part of relative(cursor, dirname(path)).split(sep).filter(Boolean)) {
    cursor = join(cursor, part);
    const stat = lstatSync(cursor);
    if (!stat.isDirectory() || stat.isSymbolicLink()) reject();
  }
}

// Read the opened regular file, bounded even if it grows. No following links,
// extraction, generated-theory loading, or filesystem repair/cleanup.
function regular(path, maxBytes, capture = true) {
  plainAncestors(path);
  const before = lstatSync(path);
  if (!before.isFile() || before.isSymbolicLink() || before.size > maxBytes) reject();
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0));
  try {
    const opened = fstatSync(fd);
    if (!opened.isFile() || opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size) reject();
    const digest = createHash('sha256'), chunks = [];
    const buffer = Buffer.alloc(Math.min(maxBytes + 1, 64 * 1024));
    let size = 0;
    for (;;) {
      const count = readSync(fd, buffer, 0, Math.min(buffer.length, maxBytes + 1 - size), null);
      if (!count) break;
      size += count;
      if (size > maxBytes) reject();
      digest.update(buffer.subarray(0, count));
      if (capture) chunks.push(Buffer.from(buffer.subarray(0, count)));
    }
    const after = fstatSync(fd), leaf = lstatSync(path);
    if (size !== opened.size || after.size !== opened.size || after.mtimeMs !== opened.mtimeMs || after.ctimeMs !== opened.ctimeMs ||
        leaf.isSymbolicLink() || !leaf.isFile() || leaf.dev !== opened.dev || leaf.ino !== opened.ino) reject();
    return { size, sha256: digest.digest('hex'), ...(capture ? { bytes: Buffer.concat(chunks, size) } : {}) };
  } finally { closeSync(fd); }
}

function utf8(bytes) {
  const text = bytes.toString('utf8');
  if (!Buffer.from(text).equals(bytes)) reject();
  return text;
}

function expectedNames(expected, baseline) {
  if (!expected || typeof expected !== 'object' || Array.isArray(expected)) reject();
  const names = Object.keys(expected);
  if (!names.length || names.length > 32) reject();
  for (const name of names) {
    const value = expected[name];
    if (!lemma(name) || !value || !['all-traces', 'exists-trace'].includes(value.trace) ||
        !['verified', 'falsified'].includes(value.verdict) || (baseline && value.verdict !== 'verified')) reject();
  }
  if (baseline ? !names.some((name) => expected[name].trace === 'exists-trace') : !names.some((name) => expected[name].verdict === 'falsified')) reject();
  return names;
}

// Pure admission: exact complete normal row set, never a diagnostic verdict.
export function admitDiagnostic(manifest, summary, root) {
  if (manifest?.version !== 1 || manifest.toolVersion !== '1.12.0' || !Array.isArray(manifest.models) ||
      manifest.models.length < 2 || manifest.models.length > 8 || !Array.isArray(manifest.sourceBindings) ||
      !manifest.sourceBindings.length || manifest.sourceBindings.length > 32 || summary?.passed !== false ||
      summary.toolVersion !== '1.12.0' || (Object.hasOwn(summary, 'status') && summary.status !== 'failed') ||
      summary.manifestSha256 !== sha256(JSON.stringify(manifest)) || !Array.isArray(summary.runs) || summary.runs.length !== ROWS) reject();
  const inputs = new Set(), plans = [], runIds = new Set(['tool-version']);
  const add = (entry) => { if (!id(entry.id) || runIds.has(entry.id)) reject(); runIds.add(entry.id); plans.push(entry); };
  for (const model of manifest.models) {
    if (!id(model.id) || inputs.has(model.id) || !/^security\/tamarin\/[A-Za-z][A-Za-z0-9_-]*\.spthy$/.test(model.path)) reject();
    inputs.add(model.id);
    const names = expectedNames(model.expected, true);
    proofRequirements(model.expected, model.helpers);
    const discharges = witnessDischarges(model);
    names.forEach((name, index) => {
      if (Object.hasOwn(discharges, name)) {
        const rowId = `${model.id}-${index + 1}`;
        for (const suffix of [...WITNESS_CONTEXTS, 'proof']) {
          const inputId = `${rowId}-${suffix}`;
          if (!id(inputId) || inputs.has(inputId)) reject();
          inputs.add(inputId);
        }
        add({ id: rowId, input: `${rowId}-good`, model, names: [discharges[name].checkedLemma],
          targetLemmas: [name], helperLemmas: [], expected: { [name]: model.expected[name] }, discharge: discharges[name] });
        return;
      }
      const expected = { [name]: model.expected[name] }, required = proofRequirements(expected, model.helpers);
      add({ id: `${model.id}-${index + 1}`, input: model.id, model, names: required.selectedLemmas,
        targetLemmas: required.targetLemmas, helperLemmas: required.helperLemmas, expected });
    });
    if (!Array.isArray(model.canaries) || !model.canaries.length || model.canaries.length > 4) reject();
    for (const canary of model.canaries) {
      if (!id(canary.id) || inputs.has(canary.id) || !canary.mutation ||
          typeof canary.mutation.from !== 'string' || !canary.mutation.from ||
          typeof canary.mutation.to !== 'string' || canary.mutation.from === canary.mutation.to) reject();
      inputs.add(canary.id);
      const selected = expectedNames(canary.expected, false);
      if (selected.some((name) => !names.includes(name))) reject();
      const counterexample = counterexampleDischarge(model, canary);
      if (counterexample) {
        for (const context of COUNTEREXAMPLE_CONTEXTS) {
          const inputId = `${canary.id}-${context}`;
          if (!id(inputId) || inputs.has(inputId) || runIds.has(inputId)) reject();
          inputs.add(inputId); runIds.add(inputId);
        }
        add({ id: canary.id, input: `${canary.id}-mutant`, model, names: [counterexample.checkedLemma],
          targetLemmas: [counterexample.obligation], helperLemmas: [], expected: canary.expected,
          mutation: canary.mutation, counterexample });
        continue;
      }
      const required = proofRequirements(canary.expected, model.helpers);
      add({ id: canary.id, input: canary.id, model, names: required.selectedLemmas,
        targetLemmas: required.targetLemmas, helperLemmas: required.helperLemmas,
        expected: canary.expected, mutation: canary.mutation });
    }
  }
  if (plans.length !== ROWS || !manifest.models.some((model) => model.id === REQUEST_MODEL)) reject();
  const rows = new Map();
  for (const row of summary.runs) {
    if (!row || !id(row.id) || rows.has(row.id) || row.cancelled !== false || row.cleanupIncomplete !== false ||
        typeof row.ok !== 'boolean' || !hash(row.modelSha256) || !hash(row.origin?.sha256)) reject();
    rows.set(row.id, row);
  }
  if (![...rows.values()].some((row) => !row.ok)) reject();
  for (const plan of plans) {
    const row = rows.get(plan.id);
    if (!row) reject();
    const snapshot = owned(root, `${NORMAL}/${plan.input}.spthy`);
    same(row.model, basename(snapshot));
    same(row.selectedLemmas, plan.names);
    // Legacy no-helper rows may lack the two new attribution fields. A helper
    // plan always requires both; partial or conflicting metadata never passes.
    if (plan.counterexample || plan.discharge || plan.helperLemmas.length || Object.hasOwn(row, 'helperLemmas') || Object.hasOwn(row, 'targetLemmas')) {
      same(row.helperLemmas, plan.helperLemmas);
      same(row.targetLemmas, plan.targetLemmas);
    }
    if (plan.counterexample) {
      same(row.mode, 'checked-counterexample');
      if (Object.hasOwn(row, 'witnessDischarge')) reject();
      same(row.arguments, counterexampleArguments(snapshot, plan.id));
      const attack = row.counterexampleDischarge;
      if (!attack || !Array.isArray(attack.checks) || attack.checks.length !== COUNTEREXAMPLE_CONTEXTS.length) reject();
      same(attack.profile, plan.counterexample.profile);
      same(attack.sourceBindings?.map(binding => binding.path), counterexampleBindingPaths(plan.model, manifest.sourceBindings));
      for (const [index, context] of COUNTEREXAMPLE_CONTEXTS.entries()) {
        const check = attack.checks[index], input = owned(root, `${NORMAL}/${plan.id}-${context}.spthy`);
        if (!check || !hash(check.modelSha256) || typeof check.ok !== 'boolean' || check.cancelled !== false || check.cleanupIncomplete !== false) reject();
        same(check.context, context); same(check.id, `${plan.id}-${context}`); same(check.model, basename(input));
        same(check.arguments, counterexampleArguments(input, plan.id));
        same(check.expectedRow, context === 'mutant' ? 'verified' : 'falsified - no trace found');
        if (Object.hasOwn(check.verdicts ?? {}, plan.targetLemmas[0])) reject();
        if (check.ok) {
          if (check.status !== 0 || check.signal || check.processError) reject();
          same(check.verdicts, { [plan.counterexample.checkedLemma]: { trace: 'exists-trace', verdict: context === 'mutant' ? 'verified' : 'falsified' } });
          const exact = context === 'mutant' ? /^verified \(\d+ steps\)$/ : /^falsified - no trace found \(\d+ steps\)$/;
          if (!exact.test(check.observedRow ?? '')) reject();
        }
      }
      const mutant = attack.checks[0];
      same(row.modelSha256, mutant.modelSha256); same(row.verdicts, mutant.verdicts);
      same(row.status, mutant.status); same(row.signal, mutant.signal); same(row.processError, mutant.processError);
      same(row.ok, attack.checks.every(check => check.ok));
      same(attack.coverage, counterexampleCoverage(attack.coverage, attack.checks));
      same(attack.coverage.discharged, row.ok);
    } else if (plan.discharge) {
      if (Object.hasOwn(row, 'counterexampleDischarge')) reject();
      same(row.mode, 'checked-strengthening');
      same(row.arguments, witnessArguments(snapshot));
      const witness = row.witnessDischarge;
      if (!witness || !hash(witness.proofSha256) || !Array.isArray(witness.checks) || witness.checks.length !== 3) reject();
      same(witness.profile, plan.discharge.profile); same(witness.proofSource, plan.discharge.proof);
      same(witness.proofSnapshot, `${plan.id}-proof.txt`);
      same(witness.sourceBindings?.map(binding => binding.path), witnessBindingPaths(plan.model, plan.discharge, manifest.sourceBindings));
      for (const [index, context] of WITNESS_CONTEXTS.entries()) {
        const check = witness.checks[index], input = owned(root, `${NORMAL}/${plan.id}-${context}.spthy`);
        if (!check || !hash(check.modelSha256) || typeof check.ok !== 'boolean' || check.cancelled !== false || check.cleanupIncomplete !== false) reject();
        same(check.context, context); same(check.id, `${plan.id}-${context}`); same(check.model, basename(input));
        same(check.arguments, witnessArguments(input));
        if (Object.hasOwn(check.verdicts ?? {}, plan.targetLemmas[0])) reject();
        same(check.expectedRow, context === 'good' ? 'verified' : 'analysis incomplete');
        if (check.ok) {
          if (check.status !== 0 || check.signal || check.processError) reject();
          same(check.verdicts, { [plan.discharge.checkedLemma]: { trace: 'exists-trace', verdict: context === 'good' ? 'verified' : 'inconclusive' } });
          const exact = context === 'good' ? /^verified \(\d+ steps\)$/ : /^analysis incomplete \(\d+ steps\)$/;
          if (!exact.test(check.observedRow ?? '')) reject();
        }
      }
      const good = witness.checks[0];
      same(row.modelSha256, good.modelSha256); same(row.verdicts, good.verdicts);
      same(row.status, good.status); same(row.signal, good.signal); same(row.processError, good.processError);
      same(row.ok, witness.checks.every(check => check.ok));
      same(witness.coverage?.discharged, row.ok);
    } else {
      if (Object.hasOwn(row, 'mode') || Object.hasOwn(row, 'witnessDischarge') || Object.hasOwn(row, 'counterexampleDischarge')) reject();
      same(row.arguments, proofArguments(snapshot, plan.expected, plan.model.helpers));
    }
    same(row.origin, { source: plan.model.path, sha256: row.origin.sha256, ...(plan.mutation ? { mutation: plan.mutation } : {}) });
  }
  // Manifest order, not log completion/array order; canaries never substitute.
  const selected = plans.find((plan) => plan.model.id === REQUEST_MODEL && !plan.mutation && rows.get(plan.id).ok === false) ?? null;
  return { plans, selected };
}

export function loadDiagnosticInputs(root) {
  root = realpathSync(root);
  const read = (path, limit = DIAGNOSTIC_OUTPUT_BYTES) => regular(owned(root, path), limit);
  const manifestFile = read('security/tamarin/manifest.json', 1024 * 1024), normal = read(`${NORMAL}/summary.json`, 2 * 1024 * 1024);
  const manifest = JSON.parse(utf8(manifestFile.bytes)), summary = JSON.parse(utf8(normal.bytes));
  const admitted = admitDiagnostic(manifest, summary, root);
  const version = read(`${NORMAL}/tool-version.log`, 1024 * 1024), versionText = utf8(version.bytes);
  if (!/tamarin[- ]prover\s+1\.12\.0\b/i.test(versionText) || /\bwarn(?:ing|ings)?\b|unsupported/i.test(versionText)) reject();
  const seenSources = new Set();
  for (const binding of manifest.sourceBindings) {
    if (!binding || !hash(binding.sha256) || seenSources.has(binding.path)) reject();
    seenSources.add(binding.path);
    if (sha256(utf8(read(binding.path).bytes).replace(/\r\n/g, '\n')) !== binding.sha256) reject();
  }
  const sources = new Map(), snapshots = new Map();
  for (const plan of admitted.plans) {
    let source = sources.get(plan.model.path);
    if (!source) { source = read(plan.model.path); sources.set(plan.model.path, source); }
    const text = utf8(source.bytes);
    validateTheoryRequirements(text, plan.model.expected, plan.model.helpers);
    if (plan.counterexample) {
      const row = summary.runs.find(candidate => candidate.id === plan.id), attack = row.counterexampleDischarge;
      if (source.sha256 !== row.origin.sha256) reject();
      for (const [index, context] of COUNTEREXAMPLE_CONTEXTS.entries()) {
        const derived = deriveCounterexample(text, plan.id, context), inputId = `${plan.id}-${context}`;
        const snapshot = read(`${NORMAL}/${inputId}.spthy`);
        if (!snapshot.bytes.equals(Buffer.from(derived.input)) || snapshot.sha256 !== attack.checks[index].modelSha256) reject();
        snapshots.set(inputId, snapshot);
        same(attack.coverage, counterexampleCoverage(derived.structural, attack.checks));
      }
      for (const binding of attack.sourceBindings) {
        if (!hash(binding.sha256) || !Number.isSafeInteger(binding.size) || binding.size <= 0 || binding.size > 1024 * 1024) reject();
        const current = read(binding.path, 1024 * 1024);
        if (current.sha256 !== binding.sha256 || current.size !== binding.size) reject();
      }
      if (!isAbsolute(attack.binary) || !hash(attack.binaryMetadata?.sha256) || !Number.isSafeInteger(attack.binaryMetadata?.size)) reject();
      const binary = regular(attack.binary, 150 * 1024 * 1024, false);
      if (binary.sha256 !== attack.binaryMetadata.sha256 || binary.size !== attack.binaryMetadata.size) reject();
      continue;
    }
    if (plan.discharge) {
      const row = summary.runs.find(candidate => candidate.id === plan.id), witness = row.witnessDischarge;
      const proof = read(plan.discharge.proof, 1024 * 1024), retained = read(`${NORMAL}/${witness.proofSnapshot}`, 1024 * 1024);
      if (!proof.bytes.equals(retained.bytes) || proof.sha256 !== witness.proofSha256 || source.sha256 !== row.origin.sha256) reject();
      for (const [index, context] of WITNESS_CONTEXTS.entries()) {
        const derived = deriveWitness(text, utf8(proof.bytes), plan.targetLemmas[0], context);
        const inputId = `${plan.id}-${context}`, snapshot = read(`${NORMAL}/${inputId}.spthy`);
        if (!snapshot.bytes.equals(Buffer.from(derived.input)) || snapshot.sha256 !== witness.checks[index].modelSha256) reject();
        snapshots.set(inputId, snapshot);
        if (context === 'good') same(witness.coverage, witnessCoverage(derived.structural, witness.checks));
      }
      for (const binding of witness.sourceBindings) {
        if (!hash(binding.sha256) || !Number.isSafeInteger(binding.size) || binding.size <= 0 || binding.size > 1024 * 1024) reject();
        const current = read(binding.path, 1024 * 1024);
        if (current.sha256 !== binding.sha256 || current.size !== binding.size) reject();
      }
      if (!isAbsolute(witness.binary) || !hash(witness.binaryMetadata?.sha256) || !Number.isSafeInteger(witness.binaryMetadata?.size)) reject();
      const binary = regular(witness.binary, 150 * 1024 * 1024, false);
      if (binary.sha256 !== witness.binaryMetadata.sha256 || binary.size !== witness.binaryMetadata.size) reject();
      continue;
    }
    let snapshot = snapshots.get(plan.input);
    if (!snapshot) { snapshot = read(`${NORMAL}/${plan.input}.spthy`); snapshots.set(plan.input, snapshot); }
    const expected = plan.mutation ? Buffer.from(mutateExactlyOnce(text, plan.mutation)) : source.bytes;
    const row = summary.runs.find((candidate) => candidate.id === plan.id);
    if (!snapshot.bytes.equals(expected) || snapshot.sha256 !== row.modelSha256 || source.sha256 !== row.origin.sha256) reject();
  }
  const identity = { normalSummarySha256: normal.sha256, manifestSha256: summary.manifestSha256,
    manifestFileSha256: manifestFile.sha256, toolVersionLogSha256: version.sha256 };
  const chosen = admitted.selected;
  return { root, identity, selected: chosen ? { row: chosen.id, lemma: chosen.discharge?.checkedLemma ?? chosen.targetLemmas[0], source: chosen.model.path,
    ...(chosen.discharge ? { originalObligation: chosen.targetLemmas[0], inputRole: 'checked-strengthening' } :
      chosen.model.helpers === undefined ? {} : { helpers: chosen.model.helpers }),
    inputSha256: snapshots.get(chosen.input).sha256, bytes: snapshots.get(chosen.input).bytes } : null };
}

export function diagnosticArguments(inputPath, selectedLemma, helpers) {
  const directory = dirname(inputPath);
  if (!isAbsolute(inputPath) || resolve(inputPath) !== inputPath || !lemma(selectedLemma) || basename(inputPath) !== 'request.input.spthy' ||
      !/^DIAGNOSTIC_ONLY-[A-Za-z0-9_-]+$/.test(basename(directory)) || basename(dirname(directory)) !== 'protocol-diagnostic' ||
      basename(dirname(dirname(directory))) !== 'artifacts') reject();
  const required = proofRequirements({ [selectedLemma]: { trace: 'all-traces', verdict: 'verified' } }, helpers);
  return [inputPath, '--quit-on-warning', ...required.selectedLemmas.map((name) => `--prove=${name}`), '--heuristic=i', `--bound=${DIAGNOSTIC_DEPTH}`, '--stop-on-trace=NONE', '+RTS', '-N2', '-M2G', '-RTS'];
}

export function diagnosticResult(result, log) {
  return { classification: 'DIAGNOSTIC_ONLY', eligibleAsProof: false,
    status: result.cancelled ? 'cancelled' : result.cleanupIncomplete ? 'cleanup_incomplete' : 'attempt_completed',
    process: { exitStatus: result.status ?? null, signal: result.signal ?? null, error: result.error ? 'prover_process_error' : null,
      cancelled: result.cancelled === true, cleanupIncomplete: result.cleanupIncomplete === true },
    log, logKind: 'combined_stdout_stderr_theory_skeleton_and_summary_not_a_pure_theory',
    normalProofVerdict: 'not_parsed_or_replaced' };
}

export function inspectDiagnosticLog(path) {
  try {
    const stat = lstatSync(path), isRegular = stat.isFile() && !stat.isSymbolicLink();
    if (!isRegular || stat.size > DIAGNOSTIC_OUTPUT_BYTES) return { exists: true, regular: isRegular,
      size: stat.size, rejected: 'nonregular_or_output_limit' };
    return { exists: true, regular: true, ...regular(path, DIAGNOSTIC_OUTPUT_BYTES, false) };
  }
  catch (error) {
    if (error.code === 'ENOENT') return { exists: false, regular: false };
    return { exists: null, regular: false, rejected: 'changed_or_unreadable' };
  }
}

function freshDirectory(root) {
  const parent = owned(root, DIAGNOSTIC);
  plainAncestors(parent);
  try { mkdirSync(parent, { mode: 0o700 }); } catch (error) { if (error.code !== 'EEXIST') throw error; }
  const stat = lstatSync(parent);
  if (!stat.isDirectory() || stat.isSymbolicLink()) reject();
  return mkdtempSync(join(parent, 'DIAGNOSTIC_ONLY-'));
}

export async function runProtocolDiagnostic(root = repository) {
  if (process.platform !== 'linux' || process.env.CI !== 'true') throw new Error('Diagnostic execution requires Linux CI.');
  const abort = new AbortController();
  const interrupt = () => abort.abort(new Error('Diagnostic interrupted by SIGINT.'));
  const terminate = () => abort.abort(new Error('Diagnostic interrupted by SIGTERM.'));
  process.on('SIGINT', interrupt); process.on('SIGTERM', terminate);
  try {
    const input = loadDiagnosticInputs(root);
    abort.signal.throwIfAborted();
    const directory = freshDirectory(input.root);
    const base = { classification: 'DIAGNOSTIC_ONLY', eligibleAsProof: false, toolVersion: '1.12.0', normal: input.identity,
      bounds: { depth: DIAGNOSTIC_DEPTH, timeoutMs: DIAGNOSTIC_TIMEOUT_MS, combinedOutputBytes: DIAGNOSTIC_OUTPUT_BYTES, maxInvocations: 1 } };
    let report;
    if (!input.selected) report = { ...base, status: 'not_applicable', reason: 'no_failed_request_baseline', attempted: false };
    else {
      const binary = process.env.TAMARIN_BIN;
      if (!binary || !isAbsolute(binary)) reject();
      const tool = regular(binary, 150 * 1024 * 1024, false);
      const path = join(directory, 'request.input.spthy');
      writeFileSync(path, input.selected.bytes, { flag: 'wx', mode: 0o400 });
      if (regular(path, DIAGNOSTIC_OUTPUT_BYTES, false).sha256 !== input.selected.inputSha256) reject();
      const args = diagnosticArguments(path, input.selected.lemma, input.selected.helpers);
      const before = loadDiagnosticInputs(input.root);
      same(before.identity, input.identity);
      same(before.selected, input.selected);
      writeFileSync(join(directory, 'invocation.json'), JSON.stringify({ ...base, selectedRow: input.selected.row,
        lemma: input.selected.lemma, source: input.selected.source, inputSha256: input.selected.inputSha256, binary, binaryMetadata: tool,
        helperLemmas: Object.keys(input.selected.helpers ?? {}), targetLemmas: [input.selected.lemma],
        binaryIdentityLimit: 'normal_summary_does_not_record_binary_identity_same_CI_TAMARIN_BIN_required', arguments: args }, null, 2), { flag: 'wx', mode: 0o600 });
      const logPath = join(directory, 'diagnostic.log');
      // Exactly one bounded runner call. It refuses an already-aborted signal.
      const result = await runProver(binary, args, { cwd: directory, logPath, timeoutMs: DIAGNOSTIC_TIMEOUT_MS,
        maxOutputBytes: DIAGNOSTIC_OUTPUT_BYTES, signal: abort.signal });
      let unchanged = false;
      try {
        const after = loadDiagnosticInputs(input.root);
        unchanged = isDeepStrictEqual(after.identity, input.identity) && isDeepStrictEqual(after.selected, input.selected) &&
          regular(path, DIAGNOSTIC_OUTPUT_BYTES, false).sha256 === input.selected.inputSha256 &&
          regular(binary, 150 * 1024 * 1024, false).sha256 === tool.sha256;
      } catch { /* Changed or unreadable evidence is not attributed to this input. */ }
      report = { ...base, ...diagnosticResult(result, inspectDiagnosticLog(logPath)), attempted: true,
        selectedRow: input.selected.row, lemma: input.selected.lemma, inputSha256: input.selected.inputSha256, inputsUnchanged: unchanged };
    }
    writeFileSync(join(directory, 'result.json'), JSON.stringify(report, null, 2), { flag: 'wx', mode: 0o600 });
    return { directory, ...report };
  } finally {
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', terminate);
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    if (process.argv.length !== 2) throw new Error('Diagnostic does not accept path or lemma overrides.');
    const report = await runProtocolDiagnostic();
    process.stdout.write(`${JSON.stringify(report)}\n`);
    if (report.status === 'cancelled') process.exitCode = 130;
    else if (report.status === 'cleanup_incomplete' || report.inputsUnchanged === false || report.log?.regular === false || report.log?.rejected) process.exitCode = 1;
  } catch {
    process.stderr.write(`${JSON.stringify({ classification: 'DIAGNOSTIC_ONLY', eligibleAsProof: false, status: 'rejected_or_unavailable' })}\n`);
    process.exitCode = 1;
  }
}
