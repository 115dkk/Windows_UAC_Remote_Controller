// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only partial-proof investigation. NEVER normal proof evidence or a fallback.
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readSync, realpathSync, writeFileSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, parse, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { isDeepStrictEqual } from 'node:util';
import { mutateExactlyOnce, proofArguments } from './protocol-security.mjs';
import { runProver } from './prover-process.mjs';

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
    names.forEach((name, index) => add({ id: `${model.id}-${index + 1}`, input: model.id, model, names: [name], expected: { [name]: model.expected[name] } }));
    if (!Array.isArray(model.canaries) || !model.canaries.length || model.canaries.length > 4) reject();
    for (const canary of model.canaries) {
      if (!id(canary.id) || inputs.has(canary.id) || !canary.mutation ||
          typeof canary.mutation.from !== 'string' || !canary.mutation.from ||
          typeof canary.mutation.to !== 'string' || canary.mutation.from === canary.mutation.to) reject();
      inputs.add(canary.id);
      const selected = expectedNames(canary.expected, false);
      if (selected.some((name) => !names.includes(name))) reject();
      add({ id: canary.id, input: canary.id, model, names: selected, expected: canary.expected, mutation: canary.mutation });
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
    same(row.arguments, proofArguments(snapshot, plan.expected));
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
  if (!/tamarin[- ]prover\s+1\.12\.0\b/i.test(versionText) || /WARNING:|unsupported/i.test(versionText)) reject();
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
    if (/^\s*#include\b/m.test(text)) reject();
    for (const name of plan.names) if ([...text.matchAll(new RegExp(`^\\s*lemma\\s+${name}\\b`, 'gm'))].length !== 1) reject();
    let snapshot = snapshots.get(plan.input);
    if (!snapshot) { snapshot = read(`${NORMAL}/${plan.input}.spthy`); snapshots.set(plan.input, snapshot); }
    const expected = plan.mutation ? Buffer.from(mutateExactlyOnce(text, plan.mutation)) : source.bytes;
    const row = summary.runs.find((candidate) => candidate.id === plan.id);
    if (!snapshot.bytes.equals(expected) || snapshot.sha256 !== row.modelSha256 || source.sha256 !== row.origin.sha256) reject();
  }
  const identity = { normalSummarySha256: normal.sha256, manifestSha256: summary.manifestSha256,
    manifestFileSha256: manifestFile.sha256, toolVersionLogSha256: version.sha256 };
  const chosen = admitted.selected;
  return { root, identity, selected: chosen ? { row: chosen.id, lemma: chosen.names[0], source: chosen.model.path,
    inputSha256: snapshots.get(chosen.input).sha256, bytes: snapshots.get(chosen.input).bytes } : null };
}

export function diagnosticArguments(inputPath, selectedLemma) {
  const directory = dirname(inputPath);
  if (!isAbsolute(inputPath) || resolve(inputPath) !== inputPath || !lemma(selectedLemma) || basename(inputPath) !== 'request.input.spthy' ||
      !/^DIAGNOSTIC_ONLY-[A-Za-z0-9_-]+$/.test(basename(directory)) || basename(dirname(directory)) !== 'protocol-diagnostic' ||
      basename(dirname(dirname(directory))) !== 'artifacts') reject();
  return [inputPath, '--quit-on-warning', `--prove=${selectedLemma}`, '--heuristic=i', `--bound=${DIAGNOSTIC_DEPTH}`, '--stop-on-trace=NONE', '+RTS', '-N2', '-M2G', '-RTS'];
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
      const args = diagnosticArguments(path, input.selected.lemma);
      const before = loadDiagnosticInputs(input.root);
      same(before.identity, input.identity);
      same(before.selected, input.selected);
      writeFileSync(join(directory, 'invocation.json'), JSON.stringify({ ...base, selectedRow: input.selected.row,
        lemma: input.selected.lemma, source: input.selected.source, inputSha256: input.selected.inputSha256, binary, binaryMetadata: tool,
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
