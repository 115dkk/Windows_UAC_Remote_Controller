// SPDX-License-Identifier: GPL-2.0-or-later
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProver } from './prover-process.mjs';

const repository = fileURLToPath(new URL('../', import.meta.url));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

const lemmaName = (name) => /^[A-Za-z][A-Za-z0-9_]{0,127}$/.test(name);
const dictionary = (value) => value !== null && typeof value === 'object' && !Array.isArray(value) &&
  [Object.prototype, null].includes(Object.getPrototypeOf(value));

function requiredEntries(expected, limit) {
  if (!dictionary(expected)) throw new Error('Expected a lemma dictionary.');
  const entries = Object.entries(expected);
  if (!entries.length || entries.length > limit || Reflect.ownKeys(expected).length !== entries.length) throw new Error('Expected a bounded nonempty lemma manifest.');
  for (const [name, result] of entries) {
    if (!lemmaName(name) || !dictionary(result) || Reflect.ownKeys(result).length !== 2 ||
        !Object.hasOwn(result, 'trace') || !Object.hasOwn(result, 'verdict') ||
        !['all-traces', 'exists-trace'].includes(result.trace) || !['verified', 'falsified'].includes(result.verdict)) throw new Error('Invalid required lemma.');
  }
  return entries;
}

// Helpers are additional same-invocation obligations, never assumed proofs or
// substitutes for selected production/canary targets. Absence retains legacy
// behavior; supplying an empty/ambiguous helper dictionary is an error.
export function proofRequirements(selectedObligations, helpers) {
  const targets = requiredEntries(selectedObligations, 32);
  const auxiliary = helpers === undefined ? [] : requiredEntries(helpers, 8);
  for (const [name, result] of auxiliary) {
    if (result.trace !== 'all-traces' || result.verdict !== 'verified' || Object.hasOwn(selectedObligations, name)) throw new Error('Helpers must be distinct verified all-traces obligations.');
  }
  const targetLemmas = targets.map(([name]) => name), helperLemmas = auxiliary.map(([name]) => name);
  return { targetLemmas, helperLemmas, selectedLemmas: [...helperLemmas, ...targetLemmas],
    expected: Object.fromEntries([...auxiliary, ...targets]) };
}

export function proofArguments(path, selectedObligations, helpers) {
  const required = proofRequirements(selectedObligations, helpers);
  // A single long branch must not starve a short honest/attack witness. BFS
  // changes search order only, never the trace set, lemmas or acceptance rule.
  const witness = Object.values(selectedObligations).every((result) =>
    result.trace === 'exists-trace' || result.verdict === 'falsified');
  return [path, '--quit-on-warning', ...required.selectedLemmas.map((name) => `--prove=${name}`),
    `--stop-on-trace=${witness ? 'BFS' : 'DFS'}`, '+RTS', '-N2', '-M2G', '-RTS'];
}

export function parseProofSummary(result, expected, knownNames = Object.keys(expected), expectedModel) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  const reasons = [];
  if (!Object.keys(expected).length) reasons.push('no required lemmas');
  if (result.error || result.signal || result.status !== 0) reasons.push('prover did not exit successfully');
  if (result.cancelled || result.cleanupIncomplete) reasons.push('prover process ownership did not complete');
  if (/\bwarn(?:ing|ings)?\b|returned unsupported version/i.test(output)) reasons.push('prover warning or unsupported dependency');
  const index = output.lastIndexOf('summary of summaries:');
  if (index < 0) reasons.push('missing final prover summary');
  if ((output.match(/summary of summaries:/g) ?? []).length !== 1) reasons.push('ambiguous prover summaries');
  const summary = index < 0 ? '' : output.slice(index);
  const analyzed = [...summary.matchAll(/^\s*analyzed:\s*([^\r\n]+)$/gm)].map((match) => match[1].trim());
  if (!expectedModel || analyzed.length !== 1 || analyzed[0] !== expectedModel) reasons.push('analyzed model does not match the exact invoked input');
  const verdicts = Object.create(null);
  for (const match of summary.matchAll(/^\s*([A-Za-z0-9_]+)\s+\((all-traces|exists-trace)\):\s*(.+)$/gm)) {
    const [, name, trace, text] = match;
    if (Object.hasOwn(verdicts, name)) reasons.push(`duplicate lemma ${name}`);
    if (!knownNames.includes(name)) reasons.push(`unregistered lemma ${name}`);
    const verdict = /^verified \(\d+ steps\)\s*$/.test(text) ? 'verified'
      : /^falsified(?: - found trace)? \(\d+ steps\)\s*$/.test(text) ? 'falsified' : 'inconclusive';
    verdicts[name] = { trace, verdict };
  }
  for (const [name, wanted] of Object.entries(expected)) {
    const actual = verdicts[name];
    if (!actual || actual.trace !== wanted.trace || actual.verdict !== wanted.verdict) reasons.push(`required lemma ${name} did not yield ${wanted.verdict}`);
  }
  return { ok: reasons.length === 0, reasons, verdicts };
}

export function mutateExactlyOnce(source, mutation) {
  if (!mutation || typeof mutation.from !== 'string' || !mutation.from || typeof mutation.to !== 'string' || mutation.to === mutation.from) throw new Error('Invalid negative-control mutation.');
  const at = source.indexOf(mutation.from);
  if (at < 0 || source.indexOf(mutation.from, at + mutation.from.length) >= 0) throw new Error('Negative-control marker must occur exactly once.');
  return source.slice(0, at) + mutation.to + source.slice(at + mutation.from.length);
}

function ownedPath(root, child) {
  if (typeof child !== 'string' || isAbsolute(child)) throw new Error('Expected a repository-relative model path.');
  const path = resolve(root, child);
  const rel = relative(root, path);
  if (!rel || rel.startsWith('..') || isAbsolute(rel)) throw new Error('Model path leaves its owned root.');
  return path;
}

function validateExpected(expected, baseline) {
  const entries = requiredEntries(expected, 32);
  for (const [, result] of entries) {
    if (baseline && result.verdict !== 'verified') throw new Error('Production models must verify every required property.');
  }
  if (baseline && !entries.some(([, value]) => value.trace === 'exists-trace')) throw new Error('Production model needs an executable honest trace (non-vacuity).');
  if (!baseline && !entries.some(([, value]) => value.verdict === 'falsified')) throw new Error('Negative control must expose an actual counterexample.');
}

// Admit authored lemma declarations, not a retained/generated proof or source
// axiom. Every helper must be declared once, before originals, with explicit
// all-traces kind and reuse only after this invocation actually proves it.
export function validateTheoryRequirements(source, obligations, helpers) {
  const required = proofRequirements(obligations, helpers);
  if (typeof source !== 'string' || /^\s*#include\b/m.test(source)) throw new Error('External model inputs need explicit immutable snapshot support.');
  const plain = source.replace(/\/\*[\s\S]*?\*\/|\/\/[^\r\n]*/g, '');
  if (/^\s*(?:by|axiom)\b/m.test(plain)) throw new Error('Imported or assumed proof text is not an authored obligation.');
  const declarations = [...plain.matchAll(/^\s*lemma\s+([A-Za-z][A-Za-z0-9_]*)\s*(?:\[([^\]\r\n]*)\])?\s*:\s*/gm)];
  const names = declarations.map((match) => match[1]);
  if (new Set(names).size !== names.length || names.length !== required.selectedLemmas.length ||
      required.selectedLemmas.some((name) => !names.includes(name))) throw new Error('Theory declarations differ from registered obligations and helpers.');
  for (const [index, declaration] of declarations.entries()) {
    const name = declaration[1], attributes = (declaration[2] ?? '').split(',').map((value) => value.trim()).filter(Boolean);
    if (attributes.includes('sources') || new Set(attributes).size !== attributes.length) throw new Error('Source assumptions or duplicate lemma attributes are not admitted.');
    const body = plain.slice(declaration.index + declaration[0].length, declarations[index + 1]?.index)
      .replace(/\s+end\s*$/, '').trim();
    const formula = /^(?:(all-traces|exists-trace)\s+)?"(?:[^"\\]|\\.)*"\s*$/.exec(body);
    if (!formula || (formula[1] ?? 'all-traces') !== required.expected[name].trace) throw new Error('Lemma kind changed or imported proof text follows its formula.');
    if (required.helperLemmas.includes(name)) {
      if (name !== required.helperLemmas[index] || formula[1] !== 'all-traces' ||
          !attributes.includes('reuse') || attributes.some((attribute) => !['reuse', 'use_induction'].includes(attribute))) throw new Error('Helper declaration kind, order or attributes changed.');
    } else if (attributes.includes('reuse')) throw new Error('Only registered same-invocation helpers may be reused.');
  }
  return required;
}

export async function runProtocolSecurity(root = repository) {
  const directory = resolve(root, 'artifacts/protocol-security');
  mkdirSync(directory, { recursive: true });
  const summary = resolve(directory, 'summary.json');
  const startedAt = new Date().toISOString();
  // Establish this invocation before manifest/tool/source checks. A failed
  // rerun must never leave a prior passed:true summary as current evidence.
  writeFileSync(summary, JSON.stringify({ passed: false, status: 'incomplete', startedAt, runs: [] }, null, 2));
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort(new Error('Protocol proof run interrupted by SIGINT.'));
  const terminate = () => cancellation.abort(new Error('Protocol proof run interrupted by SIGTERM.'));
  process.on('SIGINT', interrupt);
  process.on('SIGTERM', terminate);
  try { await runProtocolSecurityImpl(root, cancellation.signal); }
  catch (error) {
    const partial = JSON.parse(readFileSync(summary, 'utf8'));
    writeFileSync(summary, JSON.stringify({ ...partial, passed: false, status: 'failed', startedAt, error: error.message }, null, 2));
    throw error;
  } finally {
    process.removeListener('SIGINT', interrupt);
    process.removeListener('SIGTERM', terminate);
  }
}

async function runProtocolSecurityImpl(root, cancellation) {
  const config = JSON.parse(readFileSync(resolve(root, 'security/tamarin/manifest.json'), 'utf8'));
  if (config.version !== 1 || config.toolVersion !== '1.12.0' || !Array.isArray(config.models) || config.models.length < 2 || config.models.length > 8) throw new Error('Unsupported security model manifest.');
  if (!Array.isArray(config.sourceBindings) || !config.sourceBindings.length || config.sourceBindings.length > 32) throw new Error('Models need reviewed source bindings.');
  for (const binding of config.sourceBindings) {
    const path = ownedPath(root, binding.path);
    if (!/^[0-9a-f]{64}$/.test(binding.sha256) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink() || sha256(readFileSync(path, 'utf8').replace(/\r\n/g, '\n')) !== binding.sha256) {
      throw new Error(`Protocol source changed; review model alignment before updating its binding: ${binding.path}`);
    }
  }
  const inputIds = new Set(), plannedRuns = new Set(['tool-version']);
  const reserve = (set, id) => {
    if (!/^[a-z][a-z0-9-]{0,47}$/.test(id) || set.has(id)) throw new Error('Invalid/duplicate protocol evidence id.');
    set.add(id);
  };
  // Reserve input identities separately from per-lemma log identities BEFORE
  // any snapshot write. A canary must not overwrite its baseline or another
  // model's retained input merely because run IDs now end in -1, -2, etc.
  for (const model of config.models) {
    validateExpected(model.expected, true);
    proofRequirements(model.expected, model.helpers);
    reserve(inputIds, model.id);
    const names = Object.keys(model.expected);
    for (const [index] of names.entries()) reserve(plannedRuns, `${model.id}-${index + 1}`);
    if (!Array.isArray(model.canaries) || !model.canaries.length || model.canaries.length > 4) throw new Error('Every model needs bounded real negative controls.');
    for (const canary of model.canaries) {
      validateExpected(canary.expected, false);
      if (Object.keys(canary.expected).some((name) => !names.includes(name))) throw new Error('Canary must falsify a production property.');
      reserve(inputIds, canary.id);
      reserve(plannedRuns, canary.id);
    }
  }
  // The helper's Windows unit fixtures own direct children only. Actual formal
  // proofs require Linux process-group cleanup, never a partial tree promise.
  if (process.platform !== 'linux') throw new Error('Formal prover execution requires Linux process-group ownership.');
  cancellation.throwIfAborted();
  const binary = process.env.TAMARIN_BIN || 'tamarin-prover';
  const directory = resolve(root, 'artifacts/protocol-security');
  const version = await runProver(binary, ['--version'], { cwd: root,
    logPath: resolve(directory, 'tool-version.log'), timeoutMs: 30_000, maxOutputBytes: 1024 * 1024, signal: cancellation });
  cancellation.throwIfAborted();
  if (version.status !== 0 || version.error || version.signal || /\bwarn(?:ing|ings)?\b|unsupported/i.test(version.stdout + version.stderr) || !/tamarin[- ]prover\s+1\.12\.0\b/i.test(version.stdout + version.stderr)) throw new Error('Pinned Tamarin 1.12.0 and supported Maude are required; missing/unsupported tools never pass.');
  const runs = [];
  const ids = new Set();
  async function execute(id, path, expected, helpers, knownNames, origin, expectedInputHash) {
    cancellation.throwIfAborted();
    if (!/^[a-z][a-z0-9-]{0,47}$/.test(id) || ids.has(id)) throw new Error('Invalid/duplicate protocol evidence id.');
    ids.add(id);
    const before = readFileSync(path);
    const inputHash = sha256(before);
    if (inputHash !== expectedInputHash) throw new Error('Immutable prover snapshot changed before invocation.');
    const required = proofRequirements(expected, helpers);
    const args = proofArguments(path, expected, helpers);
    process.stdout.write(`Protocol security: ${id}\n`);
    const result = await runProver(binary, args, { cwd: root, logPath: joinEvidence(id, 'log'), signal: cancellation });
    const proof = parseProofSummary(result, required.expected, knownNames, path);
    try {
      if (sha256(readFileSync(path)) !== inputHash) { proof.ok = false; proof.reasons.push('prover input changed during execution'); }
    } catch { proof.ok = false; proof.reasons.push('prover input could not be re-read after execution'); }
    const row = { id, model: basename(path), modelSha256: inputHash, origin, helperLemmas: required.helperLemmas,
      targetLemmas: required.targetLemmas, selectedLemmas: required.selectedLemmas, arguments: args, status: result.status, signal: result.signal,
      processError: result.error?.message, cleanupIncomplete: result.cleanupIncomplete, cancelled: result.cancelled, ...proof };
    runs.push(row);
    process.stdout.write(`${JSON.stringify(row)}\n`);
    writeFileSync(resolve(directory, 'summary.json'), JSON.stringify({ toolVersion: config.toolVersion, passed: false, status: 'incomplete', runs }, null, 2));
    // Record the interrupted/uncertain row first, then stop this invocation.
    // A handled parent signal must not resume the remaining proof queue.
    cancellation.throwIfAborted();
    if (result.cleanupIncomplete) throw new Error('Prover cleanup is uncertain; no further proof groups may start.');
    return proof.ok;
  }
  function joinEvidence(id, extension) { return resolve(directory, `${id}.${extension}`); }
  let passed = true;
  for (const model of config.models) {
    validateExpected(model.expected, true);
    const path = ownedPath(root, model.path);
    if (!path.endsWith('.spthy') || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error('Expected a regular theory source.');
    const source = readFileSync(path, 'utf8');
    const registered = validateTheoryRequirements(source, model.expected, model.helpers);
    const names = Object.keys(model.expected);
    if (!/^[a-z][a-z0-9-]{0,47}$/.test(model.id)) throw new Error('Invalid model id.');
    const snapshot = joinEvidence(model.id, 'spthy');
    writeFileSync(snapshot, source);
    const sourceHash = sha256(source);
    // Isolate every positive lemma: one divergent search cannot hide the other
    // verdicts or consume their time/memory budget. Every lemma is still required.
    for (const [index, name] of names.entries()) {
      passed = await execute(`${model.id}-${index + 1}`, snapshot, { [name]: model.expected[name] }, model.helpers, registered.selectedLemmas, { source: model.path, sha256: sourceHash }, sourceHash) && passed;
    }
    if (!Array.isArray(model.canaries) || !model.canaries.length || model.canaries.length > 4) throw new Error('Every model needs bounded real negative controls.');
    for (const canary of model.canaries) {
      validateExpected(canary.expected, false);
      if (Object.keys(canary.expected).some((name) => !names.includes(name))) throw new Error('Canary must falsify a production property.');
      const modified = mutateExactlyOnce(source, canary.mutation);
      const path = joinEvidence(canary.id, 'spthy');
      // execute validates IDs too; validate before creating this path.
      if (!/^[a-z][a-z0-9-]{0,47}$/.test(canary.id)) throw new Error('Invalid canary id.');
      writeFileSync(path, modified);
      validateTheoryRequirements(modified, model.expected, model.helpers);
      passed = await execute(canary.id, path, canary.expected, model.helpers, registered.selectedLemmas, { source: model.path, sha256: sourceHash, mutation: canary.mutation }, sha256(modified)) && passed;
    }
  }
  writeFileSync(resolve(directory, 'summary.json'), JSON.stringify({ toolVersion: config.toolVersion, manifestSha256: sha256(JSON.stringify(config)), passed, runs,
    scope: 'Symbolic models and stated assumptions only; not implementation refinement, native isolation, real boot/authentication or latency.' }, null, 2));
  if (!passed) throw new Error('Required protocol proofs/negative controls failed or were inconclusive.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { await runProtocolSecurity(); } catch (error) { process.stderr.write(`Protocol security gate: ${error.message}\n`); process.exitCode = 1; }
}
