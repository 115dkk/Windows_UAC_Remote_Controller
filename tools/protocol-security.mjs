// SPDX-License-Identifier: GPL-2.0-or-later
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { lstatSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { basename, isAbsolute, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const repository = fileURLToPath(new URL('../', import.meta.url));
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function parseProofSummary(result, expected, knownNames = Object.keys(expected), expectedModel) {
  const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replace(/\u001b\[[0-9;]*[A-Za-z]/g, '');
  const reasons = [];
  if (!Object.keys(expected).length) reasons.push('no required lemmas');
  if (result.error || result.signal || result.status !== 0) reasons.push('prover did not exit successfully');
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
  const entries = Object.entries(expected ?? {});
  if (!entries.length || entries.length > 32) throw new Error('Expected a bounded nonempty lemma manifest.');
  for (const [name, result] of entries) {
    if (!/^[A-Za-z][A-Za-z0-9_]*$/.test(name) || !['all-traces', 'exists-trace'].includes(result.trace) || !['verified', 'falsified'].includes(result.verdict)) throw new Error('Invalid required lemma.');
    if (baseline && result.verdict !== 'verified') throw new Error('Production models must verify every required property.');
  }
  if (baseline && !entries.some(([, value]) => value.trace === 'exists-trace')) throw new Error('Production model needs an executable honest trace (non-vacuity).');
  if (!baseline && !entries.some(([, value]) => value.verdict === 'falsified')) throw new Error('Negative control must expose an actual counterexample.');
}

export function runProtocolSecurity(root = repository) {
  const directory = resolve(root, 'artifacts/protocol-security');
  mkdirSync(directory, { recursive: true });
  const summary = resolve(directory, 'summary.json');
  const startedAt = new Date().toISOString();
  // Establish this invocation before manifest/tool/source checks. A failed
  // rerun must never leave a prior passed:true summary as current evidence.
  writeFileSync(summary, JSON.stringify({ passed: false, status: 'incomplete', startedAt, runs: [] }, null, 2));
  try { runProtocolSecurityImpl(root); }
  catch (error) {
    const partial = JSON.parse(readFileSync(summary, 'utf8'));
    writeFileSync(summary, JSON.stringify({ ...partial, passed: false, status: 'failed', startedAt, error: error.message }, null, 2));
    throw error;
  }
}

function runProtocolSecurityImpl(root) {
  const config = JSON.parse(readFileSync(resolve(root, 'security/tamarin/manifest.json'), 'utf8'));
  if (config.version !== 1 || config.toolVersion !== '1.12.0' || !Array.isArray(config.models) || config.models.length < 2 || config.models.length > 8) throw new Error('Unsupported security model manifest.');
  if (!Array.isArray(config.sourceBindings) || !config.sourceBindings.length || config.sourceBindings.length > 32) throw new Error('Models need reviewed source bindings.');
  for (const binding of config.sourceBindings) {
    const path = ownedPath(root, binding.path);
    if (!/^[0-9a-f]{64}$/.test(binding.sha256) || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink() || sha256(readFileSync(path, 'utf8').replace(/\r\n/g, '\n')) !== binding.sha256) {
      throw new Error(`Protocol source changed; review model alignment before updating its binding: ${binding.path}`);
    }
  }
  const binary = process.env.TAMARIN_BIN || 'tamarin-prover';
  const version = spawnSync(binary, ['--version'], { encoding: 'utf8', timeout: 30_000 });
  if (version.status !== 0 || version.error || version.signal || !/tamarin[- ]prover\s+1\.12\.0\b/i.test(version.stdout + version.stderr)) throw new Error('Pinned Tamarin 1.12.0 is required; missing tools never pass.');
  const directory = resolve(root, 'artifacts/protocol-security');
  mkdirSync(directory, { recursive: true });
  const runs = [];
  const ids = new Set();
  function execute(id, path, expected, knownNames, selected, origin) {
    if (!/^[a-z][a-z0-9-]{0,47}$/.test(id) || ids.has(id)) throw new Error('Invalid/duplicate protocol evidence id.');
    ids.add(id);
    const before = readFileSync(path);
    const inputHash = sha256(before);
    const args = [path, '--quit-on-warning', ...(selected ? Object.keys(expected).map((name) => `--prove=${name}`) : ['--prove']), '+RTS', '-N2', '-RTS'];
    process.stdout.write(`Protocol security: ${id}\n`);
    const result = spawnSync(binary, args, { cwd: root, encoding: 'utf8', timeout: 300_000, maxBuffer: 32 * 1024 * 1024, windowsHide: true });
    const log = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
    writeFileSync(joinEvidence(id, 'log'), log);
    const proof = parseProofSummary(result, expected, knownNames, path);
    if (sha256(readFileSync(path)) !== inputHash) { proof.ok = false; proof.reasons.push('prover input changed during execution'); }
    const row = { id, model: basename(path), modelSha256: inputHash, origin, status: result.status, signal: result.signal, ...proof };
    runs.push(row);
    process.stdout.write(`${JSON.stringify(row)}\n`);
    return proof.ok;
  }
  function joinEvidence(id, extension) { return resolve(directory, `${id}.${extension}`); }
  let passed = true;
  for (const model of config.models) {
    validateExpected(model.expected, true);
    const path = ownedPath(root, model.path);
    if (!path.endsWith('.spthy') || !lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) throw new Error('Expected a regular theory source.');
    const source = readFileSync(path, 'utf8');
    if (/^\s*#include\b/m.test(source)) throw new Error('External model inputs need explicit immutable snapshot support.');
    const names = Object.keys(model.expected);
    if (!/^[a-z][a-z0-9-]{0,47}$/.test(model.id)) throw new Error('Invalid model id.');
    const snapshot = joinEvidence(model.id, 'spthy');
    writeFileSync(snapshot, source);
    const sourceHash = sha256(source);
    passed = execute(model.id, snapshot, model.expected, names, false, { source: model.path, sha256: sourceHash }) && passed;
    if (!Array.isArray(model.canaries) || !model.canaries.length || model.canaries.length > 4) throw new Error('Every model needs bounded real negative controls.');
    for (const canary of model.canaries) {
      validateExpected(canary.expected, false);
      if (Object.keys(canary.expected).some((name) => !names.includes(name))) throw new Error('Canary must falsify a production property.');
      const modified = mutateExactlyOnce(source, canary.mutation);
      const path = joinEvidence(canary.id, 'spthy');
      // execute validates IDs too; validate before creating this path.
      if (!/^[a-z][a-z0-9-]{0,47}$/.test(canary.id)) throw new Error('Invalid canary id.');
      writeFileSync(path, modified);
      passed = execute(canary.id, path, canary.expected, names, true, { source: model.path, sha256: sourceHash, mutation: canary.mutation }) && passed;
    }
  }
  writeFileSync(resolve(directory, 'summary.json'), JSON.stringify({ toolVersion: config.toolVersion, manifestSha256: sha256(JSON.stringify(config)), passed, runs,
    scope: 'Symbolic models and stated assumptions only; not implementation refinement, native isolation, real boot/authentication or latency.' }, null, 2));
  if (!passed) throw new Error('Required protocol proofs/negative controls failed or were inconclusive.');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try { runProtocolSecurity(); } catch (error) { process.stderr.write(`Protocol security gate: ${error.message}\n`); process.exitCode = 1; }
}
