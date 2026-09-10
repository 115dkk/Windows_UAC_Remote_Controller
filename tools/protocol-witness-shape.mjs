// SPDX-License-Identifier: GPL-2.0-or-later
// One isolated witness-search experiment. NEVER a normal security gate.
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
    & (All d r b #x. SnapshotCaptured(pc, d, r, b) @x ==> x = c)
    & (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> x = e)"`;
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const expected = { honest_approve_trace: { trace: 'exists-trace', verdict: 'verified' } };

export function shapeWitness(source) {
  assert.equal(typeof source, 'string');
  assert.ok(Buffer.byteLength(source) <= 1024 * 1024);
  const normalized = source.replace(/\r\n/g, '\n');
  assert.equal(hash(normalized), ORIGIN_HASH, 'The reviewed original model changed.');
  const candidate = mutateExactlyOnce(normalized, { from: ORIGINAL, to: SHAPED });
  assert.equal(mutateExactlyOnce(candidate, { from: SHAPED, to: ORIGINAL }), normalized);
  return { normalized, candidate };
}

async function main() {
  assert.equal(process.platform, 'linux');
  assert.equal(process.env.CI, 'true');
  assert.equal(process.env.GITHUB_ACTIONS, 'true');
  assert.equal(process.argv.length, 2);
  const binary = process.env.TAMARIN_BIN;
  assert.ok(typeof binary === 'string' && isAbsolute(binary));
  assert.ok(lstatSync(binary).isFile() && !lstatSync(binary).isSymbolicLink());
  const origin = resolve(root, 'security/tamarin/RequestAuthorization.spthy');
  assert.ok(lstatSync(origin).isFile() && !lstatSync(origin).isSymbolicLink());
  const { normalized, candidate } = shapeWitness(readFileSync(origin, 'utf8'));
  const base = resolve(root, 'artifacts/protocol-witness-shape');
  mkdirSync(base, { recursive: true });
  const directory = mkdtempSync(resolve(base, 'witness-'));
  const input = resolve(directory, 'request.input.spthy');
  writeFileSync(input, candidate, { flag: 'wx' });
  const args = proofArguments(input, expected);
  const controller = new AbortController();
  const stop = () => controller.abort(new Error('Witness experiment interrupted.'));
  process.once('SIGINT', stop);
  process.once('SIGTERM', stop);
  let report = {
    classification: 'WITNESS_SHAPE_EXPERIMENT_ONLY', eligibleAsNormalGate: false,
    originSha256: hash(normalized), candidateSha256: hash(candidate),
    originalRulesRestrictionsAndOtherLemmasUnchanged: true,
    bounds: { invocations: 1, timeoutMs: 120000, outputBytes: 4 * 1024 * 1024 },
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
    const manifest = JSON.parse(readFileSync(resolve(root, 'security/tamarin/manifest.json'), 'utf8'));
    const known = Object.keys(manifest.models.find((model) => model.id === 'request-authorization').expected);
    const verdict = parseProofSummary(result, expected, known, input);
    const unchanged = hash(readFileSync(input)) === hash(candidate)
      && hash(readFileSync(origin, 'utf8').replace(/\r\n/g, '\n')) === ORIGIN_HASH;
    report = { ...report, completed: !result.error && result.status === 0,
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
