// SPDX-License-Identifier: GPL-2.0-or-later
// One CI-only stored-proof navigation attempt. NEVER normal proof evidence.
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readSync, writeFileSync } from 'node:fs';
import { isAbsolute, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { runProver } from './prover-process.mjs';
import { DIAGNOSTIC_DEPTH, DIAGNOSTIC_OUTPUT_BYTES, DIAGNOSTIC_TIMEOUT_MS } from './protocol-diagnostic.mjs';

const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const ORIGIN = 'security/tamarin/RequestAuthorization.spthy';
export const CANDIDATE = 'security/tamarin/candidates/HonestApproveNavigation.spthy';
const MAX_SOURCE_BYTES = 1024 * 1024;
const HEADER = '\nlemma honest_approve_trace:\n';
const FORMULA_END = '\n    & o < u & u < a"';
const NEXT = '\nlemma honest_deny_without_approval_auth_trace:\n';
const reject = () => { throw new Error('Candidate source or execution admission rejected.'); };
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');

function normalized(text) {
  if (typeof text !== 'string' || !text || text.includes('\0') || Buffer.byteLength(text) > MAX_SOURCE_BYTES) reject();
  // Only line endings and the number of terminal LF characters are normalized.
  // Internal whitespace, comments, rules and formulas must otherwise match.
  return text.replace(/\r\n?/gu, '\n').replace(/\n+$/u, '\n');
}
function unique(text, token) {
  const at = text.indexOf(token);
  if (at < 0 || text.indexOf(token, at + token.length) >= 0) reject();
  return at;
}

/** Text admission only, NOT a Tamarin parser or a proof-syntax/validity check. */
export function admitCandidateSource(origin, candidate) {
  const production = normalized(origin), proposed = normalized(candidate);
  const head = unique(production, HEADER), end = unique(production, FORMULA_END) + FORMULA_END.length;
  const next = unique(production, NEXT);
  const proposedHead = unique(proposed, HEADER), proposedEnd = unique(proposed, FORMULA_END) + FORMULA_END.length;
  const proposedNext = unique(proposed, NEXT);
  if (!(head < end && end < next && proposedHead < proposedEnd && proposedEnd < proposedNext)) reject();
  const gap = production.slice(end, next);
  if (gap.trim() || !gap.length) reject(); // Product must not already contain a stored proof here.
  const inserted = proposed.slice(proposedEnd, proposedNext);
  const restored = proposed.slice(0, proposedEnd) + gap + proposed.slice(proposedNext);
  if (restored !== production || !inserted.includes('\nsimplify\n') || !inserted.includes('\nsolve(') || !inserted.trimEnd().endsWith('qed')) reject();
  if (/#\s*(?:include|define|undef|if|ifdef|ifndef|else|endif)\b/iu.test(proposed) ||
      /\b(?:lemma|rule|restriction|axiom|builtins|functions|equations|heuristic|tactic|configuration|theory|begin|end|oracle)\b/iu.test(inserted)) reject();
  return { insertedScript: inserted, normalizedProduction: production };
}

export function admitCandidateEnvironment(args, env, platform) {
  if (args.length !== 0 || platform !== 'linux' || env.CI !== 'true' || env.GITHUB_ACTIONS !== 'true' ||
      typeof env.TAMARIN_BIN !== 'string' || !isAbsolute(env.TAMARIN_BIN)) reject();
  return env.TAMARIN_BIN;
}

export function candidateArguments(input) {
  return [input, '--quit-on-warning', '--prove=honest_approve_trace', '--heuristic=i', `--bound=${DIAGNOSTIC_DEPTH}`,
    '--stop-on-trace=NONE', '+RTS', '-N2', '-M2G', '-RTS'];
}

export function candidateProcessResult(result) {
  const complete = result.status === 0 && !result.signal && !result.error && !result.cancelled && !result.cleanupIncomplete;
  return { classification: 'CANDIDATE_ONLY', eligibleAsProof: false, processCompleted: complete,
    process: { status: result.status ?? null, signal: result.signal ?? null,
      error: result.error ? String(result.error.message ?? result.error).slice(0, 2000) : null,
      cancelled: result.cancelled === true, cleanupIncomplete: result.cleanupIncomplete === true } };
}

function regular(path) {
  if (!lstatSync(path).isFile() || lstatSync(path).isSymbolicLink()) reject();
  const fd = openSync(path, constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0));
  try {
    const before = fstatSync(fd);
    if (!before.isFile() || before.size <= 0 || before.size > MAX_SOURCE_BYTES) reject();
    const bytes = Buffer.alloc(MAX_SOURCE_BYTES + 1);
    let used = 0;
    while (used < bytes.length) {
      const count = readSync(fd, bytes, used, bytes.length - used, null);
      if (count === 0) break;
      used += count;
    }
    if (used !== before.size || used > MAX_SOURCE_BYTES || fstatSync(fd).size !== used) reject();
    const data = bytes.subarray(0, used);
    return { bytes: data, sha256: hash(data), text: new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(data) };
  } finally { closeSync(fd); }
}

async function main() {
  const binary = admitCandidateEnvironment(process.argv.slice(2), process.env, process.platform);
  const tool = lstatSync(binary);
  if (!tool.isFile() || tool.isSymbolicLink()) reject();
  const base = resolve(ROOT, 'artifacts/protocol-candidate');
  mkdirSync(base, { recursive: true });
  if (!lstatSync(base).isDirectory() || lstatSync(base).isSymbolicLink()) reject();
  const directory = mkdtempSync(resolve(base, 'candidate-'));
  let report = { classification: 'CANDIDATE_ONLY', eligibleAsProof: false, attempted: false,
    processCompleted: false, origin: null, candidate: null, inputsUnchanged: false, error: null };
  const cancellation = new AbortController();
  const interrupt = () => cancellation.abort(new Error('Candidate interrupted by SIGINT.'));
  const terminate = () => cancellation.abort(new Error('Candidate interrupted by SIGTERM.'));
  process.once('SIGINT', interrupt); process.once('SIGTERM', terminate);
  try {
    const origin = regular(resolve(ROOT, ORIGIN)), candidate = regular(resolve(ROOT, CANDIDATE));
    admitCandidateSource(origin.text, candidate.text);
    const input = resolve(directory, 'request.input.spthy');
    writeFileSync(input, candidate.bytes, { flag: 'wx', mode: 0o600 });
    const args = candidateArguments(input);
    report = { ...report, origin: { path: ORIGIN, sha256: origin.sha256 }, candidate: { path: CANDIDATE, sha256: candidate.sha256 },
      inputSha256: candidate.sha256, binary, arguments: args,
      bounds: { depth: DIAGNOSTIC_DEPTH, timeoutMs: DIAGNOSTIC_TIMEOUT_MS, outputBytes: DIAGNOSTIC_OUTPUT_BYTES, maxInvocations: 1 } };
    cancellation.signal.throwIfAborted();
    report.attempted = true;
    const result = await runProver(binary, args, { cwd: directory, logPath: resolve(directory, 'diagnostic.log'),
      timeoutMs: DIAGNOSTIC_TIMEOUT_MS, maxOutputBytes: DIAGNOSTIC_OUTPUT_BYTES, signal: cancellation.signal });
    let unchanged = false;
    try {
      unchanged = regular(resolve(ROOT, ORIGIN)).sha256 === origin.sha256 &&
        regular(resolve(ROOT, CANDIDATE)).sha256 === candidate.sha256 && regular(input).sha256 === candidate.sha256;
    } catch { /* An unreadable or changed source is not attributed to this candidate. */ }
    report = { ...report, ...candidateProcessResult(result), inputsUnchanged: unchanged };
    if (!report.processCompleted || !unchanged) process.exitCode = 1;
  } catch (error) {
    report = { ...report, error: String(error.message ?? error).slice(0, 2000), cancelled: cancellation.signal.aborted };
    process.exitCode = 1;
  } finally {
    process.removeListener('SIGINT', interrupt); process.removeListener('SIGTERM', terminate);
    writeFileSync(resolve(directory, 'result.json'), `${JSON.stringify(report, null, 2)}\n`, { flag: 'wx', mode: 0o600 });
  }
  process.stdout.write(`${JSON.stringify({ directory, ...report })}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  await main().catch(() => {
    process.stderr.write(`${JSON.stringify({ classification: 'CANDIDATE_ONLY', eligibleAsProof: false, error: 'Candidate rejected or unavailable.' })}\n`);
    process.exitCode = 1;
  });
}
