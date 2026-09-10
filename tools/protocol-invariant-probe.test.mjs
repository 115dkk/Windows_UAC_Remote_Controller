// SPDX-License-Identifier: GPL-2.0-or-later
// Pure/source fixtures only. No Tamarin, subprocess, CI or native execution here.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  ORIGIN_PATH, ORIGIN_HASH, HELPER_NAMES, ORIGINAL_NAMES, HELPER_INSERTION,
  PROBE_TIMEOUT_MS, PROBE_OUTPUT_BYTES, insertInvariantHelpers, admitInvariantCandidate,
  selectInvariantArguments, admitInvariantEnvironment, invariantArguments,
  selectedInvariantSummary, invariantRunSummary, validateInvariantManifest,
} from './protocol-invariant-probe.mjs';

const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
const manifest = JSON.parse(readFileSync(new URL('../security/tamarin/manifest.json', import.meta.url), 'utf8'));
const input = resolve('SYNTHETIC-invariant-probe', 'request.input.spthy');
const digest = (text) => createHash('sha256').update(text).digest('hex');
const probeSource = readFileSync(new URL('./protocol-invariant-probe.mjs', import.meta.url), 'utf8');
const workflow = readFileSync(new URL('../.github/workflows/protocol-invariant-probe.yml', import.meta.url), 'utf8');

test('inserts only two independent helpers before unchanged original lemmas, with exact reversible origin hash', () => {
  const { normalized, candidate } = insertInvariantHelpers(source);
  assert.equal(digest(normalized), ORIGIN_HASH);
  assert.equal(candidate.replace(HELPER_INSERTION, ''), normalized);
  const originalFirst = normalized.indexOf('\nlemma honest_approve_trace:\n');
  assert.ok(originalFirst > 0);
  assert.equal(candidate.slice(0, originalFirst), normalized.slice(0, originalFirst));
  assert.equal(candidate.slice(originalFirst + HELPER_INSERTION.length), normalized.slice(originalFirst));
  assert.deepEqual([...candidate.matchAll(/^lemma (\w+):$/gm)].map((match) => match[1]), [...HELPER_NAMES, ...ORIGINAL_NAMES]);
  assert.doesNotMatch(candidate, /^lemma\s+\w+\s*\[|\bBuildingProduced\b|\buse_induction\b/mu);
  assert.doesNotMatch(HELPER_INSERTION, /\b(?:restriction|rule|axiom|sources|sorry|SOLVED)\b/u);
  assert.equal((HELPER_INSERTION.match(/all-traces/gu) ?? []).length, 2);
  assert.ok(HELPER_INSERTION.includes('Enrolled(pc,device,revision,ak1,dk1)@i'));
  assert.ok(HELPER_INSERTION.includes('Enrolled(pc,device,revision,ak2,dk2)@j'));
  assert.ok(HELPER_INSERTION.includes('RequestOpened(pc,binding)@i'));
  assert.ok(HELPER_INSERTION.includes('RequestOpened(pc,binding)@j'));
  assert.deepEqual(admitInvariantCandidate(source, candidate), { normalized, candidate });
});

test('normalizes CRLF only without accepting other whitespace or malformed-source changes', () => {
  const normalized = source.replace(/\r\n/g, '\n');
  assert.deepEqual(insertInvariantHelpers(normalized.replace(/\n/g, '\r\n')), insertInvariantHelpers(normalized));
  for (const invalid of [null, undefined, 1, {}, '', '\ufeff' + normalized, normalized + '\n', normalized.replace(/\n/g, '\r'),
    normalized + '\0', 'x'.repeat(1024 * 1024 + 1)]) {
    assert.throws(() => insertInvariantHelpers(invalid));
  }
});

test('rejects any changed production rule, restriction, witness, universal property or already-inserted helper', () => {
  const changes = [
    source.replace('builtins: signing', 'builtins: signing, hashing'),
    source.replace('left = right', 'left = left'),
    source.replace('& o < u & u < a', '& o < u'),
    source.replace('==> #i = #j', '==> #i < #j'),
    source.replace("Eq(verify(signature, approval_message, approval_key), true), // CANARY_APPROVAL_SIGNATURE", "Eq('x','x'), // CANARY_APPROVAL_SIGNATURE"),
    source.replace('// CANARY_REPLAY_GUARD', ", RequestSlot(request_id, pc, binding, 'pending')"),
    source + '\n#include "elsewhere.spthy"\n',
    insertInvariantHelpers(source).candidate,
  ];
  for (const altered of changes) {
    assert.notEqual(altered, source);
    assert.throws(() => insertInvariantHelpers(altered));
  }
});

test('candidate admission rejects helper weakening, attributes, duplication, extra events and stored proof', () => {
  const { candidate } = insertInvariantHelpers(source);
  const changes = [
    candidate.replace('lemma enrolled_revision_unique:', 'lemma enrolled_revision_unique [reuse]:'),
    candidate.replace('lemma request_opened_unique:', 'lemma request_opened_unique [sources]:'),
    candidate.replace('lemma request_opened_unique:', 'lemma request_opened_unique [use_induction]:'),
    candidate.replace('     ==> #i = #j"', '     ==> #i < #j"'),
    candidate.replace(HELPER_INSERTION, HELPER_INSERTION + HELPER_INSERTION),
    candidate.replace(HELPER_INSERTION, ''),
    candidate.replace('  -->\n', '  --[ BuildingProduced() ]->\n'),
    candidate.replace('lemma honest_approve_trace:', 'simplify\nby sorry\nlemma honest_approve_trace:'),
    candidate.replace('    ==> #i = #j"\n\nlemma no_accept_after_revision_revoked:', '    ==> #i < #j"\n\nlemma no_accept_after_revision_revoked:'),
    candidate + '\nrestriction unreviewed: "All #i. False()@i ==> F"\n',
    candidate.slice(0, -1),
    null,
  ];
  for (const altered of changes) {
    assert.notEqual(altered, candidate);
    assert.throws(() => admitInvariantCandidate(source, altered));
  }
});

test('selection requires exactly one fixed helper and refuses overrides, inherited names and combined runs', () => {
  assert.ok(Object.isFrozen(HELPER_NAMES) && Object.isFrozen(ORIGINAL_NAMES));
  for (const name of HELPER_NAMES) assert.equal(selectInvariantArguments([`--helper=${name}`]), name);
  for (const args of [[], ['--helper=__proto__'], ['--helper=constructor'], ['--helper=unknown'],
    ['--helper=request_accepted_at_most_once'], ['--helper=request_opened_unique', '--bound=1'],
    ['--helper=request_opened_unique', '--helper=enrolled_revision_unique'], ['--helper=request_opened_unique --reuse'],
    ['--helper=request_opened_unique\n'], ['--helper=request_opened_unique', '--helper=request_opened_unique'],
    ['--model=elsewhere'], [null], 'request_opened_unique']) {
    assert.throws(() => selectInvariantArguments(args));
  }
});

test('actual execution admission is Linux GitHub CI only with explicit binary and commit identity', () => {
  const env = { CI: 'true', GITHUB_ACTIONS: 'true', TAMARIN_BIN: resolve('SYNTHETIC-tamarin-prover'), GITHUB_SHA: 'a'.repeat(40) };
  assert.deepEqual(admitInvariantEnvironment(['--helper=request_opened_unique'], env, 'linux'), {
    selected: 'request_opened_unique', binary: env.TAMARIN_BIN, commit: env.GITHUB_SHA,
  });
  for (const [changed, platform] of [
    [env, 'win32'], [env, 'darwin'], [{ ...env, CI: 'false' }, 'linux'], [{ ...env, GITHUB_ACTIONS: 'false' }, 'linux'],
    [{ ...env, TAMARIN_BIN: 'tamarin-prover' }, 'linux'], [{ ...env, TAMARIN_BIN: undefined }, 'linux'],
    [{ ...env, GITHUB_SHA: undefined }, 'linux'], [{ ...env, GITHUB_SHA: 'not-a-commit' }, 'linux'],
  ]) assert.throws(() => admitInvariantEnvironment(['--helper=request_opened_unique'], changed, platform));
});

for (const name of HELPER_NAMES) {
  test(`${name} invocation uses only that helper, no proof-depth bound, normal DFS and the existing resource profile`, () => {
    assert.deepEqual(invariantArguments(input, name), [input, '--quit-on-warning', `--prove=${name}`, '--stop-on-trace=DFS', '+RTS', '-N2', '-M2G', '-RTS']);
    assert.equal(PROBE_TIMEOUT_MS, 120_000);
    assert.equal(PROBE_OUTPUT_BYTES, 4 * 1024 * 1024);
    assert.throws(() => invariantArguments('relative/request.input.spthy', name));
    assert.throws(() => invariantArguments(resolve('other.spthy'), name));
  });
}
test('argument construction refuses arbitrary proof names even with a valid input path', () => {
  for (const name of ['constructor', '__proto__', 'honest_approve_trace', '--prove=all', null]) {
    assert.throws(() => invariantArguments(input, name));
  }
});

function output(selected, verdict = 'verified (12 steps)') {
  return {
    status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${input}\n${[...HELPER_NAMES, ...ORIGINAL_NAMES].map((name) =>
      ` ${name} (${ORIGINAL_NAMES.indexOf(name) >= 0 && ORIGINAL_NAMES.indexOf(name) < 3 ? 'exists-trace' : 'all-traces'}): ${name === selected ? verdict : 'analysis incomplete (0 steps)'}`).join('\n')}\n`,
  };
}

for (const selected of HELPER_NAMES) {
  test(`${selected} requires its exact verified all-traces row, never another helper or an original property`, () => {
    const accepted = selectedInvariantSummary(output(selected), selected, input);
    assert.equal(accepted.ok, true);
    assert.deepEqual(accepted.verdict, { trace: 'all-traces', verdict: 'verified' });
    assert.equal(Object.hasOwn(accepted, 'verdicts'), false, 'unselected results are not published as proofs');
    for (const text of ['analysis incomplete (9 steps)', 'falsified (8 steps)', 'verified', 'verified (12 steps) trailing']) {
      assert.equal(selectedInvariantSummary(output(selected, text), selected, input).ok, false);
    }
    const other = HELPER_NAMES.find((name) => name !== selected);
    assert.equal(selectedInvariantSummary(output(other), selected, input).ok, false);
    assert.equal(selectedInvariantSummary(output('request_accepted_at_most_once'), selected, input).ok, false);
  });
}

test('summary rejects missing/duplicate/unknown rows, wrong analyzed input, trace kind, warnings and merged summaries', () => {
  const name = 'request_opened_unique';
  const valid = output(name);
  for (const stdout of [
    valid.stdout.replace(` ${name} (all-traces): verified (12 steps)\n`, ''),
    valid.stdout + ` ${name} (all-traces): verified (12 steps)\n`,
    valid.stdout + ' unregistered (all-traces): verified (1 steps)\n',
    valid.stdout.replace(`analyzed: ${input}`, 'analyzed: stale-other-input.spthy'),
    valid.stdout.replace(`${name} (all-traces)`, `${name} (exists-trace)`),
    valid.stdout + valid.stdout,
    valid.stdout.replace('summary of summaries:', 'partial summary:'),
    `WARNING: dependency mismatch\n${valid.stdout}`,
  ]) assert.equal(selectedInvariantSummary({ ...valid, stdout }, name, input).ok, false);
  assert.equal(selectedInvariantSummary({ ...valid, stderr: 'returned unsupported version' }, name, input).ok, false);
});

test('process errors, cancellation, uncertain cleanup and drift cannot become a successful helper observation', () => {
  const name = 'enrolled_revision_unique', valid = output(name);
  for (const delta of [{ status: 1 }, { status: null }, { signal: 'SIGTERM' }, { error: new Error('Prover timed out.') },
    { cancelled: true }, { cleanupIncomplete: true }]) {
    const observed = invariantRunSummary({ ...valid, ...delta }, name, input, true);
    assert.equal(observed.completed, false);
    assert.equal(observed.selectedProof.ok, false);
  }
  for (const unchanged of [false, undefined, null, 'true']) {
    const observed = invariantRunSummary(valid, name, input, unchanged);
    assert.equal(observed.inputsUnchanged, false);
    assert.equal(observed.selectedProof.ok, false);
  }
  const timedOut = invariantRunSummary({ ...valid, error: new Error('Prover timed out.') }, name, input, true);
  assert.equal(timedOut.process.error, 'Prover timed out.');
  assert.equal(invariantRunSummary(valid, name, input, true).selectedProof.ok, true);
});

test('manifest source mapping retains the original nine obligations and rejects changed or unbounded mappings', () => {
  assert.equal(manifest.models.find((entry) => entry.id === 'request-authorization').path, ORIGIN_PATH);
  assert.deepEqual(validateInvariantManifest(manifest), manifest.sourceBindings);
  const change = (edit) => { const copy = structuredClone(manifest); edit(copy); return copy; };
  for (const altered of [null, change((m) => { m.version = 2; }), change((m) => { m.toolVersion = 'other'; }),
    change((m) => { m.models.push(m.models.find((entry) => entry.id === 'request-authorization')); }),
    change((m) => { m.models.find((entry) => entry.id === 'request-authorization').path = 'elsewhere.spthy'; }),
    change((m) => { delete m.models.find((entry) => entry.id === 'request-authorization').expected.honest_approve_trace; }),
    change((m) => { m.models.find((entry) => entry.id === 'request-authorization').expected.request_accepted_at_most_once.verdict = 'falsified'; }),
    change((m) => { m.sourceBindings = []; }), change((m) => { m.sourceBindings.push(m.sourceBindings[0]); }),
    change((m) => { m.sourceBindings[0].path = 'crates/../outside.rs'; }),
    change((m) => { m.sourceBindings[0].path = 'C:/private.rs'; }),
    change((m) => { m.sourceBindings[0].sha256 = 'invalid'; }),
    change((m) => { m.sourceBindings = Array.from({ length: 33 }, () => m.sourceBindings[0]); }),
  ]) assert.throws(() => validateInvariantManifest(altered));
});

test('probe source preserves independent attribution, bounded single execution and immutable separate artifacts', () => {
  assert.equal((probeSource.match(/await runProver\(/gu) ?? []).length, 1);
  assert.ok(probeSource.includes("eligibleAsNormalGate: false, baselineOnly: true"));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run', helperReuse: false, observationalEventsAdded: false"));
  assert.ok(probeSource.includes("status: 'not-selected'"));
  assert.ok(probeSource.includes("'INVARIANT_PROBE_ONLY") || probeSource.includes('`INVARIANT_PROBE_ONLY-'));
  assert.ok(probeSource.includes("flag: 'wx', mode: 0o400"));
  assert.ok(probeSource.includes('maxOutputBytes: PROBE_OUTPUT_BYTES, signal: cancellation.signal'));
  assert.ok(probeSource.includes('regular(binary, 150 * 1024 * 1024, false).sha256 === tool.sha256'));
  assert.ok(probeSource.includes("process.on('SIGINT', stop); process.on('SIGTERM', stop)"));
  assert.ok(probeSource.includes("process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop)"));
  assert.doesNotMatch(probeSource, /artifacts\/protocol-security|--output|--bound=|spawnSync\(|execSync\(/u);
});

test('CI has two independent selected-helper jobs, fixed pins, narrow triggers and no normal-gate mutation', () => {
  assert.ok(workflow.includes("branches: ['codex/protocol-witness-shape']"));
  for (const file of ['tools/protocol-invariant-probe.mjs', 'tools/protocol-invariant-probe.test.mjs', '.github/workflows/protocol-invariant-probe.yml']) {
    assert.ok(workflow.includes(`- '${file}'`));
  }
  assert.ok(workflow.includes('workflow_dispatch:'));
  assert.ok(workflow.includes('fail-fast: false'));
  assert.ok(workflow.includes('helper: [enrolled_revision_unique, request_opened_unique]'));
  assert.ok(workflow.includes('node tools/protocol-invariant-probe.mjs "--helper=${{ matrix.helper }}"'));
  assert.ok(workflow.includes('node tools/install-tamarin.mjs'));
  assert.ok(workflow.includes('persist-credentials: false'));
  assert.ok(workflow.includes('contents: read'));
  assert.ok(workflow.includes('protocol-invariant-probe-${{ matrix.helper }}-${{ github.sha }}'));
  assert.ok(workflow.includes('if: ${{ !cancelled() }}'));
  assert.ok(workflow.includes('if-no-files-found: error'));
  assert.doesNotMatch(workflow, /continue-on-error|pull_request_target|contents: write|security\/tamarin\/|artifacts\/protocol-security|--bound=/u);
  for (const action of workflow.matchAll(/uses: ([^\s]+)@([^\s]+)/gu)) assert.match(action[2], /^[a-f0-9]{40}$/u);
});
