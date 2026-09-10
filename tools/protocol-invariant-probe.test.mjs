// SPDX-License-Identifier: GPL-2.0-or-later
// Pure/source fixtures only. No Tamarin, subprocess, CI or native execution here.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import test from 'node:test';
import {
  ORIGIN_PATH, ORIGIN_HASH, HELPER_NAMES, DIRECT_HELPER_NAMES, BUILDING_HELPER,
  DEPENDENT_PROFILE, CONTEXT_NAMES, CONTEXT_MUTATIONS, DEPENDENT_HELPER_INSERTION, REUSED_BUILDING_INSERTION,
  REQUEST_SECURITY_PROFILE, REQUEST_SECURITY_NAMES, REQUEST_WITNESS_NAMES, REQUEST_SECURITY_HELPERS,
  REQUEST_SECURITY_HELPER_INSERTION, REQUIRED_COUNTEREXAMPLES, requiredInvariantVerdicts,
  ORIGINAL_NAMES, HELPER_INSERTION, BUILDING_HELPER_INSERTION, BUILDING_ACTION_EDITS,
  PROBE_TIMEOUT_MS, PROBE_OUTPUT_BYTES, insertInvariantHelpers, admitInvariantCandidate,
  eraseInvariantCandidate, invariantProfile, invariantContextSource,
  selectInvariantArguments, selectInvariantRunArguments, admitInvariantEnvironment, invariantArguments,
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
  assert.deepEqual([...candidate.matchAll(/^lemma (\w+):$/gm)].map((match) => match[1]), [...DIRECT_HELPER_NAMES, ...ORIGINAL_NAMES]);
  assert.doesNotMatch(candidate, /^lemma\s+\w+\s*\[|\bBuildingProduced\b|\buse_induction\b/mu);
  assert.doesNotMatch(HELPER_INSERTION, /\b(?:restriction|rule|axiom|sources|sorry|SOLVED)\b/u);
  assert.equal((HELPER_INSERTION.match(/all-traces/gu) ?? []).length, 2);
  assert.ok(HELPER_INSERTION.includes('Enrolled(pc,device,revision,ak1,dk1)@i'));
  assert.ok(HELPER_INSERTION.includes('Enrolled(pc,device,revision,ak2,dk2)@j'));
  assert.ok(HELPER_INSERTION.includes('RequestOpened(pc,binding)@i'));
  assert.ok(HELPER_INSERTION.includes('RequestOpened(pc,binding)@j'));
  assert.deepEqual(admitInvariantCandidate(source, candidate), { normalized, candidate });
});

test('both legacy direct CLI profiles retain the previous exact candidate with no observations or induction', () => {
  const expected = insertInvariantHelpers(source);
  for (const selected of DIRECT_HELPER_NAMES) {
    assert.deepEqual(insertInvariantHelpers(source, selected), expected);
    assert.equal(eraseInvariantCandidate(expected.candidate, selected), expected.normalized);
    assert.deepEqual(invariantProfile(selected), {
      observationalEventsAdded: false, inductionHelpers: [], helperReuse: false, requiredLemmas: [selected], reusedHelpers: [],
      candidateLemmas: [...DIRECT_HELPER_NAMES, ...ORIGINAL_NAMES],
    });
  }
});

test('building profile adds exactly two production observations and one independent induction helper', () => {
  const direct = insertInvariantHelpers(source);
  const observed = insertInvariantHelpers(source, BUILDING_HELPER);
  assert.deepEqual(invariantProfile(BUILDING_HELPER), {
    observationalEventsAdded: true, inductionHelpers: [BUILDING_HELPER], helperReuse: false, requiredLemmas: [BUILDING_HELPER], reusedHelpers: [],
    candidateLemmas: [...HELPER_NAMES, ...ORIGINAL_NAMES],
  });
  assert.equal(eraseInvariantCandidate(observed.candidate, BUILDING_HELPER), direct.normalized);
  assert.deepEqual(admitInvariantCandidate(source, observed.candidate, BUILDING_HELPER), observed);
  let restoredDirect = observed.candidate.replace(BUILDING_HELPER_INSERTION, '');
  assert.ok(Object.isFrozen(BUILDING_ACTION_EDITS));
  assert.equal(BUILDING_ACTION_EDITS.length, 2);
  for (const edit of BUILDING_ACTION_EDITS) {
    assert.ok(Object.isFrozen(edit));
    assert.equal(observed.candidate.split(edit.to).length, 2, 'each exact producer appears once');
    restoredDirect = restoredDirect.replace(edit.to, edit.from);
  }
  assert.equal(restoredDirect, direct.candidate, 'all original rules and original/helper formulas recover exactly');
  assert.equal(BUILDING_ACTION_EDITS[0].rule, 'OpenActualRequest');
  assert.equal(BUILDING_ACTION_EDITS[0].to.replace('  --[ BuildingProduced(~request_id, pc, binding) ]->', '  -->'), BUILDING_ACTION_EDITS[0].from);
  assert.equal(BUILDING_ACTION_EDITS[1].rule, 'CaptureEligibleDevice');
  assert.equal(BUILDING_ACTION_EDITS[1].to.replace(',\n       BuildingProduced(request_id, pc, binding)', ''), BUILDING_ACTION_EDITS[1].from);
  assert.equal((observed.candidate.match(/\bBuildingProduced\(/gu) ?? []).length, 3, 'two action observations and one formula premise only');
  assert.deepEqual([...observed.candidate.matchAll(/^lemma\s+\w+\s*\[[^\r\n]*\]:$/gm)].map((match) => match[0]), [
    'lemma building_precedes_open [use_induction]:',
  ]);
  assert.ok(BUILDING_HELPER_INSERTION.includes('BuildingProduced(request_id,pc,binding)@b'));
  assert.ok(BUILDING_HELPER_INSERTION.includes('& RequestOpened(pc,binding)@o'));
  assert.ok(BUILDING_HELPER_INSERTION.includes('==> b < o'));
  assert.doesNotMatch(observed.candidate, /^lemma[^\r\n]*\b(?:reuse|sources)\b/mu);
  assert.deepEqual(insertInvariantHelpers(source.replace(/\r?\n/g, '\r\n'), BUILDING_HELPER), observed);
});

test('building admission rejects missing/duplicate/wrong production markers, attributes and unrelated rule edits', () => {
  const { candidate } = insertInvariantHelpers(source, BUILDING_HELPER);
  const [open, capture] = BUILDING_ACTION_EDITS;
  const changes = [
    candidate.replace(open.to, open.from),
    candidate.replace(capture.to, capture.from),
    candidate.replace('BuildingProduced(~request_id, pc, binding)', 'BuildingProduced(~request_id, pc, binding), BuildingProduced(~request_id, pc, binding)'),
    candidate.replace('BuildingProduced(request_id, pc, binding)', 'BuildingProduced(request_id, pc, wrong_binding)'),
    candidate.replace('rule CaptureEligibleDevice:', 'rule UnexpectedCapture:'),
    candidate.replace('  --[ RequestOpened(pc, binding) ]->', '  --[ RequestOpened(pc, binding), BuildingProduced(request_id, pc, binding) ]->'),
    candidate.replace('lemma building_precedes_open [use_induction]:', 'lemma building_precedes_open:'),
    candidate.replace('[use_induction]', '[use_induction,reuse]'),
    candidate.replace('[use_induction]', '[sources]'),
    candidate.replace('[use_induction]', '[use_induction,use_induction]'),
    candidate.replace('lemma enrolled_revision_unique:', 'lemma enrolled_revision_unique [reuse]:'),
    candidate.replace('     ==> b < o"', '     ==> #b = #o"'),
    candidate.replace(BUILDING_HELPER_INSERTION, BUILDING_HELPER_INSERTION + BUILDING_HELPER_INSERTION),
    candidate + '\n' + open.to,
    candidate.replace("RegistrySlot(device, pc, revision, 'active'),", "!RegistrySlot(device, pc, revision, 'active'),"),
    candidate.replace('    ==> #i = #j"\n\nlemma no_accept_after_revision_revoked:', '    ==> #i < #j"\n\nlemma no_accept_after_revision_revoked:'),
  ];
  for (const altered of changes) {
    assert.notEqual(altered, candidate);
    assert.throws(() => admitInvariantCandidate(source, altered, BUILDING_HELPER));
    assert.throws(() => eraseInvariantCandidate(altered, BUILDING_HELPER));
  }
  assert.throws(() => admitInvariantCandidate(source, candidate, DIRECT_HELPER_NAMES[0]));
  assert.throws(() => admitInvariantCandidate(source, insertInvariantHelpers(source).candidate, BUILDING_HELPER));
  for (const altered of [source + '\n' + open.from, source.replace(capture.from, ''),
    source.replace('SnapshotCaptured(pc, device, revision, binding)', 'SnapshotCaptured(pc, device, revision, other)')]) {
    assert.notEqual(altered, source);
    assert.throws(() => insertInvariantHelpers(altered, BUILDING_HELPER));
  }
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
  assert.ok(Object.isFrozen(HELPER_NAMES) && Object.isFrozen(DIRECT_HELPER_NAMES) && Object.isFrozen(ORIGINAL_NAMES));
  for (const name of HELPER_NAMES) assert.equal(selectInvariantArguments([`--helper=${name}`]), name);
  for (const args of [[], ['--helper=__proto__'], ['--helper=constructor'], ['--helper=unknown'],
    ['--helper=request_accepted_at_most_once'], ['--helper=BuildingProduced'], ['--helper=building_precedes_open --reuse'],
    ['--helper=building_precedes_open', '--reuse'], ['--helper=request_opened_unique', '--bound=1'],
    ['--helper=request_opened_unique', '--helper=enrolled_revision_unique'], ['--helper=request_opened_unique --reuse'],
    ['--helper=request_opened_unique\n'], ['--helper=request_opened_unique', '--helper=request_opened_unique'],
    ['--model=elsewhere'], [null], 'request_opened_unique']) {
    assert.throws(() => selectInvariantArguments(args));
  }
});

test('actual execution admission is Linux GitHub CI only with explicit binary and commit identity', () => {
  const env = { CI: 'true', GITHUB_ACTIONS: 'true', TAMARIN_BIN: resolve('SYNTHETIC-tamarin-prover'), GITHUB_SHA: 'a'.repeat(40) };
  assert.deepEqual(admitInvariantEnvironment(['--helper=request_opened_unique'], env, 'linux'), {
    selected: 'request_opened_unique', context: 'baseline', binary: env.TAMARIN_BIN, commit: env.GITHUB_SHA,
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
    assert.throws(() => insertInvariantHelpers(source, name));
    assert.throws(() => invariantProfile(name));
  }
});

function output(selected, verdict = 'verified (12 steps)') {
  const names = invariantProfile(HELPER_NAMES.includes(selected) ? selected : DIRECT_HELPER_NAMES[0]).candidateLemmas;
  return {
    status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${input}\n${names.map((name) =>
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

test('probe source preserves independent attribution, observable edit metadata and immutable separate artifacts', () => {
  assert.equal((probeSource.match(/await runProver\(/gu) ?? []).length, 1);
  assert.ok(probeSource.includes("eligibleAsNormalGate: false, baselineOnly: context === 'baseline'"));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run', ...profile"));
  assert.ok(probeSource.includes('observationalEdits: profile.observationalEventsAdded ? BUILDING_ACTION_EDITS.map'));
  assert.ok(probeSource.includes("originalRulesRestrictionsAndLemmasUnchanged: !profile.observationalEventsAdded && context === 'baseline'"));
  assert.ok(probeSource.includes("originalPremisesConclusionsAndPublicMessagesUnchanged: context === 'baseline', originalRestrictionsAndLemmasUnchanged: true"));
  assert.ok(probeSource.includes('regular(contextInput).sha256 === contextHash'));
  assert.ok(probeSource.includes('contextMutation: mutation ? { id: context, ...mutation, beforeSha256: ORIGIN_HASH, afterSha256: contextHash } : null'));
  assert.ok(probeSource.includes("status: 'not-selected'"));
  assert.ok(probeSource.includes("'INVARIANT_PROBE_ONLY") || probeSource.includes('`INVARIANT_PROBE_ONLY-'));
  assert.ok(probeSource.includes("flag: 'wx', mode: 0o400"));
  assert.ok(probeSource.includes('maxOutputBytes: PROBE_OUTPUT_BYTES, signal: cancellation.signal'));
  assert.ok(probeSource.includes('regular(binary, 150 * 1024 * 1024, false).sha256 === tool.sha256'));
  assert.ok(probeSource.includes("process.on('SIGINT', stop); process.on('SIGTERM', stop)"));
  assert.ok(probeSource.includes("process.removeListener('SIGINT', stop); process.removeListener('SIGTERM', stop)"));
  assert.doesNotMatch(probeSource, /artifacts\/protocol-security|--output|--bound=|spawnSync\(|execSync\(/u);
});

test('CI runs ONLY the fixed request-security profile in three independent contexts, not the normal gate', () => {
  assert.ok(workflow.includes("branches: ['codex/protocol-witness-shape']"));
  for (const file of ['tools/protocol-invariant-probe.mjs', 'tools/protocol-invariant-probe.test.mjs', '.github/workflows/protocol-invariant-probe.yml']) {
    assert.ok(workflow.includes(`- '${file}'`));
  }
  assert.ok(workflow.includes('workflow_dispatch:'));
  assert.doesNotMatch(workflow, /--helper=/u);
  assert.ok(workflow.includes('fail-fast: false'));
  assert.ok(workflow.includes('context: [baseline, missing-approval-signature, missing-replay-consumption]'));
  assert.ok(workflow.includes('node tools/protocol-invariant-probe.mjs --profile=request-security-with-helpers "--context=${{ matrix.context }}"'));
  assert.ok(workflow.includes('node tools/install-tamarin.mjs'));
  assert.ok(workflow.includes('persist-credentials: false'));
  assert.ok(workflow.includes('contents: read'));
  assert.ok(workflow.includes('protocol-invariant-probe-request-security-${{ matrix.context }}-${{ github.sha }}'));
  assert.ok(workflow.includes('if: ${{ !cancelled() }}'));
  assert.ok(workflow.includes('if-no-files-found: error'));
  assert.doesNotMatch(workflow, /continue-on-error|pull_request_target|contents: write|security\/tamarin\/|artifacts\/protocol-security|--bound=/u);
  for (const action of workflow.matchAll(/uses: ([^\s]+)@([^\s]+)/gu)) assert.match(action[2], /^[a-f0-9]{40}$/u);
});

function securityInput(context, invocation = 'fixture') {
  return resolve('SYNTHETIC-invariant-probe', `INVARIANT_PROBE_ONLY-${REQUEST_SECURITY_PROFILE}-${context}-${invocation}`, 'request.input.spthy');
}

function securityOutput(context, verdicts = {}, invocation = 'fixture') {
  const path = securityInput(context, invocation), profile = invariantProfile(REQUEST_SECURITY_PROFILE, context);
  const expected = requiredInvariantVerdicts(REQUEST_SECURITY_PROFILE, context);
  return { status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${path}\n${profile.candidateLemmas.map((name) => {
      const trace = REQUEST_WITNESS_NAMES.includes(name) ? 'exists-trace' : 'all-traces';
      const value = verdicts[name] ?? (Object.hasOwn(expected, name)
        ? expected[name].verdict === 'verified' ? 'verified (14 steps)' : 'falsified - found trace (17 steps)'
        : 'analysis incomplete (0 steps)');
      return ` ${name} (${trace}): ${value}`;
    }).join('\n')}\n` };
}

test('request-security selection is a closed two-argument profile; legacy selections remain distinct', () => {
  for (const fixed of [REQUEST_SECURITY_NAMES, REQUEST_WITNESS_NAMES, REQUEST_SECURITY_HELPERS, REQUIRED_COUNTEREXAMPLES]) {
    assert.ok(Object.isFrozen(fixed));
  }
  assert.deepEqual(REQUEST_SECURITY_NAMES, ORIGINAL_NAMES.slice(3));
  assert.equal(REQUEST_SECURITY_NAMES.length, 6);
  assert.deepEqual(REQUEST_WITNESS_NAMES, ORIGINAL_NAMES.slice(0, 3));
  for (const context of CONTEXT_NAMES) {
    assert.deepEqual(selectInvariantRunArguments([`--profile=${REQUEST_SECURITY_PROFILE}`, `--context=${context}`]), { selected: REQUEST_SECURITY_PROFILE, context });
    assert.deepEqual(selectInvariantRunArguments([`--profile=${DEPENDENT_PROFILE}`, `--context=${context}`]), { selected: DEPENDENT_PROFILE, context });
  }
  for (const args of [
    [`--profile=${REQUEST_SECURITY_PROFILE}`], [`--helper=${REQUEST_SECURITY_PROFILE}`],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=__proto__'],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=constructor'],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=missing-replay-consumption '],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=baseline', '--prove=all'],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=baseline', '--reuse'],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=baseline', '--context=missing-approval-signature'],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=baseline', '--timeout=1'],
    ['--context=baseline', `--profile=${REQUEST_SECURITY_PROFILE}`],
    [`--profile=${REQUEST_SECURITY_PROFILE}\n`, '--context=baseline'],
  ]) assert.throws(() => selectInvariantRunArguments(args));
});

for (const context of CONTEXT_NAMES) {
  test(`${context} security profile adds only reviewed reuse declarations/observations and exactly reverses to origin`, () => {
    const { normalized, candidate } = insertInvariantHelpers(source, REQUEST_SECURITY_PROFILE, context, manifest);
    const profile = invariantProfile(REQUEST_SECURITY_PROFILE, context);
    const selectedProperties = context === 'baseline' ? REQUEST_SECURITY_NAMES : [REQUIRED_COUNTEREXAMPLES[context]];
    assert.deepEqual(profile.requiredLemmas, [...REQUEST_SECURITY_HELPERS, ...selectedProperties]);
    assert.deepEqual(profile.reusedHelpers, REQUEST_SECURITY_HELPERS);
    assert.deepEqual(profile.candidateLemmas, [...REQUEST_SECURITY_HELPERS, ...ORIGINAL_NAMES]);
    assert.deepEqual(profile.inductionHelpers, [BUILDING_HELPER]);
    assert.equal(profile.helperReuse, true);
    assert.equal(profile.observationalEventsAdded, true);
    assert.deepEqual(admitInvariantCandidate(source, candidate, REQUEST_SECURITY_PROFILE, context, manifest), { normalized, candidate });
    assert.equal(eraseInvariantCandidate(candidate, REQUEST_SECURITY_PROFILE, context, manifest), normalized);
    assert.equal(digest(normalized), ORIGIN_HASH);
    assert.equal((candidate.match(/\bBuildingProduced\(/gu) ?? []).length, 3);
    assert.deepEqual([...candidate.matchAll(/^lemma\s+\w+\s*\[[^\r\n]*\]:$/gm)].map((match) => match[0]), [
      'lemma enrolled_revision_unique [reuse]:', 'lemma building_precedes_open [use_induction,reuse]:', 'lemma request_opened_unique [reuse]:',
    ]);
    assert.ok(candidate.indexOf('lemma building_precedes_open [use_induction,reuse]:') < candidate.indexOf('lemma request_opened_unique [reuse]:'));
    for (const helper of REQUEST_SECURITY_HELPERS) {
      assert.ok(candidate.indexOf(`lemma ${helper} `) < candidate.indexOf('lemma honest_approve_trace:'));
    }
    const anchor = '\nlemma honest_approve_trace:\n';
    assert.equal(candidate.slice(candidate.indexOf(anchor)), normalized.slice(normalized.indexOf(anchor)), 'ALL original nine declarations/formulas and existential witnesses remain exact');
    let erased = candidate.replace(REQUEST_SECURITY_HELPER_INSERTION, '');
    for (const edit of [...BUILDING_ACTION_EDITS].reverse()) erased = erased.replace(edit.to, edit.from);
    assert.equal(erased, invariantContextSource(source, REQUEST_SECURITY_PROFILE, context, manifest));
    if (context !== 'baseline') {
      const declared = manifest.models.find((model) => model.id === 'request-authorization').canaries.find((canary) => canary.id === context);
      assert.deepEqual(declared.mutation, CONTEXT_MUTATIONS[context]);
      assert.deepEqual(Object.keys(declared.expected), selectedProperties);
      assert.equal(erased, normalized.replace(declared.mutation.from, declared.mutation.to));
    }
    const withoutAttributesOrComments = (text) => text.replace(/^\/\/[^\n]*\n/gm, '').replace(/ \[(?:reuse|use_induction,reuse)\](?=:)/g, '');
    assert.equal(withoutAttributesOrComments(REQUEST_SECURITY_HELPER_INSERTION), withoutAttributesOrComments(DEPENDENT_HELPER_INSERTION), 'helper FORMULAS are unchanged');
    assert.deepEqual(insertInvariantHelpers(source.replace(/\r?\n/g, '\r\n'), REQUEST_SECURITY_PROFILE, context, manifest), { normalized, candidate });
    const unselected = profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name));
    assert.deepEqual(unselected, ORIGINAL_NAMES.filter((name) => !selectedProperties.includes(name)));
    for (const witness of REQUEST_WITNESS_NAMES) assert.ok(unselected.includes(witness));
  });

  test(`${context} security invocation requires all in-context helpers and only its original properties with unchanged controls`, () => {
    const required = requiredInvariantVerdicts(REQUEST_SECURITY_PROFILE, context);
    const properties = context === 'baseline' ? REQUEST_SECURITY_NAMES : [REQUIRED_COUNTEREXAMPLES[context]];
    for (const helper of REQUEST_SECURITY_HELPERS) assert.deepEqual(required[helper], { trace: 'all-traces', verdict: 'verified' });
    for (const property of properties) assert.deepEqual(required[property], { trace: 'all-traces', verdict: context === 'baseline' ? 'verified' : 'falsified' });
    assert.deepEqual(Object.keys(required), [...REQUEST_SECURITY_HELPERS, ...properties]);
    const path = securityInput(context);
    assert.deepEqual(invariantArguments(path, REQUEST_SECURITY_PROFILE, context), [
      path, '--quit-on-warning', ...Object.keys(required).map((name) => `--prove=${name}`), '--stop-on-trace=DFS', '+RTS', '-N2', '-M2G', '-RTS',
    ]);
    assert.equal(PROBE_TIMEOUT_MS, 120_000);
    assert.equal(PROBE_OUTPUT_BYTES, 4 * 1024 * 1024);
    assert.throws(() => invariantArguments(input, REQUEST_SECURITY_PROFILE, context));
    assert.throws(() => invariantArguments(dependentInput(context), REQUEST_SECURITY_PROFILE, context));
    for (const other of CONTEXT_NAMES.filter((name) => name !== context)) {
      assert.throws(() => invariantArguments(securityInput(other), REQUEST_SECURITY_PROFILE, context));
    }
  });

  test(`${context} cannot count correct security rows without EVERY reused helper verified in this invocation`, () => {
    const path = securityInput(context), valid = securityOutput(context);
    const expected = requiredInvariantVerdicts(REQUEST_SECURITY_PROFILE, context);
    const accepted = selectedInvariantSummary(valid, REQUEST_SECURITY_PROFILE, path, context);
    assert.equal(accepted.ok, true);
    assert.deepEqual(accepted.requiredVerdicts, expected);
    assert.equal(Object.hasOwn(accepted, 'verdicts'), false);
    for (const helper of REQUEST_SECURITY_HELPERS) {
      for (const verdict of ['analysis incomplete (0 steps)', 'falsified - found trace (5 steps)', 'verified', 'verified (14 steps) trailing']) {
        const observed = selectedInvariantSummary(securityOutput(context, { [helper]: verdict }), REQUEST_SECURITY_PROFILE, path, context);
        assert.equal(observed.ok, false);
        assert.deepEqual(observed.verdict, expected[Object.keys(expected).at(-1)], 'security consumer result is deliberately correct');
      }
      const row = ` ${helper} (all-traces): verified (14 steps)\n`;
      const missing = valid.stdout.replace(row, '');
      assert.notEqual(missing, valid.stdout);
      const importedBaseline = selectedInvariantSummary(securityOutput('baseline'), REQUEST_SECURITY_PROFILE, securityInput('baseline'), 'baseline');
      assert.equal(selectedInvariantSummary({ ...valid, stdout: missing, requiredVerdicts: importedBaseline.requiredVerdicts }, REQUEST_SECURITY_PROFILE, path, context).ok, false, 'baseline metadata is not evidence for a missing in-context helper');
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + row }, REQUEST_SECURITY_PROFILE, path, context).ok, false);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout.replace(`${helper} (all-traces)`, `${helper} (exists-trace)`) }, REQUEST_SECURITY_PROFILE, path, context).ok, false);
    }
    for (const property of Object.keys(expected).filter((name) => REQUEST_SECURITY_NAMES.includes(name))) {
      const contrary = context === 'baseline' ? 'falsified (8 steps)' : 'verified (18 steps)';
      assert.equal(selectedInvariantSummary(securityOutput(context, { [property]: contrary }), REQUEST_SECURITY_PROFILE, path, context).ok, false);
      assert.equal(selectedInvariantSummary(securityOutput(context, { [property]: 'analysis incomplete (0 steps)' }), REQUEST_SECURITY_PROFILE, path, context).ok, false);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout.replace(`${property} (all-traces)`, `${property} (exists-trace)`) }, REQUEST_SECURITY_PROFILE, path, context).ok, false);
    }
    if (context !== 'baseline') {
      const wrong = Object.values(REQUIRED_COUNTEREXAMPLES).find((name) => name !== REQUIRED_COUNTEREXAMPLES[context]);
      assert.equal(selectedInvariantSummary(securityOutput(context, { [REQUIRED_COUNTEREXAMPLES[context]]: 'verified (9 steps)', [wrong]: 'falsified - found trace (17 steps)' }), REQUEST_SECURITY_PROFILE, path, context).ok, false, 'another property counterexample never satisfies this manifest canary');
    }
  });

  test(`${context} rejects crossed invocation/context output, warning, process failure, missing property and attribution drift`, () => {
    const path = securityInput(context), valid = securityOutput(context);
    for (const other of CONTEXT_NAMES.filter((name) => name !== context)) {
      assert.equal(selectedInvariantSummary(securityOutput(other), REQUEST_SECURITY_PROFILE, path, context).ok, false);
    }
    assert.equal(selectedInvariantSummary(securityOutput(context, {}, 'older-invocation'), REQUEST_SECURITY_PROFILE, path, context).ok, false);
    for (const stdout of [
      valid.stdout + valid.stdout,
      valid.stdout + ' unexpected_property (all-traces): verified (1 steps)\n',
      valid.stdout.replace('summary of summaries:', 'partial summary:'),
      `\u001b[33mWARNING\u001b[0m: unproved dependency\n${valid.stdout}`,
      valid.stdout.replace(new RegExp(`^ ${Object.keys(requiredInvariantVerdicts(REQUEST_SECURITY_PROFILE, context)).at(-1)} \\(all-traces\\):[^\\n]*\\n`, 'm'), ''),
    ]) assert.equal(selectedInvariantSummary({ ...valid, stdout }, REQUEST_SECURITY_PROFILE, path, context).ok, false);
    assert.equal(selectedInvariantSummary({ ...valid, stderr: 'WARNING: dependency assumption' }, REQUEST_SECURITY_PROFILE, path, context).ok, false);
    for (const delta of [{ status: 1 }, { status: null }, { signal: 'SIGTERM' }, { error: new Error('Prover timed out.') }, { cancelled: true }, { cleanupIncomplete: true }]) {
      const observed = invariantRunSummary({ ...valid, ...delta }, REQUEST_SECURITY_PROFILE, path, true, context);
      assert.equal(observed.completed, false);
      assert.equal(observed.selectedProof.ok, false);
    }
    for (const unchanged of [false, null, undefined, 'true']) {
      assert.equal(invariantRunSummary(valid, REQUEST_SECURITY_PROFILE, path, unchanged, context).selectedProof.ok, false);
    }
  });
}

test('security source admission forbids reordered/missing helpers, baseline assumptions, altered formulas or enlarged mutations', () => {
  for (const context of CONTEXT_NAMES) {
    const { candidate } = insertInvariantHelpers(source, REQUEST_SECURITY_PROFILE, context, manifest);
    const movedBuilding = candidate.replace(REUSED_BUILDING_INSERTION, '').replace('\nlemma honest_approve_trace:\n', REUSED_BUILDING_INSERTION + '\nlemma honest_approve_trace:\n');
    const changes = [
      movedBuilding, candidate.replace(REQUEST_SECURITY_HELPER_INSERTION, ''),
      candidate.replace(REQUEST_SECURITY_HELPER_INSERTION, REQUEST_SECURITY_HELPER_INSERTION + REQUEST_SECURITY_HELPER_INSERTION),
      candidate.replace('lemma enrolled_revision_unique [reuse]:', 'lemma enrolled_revision_unique:'),
      candidate.replace('lemma request_opened_unique [reuse]:', 'lemma request_opened_unique:'),
      candidate.replace('[use_induction,reuse]', '[reuse]'),
      candidate.replace('[use_induction,reuse]', '[use_induction]'),
      candidate.replace('lemma enrolled_revision_unique [reuse]:', 'lemma enrolled_revision_unique [sources]:'),
      candidate.replace('     ==> b < o"', '     ==> #b = #o"'),
      candidate.replace(BUILDING_ACTION_EDITS[0].to, BUILDING_ACTION_EDITS[0].from),
      candidate.replace(BUILDING_ACTION_EDITS[1].to, BUILDING_ACTION_EDITS[1].from),
      candidate.replace('left = right', 'left = left'),
      candidate + '\nrestriction assume_baseline: "All #i. False()@i ==> F"\n',
      candidate + '\n// unreviewed mutation\n',
      ...ORIGINAL_NAMES.map((name) => candidate.replace(`lemma ${name}:`, `lemma ${name} [reuse]:`)),
    ];
    for (const changed of changes) {
      assert.notEqual(changed, candidate);
      assert.throws(() => admitInvariantCandidate(source, changed, REQUEST_SECURITY_PROFILE, context, manifest));
      assert.throws(() => eraseInvariantCandidate(changed, REQUEST_SECURITY_PROFILE, context, manifest));
    }
    for (const other of CONTEXT_NAMES.filter((name) => name !== context)) {
      assert.throws(() => admitInvariantCandidate(source, candidate, REQUEST_SECURITY_PROFILE, other, manifest));
    }
    assert.throws(() => admitInvariantCandidate(source, candidate, DEPENDENT_PROFILE, context, manifest));
    assert.throws(() => admitInvariantCandidate(source, insertInvariantHelpers(source, DEPENDENT_PROFILE, context, manifest).candidate, REQUEST_SECURITY_PROFILE, context, manifest));
    const modifiedManifest = structuredClone(manifest);
    modifiedManifest.models.find((model) => model.id === 'request-authorization').canaries[0].mutation.to += '\n// enlarged mutant';
    assert.throws(() => insertInvariantHelpers(source, REQUEST_SECURITY_PROFILE, context, modifiedManifest));
  }
});

test('security evidence remains explicitly isolated, context-attributed and honest about unselected obligations', () => {
  assert.equal((probeSource.match(/await runProver\(/gu) ?? []).length, 1);
  assert.ok(probeSource.includes("helperProofScope: 'same-invocation-same-context-only', importedProofs: false"));
  assert.ok(probeSource.includes('requiredExpected: requiredInvariantVerdicts(selected, context)'));
  assert.ok(probeSource.includes("'required-counterexample-selected'"));
  assert.ok(probeSource.includes('selectedHelper: securityProfile ? null'));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run'"));
  assert.ok(probeSource.includes('eligibleAsNormalGate: false'));
  assert.ok(probeSource.includes("'tools/protocol-invariant-probe.test.mjs', 'tools/protocol-security.mjs'"));
  assert.ok(probeSource.includes("unselectedLemmas: profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name)).map((name) => ({ name, status: 'not-selected' }))"));
  assert.doesNotMatch(workflow, /--profile=request-opened-with-building|--prove=|--reuse|--bound=|continue-on-error/u);
  assert.ok(workflow.includes('timeout-minutes: 15'));
  assert.equal((workflow.match(/run: node tools\/protocol-invariant-probe\.mjs /gu) ?? []).length, 1);
});

function dependentInput(context) {
  return resolve('SYNTHETIC-invariant-probe', `INVARIANT_PROBE_ONLY-${DEPENDENT_PROFILE}-${context}-fixture`, 'request.input.spthy');
}

function dependentOutput(context, verdicts = {}) {
  const path = dependentInput(context), profile = invariantProfile(DEPENDENT_PROFILE, context);
  return { status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${path}\n${profile.candidateLemmas.map((name) =>
      ` ${name} (${ORIGINAL_NAMES.indexOf(name) >= 0 && ORIGINAL_NAMES.indexOf(name) < 3 ? 'exists-trace' : 'all-traces'}): ${verdicts[name] ?? (profile.requiredLemmas.includes(name) ? 'verified (14 steps)' : 'analysis incomplete (0 steps)')}`).join('\n')}\n` };
}

test('dependent CLI is a fixed profile with one explicit context; independent helper CLI cannot inherit mutants', () => {
  assert.ok(Object.isFrozen(CONTEXT_NAMES) && Object.isFrozen(CONTEXT_MUTATIONS));
  for (const context of CONTEXT_NAMES) {
    assert.deepEqual(selectInvariantRunArguments([`--profile=${DEPENDENT_PROFILE}`, `--context=${context}`]), { selected: DEPENDENT_PROFILE, context });
  }
  for (const name of HELPER_NAMES) assert.deepEqual(selectInvariantRunArguments([`--helper=${name}`]), { selected: name, context: 'baseline' });
  for (const args of [
    [`--profile=${DEPENDENT_PROFILE}`], [`--profile=${DEPENDENT_PROFILE}`, '--context=__proto__'],
    [`--profile=${DEPENDENT_PROFILE}`, '--context=constructor'], [`--profile=${DEPENDENT_PROFILE}`, '--context=unknown'],
    ['--profile=other', '--context=baseline'], ['--context=baseline', `--profile=${DEPENDENT_PROFILE}`],
    [`--profile=${DEPENDENT_PROFILE}`, '--context=baseline', '--context=missing-approval-signature'],
    [`--profile=${DEPENDENT_PROFILE}`, '--context=baseline', '--prove=request_opened_unique'],
    [`--profile=${DEPENDENT_PROFILE}`, '--context=baseline', '--reuse'],
    ['--helper=request_opened_unique', '--context=baseline'], ['--helper=building_precedes_open', '--context=missing-replay-consumption'],
    [`--helper=${DEPENDENT_PROFILE}`], [`--profile=${DEPENDENT_PROFILE} --context=baseline`],
  ]) assert.throws(() => selectInvariantRunArguments(args));
  for (const name of HELPER_NAMES) for (const context of CONTEXT_NAMES.slice(1)) {
    assert.throws(() => insertInvariantHelpers(source, name, context, manifest));
    assert.throws(() => invariantArguments(input, name, context));
  }
});

for (const context of CONTEXT_NAMES) {
  test(`${context} dependent candidate has exact manifest mutation, two observations, required-before-consumer order and inverse-to-origin`, () => {
    const { normalized, candidate } = insertInvariantHelpers(source, DEPENDENT_PROFILE, context, manifest);
    assert.equal(digest(normalized), ORIGIN_HASH);
    assert.equal(eraseInvariantCandidate(candidate, DEPENDENT_PROFILE, context, manifest), normalized);
    assert.deepEqual(admitInvariantCandidate(source, candidate, DEPENDENT_PROFILE, context, manifest), { normalized, candidate });
    const profile = invariantProfile(DEPENDENT_PROFILE, context);
    assert.equal(profile.helperReuse, true);
    assert.deepEqual(profile.reusedHelpers, [BUILDING_HELPER]);
    assert.deepEqual(profile.requiredLemmas, [BUILDING_HELPER, 'request_opened_unique']);
    assert.deepEqual([...candidate.matchAll(/^lemma (\w+)(?: \[use_induction,reuse\])?:$/gm)].map((match) => match[1]), profile.candidateLemmas);
    assert.ok(candidate.indexOf('lemma building_precedes_open [use_induction,reuse]:') < candidate.indexOf('lemma request_opened_unique:'));
    assert.deepEqual([...candidate.matchAll(/^lemma\s+\w+\s*\[[^\r\n]*\]:$/gm)].map((match) => match[0]), ['lemma building_precedes_open [use_induction,reuse]:']);
    assert.equal((candidate.match(/\bBuildingProduced\(/gu) ?? []).length, 3);
    let erased = candidate.replace(DEPENDENT_HELPER_INSERTION, '');
    for (const edit of [...BUILDING_ACTION_EDITS].reverse()) erased = erased.replace(edit.to, edit.from);
    const contextual = invariantContextSource(source, DEPENDENT_PROFILE, context, manifest);
    assert.equal(erased, contextual, 'only observations/helper declarations differ from the exact selected protocol context');
    if (context === 'baseline') assert.equal(contextual, normalized);
    else {
      const declared = manifest.models.find((model) => model.id === 'request-authorization').canaries.find((canary) => canary.id === context).mutation;
      assert.deepEqual(declared, CONTEXT_MUTATIONS[context]);
      assert.equal(normalized.split(declared.from).length, 2);
      assert.equal(contextual, normalized.replace(declared.from, declared.to));
      assert.equal(contextual.split(declared.to).length, 2);
      assert.notEqual(digest(contextual), ORIGIN_HASH);
    }
    assert.deepEqual(insertInvariantHelpers(source.replace(/\r?\n/g, '\r\n'), DEPENDENT_PROFILE, context, manifest), { normalized, candidate });
    const path = dependentInput(context);
    assert.deepEqual(invariantArguments(path, DEPENDENT_PROFILE, context), [
      path, '--quit-on-warning', '--prove=building_precedes_open', '--prove=request_opened_unique', '--stop-on-trace=DFS', '+RTS', '-N2', '-M2G', '-RTS',
    ]);
  });

  test(`${context} counts no dependent proof without the verified required helper in the same exact input summary`, () => {
    const path = dependentInput(context), valid = dependentOutput(context);
    const accepted = selectedInvariantSummary(valid, DEPENDENT_PROFILE, path, context);
    assert.equal(accepted.ok, true);
    assert.deepEqual(Object.keys(accepted.requiredVerdicts), [BUILDING_HELPER, 'request_opened_unique']);
    assert.deepEqual(accepted.requiredVerdicts[BUILDING_HELPER], { trace: 'all-traces', verdict: 'verified' });
    for (const verdict of ['analysis incomplete (0 steps)', 'falsified (3 steps)', 'verified', 'verified (14 steps) extra']) {
      const rejected = selectedInvariantSummary(dependentOutput(context, { [BUILDING_HELPER]: verdict }), DEPENDENT_PROFILE, path, context);
      assert.equal(rejected.verdict.verdict, 'verified', 'the dependent row alone is deliberately present');
      assert.equal(rejected.ok, false, 'an unproved reused helper cannot be accepted');
    }
    for (const name of [BUILDING_HELPER, 'request_opened_unique']) {
      const missing = valid.stdout.replace(` ${name} (all-traces): verified (14 steps)\n`, '');
      assert.notEqual(missing, valid.stdout);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: missing }, DEPENDENT_PROFILE, path, context).ok, false);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + ` ${name} (all-traces): verified (14 steps)\n` }, DEPENDENT_PROFILE, path, context).ok, false);
    }
    for (const other of CONTEXT_NAMES.filter((name) => name !== context)) {
      assert.equal(selectedInvariantSummary(dependentOutput(other), DEPENDENT_PROFILE, path, context).ok, false);
      assert.throws(() => invariantArguments(dependentInput(other), DEPENDENT_PROFILE, context));
    }
    assert.equal(invariantRunSummary(valid, DEPENDENT_PROFILE, path, false, context).selectedProof.ok, false);
    for (const delta of [{ status: 1 }, { error: new Error('Prover timed out.') }, { cancelled: true }, { cleanupIncomplete: true }]) {
      assert.equal(invariantRunSummary({ ...valid, ...delta }, DEPENDENT_PROFILE, path, true, context).selectedProof.ok, false);
    }
  });
}

test('dependent admission rejects consumer-before-helper, unsupported reuse, missing helper and profile/context leakage', () => {
  for (const context of CONTEXT_NAMES) {
    const { candidate } = insertInvariantHelpers(source, DEPENDENT_PROFILE, context, manifest);
    const wrongOrder = candidate.replace(REUSED_BUILDING_INSERTION, '').replace('\nlemma honest_approve_trace:\n', REUSED_BUILDING_INSERTION + '\nlemma honest_approve_trace:\n');
    for (const altered of [
      wrongOrder, candidate.replace(REUSED_BUILDING_INSERTION, ''),
      candidate.replace('[use_induction,reuse]', '[use_induction]'),
      candidate.replace('[use_induction,reuse]', '[reuse]'),
      candidate.replace('lemma request_opened_unique:', 'lemma request_opened_unique [reuse]:'),
      candidate.replace('     ==> b < o"', '     ==> #b = #o"'),
      candidate + '\n// unreviewed text\n',
    ]) {
      assert.notEqual(altered, candidate);
      assert.throws(() => admitInvariantCandidate(source, altered, DEPENDENT_PROFILE, context, manifest));
      assert.throws(() => eraseInvariantCandidate(altered, DEPENDENT_PROFILE, context, manifest));
    }
    for (const other of CONTEXT_NAMES.filter((name) => name !== context)) {
      assert.throws(() => admitInvariantCandidate(source, candidate, DEPENDENT_PROFILE, other, manifest));
      assert.throws(() => eraseInvariantCandidate(candidate, DEPENDENT_PROFILE, other, manifest));
    }
    assert.throws(() => admitInvariantCandidate(source, candidate, BUILDING_HELPER));
    assert.throws(() => admitInvariantCandidate(source, insertInvariantHelpers(source, BUILDING_HELPER).candidate, DEPENDENT_PROFILE, context, manifest));
  }
});

test('context mutations are fixed manifest entries, never custom rewrites or inferred disabled mechanisms', () => {
  const changed = (edit) => { const copy = structuredClone(manifest); edit(copy.models.find((model) => model.id === 'request-authorization')); return copy; };
  for (const invalid of [
    changed((model) => { model.canaries[0].mutation.to = "Eq('anything','anything'),"; }),
    changed((model) => { model.canaries[1].mutation.from = 'RequestSlot'; }),
    changed((model) => { model.canaries.push(model.canaries[0]); }),
    changed((model) => { model.canaries[1].id = model.canaries[0].id; }),
    changed((model) => { model.canaries[0].expected.accepted_approval_requires_same_binding_auth.verdict = 'verified'; }),
  ]) {
    assert.throws(() => validateInvariantManifest(invalid));
    for (const context of CONTEXT_NAMES) assert.throws(() => insertInvariantHelpers(source, DEPENDENT_PROFILE, context, invalid));
  }
  for (const context of CONTEXT_NAMES.slice(1)) {
    assert.throws(() => insertInvariantHelpers(source, DEPENDENT_PROFILE, context));
    const alreadyMutated = source.replace(CONTEXT_MUTATIONS[context].from, CONTEXT_MUTATIONS[context].to);
    assert.notEqual(alreadyMutated, source);
    assert.throws(() => insertInvariantHelpers(alreadyMutated, DEPENDENT_PROFILE, context, manifest));
  }
});
