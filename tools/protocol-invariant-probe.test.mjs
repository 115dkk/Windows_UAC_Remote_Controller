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
  REQUEST_SECURITY_HELPERS_ONLY_PROFILE, REQUEST_SECURITY_REFERENCE_COMMIT, REQUEST_SECURITY_CANDIDATE_HASHES,
  REQUEST_SECURITY_ONE_PROPERTY_PROFILE, ONE_PROPERTY_CASES, REQUEST_SECURITY_CANARY_BFS_PROFILE,
  ACTIVE_REGISTRY_LINEAGE_PROFILE, ACTIVE_REGISTRY_HELPER, ACTIVE_REGISTRY_PROPERTY, ACTIVE_REGISTRY_HELPERS,
  ACTIVE_REGISTRY_HELPER_INSERTION, ACTIVE_REGISTRY_ACTION_EDITS, eraseActiveRegistryLineage,
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
  assert.ok(probeSource.includes('observationalEdits: profile.observationalEventsAdded ? ['));
  assert.ok(probeSource.includes('...BUILDING_ACTION_EDITS.map'));
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

test('CI runs ONLY two fixed mutant BFS diagnostics, not baseline, legacy profiles or the normal gate', () => {
  assert.ok(workflow.includes("branches: ['codex/protocol-witness-shape']"));
  for (const file of ['tools/protocol-invariant-probe.mjs', 'tools/protocol-invariant-probe.test.mjs', '.github/workflows/protocol-invariant-probe.yml']) {
    assert.ok(workflow.includes(`- '${file}'`));
  }
  assert.ok(workflow.includes('workflow_dispatch:'));
  assert.doesNotMatch(workflow, /--helper=|--property=|--context=baseline|context: baseline|property:/u);
  assert.ok(workflow.includes('fail-fast: false'));
  assert.deepEqual([...workflow.matchAll(/- context: ([a-z-]+)/gu)].map((match) => match[1]), CONTEXT_NAMES.slice(1));
  assert.doesNotMatch(workflow, /^\s+context:\s*\[/mu);
  assert.deepEqual([...workflow.matchAll(/run: node tools\/protocol-invariant-probe\.mjs ([^\r\n]+)/gu)].map((match) => match[1]), [
    '--profile=request-security-canary-bfs "--context=${{ matrix.context }}"',
  ]);
  assert.equal((workflow.match(/runs-on: ubuntu-24\.04/gu) ?? []).length, 1);
  assert.ok(workflow.includes('node tools/install-tamarin.mjs'));
  assert.ok(workflow.includes('node --test tools/protocol-invariant-probe.test.mjs tools/prover-process.test.mjs'));
  assert.ok(workflow.includes('persist-credentials: false'));
  assert.ok(workflow.includes('contents: read'));
  assert.ok(workflow.includes('protocol-invariant-probe-canary-bfs-${{ matrix.context }}-${{ github.sha }}'));
  assert.ok(workflow.includes('if: ${{ !cancelled() }}'));
  assert.ok(workflow.includes('if-no-files-found: error'));
  assert.doesNotMatch(workflow, /continue-on-error|pull_request_target|contents: write|security\/tamarin\/|artifacts\/protocol-security|--bound=|--stop-on-trace=|--profile=active-registry-lineage|--profile=request-security-one-property/u);
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
  assert.ok(probeSource.includes('requiredExpected: requiredInvariantVerdicts(selected, context, property)'));
  assert.ok(probeSource.includes("'required-counterexample-selected'"));
  assert.ok(probeSource.includes('selectedHelper: securityProfile || helpersOnlyProfile || onePropertyProfile || lineageProfile || canaryBfsProfile ? null'));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run'"));
  assert.ok(probeSource.includes('eligibleAsNormalGate: false'));
  assert.ok(probeSource.includes("'tools/protocol-invariant-probe.test.mjs', 'tools/protocol-security.mjs'"));
  assert.ok(probeSource.includes("unselectedLemmas: profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name)).map((name) => ({ name, status: 'not-selected' }))"));
  assert.doesNotMatch(workflow, /--profile=request-opened-with-building|--profile=request-security-with-helpers|--profile=request-security-helpers-only|--prove=|--reuse|--bound=|continue-on-error/u);
  assert.ok(workflow.includes('timeout-minutes: 15'));
  assert.equal((workflow.match(/run: node tools\/protocol-invariant-probe\.mjs /gu) ?? []).length, 1);
});

function helpersOnlyInput(context, invocation = 'fixture') {
  return resolve('SYNTHETIC-invariant-probe', `INVARIANT_PROBE_ONLY-${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}-${context}-${invocation}`, 'request.input.spthy');
}

function helpersOnlyOutput(context, verdicts = {}, invocation = 'fixture') {
  const path = helpersOnlyInput(context, invocation), profile = invariantProfile(REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context);
  return { status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${path}\n${profile.candidateLemmas.map((name) => {
      const trace = REQUEST_WITNESS_NAMES.includes(name) ? 'exists-trace' : 'all-traces';
      return ` ${name} (${trace}): ${verdicts[name] ?? (REQUEST_SECURITY_HELPERS.includes(name) ? 'verified (14 steps)' : 'analysis incomplete (0 steps)')}`;
    }).join('\n')}\n` };
}

test('helpers-only CLI is fixed and does not accept property, mutation, reuse or context overrides', () => {
  for (const context of CONTEXT_NAMES) {
    assert.deepEqual(selectInvariantRunArguments([`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, `--context=${context}`]), { selected: REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context });
  }
  for (const args of [
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`], [`--helper=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`],
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, '--context=constructor'],
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, '--context=__proto__'],
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, '--context=baseline', '--prove=honest_approve_trace'],
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, '--context=baseline', '--reuse'],
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, '--context=baseline', '--mutation=other'],
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, '--context=baseline', '--context=missing-replay-consumption'],
    ['--context=baseline', `--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`],
  ]) assert.throws(() => selectInvariantRunArguments(args));
});

for (const context of CONTEXT_NAMES) {
  test(`${context} helpers-only candidate is byte-identical to 8629bac full-profile input and erases to the original`, () => {
    const oldProfile = insertInvariantHelpers(source, REQUEST_SECURITY_PROFILE, context, manifest);
    const diagnostic = insertInvariantHelpers(source, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context, manifest);
    assert.deepEqual(diagnostic, oldProfile);
    assert.ok(Object.isFrozen(REQUEST_SECURITY_CANDIDATE_HASHES));
    assert.equal(REQUEST_SECURITY_REFERENCE_COMMIT, '8629bac07c27d86641f9ba2e8f8faaa99726a444');
    assert.equal(digest(diagnostic.candidate), REQUEST_SECURITY_CANDIDATE_HASHES[context]);
    assert.equal(eraseInvariantCandidate(diagnostic.candidate, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context, manifest), diagnostic.normalized);
    assert.equal(digest(diagnostic.normalized), ORIGIN_HASH);
    assert.deepEqual(admitInvariantCandidate(source, oldProfile.candidate, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context, manifest), diagnostic);
    for (const altered of [
      diagnostic.candidate + '\n',
      diagnostic.candidate.replace('lemma enrolled_revision_unique [reuse]:', 'lemma enrolled_revision_unique:'),
      diagnostic.candidate.replace('lemma request_opened_unique [reuse]:', 'lemma request_opened_unique:'),
      diagnostic.candidate.replace(BUILDING_ACTION_EDITS[0].to, BUILDING_ACTION_EDITS[0].from),
      diagnostic.candidate + '\nrestriction no_duplicate_captures: "All #i. False()@i ==> F"\n',
    ]) {
      assert.throws(() => admitInvariantCandidate(source, altered, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context, manifest));
      assert.throws(() => eraseInvariantCandidate(altered, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context, manifest));
    }
    const profile = invariantProfile(REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context);
    assert.deepEqual(profile.requiredLemmas, REQUEST_SECURITY_HELPERS);
    assert.deepEqual(profile.reusedHelpers, REQUEST_SECURITY_HELPERS);
    assert.deepEqual(profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name)), ORIGINAL_NAMES);
    const expected = Object.fromEntries(REQUEST_SECURITY_HELPERS.map((name) => [name, { trace: 'all-traces', verdict: 'verified' }]));
    assert.deepEqual(requiredInvariantVerdicts(REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context), expected);
    assert.deepEqual(invariantArguments(helpersOnlyInput(context), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context), [
      helpersOnlyInput(context), '--quit-on-warning', ...REQUEST_SECURITY_HELPERS.map((name) => `--prove=${name}`), '--stop-on-trace=DFS', '+RTS', '-N2', '-M2G', '-RTS',
    ]);
    assert.equal(PROBE_TIMEOUT_MS, 120_000);
    assert.equal(PROBE_OUTPUT_BYTES, 4 * 1024 * 1024);
  });

  test(`${context} helpers-only counts no partial helper stack or crossed invocation even with identical candidate bytes`, () => {
    const path = helpersOnlyInput(context), valid = helpersOnlyOutput(context);
    const expected = requiredInvariantVerdicts(REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context);
    const observed = selectedInvariantSummary(valid, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context);
    assert.equal(observed.ok, true);
    assert.deepEqual(observed.requiredVerdicts, expected);
    for (const name of REQUEST_SECURITY_HELPERS) {
      for (const verdict of ['falsified (7 steps)', 'analysis incomplete (0 steps)', 'verified', 'verified (14 steps) extra']) {
        assert.equal(selectedInvariantSummary(helpersOnlyOutput(context, { [name]: verdict }), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
      }
      const row = ` ${name} (all-traces): verified (14 steps)\n`;
      const missing = valid.stdout.replace(row, '');
      assert.notEqual(missing, valid.stdout);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: missing, requiredVerdicts: expected, candidateSha256: REQUEST_SECURITY_CANDIDATE_HASHES[context] }, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false, 'reference hashes or imported verdict fields supply no missing proof');
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + row }, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout.replace(`${name} (all-traces)`, `${name} (exists-trace)`) }, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
    }
    for (const other of CONTEXT_NAMES.filter((name) => name !== context)) {
      assert.equal(selectedInvariantSummary(helpersOnlyOutput(other), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
      assert.throws(() => invariantArguments(helpersOnlyInput(other), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context));
    }
    assert.equal(selectedInvariantSummary(helpersOnlyOutput(context, {}, 'old-run'), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
    assert.throws(() => invariantArguments(securityInput(context), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context));
    assert.equal(selectedInvariantSummary(securityOutput(context), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
    const relabeledOldScope = securityOutput(context).stdout.replace(securityInput(context), path);
    assert.equal(selectedInvariantSummary({ ...valid, stdout: relabeledOldScope }, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false, 'full-property verdicts cannot be relabeled as a helpers-only invocation');
    assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + valid.stdout }, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
    assert.equal(selectedInvariantSummary({ ...valid, stderr: '\u001b[33mWARNING\u001b[0m: dependency' }, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, context).ok, false);
    for (const delta of [{ status: 1 }, { signal: 'SIGTERM' }, { error: new Error('Prover timed out.') }, { cancelled: true }, { cleanupIncomplete: true }]) {
      const result = invariantRunSummary({ ...valid, ...delta }, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, true, context);
      assert.equal(result.completed, false);
      assert.equal(result.selectedProof.ok, false);
    }
    assert.equal(invariantRunSummary(valid, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, path, false, context).selectedProof.ok, false);
  });
}

test('helpers-only report never attributes original obligations or prior candidate identities as proof', () => {
  assert.ok(probeSource.includes("proofAuthority: 'none-source-identity-only'"));
  assert.ok(probeSource.includes("helperProofScope: 'same-invocation-same-context-only', importedProofs: false"));
  assert.ok(probeSource.includes('ALL original nine obligations, including existential witnesses and required mutant counterexamples, are unselected'));
  assert.ok(probeSource.includes('selectedSecurityProperties: securityProfile || onePropertyProfile || lineageProfile || canaryBfsProfile ?'));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run'"));
  assert.ok(probeSource.includes('eligibleAsNormalGate: false'));
  assert.ok(probeSource.includes('hash(candidate) !== REQUEST_SECURITY_CANDIDATE_HASHES[context]'));
  assert.equal((probeSource.match(/await runProver\(/gu) ?? []).length, 1);
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

function onePropertyInput(context, property, invocation = 'fixture') {
  return resolve('SYNTHETIC-invariant-probe', `INVARIANT_PROBE_ONLY-${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}-${context}-${property}-${invocation}`, 'request.input.spthy');
}

function onePropertyOutput(context, property, overrides = {}, invocation = 'fixture') {
  const profile = invariantProfile(REQUEST_SECURITY_ONE_PROPERTY_PROFILE, context, property);
  const expected = requiredInvariantVerdicts(REQUEST_SECURITY_ONE_PROPERTY_PROFILE, context, property);
  return { status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${onePropertyInput(context, property, invocation)}\n${profile.candidateLemmas.map((name) => {
      const trace = REQUEST_WITNESS_NAMES.includes(name) ? 'exists-trace' : 'all-traces';
      return ` ${name} (${trace}): ${overrides[name] ?? (Object.hasOwn(expected, name)
        ? expected[name].verdict === 'verified' ? 'verified (14 steps)' : 'falsified - found trace (17 steps)'
        : 'analysis incomplete (0 steps)')}`;
    }).join('\n')}\n` };
}

test('one-property CLI permits exactly six baseline cases and the two exact manifest canaries', () => {
  assert.ok(Object.isFrozen(ONE_PROPERTY_CASES));
  assert.equal(ONE_PROPERTY_CASES.length, 8);
  for (const entry of ONE_PROPERTY_CASES) {
    assert.ok(Object.isFrozen(entry));
    const { context, property } = entry;
    assert.deepEqual(selectInvariantRunArguments([`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`, `--context=${context}`, `--property=${property}`]), {
      selected: REQUEST_SECURITY_ONE_PROPERTY_PROFILE, context, property,
    });
  }
  assert.deepEqual(ONE_PROPERTY_CASES.filter((entry) => entry.context === 'baseline').map((entry) => entry.property), REQUEST_SECURITY_NAMES);
  for (const context of CONTEXT_NAMES.slice(1)) {
    const canary = manifest.models.find((model) => model.id === 'request-authorization').canaries.find((value) => value.id === context);
    assert.deepEqual(ONE_PROPERTY_CASES.filter((entry) => entry.context === context).map((entry) => entry.property), Object.keys(canary.expected));
  }
  for (const context of CONTEXT_NAMES) for (const property of [...ORIGINAL_NAMES, ...HELPER_NAMES, '__proto__', 'constructor', 'all']) {
    if (!ONE_PROPERTY_CASES.some((entry) => entry.context === context && entry.property === property)) {
      assert.throws(() => selectInvariantRunArguments([`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`, `--context=${context}`, `--property=${property}`]));
      assert.throws(() => invariantProfile(REQUEST_SECURITY_ONE_PROPERTY_PROFILE, context, property));
    }
  }
  const property = REQUEST_SECURITY_NAMES[0];
  for (const args of [
    [`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`],
    [`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`, '--context=baseline'],
    [`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`, `--property=${property}`, '--context=baseline'],
    [`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`, '--context=baseline', `--property=${property} `],
    [`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`, '--context=baseline', `--property=${property}`, '--reuse'],
    [`--profile=${REQUEST_SECURITY_ONE_PROPERTY_PROFILE}`, '--context=baseline', `--property=${property}`, `--property=${REQUEST_SECURITY_NAMES[1]}`],
    [`--profile=${REQUEST_SECURITY_HELPERS_ONLY_PROFILE}`, '--context=baseline', `--property=${property}`],
    [`--profile=${REQUEST_SECURITY_PROFILE}`, '--context=baseline', `--property=${property}`],
  ]) assert.throws(() => selectInvariantRunArguments(args));
  for (const selected of [...HELPER_NAMES, DEPENDENT_PROFILE, REQUEST_SECURITY_PROFILE, REQUEST_SECURITY_HELPERS_ONLY_PROFILE]) {
    assert.throws(() => invariantProfile(selected, 'baseline', property), 'old profiles cannot silently ignore a property override');
  }
});

for (const { context, property } of ONE_PROPERTY_CASES) {
  test(`${context}/${property} selects exactly three helpers plus one original property on the pinned unchanged candidate`, () => {
    const selected = REQUEST_SECURITY_ONE_PROPERTY_PROFILE;
    const old = insertInvariantHelpers(source, REQUEST_SECURITY_PROFILE, context, manifest);
    const candidate = insertInvariantHelpers(source, selected, context, manifest, property);
    assert.deepEqual(candidate, old);
    assert.equal(digest(candidate.candidate), REQUEST_SECURITY_CANDIDATE_HASHES[context]);
    assert.equal(eraseInvariantCandidate(candidate.candidate, selected, context, manifest, property), candidate.normalized);
    assert.equal(digest(candidate.normalized), ORIGIN_HASH);
    assert.deepEqual(admitInvariantCandidate(source, old.candidate, selected, context, manifest, property), candidate);
    assert.throws(() => insertInvariantHelpers(source, selected, context, manifest));
    assert.throws(() => eraseInvariantCandidate(candidate.candidate + '\n', selected, context, manifest, property));
    const profile = invariantProfile(selected, context, property);
    assert.deepEqual(profile.requiredLemmas, [...REQUEST_SECURITY_HELPERS, property]);
    assert.deepEqual(profile.reusedHelpers, REQUEST_SECURITY_HELPERS);
    assert.deepEqual(profile.candidateLemmas, [...REQUEST_SECURITY_HELPERS, ...ORIGINAL_NAMES]);
    assert.deepEqual(profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name)), ORIGINAL_NAMES.filter((name) => name !== property));
    const expected = Object.fromEntries([...REQUEST_SECURITY_HELPERS, property].map((name) => [name, {
      trace: 'all-traces', verdict: name === property && context !== 'baseline' ? 'falsified' : 'verified',
    }]));
    assert.deepEqual(requiredInvariantVerdicts(selected, context, property), expected);
    const input = onePropertyInput(context, property);
    assert.deepEqual(invariantArguments(input, selected, context, property), [
      input, '--quit-on-warning', ...Object.keys(expected).map((name) => `--prove=${name}`), '--stop-on-trace=DFS', '+RTS', '-N2', '-M2G', '-RTS',
    ]);
    assert.equal(Object.keys(expected).length, 4);
    assert.equal(PROBE_TIMEOUT_MS, 120_000);
    assert.equal(PROBE_OUTPUT_BYTES, 4 * 1024 * 1024);
  });

  test(`${context}/${property} requires fresh same-invocation helpers and rejects crossed or incomplete property evidence`, () => {
    const selected = REQUEST_SECURITY_ONE_PROPERTY_PROFILE, input = onePropertyInput(context, property);
    const expected = requiredInvariantVerdicts(selected, context, property), valid = onePropertyOutput(context, property);
    assert.equal(selectedInvariantSummary(valid, selected, input, context, property).ok, true);
    assert.deepEqual(selectedInvariantSummary(valid, selected, input, context, property).requiredVerdicts, expected);
    for (const name of Object.keys(expected)) {
      for (const verdict of ['analysis incomplete (0 steps)', expected[name].verdict === 'verified' ? 'falsified (3 steps)' : 'verified (14 steps)']) {
        assert.equal(selectedInvariantSummary(onePropertyOutput(context, property, { [name]: verdict }), selected, input, context, property).ok, false);
      }
      const row = valid.stdout.split('\n').find((line) => line.startsWith(` ${name} (all-traces):`));
      assert.ok(row);
      const missing = valid.stdout.replace(`${row}\n`, '');
      assert.equal(selectedInvariantSummary({ ...valid, stdout: missing, requiredVerdicts: expected }, selected, input, context, property).ok, false);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + `${row}\n` }, selected, input, context, property).ok, false);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout.replace(`${name} (all-traces)`, `${name} (exists-trace)`) }, selected, input, context, property).ok, false);
    }
    for (const other of ONE_PROPERTY_CASES.filter((entry) => entry.context !== context || entry.property !== property)) {
      assert.throws(() => invariantArguments(onePropertyInput(other.context, other.property), selected, context, property));
      assert.equal(selectedInvariantSummary(onePropertyOutput(other.context, other.property), selected, input, context, property).ok, false);
    }
    assert.equal(selectedInvariantSummary(onePropertyOutput(context, property, {}, 'old-run'), selected, input, context, property).ok, false);
    assert.throws(() => invariantArguments(helpersOnlyInput(context), selected, context, property));
    assert.throws(() => invariantArguments(securityInput(context), selected, context, property));
    const relabeledHelpers = helpersOnlyOutput(context).stdout.replace(helpersOnlyInput(context), input);
    assert.equal(selectedInvariantSummary({ ...valid, stdout: relabeledHelpers }, selected, input, context, property).ok, false, 'completed helper-only diagnostic is not a property result');
    for (const unselected of ORIGINAL_NAMES.filter((name) => name !== property)) {
      assert.equal(selectedInvariantSummary(onePropertyOutput(context, property, { [unselected]: 'verified (14 steps)' }), selected, input, context, property).ok, false);
    }
    assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + valid.stdout }, selected, input, context, property).ok, false);
    assert.equal(selectedInvariantSummary({ ...valid, stderr: 'WARNING: imported assumption' }, selected, input, context, property).ok, false);
    for (const delta of [{ status: 1 }, { signal: 'SIGTERM' }, { error: new Error('Prover timed out.') }, { cancelled: true }, { cleanupIncomplete: true }]) {
      const observed = invariantRunSummary({ ...valid, ...delta }, selected, input, true, context, property);
      assert.equal(observed.completed, false);
      assert.equal(observed.selectedProof.ok, false);
    }
    assert.equal(invariantRunSummary(valid, selected, input, false, context, property).selectedProof.ok, false);
  });
}

test('one-property attribution is explicit and cannot become a cached-helper or aggregate normal-gate claim', () => {
  assert.ok(probeSource.includes('selectedProperty: onePropertyProfile ? property : lineageProfile ? ACTIVE_REGISTRY_PROPERTY : canaryBfsProfile ? REQUIRED_COUNTEREXAMPLES[context] : null'));
  assert.ok(probeSource.includes('requiredExpected: requiredInvariantVerdicts(selected, context, property)'));
  assert.ok(probeSource.includes('invariantRunSummary(result, selected, input, inputsUnchanged, context, property)'));
  assert.ok(probeSource.includes("proofAuthority: 'none-source-identity-only'"));
  assert.ok(probeSource.includes("helperProofScope: 'same-invocation-same-context-only', importedProofs: false"));
  assert.ok(probeSource.includes('Only ONE closed selected original property in this exact context'));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run'"));
  assert.ok(probeSource.includes('eligibleAsNormalGate: false'));
  assert.equal((probeSource.match(/await runProver\(/gu) ?? []).length, 1);
  assert.equal((workflow.match(/run: node tools\/protocol-invariant-probe\.mjs /gu) ?? []).length, 1);
});

function lineageInput(invocation = 'fixture') {
  return resolve('SYNTHETIC-invariant-probe', `INVARIANT_PROBE_ONLY-${ACTIVE_REGISTRY_LINEAGE_PROFILE}-baseline-${invocation}`, 'request.input.spthy');
}

function lineageOutput(overrides = {}, invocation = 'fixture') {
  const profile = invariantProfile(ACTIVE_REGISTRY_LINEAGE_PROFILE, 'baseline');
  return { status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${lineageInput(invocation)}\n${profile.candidateLemmas.map((name) => {
      const trace = REQUEST_WITNESS_NAMES.includes(name) ? 'exists-trace' : 'all-traces';
      return ` ${name} (${trace}): ${overrides[name] ?? (profile.requiredLemmas.includes(name) ? 'verified (14 steps)' : 'analysis incomplete (0 steps)')}`;
    }).join('\n')}\n` };
}

test('lineage CLI is exactly one baseline-only profile with no property, helper, mutant or strategy override', () => {
  const selected = ACTIVE_REGISTRY_LINEAGE_PROFILE;
  assert.equal(selected, 'active-registry-lineage');
  assert.deepEqual(selectInvariantRunArguments([`--profile=${selected}`, '--context=baseline']), { selected, context: 'baseline' });
  for (const args of [
    [`--profile=${selected}`], [`--helper=${selected}`], [`--helper=${ACTIVE_REGISTRY_HELPER}`],
    [`--profile=${selected}`, '--context=missing-approval-signature'],
    [`--profile=${selected}`, '--context=missing-replay-consumption'],
    [`--profile=${selected}`, '--context=__proto__'], [`--profile=${selected}`, '--context=constructor'],
    [`--profile=${selected}`, '--context=baseline '], ['--context=baseline', `--profile=${selected}`],
    [`--profile=${selected}`, '--context=baseline', `--property=${ACTIVE_REGISTRY_PROPERTY}`],
    [`--profile=${selected}`, '--context=baseline', '--prove=all'],
    [`--profile=${selected}`, '--context=baseline', '--stop-on-trace=BFS'],
    [`--profile=${selected}`, '--context=baseline', '--context=baseline'],
  ]) assert.throws(() => selectInvariantRunArguments(args));
  for (const context of CONTEXT_NAMES.slice(1)) {
    assert.throws(() => invariantProfile(selected, context));
    assert.throws(() => insertInvariantHelpers(source, selected, context, manifest));
    assert.throws(() => invariantArguments(lineageInput(), selected, context));
  }
  assert.throws(() => invariantProfile(selected, 'baseline', ACTIVE_REGISTRY_PROPERTY));
  assert.throws(() => invariantProfile(ACTIVE_REGISTRY_HELPER));
});

test('lineage adds exactly six active-production actions and one required helper, with two exact inverse stages', () => {
  const selected = ACTIVE_REGISTRY_LINEAGE_PROFILE;
  const { normalized, candidate } = insertInvariantHelpers(source, selected, 'baseline', manifest);
  assert.equal(digest(candidate), '42b467b376c93d3e237021e420798a67549a1aedd17ccde6a001eb73c3d7385d', '65664b lineage candidate remains unchanged');
  const previous = insertInvariantHelpers(source, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, 'baseline', manifest);
  assert.ok(Object.isFrozen(ACTIVE_REGISTRY_ACTION_EDITS) && Object.isFrozen(ACTIVE_REGISTRY_HELPERS));
  assert.deepEqual(ACTIVE_REGISTRY_ACTION_EDITS.map((edit) => edit.rule), [
    'TrustedEnrollment', 'CaptureEligibleDevice', 'AcceptApproval', 'AcceptDenial',
    'TrustedReenrollmentWithSameKeys', 'TrustedReplacementWithSameKeys',
  ]);
  assert.equal(ACTIVE_REGISTRY_ACTION_EDITS.length, 6);
  assert.equal((candidate.match(/\bActiveRegistryProduced\(/gu) ?? []).length, 7, 'six action observations plus the helper premise');
  assert.equal((candidate.match(/\bBuildingProduced\(/gu) ?? []).length, 3, 'the existing two observations and helper are preserved');
  let manuallyErased = candidate.replace(ACTIVE_REGISTRY_HELPER_INSERTION, '');
  for (const edit of [...ACTIVE_REGISTRY_ACTION_EDITS].reverse()) {
    assert.ok(Object.isFrozen(edit));
    assert.equal(candidate.split(edit.to).length, 2, `${edit.rule} has exactly one reviewed addition`);
    assert.equal(edit.to.replace(`,\n       ${edit.observation}`, ''), edit.from, 'only one action was appended');
    manuallyErased = manuallyErased.replace(edit.to, edit.from);
  }
  assert.equal(manuallyErased, previous.candidate);
  assert.equal(eraseActiveRegistryLineage(candidate), previous.candidate);
  assert.equal(digest(eraseActiveRegistryLineage(candidate)), REQUEST_SECURITY_CANDIDATE_HASHES.baseline);
  assert.equal(eraseInvariantCandidate(candidate, selected, 'baseline', manifest), normalized);
  assert.equal(digest(normalized), ORIGIN_HASH);
  assert.deepEqual(admitInvariantCandidate(source, candidate, selected, 'baseline', manifest), { normalized, candidate });
  assert.deepEqual(insertInvariantHelpers(source.replace(/\r?\n/g, '\r\n'), selected, 'baseline', manifest), { normalized, candidate });
  const anchor = '\nlemma honest_approve_trace:\n';
  assert.equal(candidate.slice(candidate.indexOf(anchor)), normalized.slice(normalized.indexOf(anchor)), 'all original nine formulas remain byte-identical');
  assert.equal(ACTIVE_REGISTRY_HELPER_INSERTION, `
// ACTIVE_REGISTRY_LINEAGE_PROBE_ONLY: this helper MUST verify in this invocation before revocation counts.
lemma active_registry_production_precedes_revocation [use_induction,reuse]:
  all-traces
  "All pc device revision #p #r.
     ActiveRegistryProduced(pc, device, revision) @p
     & RegistryRevoked(pc, device, revision) @r
     ==> p < r"
`);
  const activeProducers = [];
  for (const [, rule, body] of candidate.matchAll(/^rule (\w+):\n([\s\S]*?)(?=^rule |^lemma |^end\s*$)/gm)) {
    const conclusions = body.match(/(?:--\[[\s\S]*?\]->|-->)([\s\S]*)$/u)?.[1];
    assert.ok(conclusions, `${rule} has a transition`);
    const production = conclusions.match(/\bRegistrySlot\(([^\n]*), 'active'\)/u);
    const actions = body.match(/--\[([\s\S]*?)\]->/u)?.[1] ?? '';
    if (production) {
      activeProducers.push(rule);
      const edit = ACTIVE_REGISTRY_ACTION_EDITS.find((entry) => entry.rule === rule);
      assert.ok(edit, `${rule} must have a production observation`);
      assert.equal(actions.split(edit.observation).length, 2);
      const [device, pc, revision] = production[1].split(', ');
      assert.equal(edit.observation, `ActiveRegistryProduced(${pc}, ${device}, ${revision})`, 'observation matches the exact produced tuple, not a retired tuple');
      if (rule === 'TrustedReplacementWithSameKeys') {
        assert.ok(actions.includes('RegistryRevoked(pc, device, old_revision)'));
        assert.equal(edit.observation, 'ActiveRegistryProduced(pc, device, ~new_revision)');
      }
    } else assert.doesNotMatch(actions, /\bActiveRegistryProduced\(/u, `${rule} is not an active-slot producer`);
  }
  assert.deepEqual(activeProducers, ACTIVE_REGISTRY_ACTION_EDITS.map((edit) => edit.rule));
  assert.deepEqual([...candidate.matchAll(/^lemma (\w+)(?: \[[^\r\n]*\])?:$/gm)].map((match) => match[1]), [
    ...ACTIVE_REGISTRY_HELPERS, ...ORIGINAL_NAMES,
  ]);
  for (const context of CONTEXT_NAMES) {
    const legacy = insertInvariantHelpers(source, REQUEST_SECURITY_ONE_PROPERTY_PROFILE, context, manifest,
      context === 'baseline' ? ACTIVE_REGISTRY_PROPERTY : REQUIRED_COUNTEREXAMPLES[context]);
    assert.equal(digest(legacy.candidate), REQUEST_SECURITY_CANDIDATE_HASHES[context], 'every legacy candidate pin remains unchanged');
    assert.doesNotMatch(legacy.candidate, /ActiveRegistryProduced|active_registry_production_precedes_revocation/u);
  }
});

test('lineage admission rejects omitted/duplicated observations, old revision, wrong order and any unreviewed change', () => {
  const selected = ACTIVE_REGISTRY_LINEAGE_PROFILE;
  const { candidate } = insertInvariantHelpers(source, selected, 'baseline', manifest);
  const wrongOrder = candidate.replace(ACTIVE_REGISTRY_HELPER_INSERTION, '').replace('\nlemma no_accept_after_request_cancelled:\n',
    ACTIVE_REGISTRY_HELPER_INSERTION + '\nlemma no_accept_after_request_cancelled:\n');
  const changes = [
    ...ACTIVE_REGISTRY_ACTION_EDITS.map((edit) => candidate.replace(edit.to, edit.from)),
    ...ACTIVE_REGISTRY_ACTION_EDITS.map((edit) => candidate.replace(edit.to, edit.to.replace(edit.observation, `${edit.observation}, ${edit.observation}`))),
    ...ACTIVE_REGISTRY_ACTION_EDITS.filter((edit) => edit.rule.startsWith('TrustedRe')).map((edit) =>
      candidate.replace(edit.to, edit.to.replace(edit.observation, 'ActiveRegistryProduced(pc, device, old_revision)'))),
    candidate.replace('ActiveRegistryProduced(pc, ~device, ~revision)', 'ActiveRegistryProduced(~device, pc, ~revision)'),
    candidate.replace(ACTIVE_REGISTRY_HELPER_INSERTION, ''),
    candidate.replace(ACTIVE_REGISTRY_HELPER_INSERTION, ACTIVE_REGISTRY_HELPER_INSERTION + ACTIVE_REGISTRY_HELPER_INSERTION),
    candidate.replace(`lemma ${ACTIVE_REGISTRY_HELPER} [use_induction,reuse]:`, `lemma ${ACTIVE_REGISTRY_HELPER} [reuse]:`),
    candidate.replace(`lemma ${ACTIVE_REGISTRY_HELPER} [use_induction,reuse]:`, `lemma ${ACTIVE_REGISTRY_HELPER} [use_induction]:`),
    candidate.replace(`lemma ${ACTIVE_REGISTRY_HELPER} [use_induction,reuse]:`, `lemma ${ACTIVE_REGISTRY_HELPER} [sources]:`),
    candidate.replace('     ==> p < r"', '     ==> r < p"'),
    candidate.replace('     ==> p < r"', '     ==> not (r < p)"'),
    wrongOrder,
    candidate.replace('lemma enrolled_revision_unique [reuse]:', 'lemma enrolled_revision_unique:'),
    candidate.replace(REUSED_BUILDING_INSERTION, ''),
    candidate.replace(BUILDING_ACTION_EDITS[0].to, BUILDING_ACTION_EDITS[0].from),
    candidate.replace('BuildingProduced(request_id, pc, binding)', 'BuildingProduced(request_id, pc, other_binding)'),
    candidate.replace("RegistrySlot(device, pc, revision, 'active'),", "!RegistrySlot(device, pc, revision, 'active'),"),
    candidate.replace('Fr(~new_revision)', 'In(~new_revision)'),
    candidate.replace('Out(~new_revision)', 'Out(old_revision)'),
    candidate.replace('left = right', 'left = left'),
    candidate.replace('==> not (r < a)', '==> not (a < r)'),
    candidate.replace(CONTEXT_MUTATIONS['missing-approval-signature'].from, CONTEXT_MUTATIONS['missing-approval-signature'].to),
    candidate.replace(CONTEXT_MUTATIONS['missing-replay-consumption'].from, CONTEXT_MUTATIONS['missing-replay-consumption'].to),
    candidate + '\nrestriction unreviewed: "All #i. False()@i ==> F"\n',
    candidate + '\n',
  ];
  for (const altered of changes) {
    assert.notEqual(altered, candidate);
    assert.throws(() => admitInvariantCandidate(source, altered, selected, 'baseline', manifest));
    assert.throws(() => eraseActiveRegistryLineage(altered));
    assert.throws(() => eraseInvariantCandidate(altered, selected, 'baseline', manifest));
  }
  const old = insertInvariantHelpers(source, REQUEST_SECURITY_PROFILE, 'baseline', manifest).candidate;
  assert.throws(() => admitInvariantCandidate(source, old, selected, 'baseline', manifest));
  assert.throws(() => admitInvariantCandidate(source, candidate, REQUEST_SECURITY_HELPERS_ONLY_PROFILE, 'baseline', manifest));
  for (const invalid of [null, '', candidate + '\0', 'x'.repeat(1024 * 1024 + 1)]) assert.throws(() => eraseActiveRegistryLineage(invalid));
});

test('lineage selects all four same-invocation helpers plus only unchanged revocation with fixed DFS controls', () => {
  const selected = ACTIVE_REGISTRY_LINEAGE_PROFILE, path = lineageInput();
  const profile = invariantProfile(selected, 'baseline');
  assert.deepEqual(ACTIVE_REGISTRY_HELPERS, [...REQUEST_SECURITY_HELPERS, ACTIVE_REGISTRY_HELPER]);
  assert.deepEqual(profile, {
    observationalEventsAdded: true, inductionHelpers: [BUILDING_HELPER, ACTIVE_REGISTRY_HELPER], helperReuse: true,
    requiredLemmas: [...ACTIVE_REGISTRY_HELPERS, ACTIVE_REGISTRY_PROPERTY], reusedHelpers: [...ACTIVE_REGISTRY_HELPERS],
    candidateLemmas: [...ACTIVE_REGISTRY_HELPERS, ...ORIGINAL_NAMES],
  });
  const expected = Object.fromEntries([...ACTIVE_REGISTRY_HELPERS, ACTIVE_REGISTRY_PROPERTY].map((name) => [name, { trace: 'all-traces', verdict: 'verified' }]));
  assert.deepEqual(requiredInvariantVerdicts(selected, 'baseline'), expected);
  assert.equal(Object.keys(expected).length, 5);
  assert.deepEqual(profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name)), ORIGINAL_NAMES.filter((name) => name !== ACTIVE_REGISTRY_PROPERTY));
  assert.deepEqual(invariantArguments(path, selected, 'baseline'), [
    path, '--quit-on-warning', ...Object.keys(expected).map((name) => `--prove=${name}`), '--stop-on-trace=DFS', '+RTS', '-N2', '-M2G', '-RTS',
  ]);
  assert.equal(PROBE_TIMEOUT_MS, 120_000);
  assert.equal(PROBE_OUTPUT_BYTES, 4 * 1024 * 1024);
  for (const other of [input, securityInput('baseline'), helpersOnlyInput('baseline'),
    onePropertyInput('baseline', ACTIVE_REGISTRY_PROPERTY),
    resolve('SYNTHETIC-invariant-probe', `INVARIANT_PROBE_ONLY-${selected}-missing-replay-consumption-fixture`, 'request.input.spthy')]) {
    assert.throws(() => invariantArguments(other, selected, 'baseline'));
  }
});

test('lineage counts no correct revocation result without every helper verified in this same invocation', () => {
  const selected = ACTIVE_REGISTRY_LINEAGE_PROFILE, path = lineageInput(), valid = lineageOutput();
  const expected = requiredInvariantVerdicts(selected, 'baseline');
  const accepted = selectedInvariantSummary(valid, selected, path, 'baseline');
  assert.equal(accepted.ok, true);
  assert.deepEqual(accepted.requiredVerdicts, expected);
  assert.deepEqual(accepted.verdict, expected[ACTIVE_REGISTRY_PROPERTY]);
  assert.equal(Object.hasOwn(accepted, 'verdicts'), false);
  for (const name of Object.keys(expected)) {
    for (const verdict of ['analysis incomplete (0 steps)', 'falsified - found trace (5 steps)', 'verified', 'verified (14 steps) trailing']) {
      const observed = selectedInvariantSummary(lineageOutput({ [name]: verdict }), selected, path, 'baseline');
      assert.equal(observed.ok, false);
      if (name !== ACTIVE_REGISTRY_PROPERTY) assert.deepEqual(observed.verdict, expected[ACTIVE_REGISTRY_PROPERTY], 'consumer row is deliberately correct');
    }
    const row = ` ${name} (all-traces): verified (14 steps)\n`;
    const missing = valid.stdout.replace(row, '');
    assert.notEqual(missing, valid.stdout);
    assert.equal(selectedInvariantSummary({ ...valid, stdout: missing, requiredVerdicts: expected,
      lineageReference: { sha256: REQUEST_SECURITY_CANDIDATE_HASHES.baseline, importedProofs: true } }, selected, path, 'baseline').ok, false,
    'prior candidate identity or attached verdict metadata cannot supply a missing helper/property row');
    assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + row }, selected, path, 'baseline').ok, false);
    assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout.replace(`${name} (all-traces)`, `${name} (exists-trace)`) }, selected, path, 'baseline').ok, false);
  }
  for (const name of ORIGINAL_NAMES.filter((entry) => entry !== ACTIVE_REGISTRY_PROPERTY)) {
    for (const verdict of ['verified (14 steps)', 'falsified - found trace (5 steps)']) {
      assert.equal(selectedInvariantSummary(lineageOutput({ [name]: verdict }), selected, path, 'baseline').ok, false, 'unselected original obligations cannot receive attributed verdicts');
    }
  }
});

test('lineage rejects missing final summary, crossed proof scopes, warnings, timeout and attribution drift', () => {
  const selected = ACTIVE_REGISTRY_LINEAGE_PROFILE, path = lineageInput(), valid = lineageOutput();
  assert.equal(selectedInvariantSummary(lineageOutput({}, 'old-run'), selected, path, 'baseline').ok, false);
  const legacy = onePropertyOutput('baseline', ACTIVE_REGISTRY_PROPERTY);
  assert.equal(selectedInvariantSummary({ ...legacy, stdout: legacy.stdout.replace(onePropertyInput('baseline', ACTIVE_REGISTRY_PROPERTY), path) }, selected, path, 'baseline').ok, false,
    'the prior same-property diagnostic lacks the required new helper even if relabeled');
  for (const context of CONTEXT_NAMES) {
    assert.equal(selectedInvariantSummary(securityOutput(context), selected, path, 'baseline').ok, false);
    assert.equal(selectedInvariantSummary(helpersOnlyOutput(context), selected, path, 'baseline').ok, false);
  }
  for (const stdout of ['', 'source saturation complete; no final summary\n',
    valid.stdout + valid.stdout, valid.stdout.replace('summary of summaries:', 'partial summary:'),
    valid.stdout + ' unexpected (all-traces): verified (1 steps)\n',
    `\u001b[33mWARNING\u001b[0m: unproved helper\n${valid.stdout}`,
  ]) assert.equal(selectedInvariantSummary({ ...valid, stdout }, selected, path, 'baseline').ok, false);
  assert.equal(selectedInvariantSummary({ ...valid, stderr: 'WARNING: imported assumption' }, selected, path, 'baseline').ok, false);
  for (const delta of [{ status: 1 }, { status: null }, { signal: 'SIGTERM' }, { error: new Error('Prover timed out.') }, { cancelled: true }, { cleanupIncomplete: true }]) {
    const observed = invariantRunSummary({ ...valid, ...delta }, selected, path, true, 'baseline');
    assert.equal(observed.completed, false);
    assert.equal(observed.selectedProof.ok, false);
  }
  for (const unchanged of [false, undefined, null, 'true']) {
    assert.equal(invariantRunSummary(valid, selected, path, unchanged, 'baseline').selectedProof.ok, false);
  }
});

test('lineage report distinguishes its changed candidate from the prior hash and leaves eight obligations unselected', () => {
  assert.ok(probeSource.includes("'BASELINE_ACTIVE_REGISTRY_LINEAGE_PROBE_ONLY'"));
  assert.ok(probeSource.includes("relationship: 'exact-after-erasing-six-lineage-actions-and-new-helper'"));
  assert.ok(probeSource.includes('previousCandidateAfterLineageErasureSha256: lineageProfile ? hash(eraseActiveRegistryLineage(candidate)) : null'));
  assert.ok(probeSource.includes('return eraseInvariantCandidate(eraseActiveRegistryLineage(candidate), REQUEST_SECURITY_HELPERS_ONLY_PROFILE, context, manifest)'));
  assert.ok(probeSource.includes('hash(restored) !== REQUEST_SECURITY_CANDIDATE_HASHES.baseline'));
  assert.ok(probeSource.includes("event: 'ActiveRegistryProduced', observation: edit.observation"));
  assert.ok(probeSource.includes('ALL FOUR reused helpers verifying in this SAME invocation'));
  assert.ok(probeSource.includes('All other original eight obligations and both mutant counterexamples remain unselected'));
  assert.ok(probeSource.includes("helperProofScope: 'same-invocation-same-context-only', importedProofs: false"));
  assert.ok(probeSource.includes("proofAuthority: 'none-source-identity-only'"));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run'"));
  assert.ok(probeSource.includes('eligibleAsNormalGate: false'));
  assert.equal((probeSource.match(/await runProver\(/gu) ?? []).length, 1);
  assert.doesNotMatch(probeSource, /--bound=|no_duplicate_captures|CaptureOnce/u);
  assert.doesNotMatch(invariantArguments(lineageInput(), ACTIVE_REGISTRY_LINEAGE_PROFILE, 'baseline').join('\n'), /--stop-on-trace=BFS/u);
});

function canaryBfsInput(context, invocation = 'fixture') {
  return resolve('SYNTHETIC-invariant-probe', `INVARIANT_PROBE_ONLY-${REQUEST_SECURITY_CANARY_BFS_PROFILE}-${context}-${invocation}`, 'request.input.spthy');
}

function canaryBfsOutput(context, overrides = {}, invocation = 'fixture') {
  const profile = invariantProfile(REQUEST_SECURITY_CANARY_BFS_PROFILE, context);
  return { status: 0, signal: null, error: null, cancelled: false, cleanupIncomplete: false, stderr: '',
    stdout: `summary of summaries:\n analyzed: ${canaryBfsInput(context, invocation)}\n${profile.candidateLemmas.map((name) => {
      const trace = REQUEST_WITNESS_NAMES.includes(name) ? 'exists-trace' : 'all-traces';
      const value = overrides[name] ?? (REQUEST_SECURITY_HELPERS.includes(name) ? 'verified (14 steps)'
        : name === REQUIRED_COUNTEREXAMPLES[context] ? 'falsified - found trace (17 steps)' : 'analysis incomplete (0 steps)');
      return ` ${name} (${trace}): ${value}`;
    }).join('\n')}\n` };
}

test('canary BFS CLI permits exactly two mutant contexts and no baseline, third argument or strategy override', () => {
  const selected = REQUEST_SECURITY_CANARY_BFS_PROFILE;
  assert.equal(selected, 'request-security-canary-bfs');
  assert.deepEqual(CONTEXT_NAMES.slice(1), ['missing-approval-signature', 'missing-replay-consumption']);
  for (const context of CONTEXT_NAMES.slice(1)) {
    assert.deepEqual(selectInvariantRunArguments([`--profile=${selected}`, `--context=${context}`]), { selected, context });
    const env = { CI: 'true', GITHUB_ACTIONS: 'true', TAMARIN_BIN: resolve('SYNTHETIC-tamarin-prover'), GITHUB_SHA: 'a'.repeat(40) };
    assert.deepEqual(admitInvariantEnvironment([`--profile=${selected}`, `--context=${context}`], env, 'linux'), {
      selected, context, binary: env.TAMARIN_BIN, commit: env.GITHUB_SHA,
    });
    assert.throws(() => admitInvariantEnvironment([`--profile=${selected}`, `--context=${context}`], env, 'win32'));
    assert.throws(() => invariantProfile(selected, context, REQUIRED_COUNTEREXAMPLES[context]));
    for (const extra of [`--property=${REQUIRED_COUNTEREXAMPLES[context]}`, '--prove=all', '--stop-on-trace=BFS', '--stop-on-trace=DFS', '--reuse', '--bound=1', `--context=${context}`]) {
      assert.throws(() => selectInvariantRunArguments([`--profile=${selected}`, `--context=${context}`, extra]));
    }
  }
  for (const args of [[], [`--profile=${selected}`], [`--helper=${selected}`],
    [`--profile=${selected}`, '--context=baseline'], [`--profile=${selected}`, '--context=__proto__'],
    [`--profile=${selected}`, '--context=constructor'], [`--profile=${selected}`, '--context=other'],
    [`--profile=${selected}`, '--context=missing-approval-signature '],
    ['--context=missing-approval-signature', `--profile=${selected}`],
    [`--profile=${selected} --context=missing-approval-signature`],
    [`--profile=${selected}`, '--context=missing-approval-signature', '--context=missing-replay-consumption'],
  ]) assert.throws(() => selectInvariantRunArguments(args));
  assert.throws(() => invariantProfile(selected));
  assert.throws(() => insertInvariantHelpers(source, selected, 'baseline', manifest));
  assert.throws(() => requiredInvariantVerdicts(selected, 'baseline'));
});

for (const context of CONTEXT_NAMES.slice(1)) {
  test(`${context} BFS uses the exact pinned three-helper candidate, original formulas and exact manifest mutation`, () => {
    const selected = REQUEST_SECURITY_CANARY_BFS_PROFILE, property = REQUIRED_COUNTEREXAMPLES[context];
    const old = insertInvariantHelpers(source, REQUEST_SECURITY_ONE_PROPERTY_PROFILE, context, manifest, property);
    const observed = insertInvariantHelpers(source, selected, context, manifest);
    assert.deepEqual(observed, old);
    assert.equal(digest(observed.candidate), REQUEST_SECURITY_CANDIDATE_HASHES[context]);
    assert.equal(eraseInvariantCandidate(observed.candidate, selected, context, manifest), observed.normalized);
    assert.equal(digest(observed.normalized), ORIGIN_HASH);
    assert.deepEqual(admitInvariantCandidate(source, observed.candidate, selected, context, manifest), observed);
    assert.deepEqual(insertInvariantHelpers(source.replace(/\r?\n/g, '\r\n'), selected, context, manifest), observed);
    const anchor = '\nlemma honest_approve_trace:\n';
    assert.equal(observed.candidate.slice(observed.candidate.indexOf(anchor)), observed.normalized.slice(observed.normalized.indexOf(anchor)), 'all original nine formulas are unchanged');
    assert.doesNotMatch(observed.candidate, /ActiveRegistryProduced|active_registry_production_precedes_revocation/u);
    assert.equal((observed.candidate.match(/\bBuildingProduced\(/gu) ?? []).length, 3);
    const canary = manifest.models.find((model) => model.id === 'request-authorization').canaries.find((entry) => entry.id === context);
    assert.deepEqual(canary.mutation, CONTEXT_MUTATIONS[context]);
    assert.deepEqual(canary.expected, { [property]: { trace: 'all-traces', verdict: 'falsified' } });
    assert.equal(invariantContextSource(source, selected, context, manifest), observed.normalized.replace(canary.mutation.from, canary.mutation.to));
    for (const changed of [
      observed.candidate + '\n',
      observed.candidate.replace(REUSED_BUILDING_INSERTION, ''),
      observed.candidate.replace('lemma enrolled_revision_unique [reuse]:', 'lemma enrolled_revision_unique:'),
      observed.candidate.replace('lemma request_opened_unique [reuse]:', 'lemma request_opened_unique:'),
      observed.candidate.replace('[use_induction,reuse]', '[sources]'),
      observed.candidate.replace(BUILDING_ACTION_EDITS[0].to, BUILDING_ACTION_EDITS[0].from),
      observed.candidate.replace(BUILDING_ACTION_EDITS[1].to, BUILDING_ACTION_EDITS[1].from),
      observed.candidate.replace(`lemma ${property}:`, `lemma ${property} [reuse]:`),
      observed.candidate.replace('left = right', 'left = left'),
      observed.candidate + '\nrestriction unreviewed: "All #i. False()@i ==> F"\n',
      insertInvariantHelpers(source, ACTIVE_REGISTRY_LINEAGE_PROFILE, 'baseline', manifest).candidate,
    ]) {
      assert.notEqual(changed, observed.candidate);
      assert.throws(() => admitInvariantCandidate(source, changed, selected, context, manifest));
      assert.throws(() => eraseInvariantCandidate(changed, selected, context, manifest));
    }
    for (const other of CONTEXT_NAMES.filter((entry) => entry !== context)) {
      assert.throws(() => admitInvariantCandidate(source, observed.candidate, selected, other, manifest));
    }
    assert.throws(() => insertInvariantHelpers(source, selected, context));
    const alteredManifest = structuredClone(manifest);
    alteredManifest.models.find((model) => model.id === 'request-authorization').canaries.find((entry) => entry.id === context).mutation.to += '\n// extra mutation';
    assert.throws(() => insertInvariantHelpers(source, selected, context, alteredManifest));
  });

  test(`${context} BFS requires three verified helpers and the exact falsified canary with only search order changed`, () => {
    const selected = REQUEST_SECURITY_CANARY_BFS_PROFILE, property = REQUIRED_COUNTEREXAMPLES[context], path = canaryBfsInput(context);
    const profile = invariantProfile(selected, context);
    assert.deepEqual(profile, {
      observationalEventsAdded: true, inductionHelpers: [BUILDING_HELPER], helperReuse: true,
      requiredLemmas: [...REQUEST_SECURITY_HELPERS, property], reusedHelpers: [...REQUEST_SECURITY_HELPERS],
      candidateLemmas: [...REQUEST_SECURITY_HELPERS, ...ORIGINAL_NAMES],
    });
    const expected = Object.fromEntries([...REQUEST_SECURITY_HELPERS, property].map((name) => [name, {
      trace: 'all-traces', verdict: name === property ? 'falsified' : 'verified',
    }]));
    assert.deepEqual(requiredInvariantVerdicts(selected, context), expected);
    assert.equal(Object.keys(expected).length, 4);
    const unselected = profile.candidateLemmas.filter((name) => !profile.requiredLemmas.includes(name));
    assert.deepEqual(unselected, ORIGINAL_NAMES.filter((name) => name !== property));
    assert.equal(unselected.length, 8);
    const argv = invariantArguments(path, selected, context);
    assert.deepEqual(argv, [path, '--quit-on-warning', ...Object.keys(expected).map((name) => `--prove=${name}`), '--stop-on-trace=BFS', '+RTS', '-N2', '-M2G', '-RTS']);
    const prior = invariantArguments(onePropertyInput(context, property), REQUEST_SECURITY_ONE_PROPERTY_PROFILE, context, property);
    assert.deepEqual(argv.slice(1), prior.slice(1).map((argument) => argument === '--stop-on-trace=DFS' ? '--stop-on-trace=BFS' : argument));
    assert.equal(prior.filter((argument) => argument === '--stop-on-trace=DFS').length, 1, 'the old mixed helper/canary profile stays DFS');
    assert.equal(PROBE_TIMEOUT_MS, 120_000);
    assert.equal(PROBE_OUTPUT_BYTES, 4 * 1024 * 1024);
    for (const other of [input, lineageInput(), securityInput(context), helpersOnlyInput(context), onePropertyInput(context, property),
      ...CONTEXT_NAMES.filter((entry) => entry !== context).map((entry) => canaryBfsInput(entry))]) {
      assert.throws(() => invariantArguments(other, selected, context));
    }
  });

  test(`${context} BFS never counts a counterexample with a falsified, absent or unproved reused helper`, () => {
    const selected = REQUEST_SECURITY_CANARY_BFS_PROFILE, property = REQUIRED_COUNTEREXAMPLES[context], path = canaryBfsInput(context), valid = canaryBfsOutput(context);
    const expected = requiredInvariantVerdicts(selected, context);
    const accepted = selectedInvariantSummary(valid, selected, path, context);
    assert.equal(accepted.ok, true);
    assert.deepEqual(accepted.requiredVerdicts, expected);
    assert.deepEqual(accepted.verdict, { trace: 'all-traces', verdict: 'falsified' });
    assert.equal(Object.hasOwn(accepted, 'verdicts'), false);
    for (const name of Object.keys(expected)) {
      for (const verdict of ['analysis incomplete (0 steps)', 'verified', 'verified (14 steps) trailing',
        name === property ? 'verified (14 steps)' : 'falsified - found trace (17 steps)']) {
        const observed = selectedInvariantSummary(canaryBfsOutput(context, { [name]: verdict }), selected, path, context);
        assert.equal(observed.ok, false);
        if (name !== property) assert.deepEqual(observed.verdict, expected[property], 'the correct counterexample row alone is deliberately present');
      }
      const row = valid.stdout.split('\n').find((line) => line.startsWith(` ${name} (all-traces):`));
      assert.ok(row);
      const missing = valid.stdout.replace(`${row}\n`, '');
      assert.notEqual(missing, valid.stdout);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: missing, requiredVerdicts: expected,
        candidateSha256: REQUEST_SECURITY_CANDIDATE_HASHES[context], searchStrategy: 'BFS' }, selected, path, context).ok, false,
      'reference hashes, attached results or strategy metadata cannot replace a missing in-invocation result');
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout + `${row}\n` }, selected, path, context).ok, false);
      assert.equal(selectedInvariantSummary({ ...valid, stdout: valid.stdout.replace(`${name} (all-traces)`, `${name} (exists-trace)`) }, selected, path, context).ok, false);
    }
    const wrong = Object.values(REQUIRED_COUNTEREXAMPLES).find((name) => name !== property);
    assert.equal(selectedInvariantSummary(canaryBfsOutput(context, { [property]: 'analysis incomplete (0 steps)', [wrong]: 'falsified - found trace (17 steps)' }), selected, path, context).ok, false);
    for (const unselected of ORIGINAL_NAMES.filter((name) => name !== property)) {
      for (const verdict of ['verified (14 steps)', 'falsified - found trace (17 steps)']) {
        assert.equal(selectedInvariantSummary(canaryBfsOutput(context, { [unselected]: verdict }), selected, path, context).ok, false);
      }
    }
  });

  test(`${context} BFS rejects crossed summaries, unknown rows, process errors, timeout and changed attribution`, () => {
    const selected = REQUEST_SECURITY_CANARY_BFS_PROFILE, path = canaryBfsInput(context), valid = canaryBfsOutput(context);
    assert.equal(selectedInvariantSummary(canaryBfsOutput(context, {}, 'previous-invocation'), selected, path, context).ok, false);
    const other = CONTEXT_NAMES.slice(1).find((entry) => entry !== context);
    assert.equal(selectedInvariantSummary(canaryBfsOutput(other), selected, path, context).ok, false);
    assert.equal(selectedInvariantSummary(onePropertyOutput(context, REQUIRED_COUNTEREXAMPLES[context]), selected, path, context).ok, false);
    assert.equal(selectedInvariantSummary(securityOutput(context), selected, path, context).ok, false);
    assert.equal(selectedInvariantSummary(lineageOutput(), selected, path, context).ok, false);
    const helpersOnly = helpersOnlyOutput(context);
    assert.equal(selectedInvariantSummary({ ...helpersOnly, stdout: helpersOnly.stdout.replace(helpersOnlyInput(context), path) }, selected, path, context).ok, false, 'helper proofs alone do not establish a counterexample');
    for (const stdout of ['', 'source saturation finished; no final summary\n', valid.stdout + valid.stdout,
      valid.stdout.replace('summary of summaries:', 'partial summary:'),
      valid.stdout + ' unregistered (all-traces): falsified - found trace (1 steps)\n',
      `\u001b[33mWARNING\u001b[0m: unproved dependency\n${valid.stdout}`,
    ]) assert.equal(selectedInvariantSummary({ ...valid, stdout }, selected, path, context).ok, false);
    for (const stderr of ['WARNING: imported assumption', 'returned unsupported version']) {
      assert.equal(selectedInvariantSummary({ ...valid, stderr }, selected, path, context).ok, false);
    }
    for (const delta of [{ status: 1 }, { status: null }, { signal: 'SIGTERM' }, { error: new Error('Prover timed out.') }, { cancelled: true }, { cleanupIncomplete: true }]) {
      const observed = invariantRunSummary({ ...valid, ...delta }, selected, path, true, context);
      assert.equal(observed.completed, false);
      assert.equal(observed.selectedProof.ok, false);
    }
    for (const unchanged of [false, null, undefined, 'true']) {
      assert.equal(invariantRunSummary(valid, selected, path, unchanged, context).selectedProof.ok, false);
    }
  });
}

test('canary BFS metadata records only search order, pinned source identity and same-invocation proof authority', () => {
  assert.ok(probeSource.includes("'MUTANT_REQUEST_SECURITY_CANARY_BFS_PROBE_ONLY'"));
  assert.ok(probeSource.includes("searchStrategy: canaryBfsProfile ? { method: 'BFS', change: 'search-order-only', depthBound: null } : null"));
  assert.ok(probeSource.includes("same(argv.filter((argument) => argument.startsWith('--stop-on-trace=')), ['--stop-on-trace=DFS'])"));
  assert.ok(probeSource.includes('if (selected === REQUEST_SECURITY_CANARY_BFS_PROFILE) {'));
  assert.ok(probeSource.includes('Fixed BFS changes search order only, with no depth bound or imported assumptions/proofs'));
  assert.ok(probeSource.includes('All other original eight obligations and the other mutant remain unselected'));
  assert.ok(probeSource.includes('candidateReference: pinnedSecurityCandidate(selected) ?'));
  assert.ok(probeSource.includes('sha256: REQUEST_SECURITY_CANDIDATE_HASHES[context]'));
  assert.ok(probeSource.includes("helperProofScope: 'same-invocation-same-context-only', importedProofs: false"));
  assert.ok(probeSource.includes("proofAuthority: 'none-source-identity-only'"));
  assert.ok(probeSource.includes("securityProfile || onePropertyProfile || canaryBfsProfile ? 'required-counterexample-selected'"));
  assert.ok(probeSource.includes('sources, binary, binaryMetadata: tool, arguments: argv'));
  assert.ok(probeSource.includes('maxOutputBytes: PROBE_OUTPUT_BYTES, signal: cancellation.signal'));
  assert.ok(probeSource.includes("normalGateStatus: 'not-run'"));
  assert.ok(probeSource.includes('eligibleAsNormalGate: false'));
  assert.equal((probeSource.match(/await runProver\(/gu) ?? []).length, 1);
  assert.doesNotMatch(probeSource, /--bound=|--no-reuse|--no-restrictions|no_duplicate_captures|CaptureOnce/u);
});
