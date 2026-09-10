// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { mutateExactlyOnce, parseProofSummary, proofArguments, proofRequirements, runProtocolSecurity, validateTheoryRequirements } from './protocol-security.mjs';
import { WITNESS_CONTEXTS, deriveWitness, exactWitnessResult, requireDerivedWitness, witnessArguments,
  witnessCoverage, witnessDischarges, witnessExpected, witnessProfile } from './protocol-witness-discharge.mjs';
import { COUNTEREXAMPLE_CONTEXTS, counterexampleArguments, counterexampleCoverage, counterexampleDischarge,
  counterexampleExpected, counterexampleProfile, deriveCounterexample, exactCounterexampleResult,
  requireDerivedCounterexample } from './protocol-counterexample-discharge.mjs';
const expected = { auth: { trace: 'all-traces', verdict: 'verified' }, executable: { trace: 'exists-trace', verdict: 'verified' } };
const text = 'summary of summaries:\n analyzed: Model.spthy\n auth (all-traces): verified (5 steps)\n executable (exists-trace): verified (3 steps)\n';
const result = (stdout) => ({ stdout, stderr: '', status: 0, signal: null });
const parse = (input, expected, known) => parseProofSummary(input, expected, known, 'Model.spthy');
const helpers = {
  enrolled_revision_unique: { trace: 'all-traces', verdict: 'verified' },
  building_precedes_open: { trace: 'all-traces', verdict: 'verified' },
  request_opened_unique: { trace: 'all-traces', verdict: 'verified' },
  active_registry_production_precedes_revocation: { trace: 'all-traces', verdict: 'verified' },
};
const declarations = (wanted, auxiliary = false) => Object.entries(wanted).map(([name, value]) =>
  `lemma ${name}${auxiliary ? ' [reuse]' : ''}:\n  ${value.trace}\n  "synthetic statement"\n`).join('\n');

test('closed canary profiles retain both original universal obligations and sixteen normal rows', () => {
  const manifest = JSON.parse(readFileSync(new URL('../security/tamarin/manifest.json', import.meta.url), 'utf8'));
  const model = manifest.models.find(model => model.id === 'request-authorization');
  assert.equal(manifest.models.reduce((count, model) => count + Object.keys(model.expected).length + model.canaries.length, 0), 16);
  for (const canary of model.canaries) {
    const profile = counterexampleDischarge(model, canary);
    assert.deepEqual(canary.expected, { [profile.obligation]: { trace: 'all-traces', verdict: 'falsified' } });
    assert.equal(counterexampleDischarge(model, { ...canary, counterexampleDischarge: undefined }), null);
    for (const changed of [null, {}, { profile: 'unknown' }, { profile: profile.profile, proof: 'cached.proof' },
      { profile: profile.profile, helpers: helpers }]) assert.throws(() => counterexampleDischarge(model, { ...canary, counterexampleDischarge: changed }));
    assert.throws(() => counterexampleDischarge({ ...model, id: 'pinned-channel' }, canary));
    assert.throws(() => counterexampleDischarge({ ...model, expected: { ...model.expected,
      [profile.obligation]: { trace: 'exists-trace', verdict: 'verified' } } }, canary));
    assert.throws(() => counterexampleDischarge(model, { ...canary, expected: { [profile.checkedLemma]: { trace: 'exists-trace', verdict: 'verified' } } }));
    assert.throws(() => counterexampleDischarge(model, { ...canary, mutation: { ...canary.mutation, to: 'different mutation' } }));
    assert.throws(() => counterexampleDischarge(model, { ...canary, id: 'renamed-canary' }));
  }
});

test('attack templates derive current exact prefixes with only the registered mutation and no proof assumptions', () => {
  const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
  for (const id of ['missing-approval-signature', 'missing-replay-consumption']) {
    const profile = counterexampleProfile(id), normalized = source.replace(/\r\n/g, '\n');
    const baseline = deriveCounterexample(source, id, 'baseline'), mutant = deriveCounterexample(source, id, 'mutant');
    assert.equal(baseline.transitionSource, source.slice(0, /^lemma\s/m.exec(source).index));
    assert.equal(mutant.transitionSource, mutateExactlyOnce(baseline.transitionSource, profile.mutation));
    assert.equal(mutant.input.slice(mutant.transitionSource.length), baseline.input.slice(baseline.transitionSource.length));
    assert.deepEqual(mutant.structural.assumedHelpers, []); assert.deepEqual(mutant.structural.suppliedProofs, []);
    assert.equal(mutant.structural.originalUniversalDirectlyChecked, false);
    assert.equal(mutant.structural.baselineNoTraceDoesNotProveOriginalUniversal, true);
    for (const context of COUNTEREXAMPLE_CONTEXTS) {
      const derived = deriveCounterexample(source, id, context), args = counterexampleArguments('/input.spthy', id);
      assert.equal((derived.input.match(/^lemma\s/gm) ?? []).length, 1);
      assert.doesNotMatch(derived.input, /\[reuse\]|\[sources\]|^\s*by\b/m);
      assert.deepEqual(args, ['/input.spthy', '--quit-on-warning', `--prove=${profile.checkedLemma}`,
        `--stop-on-trace=${id === 'missing-replay-consumption' ? 'DFS' : 'BFS'}`, '+RTS', '-N2', '-M2G', '-RTS']);
      for (const changed of [derived.input.replace('builtins: signing', 'builtins: signing, hashing'),
        derived.input.replace('& a1 < a2', '& a1 = a2'), derived.input.replace('& not (Ex #u.', '& (Ex #u.'),
        derived.input.replace('exists-trace', 'all-traces'), derived.input.replace('\n\nend\n', '\nby SOLVED\n\nend\n'),
        `${derived.input}\nrestriction injected: "T"\n`].filter(value => value !== derived.input)) {
        assert.throws(() => requireDerivedCounterexample(source, id, context, changed));
      }
    }
    for (const changed of [normalized.replace(profile.original, profile.original.replace('"All pc ', '"All pc other_pc ')),
      normalized.replace(profile.original, profile.original.replace('==>', '|')),
      normalized.replace(profile.original, profile.original.replace('@a', '@other').replace('@i', '@other')),
      `${source}\n// ${profile.mutation.from}\n`, source.replace(profile.mutation.from, 'missing marker'),
      source.replace('begin', 'begin\n#include "foreign.spthy"'), source.replace('begin', 'begin\naxiom injected: "T"')].filter(value => value !== source)) {
      assert.throws(() => deriveCounterexample(changed, id, 'mutant'));
    }
  }
  const auth = counterexampleProfile('missing-approval-signature').attack;
  assert.ok(auth.includes("RequestAccepted(pc, device, revision, binding, 'approve') @a\n    & not (Ex #u. UserAuthenticated(device, binding) @u & u < a)"));
  const replay = counterexampleProfile('missing-replay-consumption').attack;
  assert.ok(replay.includes("RequestAccepted(pc, device, revision, binding, 'approve') @a1\n    & RequestAccepted(pc, device, revision, binding, 'approve') @a2\n    & a1 < a2"));
});

test('falsified existential means no trace and is never parsed as a universal counterexample', () => {
  const output = (trace, verdict) => result(`summary of summaries:\n analyzed: Model.spthy\n auth (${trace}): ${verdict} (5 steps)\n`);
  for (const trace of ['exists-trace', 'all-traces']) {
    const wanted = { auth: { trace, verdict: 'falsified' } };
    assert.equal(parse(output(trace, trace === 'exists-trace' ? 'falsified - no trace found' : 'falsified - found trace'), wanted).ok, true);
    assert.equal(parse(output(trace, trace === 'exists-trace' ? 'falsified - found trace' : 'falsified - no trace found'), wanted).ok, false);
  }
});

test('counterexample coverage needs both exact current-context verdicts, not cached, crossed or unknown summaries', () => {
  const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
  for (const id of ['missing-approval-signature', 'missing-replay-consumption']) {
    const profile = counterexampleProfile(id), structural = deriveCounterexample(source, id, 'mutant').structural;
    const make = (context, verdict) => ({ status: 0, signal: null, cancelled: false, cleanupIncomplete: false,
      stdout: `summary of summaries:\n analyzed: ${context}.spthy\n ${profile.checkedLemma} (exists-trace): ${verdict}\n`, stderr: '' });
    const check = (context, value) => ({ context, status: value.status, signal: value.signal, processError: value.error?.message,
      cancelled: value.cancelled, cleanupIncomplete: value.cleanupIncomplete,
      ...exactCounterexampleResult(parseProofSummary(value, counterexampleExpected(id, context), [profile.checkedLemma], `${context}.spthy`), value, id, context) });
    const mutant = check('mutant', make('mutant', 'verified (35 steps)'));
    const baseline = check('baseline', make('baseline', 'falsified - no trace found (26 steps)'));
    assert.equal(counterexampleCoverage(structural, [mutant, baseline]).discharged, true);
    assert.deepEqual(Object.keys(mutant.verdicts), [profile.checkedLemma]);
    assert.equal(Object.hasOwn(mutant.verdicts, profile.obligation), false);
    for (const context of COUNTEREXAMPLE_CONTEXTS) {
      const good = make(context, context === 'mutant' ? 'verified (1 steps)' : 'falsified - no trace found (1 steps)');
      for (const patch of [{ status: 1 }, { signal: 'SIGTERM' }, { cancelled: true }, { cleanupIncomplete: true },
        { error: new Error('timeout') }, { stderr: 'Warning: dependency issue' },
        { stdout: good.stdout + good.stdout }, { stdout: good.stdout.replace(`${context}.spthy`, 'other.spthy') },
        { stdout: good.stdout.replace(profile.checkedLemma, profile.obligation) },
        { stdout: good.stdout.replace('(exists-trace)', '(all-traces)') },
        { stdout: good.stdout.replace(/: (?:verified|falsified - no trace found) \(1 steps\)/, ': unknown (1 steps)') }]) {
        assert.equal(check(context, { ...good, ...patch }).ok, false);
      }
    }
    for (const verdict of ['verified (1 steps)', 'analysis incomplete (1 steps)', 'falsified - found trace (1 steps)', 'falsified (1 steps)']) {
      assert.equal(check('baseline', make('baseline', verdict)).ok, false);
    }
    assert.equal(counterexampleCoverage(structural, [mutant, { ...baseline, ok: false }]).discharged, false);
    assert.throws(() => counterexampleCoverage(structural, [mutant]));
    assert.throws(() => counterexampleCoverage(structural, [baseline, mutant]));
    assert.throws(() => counterexampleCoverage({ ...structural, originalUniversalDirectlyChecked: true }, [mutant, baseline]));
    assert.throws(() => counterexampleCoverage({ ...structural, assumedHelpers: ['assumed'] }, [mutant, baseline]));
  }
});

test('closed discharge profiles cover only the three approved existentials and preserve every manifest obligation', () => {
  const manifest = JSON.parse(readFileSync(new URL('../security/tamarin/manifest.json', import.meta.url), 'utf8'));
  const model = manifest.models.find(model => model.id === 'request-authorization');
  assert.deepEqual(Object.keys(witnessDischarges(model)), ['honest_approve_trace', 'honest_deny_without_approval_auth_trace', 'honest_two_approvers_single_winner_trace']);
  assert.equal(manifest.models.reduce((count, model) => count + Object.keys(model.expected).length + model.canaries.length, 0), 16);
  assert.deepEqual(witnessDischarges({ expected: {} }), {});
  for (const changed of [{}, { bogus: {} }, { honest_approve_trace: { profile: 'approval-conjunction-v1', proof: '../outside.proof' } },
    { honest_approve_trace: { ...model.witnessDischarges.honest_approve_trace, assumed: true } }]) {
    assert.throws(() => witnessDischarges({ ...model, witnessDischarges: changed }));
  }
  assert.throws(() => witnessDischarges({ ...model, id: 'pinned-channel' }));
  assert.throws(() => witnessDischarges({ ...model, expected: { ...model.expected, honest_approve_trace: { trace: 'all-traces', verdict: 'verified' } } }));
});

test('current transition bytes remain exact while independent witness input contains no helper declarations', () => {
  const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
  for (const obligation of ['honest_approve_trace', 'honest_deny_without_approval_auth_trace', 'honest_two_approvers_single_winner_trace']) {
    const profile = witnessProfile(obligation), proof = readFileSync(new URL(`../${profile.proof}`, import.meta.url), 'utf8');
    const originalConjuncts = profile.original.slice(profile.original.indexOf('.\n') + 2, -1);
    assert.ok(profile.stronger.includes(originalConjuncts));
    for (const context of WITNESS_CONTEXTS) {
      const derived = deriveWitness(source, proof, obligation, context);
      assert.equal(derived.input.slice(0, derived.transitionSource.length), derived.transitionSource);
      assert.equal(derived.transitionSource, source.slice(0, /^lemma\s/m.exec(source).index));
      assert.equal((derived.input.match(/^lemma\s/gm) ?? []).length, 1);
      assert.doesNotMatch(derived.input, /^lemma[^\n]*\[(?:[^\]]*reuse|[^\]]*sources)/m);
      assert.deepEqual(derived.structural.assumedHelpers, []);
      assert.equal(derived.structural.originalDirectlyVerified, false);
      assert.equal(derived.structural.obligation, obligation);
      if (context !== 'good') assert.ok(derived.input.includes(`\nby ${context}\n`));
      assert.deepEqual(witnessArguments('/checked.spthy'), ['/checked.spthy', '--quit-on-warning', '+RTS', '-N2', '-M2G', '-RTS']);
      for (const changed of [derived.input.replace('builtins: signing', 'builtins: signing, hashing'),
        derived.input.replace("'approve'", "'deny'"), derived.input.replace(' & o < u', ' | o < u'),
        `${derived.input}\nrestriction injected: "T"\n`].filter(value => value !== derived.input)) {
        assert.throws(() => requireDerivedWitness(source, proof, obligation, context, changed));
      }
    }
    const normalized = source.replace(/\r\n/g, '\n');
    for (const changed of [normalized.replace(profile.original, profile.original.replace('"Ex pc ', '"Ex pc pc ')),
      normalized.replace(profile.original, profile.original.replace(' & o <', ' | o <')),
      normalized.replace(profile.original, profile.original.replace('exists-trace', 'all-traces')),
      normalized.replace(profile.original, profile.original.replace(' & o <', ' & a <')) + `\n/*${profile.original}*/\n`]) {
      assert.throws(() => deriveWitness(changed, proof, obligation));
    }
    for (const injection of ['\nrule Injected:\n', '\nlemma fake [reuse]: "T"\n', '\n#include "outside"\n']) {
      assert.throws(() => deriveWitness(source, proof.replace('simplify\n', `simplify${injection}`), obligation));
    }
  }
  assert.doesNotMatch(witnessProfile('honest_deny_without_approval_auth_trace').stronger, /All #x\. DenialSigned/);
});

test('raw stronger verdict is distinct from implication coverage and both exact negative controls are mandatory', () => {
  for (const obligation of ['honest_approve_trace', 'honest_deny_without_approval_auth_trace', 'honest_two_approvers_single_winner_trace']) {
    const name = witnessProfile(obligation).checkedLemma;
    const result = verdict => ({ status: 0, signal: null, cancelled: false, cleanupIncomplete: false,
      stdout: `summary of summaries:\n analyzed: Checked.spthy\n ${name} (exists-trace): ${verdict}\n`, stderr: '' });
    const check = (context, value) => exactWitnessResult(parseProofSummary(value, witnessExpected(obligation, context), [name], 'Checked.spthy'), value, obligation, context);
    assert.equal(check('good', result('verified (43 steps)')).ok, true);
    assert.equal(check('good', result('analysis incomplete (1 steps)')).ok, false);
    for (const context of ['sorry', 'contradiction']) {
      assert.equal(check(context, result('analysis incomplete (2 steps)')).ok, true);
      for (const verdict of ['unknown (2 steps)', 'analysis undetermined (2 steps)', 'verified (43 steps)', 'analysis incomplete']) assert.equal(check(context, result(verdict)).ok, false);
      for (const changed of [{ status: 1 }, { signal: 'SIGTERM' }, { error: new Error('timeout') }, { cancelled: true },
        { cleanupIncomplete: true }, { stderr: 'Warning: invalid input' }, { stdout: result('analysis incomplete (2 steps)').stdout.replace(name, obligation) }]) {
        assert.equal(check(context, { ...result('analysis incomplete (2 steps)'), ...changed }).ok, false);
      }
    }
    const raw = check('good', result('verified (43 steps)'));
    assert.deepEqual(Object.keys(raw.verdicts), [name]);
    assert.equal(Object.hasOwn(raw.verdicts, obligation), false);
    const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
    const proof = readFileSync(new URL(`../${witnessProfile(obligation).proof}`, import.meta.url), 'utf8');
    const structural = deriveWitness(source, proof, obligation).structural;
    assert.equal(witnessCoverage(structural, WITNESS_CONTEXTS.map(context => ({ context, ok: true }))).discharged, true);
    assert.equal(witnessCoverage(structural, WITNESS_CONTEXTS.map(context => ({ context, ok: context !== 'contradiction' }))).discharged, false);
    assert.throws(() => witnessCoverage(structural, [{ context: 'good', ok: true }]));
    assert.throws(() => witnessCoverage({ ...structural, originalDirectlyVerified: true }, WITNESS_CONTEXTS.map(context => ({ context, ok: true }))));
  }
});

test('breadth-first witness search changes no proof requirements or model bounds', () => {
  for (const wanted of [
    { honest: { trace: 'exists-trace', verdict: 'verified' } },
    { auth: { trace: 'all-traces', verdict: 'falsified' } },
  ]) {
    const args = proofArguments('Model.spthy', wanted);
    assert.ok(args.includes('--stop-on-trace=BFS'));
    assert.ok(args.includes('--quit-on-warning'));
    assert.equal(args.filter((arg) => arg.startsWith('--prove=')).length, 1);
    assert.ok(args.every((arg) => !arg.startsWith('--bound') && !arg.includes('sorry')));
    assert.equal(args[0], 'Model.spthy');
  }
  assert.ok(proofArguments('Model.spthy', expected).includes('--stop-on-trace=DFS'));
  assert.ok(proofArguments('Model.spthy', { auth: expected.auth }).includes('--stop-on-trace=DFS'));
});
test('actual summary needs every property and honest executable trace', () => {
  assert.equal(parse(result(text), expected).ok, true);
  assert.equal(parse(result(text.replace('executable (exists-trace): verified (3 steps)', '')), expected).ok, false);
});
test('helpers precede every selected target but never change target-driven BFS or DFS', () => {
  for (const [wanted, strategy] of [
    [{ honest: { trace: 'exists-trace', verdict: 'verified' } }, 'BFS'],
    [{ auth: { trace: 'all-traces', verdict: 'falsified' } }, 'BFS'],
    [{ auth: expected.auth }, 'DFS'],
    [expected, 'DFS'],
  ]) {
    const requirements = proofRequirements(wanted, helpers), args = proofArguments('Model.spthy', wanted, helpers);
    assert.deepEqual(requirements.helperLemmas, Object.keys(helpers));
    assert.deepEqual(requirements.targetLemmas, Object.keys(wanted));
    assert.deepEqual(args.filter(arg => arg.startsWith('--prove=')),
      [...Object.keys(helpers), ...Object.keys(wanted)].map(name => `--prove=${name}`));
    assert.ok(args.includes(`--stop-on-trace=${strategy}`));
    assert.ok(args.includes('--quit-on-warning'));
    assert.ok(args.every(arg => !arg.startsWith('--bound') && !arg.includes('sorry')));
  }
  assert.deepEqual(proofRequirements(expected).selectedLemmas, Object.keys(expected));
  assert.deepEqual(proofRequirements(expected).helperLemmas, []);
});
test('helper manifests reject empty, excessive, colliding, nonuniversal or assumption entries', () => {
  for (const invalid of [null, [], {}, { auth: expected.auth }, { helper: { trace: 'exists-trace', verdict: 'verified' } },
    { helper: { trace: 'all-traces', verdict: 'falsified' } }, { helper: { trace: 'all-traces', verdict: 'verified', assumed: true } },
    { helper: null }, { 'bad-name': expected.auth }, Object.create({ inherited: expected.auth }),
    Object.fromEntries(Array.from({ length: 9 }, (_, index) => [`helper_${index}`, expected.auth]))]) {
    assert.throws(() => proofRequirements(expected, invalid));
  }
  assert.throws(() => proofRequirements({ auth: { ...expected.auth, ignored: true } }, helpers));
  assert.throws(() => proofRequirements({}, helpers));
});
test('every helper must verify in the same exact successful invocation as its target', () => {
  const required = proofRequirements({ auth: expected.auth }, helpers).expected;
  const helperRows = Object.keys(helpers).map(name => ` ${name} (all-traces): verified (1 steps)\n`).join('');
  const complete = `summary of summaries:\n analyzed: Model.spthy\n${helperRows} auth (all-traces): verified (5 steps)\n`;
  assert.equal(parse(result(complete), required).ok, true);
  for (const name of Object.keys(helpers)) {
    const row = ` ${name} (all-traces): verified (1 steps)\n`;
    for (const replacement of ['', row.replace('verified', 'falsified - found trace'),
      row.replace('verified', 'analysis incomplete'), row.replace('all-traces', 'exists-trace')]) {
      assert.equal(parse(result(complete.replace(row, replacement)), required).ok, false);
    }
  }
  for (const broken of [complete.replace('Model.spthy', 'Mutant.spthy'), complete + complete,
    `${helperRows}${text}`, `summary of summaries:\n analyzed: Cached.spthy\n${helperRows}\n${text}`]) {
    assert.equal(parse(result(broken), required, [...Object.keys(helpers), ...Object.keys(expected)]).ok, false);
  }
  assert.equal(parse({ ...result(complete), status: 1 }, required).ok, false);
  assert.equal(parse({ ...result(complete), cancelled: true }, required).ok, false);
  assert.equal(parse({ ...result(complete), cleanupIncomplete: true }, required).ok, false);
});
test('a correct mutant target cannot hide an unproved helper or use a baseline summary', () => {
  const required = proofRequirements({ auth: { trace: 'all-traces', verdict: 'falsified' } }, helpers).expected;
  const output = `summary of summaries:\n analyzed: Mutant.spthy\n` +
    Object.keys(helpers).map(name => ` ${name} (all-traces): verified (1 steps)\n`).join('') +
    ' auth (all-traces): falsified - found trace (3 steps)\n';
  assert.equal(parseProofSummary(result(output), required, Object.keys(required), 'Mutant.spthy').ok, true);
  assert.equal(parseProofSummary(result(output.replace('Mutant.spthy', 'Model.spthy')), required, Object.keys(required), 'Mutant.spthy').ok, false);
  assert.equal(parseProofSummary(result(output.replace('enrolled_revision_unique (all-traces): verified',
    'enrolled_revision_unique (all-traces): analysis incomplete')), required, Object.keys(required), 'Mutant.spthy').ok, false);
});
test('general prover warnings fail even when process zero and all verdicts verify', () => {
  for (const warning of ['WARNING: wellformedness', 'Warning (lemma selection)', 'warning: unsupported detail', 'WARN: ignored input', 'Warnings found']) {
    assert.equal(parse({ ...result(text), stderr: warning }, expected).ok, false);
  }
});
test('authored helper admission rejects missing, reordered, unknown, wrong-kind and retained proofs', () => {
  const source = declarations(helpers, true) + declarations(expected) + '\nend\n';
  assert.deepEqual(validateTheoryRequirements(source, expected, helpers).helperLemmas, Object.keys(helpers));
  assert.doesNotThrow(() => validateTheoryRequirements(declarations(expected) + '\nend\n', expected));
  for (const changed of [
    source.replace('lemma enrolled_revision_unique', 'lemma unknown_helper'),
    source.replace('[reuse]', '[sources,reuse]'), source.replace('[reuse]', '[reuse,reuse]'),
    source.replace('[reuse]', ''), source.replace('all-traces', 'exists-trace'),
    source.replace('"synthetic statement"', '"synthetic statement" by sorry'),
    source.replace('"synthetic statement"', '"synthetic statement"\nsimplify\nqed'),
    declarations(expected) + declarations(helpers, true) + '\nend\n',
    source + '\nlemma unregistered [reuse]: all-traces "synthetic"\n',
    '#include "retained-proof.spthy"\n' + source,
  ]) assert.throws(() => validateTheoryRequirements(changed, expected, helpers));
  assert.throws(() => validateTheoryRequirements(source, expected));
});
test('production observation-only helper insertion exactly erases to the retained original model', () => {
  const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8').replace(/\r\n/g, '\n');
  const digest = value => createHash('sha256').update(value).digest('hex');
  assert.equal(digest(source), '42b467b376c93d3e237021e420798a67549a1aedd17ccde6a001eb73c3d7385d');
  const beginning = source.indexOf('// REQUEST_SECURITY_PROBE_ONLY:'), ending = source.indexOf('lemma honest_approve_trace:');
  assert.ok(beginning > 0 && ending > beginning);
  let erased = source.slice(0, beginning) + source.slice(ending);
  assert.equal((erased.match(/ActiveRegistryProduced\(/g) ?? []).length, 6);
  assert.equal((erased.match(/BuildingProduced\(/g) ?? []).length, 2);
  erased = erased.replace(/,\n       ActiveRegistryProduced\([^\n]*\)/g, '')
    .replace(',\n       BuildingProduced(request_id, pc, binding)', '')
    .replace('--[ BuildingProduced(~request_id, pc, binding) ]->', '-->');
  assert.equal(digest(erased), '7af08df4610de1d2eeac1f441339df76d5949b9c58be994fc272798559002460');
  const manifest = JSON.parse(readFileSync(new URL('../security/tamarin/manifest.json', import.meta.url), 'utf8'));
  const request = manifest.models.find(model => model.id === 'request-authorization');
  assert.deepEqual(request.helpers, helpers);
  assert.equal(Object.keys(request.expected).length, 9);
  assert.equal(manifest.models.reduce((count, model) => count + Object.keys(model.expected).length + model.canaries.length, 0), 16);
  assert.equal(manifest.models.filter(model => model.helpers !== undefined).length, 1);
  assert.equal(manifest.sourceBindings.find(binding => binding.path === 'crates/secure-channel/src/identity.rs').sha256,
    '76ae613b558921d8fb629380a79c7a3c47494cea7964fd873e7b8c657ec1f195');
  assert.deepEqual(validateTheoryRequirements(source, request.expected, request.helpers).helperLemmas, Object.keys(helpers));
});
test('exit zero does not turn falsified/incomplete/unknown into proof', () => {
  for (const status of ['falsified - found trace', 'analysis incomplete', 'unknown']) {
    assert.equal(parse(result(text.replace('auth (all-traces): verified', `auth (all-traces): ${status}`)), expected).ok, false);
  }
  assert.equal(parse({ ...result(text), status: 1 }, expected).ok, false);
  assert.equal(parse({ ...result(text), signal: 'SIGTERM' }, expected).ok, false);
  assert.equal(parse({ ...result(text), error: new Error('missing tool') }, expected).ok, false);
  assert.equal(parse({ ...result(text), cancelled: true }, expected).ok, false);
  assert.equal(parse({ ...result(text), cleanupIncomplete: true }, expected).ok, false);
  assert.equal(parse({ ...result(text), stderr: 'checking version: WARNING: returned unsupported version' }, expected).ok, false);
});
test('negative control requires a real counterexample to a named production lemma', () => {
  const wanted = { auth: { trace: 'all-traces', verdict: 'falsified' } };
  assert.equal(parse(result(text), wanted, Object.keys(expected)).ok, false);
  assert.equal(parse(result(text.replace('auth (all-traces): verified', 'auth (all-traces): falsified - found trace')), wanted, Object.keys(expected)).ok, true);
});
test('truncated, duplicate, unregistered and wrong trace summaries fail', () => {
  for (const broken of [text.replace('summary of summaries:', ''), text.replace('analyzed:', 'missing:'), text + ' auth (all-traces): verified (1 steps)\n', text + ' surprise (all-traces): verified (1 steps)\n', text.replace('auth (all-traces)', 'auth (exists-trace)')]) {
    assert.equal(parse(result(broken), expected).ok, false);
  }
  assert.equal(parse(result(text), {}).ok, false);
  assert.equal(parse(result(text.replace('verified (5 steps)', 'verified but incomplete')), expected).ok, false);
});
test('proof is tied to exactly one invoked model, not a neighboring or mixed summary', () => {
  assert.equal(parse(result(text.replace('Model.spthy', 'Other.spthy')), expected).ok, false);
  assert.equal(parse(result(text + ' analyzed: Other.spthy\n'), expected).ok, false);
  assert.equal(parse(result(text + text), expected).ok, false);
  assert.equal(parseProofSummary(result(text), expected).ok, false);
});
test('canary mutation must change exactly one current source marker', () => {
  assert.equal(mutateExactlyOnce('a GUARD b', { from: 'GUARD', to: 'BROKEN' }), 'a BROKEN b');
  for (const source of ['a b', 'GUARD GUARD']) assert.throws(() => mutateExactlyOnce(source, { from: 'GUARD', to: '' }));
  assert.throws(() => mutateExactlyOnce('GUARD', { from: '', to: 'x' }));
  assert.throws(() => mutateExactlyOnce('GUARD', { from: 'GUARD', to: 'GUARD' }));
});
test('early missing-manifest failure cannot leave a prior passing summary', async () => {
  const temp = mkdtempSync(join(tmpdir(), 'uac-protocol-gate-test-'));
  try {
    const directory = join(temp, 'artifacts/protocol-security');
    mkdirSync(directory, { recursive: true });
    const path = join(directory, 'summary.json');
    writeFileSync(path, JSON.stringify({ passed: true, runs: [{ id: 'old-proof' }] }));
    await assert.rejects(() => runProtocolSecurity(temp));
    const current = JSON.parse(readFileSync(path, 'utf8'));
    assert.equal(current.passed, false);
    assert.equal(current.status, 'failed');
    assert.deepEqual(current.runs, []);
  } finally {
    // Only the exact newly-created isolated test fixture, never a user cache.
    assert.equal(resolve(temp).startsWith(resolve(tmpdir()) + sep + 'uac-protocol-gate-test-'), true);
    rmSync(temp, { recursive: true });
  }
});

// Synthetic runner fixture, NOT Tamarin or evidence of a security proof. The
// fake process reports controlled verdict text solely to test orchestration.
function runnerFixture(t, { auxiliary, omitHelper = false, discharge = false, badWitnessControl = false,
  counterexamples = false, badCounterexampleBaseline = false } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'uac-protocol-runner-test-'));
  const directory = join(root, 'artifacts/protocol-security');
  const manifestPath = join(root, 'security/tamarin/manifest.json');
  mkdirSync(directory, { recursive: true });
  mkdirSync(join(root, 'security/tamarin'), { recursive: true });
  writeFileSync(join(root, 'source.rs'), 'synthetic reviewed source\n');
  const model = (id) => ({ id, path: `security/tamarin/${id}.spthy`, expected,
    canaries: [{ id: `${id}-mutant`, expected: { auth: { trace: 'all-traces', verdict: 'falsified' } },
      mutation: { from: 'GUARD', to: 'MUTANT' } }] });
  const config = { version: 1, toolVersion: '1.12.0',
    sourceBindings: [{ path: 'source.rs', sha256: createHash('sha256').update('synthetic reviewed source\n').digest('hex') }],
    models: [model('alpha'), model('beta')] };
  if (counterexamples) {
    config.models = JSON.parse(readFileSync(new URL('../security/tamarin/manifest.json', import.meta.url), 'utf8')).models;
    for (const value of config.models) delete value.witnessDischarges;
    mkdirSync(join(root, 'tools'));
    for (const file of ['protocol-security.mjs', 'protocol-counterexample-discharge.mjs', 'protocol-witness-discharge.mjs', 'prover-process.mjs']) {
      writeFileSync(join(root, 'tools', file), '// synthetic code snapshot, not executed\n');
    }
  }
  if (auxiliary !== undefined) config.models[0].helpers = auxiliary;
  if (discharge) {
    const first = config.models[0]; first.id = 'request-authorization';
    first.expected = { honest_approve_trace: expected.executable, honest_deny_without_approval_auth_trace: expected.executable, auth: expected.auth };
    first.witnessDischarges = Object.fromEntries(Object.keys(first.expected).filter(name => name !== 'auth').map(name => {
      const profile = witnessProfile(name); return [name, { profile: profile.profile, proof: profile.proof }];
    }));
    mkdirSync(join(root, 'security/tamarin/witnesses'));
    for (const spec of Object.values(first.witnessDischarges)) writeFileSync(join(root, spec.proof), readFileSync(new URL(`../${spec.proof}`, import.meta.url)));
    mkdirSync(join(root, 'tools'));
    for (const file of ['protocol-security.mjs', 'protocol-witness-discharge.mjs', 'prover-process.mjs']) writeFileSync(join(root, 'tools', file), '// synthetic code snapshot, not executed\n');
  }
  for (const value of config.models) {
    const contents = counterexamples ? readFileSync(new URL(`../${value.path}`, import.meta.url), 'utf8') : discharge && value.id === 'request-authorization'
      ? `theory RequestAuthorization\nbegin\n// synthetic GUARD input\n${witnessProfile('honest_approve_trace').original}\n\n${witnessProfile('honest_deny_without_approval_auth_trace').original}\n\n${declarations({ auth: expected.auth })}\nend\n`
      : '// synthetic GUARD input\n' + (value.helpers ? declarations(value.helpers, true) : '') + declarations(value.expected) + '\nend\n';
    writeFileSync(join(root, value.path), contents);
  }
  const save = () => writeFileSync(manifestPath, JSON.stringify(config));
  save();
  const fake = join(root, 'fake-prover');
  writeFileSync(fake, `#!${process.execPath}
    const fs = require('node:fs');
    fs.appendFileSync('invocations.log', JSON.stringify(process.argv.slice(2)) + '\\n');
    if (process.argv.includes('--version')) { console.log('tamarin-prover 1.12.0'); process.exit(0); }
    const file = process.argv[2];
    const source = fs.readFileSync(file, 'utf8');
    const mutant = source.includes('MUTANT') || file.endsWith('missing-pc-pin.spthy');
    const helpers = new Set(${JSON.stringify(Object.keys(auxiliary ?? {}))});
    console.log('summary of summaries:\\n analyzed: ' + file);
    const selected = process.argv.filter(x => x.startsWith('--prove=')).map(arg => arg.slice(8));
    const names = selected.length ? selected : [...source.matchAll(/^lemma ([A-Za-z0-9_]+):/gm)].map(match => match[1]);
    for (const name of names) {
      if (${omitHelper} && name === ${JSON.stringify(Object.keys(auxiliary ?? {})[0] ?? '')}) continue;
      const attack = name.startsWith('attack_');
      const kind = attack || name === 'executable' || name.startsWith('honest_') || name.startsWith('checked_') ? 'exists-trace' : 'all-traces';
      const negative = /-(sorry|contradiction)\\.spthy$/.test(file);
      const verdict = attack ? (file.endsWith('-baseline.spthy') ? (${badCounterexampleBaseline} ? 'unknown' : 'falsified - no trace found') : 'verified')
        : !selected.length && negative ? (${badWitnessControl} ? 'unknown' : 'analysis incomplete')
        : mutant && !helpers.has(name) ? 'falsified - found trace' : 'verified';
      console.log(' ' + name + ' (' + kind + '): ' + verdict + ' (1 steps)');
    }
  `);
  if (process.platform === 'linux') chmodSync(fake, 0o700);
  const previous = process.env.TAMARIN_BIN;
  process.env.TAMARIN_BIN = fake;
  t.after(() => {
    if (previous === undefined) delete process.env.TAMARIN_BIN;
    else process.env.TAMARIN_BIN = previous;
    assert.equal(resolve(root).startsWith(resolve(tmpdir()) + sep + 'uac-protocol-runner-test-'), true);
    rmSync(root, { recursive: true });
  });
  return { root, directory, config, save };
}

test('synthetic counterexample orchestration retains sixteen originals with two fresh no-helper auto checks per request canary',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t, { counterexamples: true });
    await runProtocolSecurity(f.root);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, true); // Synthetic runner behavior, not proof evidence.
    assert.equal(summary.runs.length, 16);
    const rows = summary.runs.filter(row => row.mode === 'checked-counterexample');
    assert.equal(rows.length, 2);
    for (const row of rows) {
      const profile = counterexampleProfile(row.id), attack = row.counterexampleDischarge;
      assert.deepEqual(row.targetLemmas, [profile.obligation]); assert.deepEqual(row.helperLemmas, []);
      assert.deepEqual(row.selectedLemmas, [profile.checkedLemma]);
      assert.deepEqual(Object.keys(row.verdicts), [profile.checkedLemma]);
      assert.equal(Object.hasOwn(row.verdicts, profile.obligation), false);
      assert.deepEqual(attack.checks.map(check => check.context), COUNTEREXAMPLE_CONTEXTS);
      assert.ok(attack.checks.every(check => check.ok)); assert.equal(attack.coverage.discharged, true);
      assert.equal(attack.coverage.originalUniversalDirectlyChecked, false);
      for (const check of attack.checks) {
        assert.deepEqual(check.arguments, counterexampleArguments(join(f.directory, check.model), row.id));
        assert.equal(check.arguments.filter(arg => arg.startsWith('--prove=')).length, 1);
      }
    }
    assert.ok(summary.runs.some(row => row.id === 'missing-pc-pin' && row.ok));
    const calls = readFileSync(join(f.root, 'invocations.log'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.equal(calls.length, 19, 'one version + fourteen ordinary rows + four attack contexts');
  });

test('synthetic no-trace baseline failure cannot discharge either canary despite verified mutant attacks',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t, { counterexamples: true, badCounterexampleBaseline: true });
    await assert.rejects(() => runProtocolSecurity(f.root), /proofs\/negative controls failed/);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, false); assert.equal(summary.runs.length, 16);
    for (const row of summary.runs.filter(row => row.mode === 'checked-counterexample')) {
      assert.equal(row.counterexampleDischarge.checks[0].ok, true);
      assert.equal(row.counterexampleDischarge.checks[1].ok, false);
      assert.equal(row.counterexampleDischarge.coverage.discharged, false); assert.equal(row.ok, false);
    }
  });

test('nested counterexample input names are reserved before any tool or snapshot replacement', async (t) => {
  const f = runnerFixture(t, { counterexamples: true });
  f.config.models[0].id = 'missing-approval-signature-baseline'; f.save();
  const retained = join(f.directory, 'missing-approval-signature-baseline.spthy');
  writeFileSync(retained, 'pre-existing snapshot sentinel');
  await assert.rejects(() => runProtocolSecurity(f.root), /duplicate protocol evidence id/);
  assert.equal(readFileSync(retained, 'utf8'), 'pre-existing snapshot sentinel');
  assert.equal(existsSync(join(f.root, 'invocations.log')), false);
});

test('counterexample source drift or cancellation stops before a baseline successor can be attributed',
  { skip: process.platform !== 'linux' }, async (t) => {
    for (const mode of ['source-drift', 'cancel']) await t.test(mode, async (t) => {
      const f = runnerFixture(t, { counterexamples: true }), originalWrite = process.stdout.write;
      const previous = process.listeners('SIGTERM'); let changed = false;
      process.stdout.write = function(chunk, ...rest) {
        if (!changed && String(chunk) === 'Protocol security: missing-approval-signature-mutant\n') {
          changed = true;
          if (mode === 'source-drift') writeFileSync(join(f.root, 'tools/protocol-counterexample-discharge.mjs'), '// changed code identity\n');
          else {
            const handlers = process.listeners('SIGTERM').filter(handler => !previous.includes(handler));
            assert.equal(handlers.length, 1); handlers[0]();
          }
        }
        return originalWrite.call(this, chunk, ...rest);
      };
      try { await assert.rejects(() => runProtocolSecurity(f.root), mode === 'cancel' ? /interrupted by SIGTERM/ : /source\/code binding changed/); }
      finally { process.stdout.write = originalWrite; }
      const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
      assert.equal(changed, true); assert.equal(summary.passed, false);
      const row = summary.runs.find(row => row.id === 'missing-approval-signature');
      assert.equal(row.ok, false); assert.equal(row.counterexampleDischarge.coverage.discharged, false);
      assert.equal(existsSync(join(f.directory, 'missing-approval-signature-baseline.log')), false);
      assert.equal(existsSync(join(f.directory, 'missing-replay-consumption-mutant.log')), false);
    });
  });

test('synthetic discharge runner retains original rows but records only genuine stronger-name verdicts and three nested checks',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t, { discharge: true });
    await runProtocolSecurity(f.root);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, true); // Controlled orchestration fixture, never real protocol evidence.
    assert.equal(summary.runs.length, 7);
    const rows = summary.runs.filter(row => row.mode === 'checked-strengthening');
    assert.equal(rows.length, 2);
    for (const row of rows) {
      const obligation = row.targetLemmas[0], profile = witnessProfile(obligation), witness = row.witnessDischarge;
      assert.deepEqual(row.helperLemmas, []);
      assert.deepEqual(Object.keys(row.verdicts), [profile.checkedLemma]);
      assert.equal(Object.hasOwn(row.verdicts, obligation), false);
      assert.deepEqual(witness.checks.map(check => check.context), WITNESS_CONTEXTS);
      assert.ok(witness.checks.every(check => check.ok));
      assert.equal(witness.coverage.discharged, true);
      assert.equal(witness.coverage.originalDirectlyVerified, false);
      assert.deepEqual(witness.coverage.assumedHelpers, []);
      for (const check of witness.checks) assert.deepEqual(check.arguments.slice(1), ['--quit-on-warning', '+RTS', '-N2', '-M2G', '-RTS']);
    }
    assert.ok(summary.runs.some(row => row.id === 'alpha-mutant' && row.ok), 'original protocol canary still runs independently');
  });

test('synthetic witness control unknown results cannot discharge originals even when both stronger witnesses verify',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t, { discharge: true, badWitnessControl: true });
    await assert.rejects(() => runProtocolSecurity(f.root), /proofs\/negative controls failed/);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, false); assert.equal(summary.runs.length, 7);
    for (const row of summary.runs.filter(row => row.mode === 'checked-strengthening')) {
      assert.equal(row.witnessDischarge.checks[0].ok, true);
      assert.equal(row.ok, false); assert.equal(row.witnessDischarge.coverage.discharged, false);
      assert.ok(row.reasons.some(reason => reason.includes('exact required verdict')));
    }
  });

test('witness cancellation records incomplete coverage and launches no integrity-control successor',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t, { discharge: true }), originalWrite = process.stdout.write;
    const previous = process.listeners('SIGTERM');
    let cancelled = false;
    process.stdout.write = function(chunk, ...rest) {
      if (!cancelled && String(chunk) === 'Protocol security: request-authorization-1-good\n') {
        cancelled = true;
        const handlers = process.listeners('SIGTERM').filter(handler => !previous.includes(handler));
        assert.equal(handlers.length, 1); handlers[0]();
      }
      return originalWrite.call(this, chunk, ...rest);
    };
    try { await assert.rejects(() => runProtocolSecurity(f.root), /interrupted by SIGTERM/); }
    finally { process.stdout.write = originalWrite; }
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(cancelled, true); assert.equal(summary.passed, false); assert.equal(summary.runs.length, 1);
    assert.equal(summary.runs[0].cancelled, true);
    assert.equal(summary.runs[0].witnessDischarge.coverage.discharged, false);
    assert.equal(existsSync(join(f.directory, 'request-authorization-1-sorry.log')), false);
  });

test('synthetic orchestration reproves every helper per original and per mutant without adding rows',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t, { auxiliary: helpers });
    await runProtocolSecurity(f.root);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, true); // Synthetic orchestration only, not a protocol proof.
    assert.equal(summary.runs.length, 6);
    for (const row of summary.runs.filter(row => row.id.startsWith('alpha-'))) {
      assert.deepEqual(row.helperLemmas, Object.keys(helpers));
      assert.equal(row.targetLemmas.length, 1);
      assert.deepEqual(row.selectedLemmas, [...Object.keys(helpers), ...row.targetLemmas]);
      for (const name of Object.keys(helpers)) assert.deepEqual(row.verdicts[name], helpers[name]);
      assert.equal(row.arguments.includes('--stop-on-trace=BFS'), row.id !== 'alpha-1');
    }
  });

test('synthetic runner fails whole original and mutant rows when a helper is absent',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t, { auxiliary: helpers, omitHelper: true });
    await assert.rejects(() => runProtocolSecurity(f.root), /proofs\/negative controls failed/);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, false);
    assert.equal(summary.runs.length, 6);
    for (const row of summary.runs.filter(row => row.id.startsWith('alpha-'))) {
      assert.equal(row.ok, false);
      assert.ok(row.reasons.some(reason => reason.includes('enrolled_revision_unique')));
      assert.equal(row.verdicts[row.targetLemmas[0]].verdict, row.id === 'alpha-mutant' ? 'falsified' : 'verified');
    }
  });

test('helper collisions with an unselected original reject before any prover invocation', async (t) => {
  const f = runnerFixture(t);
  f.config.models[0].helpers = { executable: { trace: 'all-traces', verdict: 'verified' } };
  f.save();
  await assert.rejects(() => runProtocolSecurity(f.root), /Helpers must be distinct/);
  assert.equal(existsSync(join(f.root, 'invocations.log')), false);
});

test('input identities are reserved before any baseline/canary can overwrite evidence', async (t) => {
  for (const collision of ['own-baseline', 'later-baseline', 'run-id']) {
    await t.test(collision, async (t) => {
      const f = runnerFixture(t);
      if (collision === 'own-baseline') f.config.models[0].canaries[0].id = 'alpha';
      if (collision === 'later-baseline') f.config.models[0].canaries[0].id = 'beta';
      if (collision === 'run-id') f.config.models[0].canaries[0].id = 'alpha-1';
      f.save();
      const retained = join(f.directory, 'alpha.spthy');
      writeFileSync(retained, 'existing evidence sentinel');
      await assert.rejects(() => runProtocolSecurity(f.root), /duplicate protocol evidence id/);
      assert.equal(readFileSync(retained, 'utf8'), 'existing evidence sentinel');
      assert.equal(existsSync(join(f.root, 'invocations.log')), false);
    });
  }
});

test('an input changed BETWEEN per-lemma runs cannot receive another attributed proof',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t);
    const originalWrite = process.stdout.write;
    let changed = false;
    process.stdout.write = function(chunk, ...rest) {
      if (!changed && String(chunk).startsWith('{"id":"alpha-1",')) {
        changed = true;
        writeFileSync(join(f.directory, 'alpha.spthy'), 'different model between runs');
      }
      return originalWrite.call(this, chunk, ...rest);
    };
    try {
      await assert.rejects(() => runProtocolSecurity(f.root), /snapshot changed before invocation/);
    } finally { process.stdout.write = originalWrite; }
    assert.equal(changed, true);
    assert.equal(existsSync(join(f.directory, 'alpha-2.log')), false);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, false);
    assert.equal(summary.status, 'failed');
    assert.equal(summary.runs.length, 1);
  });

test('a handled parent signal records cancellation and never starts remaining proofs',
  { skip: process.platform !== 'linux' }, async (t) => {
    const f = runnerFixture(t);
    const originalWrite = process.stdout.write;
    const previousHandlers = process.listeners('SIGTERM');
    let cancelled = false;
    process.stdout.write = function(chunk, ...rest) {
      if (!cancelled && String(chunk) === 'Protocol security: alpha-1\n') {
        cancelled = true;
        // Invoke only this wrapper's real registered handler; do not signal
        // the test runner PID or unrelated test-harness signal listeners.
        const ownedHandlers = process.listeners('SIGTERM').filter(handler => !previousHandlers.includes(handler));
        assert.equal(ownedHandlers.length, 1);
        ownedHandlers[0]();
      }
      return originalWrite.call(this, chunk, ...rest);
    };
    try {
      await assert.rejects(() => runProtocolSecurity(f.root), /interrupted by SIGTERM/);
    } finally { process.stdout.write = originalWrite; }
    assert.equal(cancelled, true);
    assert.equal(process.listenerCount('SIGTERM'), previousHandlers.length);
    const summary = JSON.parse(readFileSync(join(f.directory, 'summary.json'), 'utf8'));
    assert.equal(summary.passed, false);
    assert.equal(summary.status, 'failed');
    assert.equal(summary.runs.length, 1);
    assert.equal(summary.runs[0].cancelled, true);
    assert.equal(summary.runs[0].ok, false);
    assert.equal(existsSync(join(f.directory, 'alpha-2.log')), false);
    const calls = readFileSync(join(f.root, 'invocations.log'), 'utf8').trim().split('\n').map(JSON.parse);
    assert.deepEqual(calls, [['--version']]);
  });
