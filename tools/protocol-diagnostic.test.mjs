// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic metadata/files only. These fixtures never run Tamarin or prove a lemma.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { mutateExactlyOnce, proofArguments, proofRequirements } from './protocol-security.mjs';
import { WITNESS_CONTEXTS, deriveWitness, witnessArguments, witnessBindingPaths, witnessCoverage, witnessProfile } from './protocol-witness-discharge.mjs';
import { COUNTEREXAMPLE_CONTEXTS, counterexampleArguments, counterexampleBindingPaths, counterexampleCoverage,
  counterexampleProfile, deriveCounterexample } from './protocol-counterexample-discharge.mjs';
import { admitDiagnostic, diagnosticArguments, diagnosticResult, DIAGNOSTIC_OUTPUT_BYTES, DIAGNOSTIC_TIMEOUT_MS,
  inspectDiagnosticLog, loadDiagnosticInputs } from './protocol-diagnostic.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const normalDirectory = 'artifacts/protocol-security';
const property = (trace = 'all-traces', verdict = 'verified') => ({ trace, verdict });
const helpers = { enrolled_revision_unique: property(), building_precedes_open: property(),
  request_opened_unique: property(), active_registry_production_precedes_revocation: property() };

function fixture(t, auxiliary, withDischarges = false, withCounterexamples = false) {
  const root = mkdtempSync(join(tmpdir(), 'uac-protocol-diagnostic-test-'));
  t.after(() => {
    // Only this exact newly-created fixture. Never old diagnostic/proof artifacts.
    assert.equal(dirname(resolve(root)), resolve(tmpdir()));
    assert.match(basename(root), /^uac-protocol-diagnostic-test-[A-Za-z0-9]+$/);
    rmSync(root, { recursive: true });
  });
  const model = (id, path, count) => {
    const expected = { [`honest_${id.replaceAll('-', '_')}_trace`]: property('exists-trace') };
    for (let index = 2; index <= count; index++) expected[`property_${index}`] = property();
    return { id, path, expected, canaries: [{ id: `${id}-canary`, mutation: { from: `GUARD_${id}`, to: `BROKEN_${id}` },
      expected: { property_2: property('all-traces', 'falsified') } }] };
  };
  const manifest = { version: 1, toolVersion: '1.12.0',
    sourceBindings: [{ path: 'crates/fixture/src/lib.rs', sha256: sha256('// SYNTHETIC source binding\n') }],
    models: [model('pinned-channel', 'security/tamarin/PinnedTransport.spthy', 4),
      model('request-authorization', 'security/tamarin/RequestAuthorization.spthy', 9)] };
  manifest.models[1].canaries.push({ id: 'request-replay-canary', mutation: { from: 'GUARD_request-authorization', to: 'REPLAY_BROKEN' },
    expected: { property_3: property('all-traces', 'falsified') } });
  if (auxiliary !== undefined) manifest.models[1].helpers = auxiliary;
  if (withCounterexamples) {
    const reviewed = JSON.parse(readFileSync(new URL('../security/tamarin/manifest.json', import.meta.url), 'utf8')).models.find(model => model.id === 'request-authorization');
    Object.assign(manifest.models[1], { expected: reviewed.expected, canaries: reviewed.canaries, helpers: reviewed.helpers });
  }
  if (withDischarges) {
    const request = manifest.models[1];
    request.expected = { honest_approve_trace: property('exists-trace'), honest_deny_without_approval_auth_trace: property('exists-trace'),
      ...Object.fromEntries(Array.from({ length: 7 }, (_, index) => [`property_${index + 2}`, property()])) };
    request.witnessDischarges = Object.fromEntries(['honest_approve_trace', 'honest_deny_without_approval_auth_trace'].map(name => {
      const profile = witnessProfile(name); return [name, { profile: profile.profile, proof: profile.proof }];
    }));
  }
  const write = (path, value) => {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, value);
  };
  write('crates/fixture/src/lib.rs', '// SYNTHETIC source binding\r\n');
  write(`${normalDirectory}/tool-version.log`, 'SYNTHETIC FIXTURE ONLY\ntamarin-prover 1.12.0\n');
  if (withDischarges || withCounterexamples) {
    write('fake-tamarin', 'SYNTHETIC BINARY IDENTITY, NEVER EXECUTED\n');
    for (const path of ['tools/protocol-security.mjs', 'tools/protocol-witness-discharge.mjs', 'tools/protocol-counterexample-discharge.mjs', 'tools/prover-process.mjs']) write(path, '// synthetic code identity only\n');
    for (const profile of Object.values(manifest.models[1].witnessDischarges ?? {})) write(profile.proof, readFileSync(new URL(`../${profile.proof}`, import.meta.url)));
  }
  for (const value of manifest.models) write(value.path, `theory RequestAuthorization\nbegin\n// SYNTHETIC MODEL, NEVER EXECUTED\n// GUARD_${value.id}\n` +
    Object.keys(value.helpers ?? {}).map((name) => `lemma ${name} [reuse]: all-traces "synthetic statement"\n`).join('') +
    Object.entries(value.expected).map(([name, result]) => withDischarges && value.witnessDischarges?.[name]
      ? `${witnessProfile(name).original}\n\n` : `lemma ${name}: ${result.trace} "synthetic statement"\n`).join('') + '\nend\n');
  if (withCounterexamples) write(manifest.models[1].path, readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url)));
  let summary;
  const refresh = () => {
    const runs = [];
    write('security/tamarin/manifest.json', JSON.stringify(manifest));
    for (const value of manifest.models) {
      const bytes = readFileSync(join(root, value.path)), text = bytes.toString('utf8');
      const push = (id, input, selected, mutation) => {
        const obligation = Object.keys(selected)[0];
        const canary = value.canaries.find(canary => canary.id === id);
        if (mutation && canary?.counterexampleDischarge) {
          const profile = counterexampleProfile(id); let structural;
          const checks = COUNTEREXAMPLE_CONTEXTS.map(context => {
            const derived = deriveCounterexample(text, id, context), path = join(root, normalDirectory, `${id}-${context}.spthy`);
            structural = derived.structural; write(`${normalDirectory}/${id}-${context}.spthy`, derived.input);
            return { context, id: `${id}-${context}`, model: basename(path), modelSha256: sha256(derived.input),
              arguments: counterexampleArguments(path, id), status: 0, signal: null, cancelled: false, cleanupIncomplete: false, ok: true,
              expectedRow: context === 'mutant' ? 'verified' : 'falsified - no trace found',
              observedRow: context === 'mutant' ? 'verified (35 steps)' : 'falsified - no trace found (26 steps)',
              verdicts: { [profile.checkedLemma]: property('exists-trace', context === 'mutant' ? 'verified' : 'falsified') }, reasons: [] };
          });
          const mutant = checks[0], binary = join(root, 'fake-tamarin'), binaryBytes = readFileSync(binary);
          runs.push({ id, mode: 'checked-counterexample', model: mutant.model, modelSha256: mutant.modelSha256,
            origin: { source: value.path, sha256: sha256(bytes), mutation }, helperLemmas: [], targetLemmas: [obligation], selectedLemmas: [profile.checkedLemma],
            arguments: mutant.arguments, status: mutant.status, signal: mutant.signal, cancelled: false, cleanupIncomplete: false,
            ok: true, reasons: [], verdicts: mutant.verdicts,
            counterexampleDischarge: { profile: profile.profile, checks, coverage: counterexampleCoverage(structural, checks),
              binary, binaryMetadata: { size: binaryBytes.length, sha256: sha256(binaryBytes) },
              sourceBindings: counterexampleBindingPaths(value, manifest.sourceBindings).map(path => {
                const bytes = readFileSync(join(root, path)); return { path, size: bytes.length, sha256: sha256(bytes) };
              }) } });
          return;
        }
        if (!mutation && value.witnessDischarges?.[obligation]) {
          const profile = witnessProfile(obligation), proofBytes = readFileSync(join(root, profile.proof)), proof = proofBytes.toString('utf8');
          const proofSnapshot = `${id}-proof.txt`;
          write(`${normalDirectory}/${proofSnapshot}`, proofBytes);
          let structural;
          const checks = WITNESS_CONTEXTS.map(context => {
            const derived = deriveWitness(text, proof, obligation, context), path = join(root, normalDirectory, `${id}-${context}.spthy`);
            structural = derived.structural; write(`${normalDirectory}/${id}-${context}.spthy`, derived.input);
            const ok = !(id === 'request-authorization-1' && context === 'good');
            const verified = context === 'good' && ok;
            return { context, id: `${id}-${context}`, model: basename(path), modelSha256: sha256(derived.input),
              arguments: witnessArguments(path), status: 0, signal: null, cancelled: false, cleanupIncomplete: false, ok,
              expectedRow: context === 'good' ? 'verified' : 'analysis incomplete',
              observedRow: verified ? 'verified (43 steps)' : 'analysis incomplete (1 steps)',
              verdicts: { [profile.checkedLemma]: property('exists-trace', verified ? 'verified' : 'inconclusive') },
              reasons: ok ? [] : ['synthetic incomplete fixture, not a prover result'] };
          });
          const good = checks[0], binary = join(root, 'fake-tamarin'), binaryBytes = readFileSync(binary);
          runs.push({ id, mode: 'checked-strengthening', model: good.model, modelSha256: good.modelSha256,
            origin: { source: value.path, sha256: sha256(bytes) }, helperLemmas: [], targetLemmas: [obligation], selectedLemmas: [profile.checkedLemma],
            arguments: good.arguments, status: good.status, signal: good.signal, cancelled: false, cleanupIncomplete: false,
            ok: checks.every(check => check.ok), reasons: good.reasons, verdicts: good.verdicts,
            witnessDischarge: { profile: profile.profile, proofSource: profile.proof, proofSnapshot, proofSha256: sha256(proofBytes), checks,
              coverage: witnessCoverage(structural, checks), binary, binaryMetadata: { size: binaryBytes.length, sha256: sha256(binaryBytes) },
              sourceBindings: witnessBindingPaths(value, profile, manifest.sourceBindings).map(path => {
                const bytes = readFileSync(join(root, path)); return { path, size: bytes.length, sha256: sha256(bytes) };
              }) } });
          return;
        }
        const content = mutation ? Buffer.from(mutateExactlyOnce(text, mutation)) : bytes;
        const path = join(root, normalDirectory, `${input}.spthy`);
        const required = proofRequirements(selected, value.helpers);
        write(`${normalDirectory}/${input}.spthy`, content);
        runs.push({ id, model: basename(path), modelSha256: sha256(content), origin: { source: value.path,
          sha256: sha256(bytes), ...(mutation ? { mutation } : {}) }, selectedLemmas: required.selectedLemmas,
          ...(value.helpers === undefined ? {} : { helperLemmas: required.helperLemmas, targetLemmas: required.targetLemmas }),
          arguments: proofArguments(path, selected, value.helpers), status: 0, signal: null, cleanupIncomplete: false, cancelled: false,
          ok: id !== 'request-authorization-1', reasons: ['synthetic fixture, not a prover result'], verdicts: {} });
      };
      Object.keys(value.expected).forEach((name, index) => push(`${value.id}-${index + 1}`, value.id, { [name]: value.expected[name] }));
      for (const canary of value.canaries) push(canary.id, canary.id, canary.expected, canary.mutation);
    }
    summary = { toolVersion: '1.12.0', manifestSha256: sha256(JSON.stringify(manifest)), passed: false, runs };
    write('security/tamarin/manifest.json', JSON.stringify(manifest));
    write(`${normalDirectory}/summary.json`, JSON.stringify(summary));
    return summary;
  };
  refresh();
  return { root, manifest, write, refresh, get summary() { return summary; } };
}

test('complete normal failure selects first request baseline in manifest order', (t) => {
  const f = fixture(t);
  assert.equal(f.summary.runs.length, 16);
  f.summary.runs.find((row) => row.id === 'request-authorization-2').ok = false;
  f.summary.runs.reverse();
  assert.equal(admitDiagnostic(f.manifest, f.summary, f.root).selected.id, 'request-authorization-1');
  f.summary.status = 'failed';
  assert.equal(admitDiagnostic(f.manifest, f.summary, f.root).selected.id, 'request-authorization-1');
  const loaded = loadDiagnosticInputs(f.root);
  assert.equal(loaded.selected.row, 'request-authorization-1');
  assert.equal(loaded.selected.inputSha256, sha256(loaded.selected.bytes));
});

test('attack-discharge diagnostic admission keeps sixteen originals and never selects a canary attack as baseline', (t) => {
  const f = fixture(t, undefined, false, true);
  const admitted = admitDiagnostic(f.manifest, f.summary, f.root);
  assert.equal(admitted.plans.length, 16);
  assert.equal(admitted.plans.filter(plan => plan.counterexample).length, 2);
  assert.equal(loadDiagnosticInputs(f.root).selected.lemma, 'honest_approve_trace');
  for (const row of f.summary.runs) row.ok = true;
  const row = f.summary.runs.find(row => row.id === 'missing-replay-consumption'), attack = row.counterexampleDischarge;
  attack.checks[1].ok = false;
  attack.checks[1].observedRow = 'analysis incomplete (1 steps)';
  attack.checks[1].verdicts[row.selectedLemmas[0]] = property('exists-trace', 'inconclusive');
  attack.coverage = counterexampleCoverage(attack.coverage, attack.checks); row.ok = false;
  f.write(`${normalDirectory}/summary.json`, JSON.stringify(f.summary));
  assert.equal(admitDiagnostic(f.manifest, f.summary, f.root).selected, null);
  assert.equal(loadDiagnosticInputs(f.root).selected, null);
});

test('attack diagnostic admission rejects skipped baseline, fabricated universal verdicts, crossed contexts and strategy drift', (t) => {
  const f = fixture(t, undefined, false, true);
  for (const change of [
    row => { row.counterexampleDischarge.checks.pop(); },
    row => { row.counterexampleDischarge.checks.reverse(); },
    row => { row.counterexampleDischarge.checks[1].observedRow = 'falsified - found trace (1 steps)'; },
    row => { row.counterexampleDischarge.checks[1].verdicts[row.selectedLemmas[0]].trace = 'all-traces'; },
    row => { row.counterexampleDischarge.checks[1].status = 1; },
    row => { row.counterexampleDischarge.checks[1].reasons = ['prover warning']; },
    row => { row.counterexampleDischarge.checks[1].cancelled = true; },
    row => { row.counterexampleDischarge.checks[1].cleanupIncomplete = true; },
    row => { row.counterexampleDischarge.checks[1].modelSha256 = 'invalid'; },
    row => { row.counterexampleDischarge.checks[1].arguments = [...row.counterexampleDischarge.checks[0].arguments]; },
    row => { row.counterexampleDischarge.checks[0].arguments.push('--prove=request_accepted_at_most_once'); },
    row => { row.counterexampleDischarge.coverage.originalUniversalDirectlyChecked = true; },
    row => { row.counterexampleDischarge.coverage.baselineNoTraceDoesNotProveOriginalUniversal = false; },
    row => { row.counterexampleDischarge.coverage.assumedHelpers = ['enrolled_revision_unique']; },
    row => { row.verdicts[row.targetLemmas[0]] = property('all-traces', 'falsified'); },
    row => { row.selectedLemmas = [...row.targetLemmas]; },
    row => { row.helperLemmas = ['enrolled_revision_unique']; },
    row => { delete row.helperLemmas; delete row.targetLemmas; },
    row => { row.arguments = row.arguments.map(arg => arg === '--stop-on-trace=DFS' ? '--stop-on-trace=BFS' : arg); },
  ]) {
    const summary = structuredClone(f.summary);
    change(summary.runs.find(row => row.id === 'missing-replay-consumption'));
    assert.throws(() => admitDiagnostic(f.manifest, summary, f.root));
  }
});

test('attack diagnostic filesystem admission rejects mutant/baseline substitution and source-code-tool drift', async (t) => {
  for (const target of ['crossed-input', 'formula', 'source', 'code', 'binary', 'mutation']) await t.test(target, (t) => {
    const f = fixture(t, undefined, false, true), id = 'missing-approval-signature';
    const sourcePath = f.manifest.models[1].path;
    if (target === 'crossed-input') f.write(`${normalDirectory}/${id}-baseline.spthy`, readFileSync(join(f.root, normalDirectory, `${id}-mutant.spthy`)));
    if (target === 'formula') {
      const path = `${normalDirectory}/${id}-mutant.spthy`, text = readFileSync(join(f.root, path), 'utf8');
      f.write(path, text.replace('& not (Ex #u.', '& (Ex #u.'));
    }
    if (target === 'source') f.write(sourcePath, readFileSync(join(f.root, sourcePath), 'utf8') + '\n// changed current source\n');
    if (target === 'code') f.write('tools/protocol-counterexample-discharge.mjs', '// different checker\n');
    if (target === 'binary') f.write('fake-tamarin', 'different tool\n');
    if (target === 'mutation') {
      const changed = structuredClone(f.summary);
      changed.runs.find(row => row.id === id).counterexampleDischarge.coverage.mutation.to = 'other mutation';
      f.write(`${normalDirectory}/summary.json`, JSON.stringify(changed));
    }
    assert.throws(() => loadDiagnosticInputs(f.root));
    assert.equal(existsSync(join(f.root, 'artifacts/protocol-diagnostic')), false);
  });
});

test('discharge diagnostics retain sixteen original rows and select the actual stronger input without claiming original replay', (t) => {
  const f = fixture(t, helpers, true), admitted = admitDiagnostic(f.manifest, f.summary, f.root);
  assert.equal(admitted.plans.length, 16);
  assert.deepEqual(admitted.selected.targetLemmas, ['honest_approve_trace']);
  assert.deepEqual(admitted.selected.names, ['checked_approval_witness']);
  const loaded = loadDiagnosticInputs(f.root);
  assert.equal(loaded.selected.lemma, 'checked_approval_witness');
  assert.equal(loaded.selected.originalObligation, 'honest_approve_trace');
  assert.equal(loaded.selected.inputRole, 'checked-strengthening');
  assert.equal(Object.hasOwn(loaded.selected, 'helpers'), false);
  assert.match(loaded.selected.bytes.toString('utf8'), /lemma checked_approval_witness:/);
  assert.doesNotMatch(loaded.selected.bytes.toString('utf8'), /^lemma enrolled_revision_unique/m);
});

test('discharge admission rejects missing controls, original-name fake verdicts, wrong proof scopes and auto-search substitutions', (t) => {
  const f = fixture(t, helpers, true);
  for (const change of [
    row => { row.witnessDischarge.checks.pop(); },
    row => { row.witnessDischarge.checks[1].context = 'good'; },
    row => { row.witnessDischarge.checks[1].observedRow = 'unknown (1 steps)'; },
    row => { row.witnessDischarge.checks[1].cancelled = true; },
    row => { row.witnessDischarge.checks[1].status = 1; },
    row => { row.verdicts.honest_approve_trace = property('exists-trace'); },
    row => { row.selectedLemmas = ['honest_approve_trace']; },
    row => { row.arguments.push('--prove=checked_approval_witness'); },
    row => { row.witnessDischarge.proofSource = 'security/tamarin/witnesses/Deny.proof'; },
    row => { row.witnessDischarge.coverage.discharged = true; },
  ]) {
    const summary = structuredClone(f.summary);
    change(summary.runs.find(row => row.id === 'request-authorization-1'));
    assert.throws(() => admitDiagnostic(f.manifest, summary, f.root));
  }
});

test('discharge filesystem admission binds every derived control, proof fixture and structural implication receipt', async (t) => {
  for (const target of ['proof', 'control', 'coverage']) await t.test(target, (t) => {
    const f = fixture(t, helpers, true), row = f.summary.runs.find(row => row.id === 'request-authorization-1');
    if (target === 'proof') f.write(row.witnessDischarge.proofSource, 'by sorry\n');
    if (target === 'control') f.write(`${normalDirectory}/request-authorization-1-contradiction.spthy`, 'different input\n');
    if (target === 'coverage') {
      row.witnessDischarge.coverage.originalDirectlyVerified = true;
      f.write(`${normalDirectory}/summary.json`, JSON.stringify(f.summary));
    }
    assert.throws(() => loadDiagnosticInputs(f.root));
    assert.equal(existsSync(join(f.root, 'artifacts/protocol-diagnostic')), false);
  });
});

test('helper-aware normal plans keep all sixteen rows and diagnose the original, not helper zero', (t) => {
  const f = fixture(t, helpers), admitted = admitDiagnostic(f.manifest, f.summary, f.root);
  assert.equal(admitted.plans.length, 16);
  assert.deepEqual(admitted.selected.helperLemmas, Object.keys(helpers));
  assert.deepEqual(admitted.selected.targetLemmas, ['honest_request_authorization_trace']);
  const loaded = loadDiagnosticInputs(f.root);
  assert.equal(loaded.selected.lemma, 'honest_request_authorization_trace');
  assert.deepEqual(loaded.selected.helpers, helpers);
  const path = join(f.root, 'artifacts/protocol-diagnostic/DIAGNOSTIC_ONLY-fixture/request.input.spthy');
  const args = diagnosticArguments(path, loaded.selected.lemma, loaded.selected.helpers);
  assert.deepEqual(args.filter(arg => arg.startsWith('--prove=')),
    [...Object.keys(helpers), loaded.selected.lemma].map(name => `--prove=${name}`));
  assert.ok(args.includes('--stop-on-trace=NONE'));
  assert.ok(args.includes('--bound=12'));
});

test('missing helper selection, helper-as-target, wrong witness strategy and stale plan reject', (t) => {
  const f = fixture(t, helpers);
  for (const change of [
    row => { row.helperLemmas = []; }, row => { delete row.helperLemmas; }, row => { delete row.targetLemmas; },
    row => { row.targetLemmas = [Object.keys(helpers)[0]]; },
    row => { row.selectedLemmas = [...row.targetLemmas]; },
    row => { row.selectedLemmas.reverse(); },
    row => { row.arguments = row.arguments.filter(arg => arg !== `--prove=${Object.keys(helpers)[0]}`); },
    row => { row.arguments = row.arguments.map(arg => arg === '--stop-on-trace=BFS' ? '--stop-on-trace=DFS' : arg); },
  ]) {
    const summary = structuredClone(f.summary);
    change(summary.runs.find(row => row.id === 'request-authorization-1'));
    assert.throws(() => admitDiagnostic(f.manifest, summary, f.root));
  }
  const oldManifest = structuredClone(f.manifest);
  delete oldManifest.models[1].helpers;
  assert.throws(() => admitDiagnostic(oldManifest, f.summary, f.root));
});

test('helper-source drift and mutant/baseline snapshot substitution remain inadmissible', async (t) => {
  for (const mutation of ['helper-kind', 'imported-proof', 'helper-missing', 'mutant-source']) await t.test(mutation, (t) => {
    const f = fixture(t, helpers), source = f.manifest.models[1].path;
    const original = readFileSync(join(f.root, source), 'utf8');
    if (mutation === 'mutant-source') {
      f.write(`${normalDirectory}/request-replay-canary.spthy`, original);
    } else {
      const altered = mutation === 'helper-kind' ? original.replace('[reuse]: all-traces', '[reuse]: exists-trace')
        : mutation === 'imported-proof' ? original.replace('"synthetic statement"', '"synthetic statement" by sorry')
          : original.replace('lemma enrolled_revision_unique', 'lemma missing_helper');
      f.write(source, altered);
      f.refresh();
    }
    assert.throws(() => loadDiagnosticInputs(f.root));
    assert.equal(existsSync(join(f.root, 'artifacts/protocol-diagnostic')), false);
  });
});

test('legacy no-helper metadata and explicit empty attribution retain exact original admission', (t) => {
  const f = fixture(t);
  assert.equal(admitDiagnostic(f.manifest, f.summary, f.root).plans.length, 16);
  for (const row of f.summary.runs) {
    row.helperLemmas = [];
    row.targetLemmas = [...row.selectedLemmas];
  }
  assert.equal(admitDiagnostic(f.manifest, f.summary, f.root).selected.id, 'request-authorization-1');
  f.summary.runs[0].helperLemmas = ['unregistered_helper'];
  assert.throws(() => admitDiagnostic(f.manifest, f.summary, f.root));
});

test('failed pin/canary only is not applicable; never substituted for request baseline', (t) => {
  const f = fixture(t);
  for (const row of f.summary.runs) row.ok = row.id !== 'request-replay-canary';
  assert.equal(admitDiagnostic(f.manifest, f.summary, f.root).selected, null);
  f.write(`${normalDirectory}/summary.json`, JSON.stringify(f.summary));
  assert.equal(loadDiagnosticInputs(f.root).selected, null);
});

test('passed, incomplete, wrong-version, absent/extra/duplicate and uncertain normal rows reject', (t) => {
  const f = fixture(t);
  const changes = [
    (s) => { s.passed = true; }, (s) => { s.status = 'incomplete'; }, (s) => { s.status = 'complete'; },
    (s) => { s.toolVersion = '1.11.0'; }, (s) => { delete s.manifestSha256; }, (s) => { s.manifestSha256 = '0'.repeat(64); },
    (s) => { s.runs.pop(); }, (s) => { s.runs.push(structuredClone(s.runs[0])); },
    (s) => { s.runs[1] = structuredClone(s.runs[0]); }, (s) => { s.runs[15].cancelled = true; },
    (s) => { s.runs[0].cleanupIncomplete = true; }, (s) => { delete s.runs[0].cleanupIncomplete; },
    (s) => { for (const row of s.runs) row.ok = true; },
  ];
  for (const change of changes) {
    const summary = structuredClone(f.summary); change(summary);
    assert.throws(() => admitDiagnostic(f.manifest, summary, f.root));
  }
});

test('unknown row/lemma/input/origin and altered normal invocation reject', (t) => {
  const f = fixture(t);
  const changes = [
    (row) => { row.id = 'unregistered'; }, (row) => { row.selectedLemmas = ['unknown_lemma']; },
    (row) => { row.model = '../outside.spthy'; }, (row) => { row.origin.source = 'security/tamarin/Other.spthy'; },
    (row) => { row.arguments[0] = join(f.root, 'outside.spthy'); },
    (row) => { row.arguments.push('--bound=8'); },
    (row) => { row.arguments.push('--bound=16'); },
    (row) => { row.arguments.push('--bound=12'); },
    (row) => { row.origin.mutation = { from: 'a', to: 'b' }; },
  ];
  for (const change of changes) {
    const summary = structuredClone(f.summary); change(summary.runs[5]);
    assert.throws(() => admitDiagnostic(f.manifest, summary, f.root));
  }
});

test('filesystem admission rejects altered current source/model/normal snapshot and writes no artifact', async (t) => {
  for (const path of ['crates/fixture/src/lib.rs', 'security/tamarin/RequestAuthorization.spthy',
    `${normalDirectory}/request-authorization.spthy`, `${normalDirectory}/request-replay-canary.spthy`]) {
    await t.test(path, (t) => {
      const f = fixture(t);
      f.write(path, '// changed after normal evidence\n');
      assert.throws(() => loadDiagnosticInputs(f.root));
      assert.equal(existsSync(join(f.root, 'artifacts/protocol-diagnostic')), false);
    });
  }
});

test('unknown declared lemma and external include reject even with self-consistent source hashes', async (t) => {
  for (const change of [
    (text) => text.replace('lemma honest_request_authorization_trace:', 'lemma a_different_name:'),
    (text) => `${text}\n#include "other.spthy"\n`,
  ]) await t.test('invalid named theory input', (t) => {
    const f = fixture(t), path = f.manifest.models[1].path;
    f.write(path, change(readFileSync(join(f.root, path), 'utf8')));
    f.refresh();
    assert.throws(() => loadDiagnosticInputs(f.root));
  });
});

test('path traversal and oversized normal metadata reject before diagnostic publication', (t) => {
  const f = fixture(t);
  f.manifest.sourceBindings[0].path = '../outside.rs';
  f.refresh();
  assert.throws(() => loadDiagnosticInputs(f.root));
  f.write(`${normalDirectory}/summary.json`, Buffer.alloc(2 * 1024 * 1024 + 1, 32));
  assert.throws(() => loadDiagnosticInputs(f.root));
  assert.equal(existsSync(join(f.root, 'artifacts/protocol-diagnostic')), false);
});

test('read-only normal summary and snapshot symlinks are rejected', { skip: process.platform === 'win32' }, async (t) => {
  for (const leaf of ['summary.json', 'request-authorization.spthy']) await t.test(leaf, (t) => {
    const f = fixture(t), path = join(f.root, normalDirectory, leaf), saved = `${path}.saved`;
    renameSync(path, saved);
    symlinkSync(saved, path);
    assert.throws(() => loadDiagnosticInputs(f.root));
  });
});

test('diagnostic arguments are one depth12/i/NONE run with no output/extraction flags', (t) => {
  const f = fixture(t), path = join(f.root, 'artifacts/protocol-diagnostic/DIAGNOSTIC_ONLY-fixture/request.input.spthy');
  assert.deepEqual(diagnosticArguments(path, 'honest_approve_trace'), [path, '--quit-on-warning', '--prove=honest_approve_trace',
    '--heuristic=i', '--bound=12', '--stop-on-trace=NONE', '+RTS', '-N2', '-M2G', '-RTS']);
  assert.throws(() => diagnosticArguments(join(f.root, normalDirectory, 'request-authorization.spthy'), 'honest_approve_trace'));
  assert.throws(() => diagnosticArguments(path, 'lemma --prove=other'));
  assert.equal(DIAGNOSTIC_TIMEOUT_MS, 60_000);
  assert.equal(DIAGNOSTIC_OUTPUT_BYTES, 4 * 1024 * 1024);
});

test('even successful/verifying stdout never becomes positive proof metadata', () => {
  const complete = { status: 0, signal: null, cleanupIncomplete: false, cancelled: false, stdout: 'verified (1 steps)' };
  const report = diagnosticResult(complete, { exists: true, regular: true, size: 10, sha256: 'a'.repeat(64) });
  assert.equal(report.eligibleAsProof, false);
  assert.equal(report.classification, 'DIAGNOSTIC_ONLY');
  assert.equal(report.status, 'attempt_completed');
  assert.equal(report.normalProofVerdict, 'not_parsed_or_replaced');
  assert.equal(Object.hasOwn(report, 'passed'), false);
  assert.equal(Object.hasOwn(report, 'verdicts'), false);
  assert.equal(diagnosticResult({ ...complete, cancelled: true }, null).status, 'cancelled');
  assert.equal(diagnosticResult({ ...complete, cleanupIncomplete: true }, null).status, 'cleanup_incomplete');
  assert.equal(diagnosticResult({ ...complete, status: null, signal: 'SIGTERM', error: new Error('timeout') }, null).process.signal, 'SIGTERM');
});

test('combined log existence, regularness, exact byte bound and hash are separate from process completeness', (t) => {
  const f = fixture(t), path = join(f.root, 'diagnostic.log');
  assert.deepEqual(inspectDiagnosticLog(path), { exists: false, regular: false });
  const bytes = Buffer.alloc(DIAGNOSTIC_OUTPUT_BYTES, 120);
  writeFileSync(path, bytes);
  assert.deepEqual(inspectDiagnosticLog(path), { exists: true, regular: true, size: bytes.length, sha256: sha256(bytes) });
  writeFileSync(path, Buffer.alloc(DIAGNOSTIC_OUTPUT_BYTES + 1));
  const tooLarge = inspectDiagnosticLog(path);
  assert.equal(tooLarge.rejected, 'nonregular_or_output_limit');
  assert.equal(Object.hasOwn(tooLarge, 'sha256'), false);
  assert.equal(inspectDiagnosticLog(f.root).regular, false);
});
