// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { tmpdir } from 'node:os';
import { join, resolve, sep } from 'node:path';
import { mutateExactlyOnce, parseProofSummary, proofArguments, proofRequirements, runProtocolSecurity, validateTheoryRequirements } from './protocol-security.mjs';
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
function runnerFixture(t, { auxiliary, omitHelper = false } = {}) {
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
  if (auxiliary !== undefined) config.models[0].helpers = auxiliary;
  for (const value of config.models) writeFileSync(join(root, value.path), '// synthetic GUARD input\n' +
    (value.helpers ? declarations(value.helpers, true) : '') + declarations(value.expected) + '\nend\n');
  const save = () => writeFileSync(manifestPath, JSON.stringify(config));
  save();
  const fake = join(root, 'fake-prover');
  writeFileSync(fake, `#!${process.execPath}
    const fs = require('node:fs');
    fs.appendFileSync('invocations.log', JSON.stringify(process.argv.slice(2)) + '\\n');
    if (process.argv.includes('--version')) { console.log('tamarin-prover 1.12.0'); process.exit(0); }
    const file = process.argv[2];
    const mutant = fs.readFileSync(file, 'utf8').includes('MUTANT');
    const helpers = new Set(${JSON.stringify(Object.keys(auxiliary ?? {}))});
    console.log('summary of summaries:\\n analyzed: ' + file);
    for (const arg of process.argv.filter(x => x.startsWith('--prove='))) {
      const name = arg.slice(8);
      if (${omitHelper} && name === ${JSON.stringify(Object.keys(auxiliary ?? {})[0] ?? '')}) continue;
      const kind = name === 'executable' ? 'exists-trace' : 'all-traces';
      console.log(' ' + name + ' (' + kind + '): ' + (mutant && !helpers.has(name) ? 'falsified - found trace' : 'verified') + ' (1 steps)');
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
