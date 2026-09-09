// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic metadata/files only. These fixtures never run Tamarin or prove a lemma.
import assert from 'node:assert/strict';
import test from 'node:test';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { basename, dirname, join, resolve } from 'node:path';
import { mutateExactlyOnce, proofArguments } from './protocol-security.mjs';
import { admitDiagnostic, diagnosticArguments, diagnosticResult, DIAGNOSTIC_OUTPUT_BYTES, DIAGNOSTIC_TIMEOUT_MS,
  inspectDiagnosticLog, loadDiagnosticInputs } from './protocol-diagnostic.mjs';

const sha256 = (value) => createHash('sha256').update(value).digest('hex');
const normalDirectory = 'artifacts/protocol-security';
const property = (trace = 'all-traces', verdict = 'verified') => ({ trace, verdict });

function fixture(t) {
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
  const write = (path, value) => {
    const full = join(root, path);
    mkdirSync(dirname(full), { recursive: true });
    writeFileSync(full, value);
  };
  write('crates/fixture/src/lib.rs', '// SYNTHETIC source binding\r\n');
  write(`${normalDirectory}/tool-version.log`, 'SYNTHETIC FIXTURE ONLY\ntamarin-prover 1.12.0\n');
  for (const value of manifest.models) write(value.path, `// SYNTHETIC MODEL, NEVER EXECUTED\n// GUARD_${value.id}\n` +
    Object.keys(value.expected).map((name) => `lemma ${name}: "synthetic statement"\n`).join(''));
  let summary;
  const refresh = () => {
    const runs = [];
    for (const value of manifest.models) {
      const bytes = readFileSync(join(root, value.path)), text = bytes.toString('utf8');
      const push = (id, input, selected, mutation) => {
        const content = mutation ? Buffer.from(mutateExactlyOnce(text, mutation)) : bytes;
        const path = join(root, normalDirectory, `${input}.spthy`);
        write(`${normalDirectory}/${input}.spthy`, content);
        runs.push({ id, model: basename(path), modelSha256: sha256(content), origin: { source: value.path,
          sha256: sha256(bytes), ...(mutation ? { mutation } : {}) }, selectedLemmas: Object.keys(selected),
          arguments: proofArguments(path, selected), status: 0, signal: null, cleanupIncomplete: false, cancelled: false,
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
