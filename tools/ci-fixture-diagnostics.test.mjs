// SPDX-License-Identifier: GPL-2.0-or-later
// Pure diagnostic projection tests: no native calls or raw transcript artifacts.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fixtureDiagnostic } from './ci-fixture-diagnostics.mjs';
import { awaitQrEnrollment } from './ci-presentation-readiness.mjs';

test('closed operator and phone classifications retain exact fixed cause', () => {
  assert.deepEqual(fixtureDiagnostic({ status: 'failed', source: 'operator', stage: 'initial_consent', gate: 'native_program_location_unbound' }),
    { source: 'operator', stage: 'initial_consent', reason: 'native_program_location_unbound' });
  assert.deepEqual(fixtureDiagnostic({ state: 'failed', identity: 'software_ci_fixture', reason: 'request_signature_rejected' }),
    { source: 'phone', stage: 'fixture', reason: 'request_signature_rejected' });
});

test('unknown/extra/payload-shaped data cannot enter diagnostic evidence', () => {
  const valid = { status: 'failed', source: 'operator', stage: 'initial_consent', gate: 'native_program_location_unbound' };
  for (const input of [null, [], 'failed', { ...valid, pngBase64: 'synthetic' }, { ...valid, gate: 'ascii_but_not_a_closed_gate' },
    { ...valid, stage: 'control_wait' }, { ...valid, source: 'phone' }, { ...valid, gate: 'private/path' },
    { ...valid, gate: 'code_123456' }, { ...valid, gate: 'line\nbreak' },
    { state: 'failed', identity: 'hardware_phone', reason: 'fixture_panic' },
    { state: 'failed', identity: 'software_ci_fixture', reason: 'fixture_panic', qr: 'synthetic' }]) {
    assert.equal(fixtureDiagnostic(input), null);
  }
});

test('shared vocabulary is bounded, unique and fixed-token only', () => {
  const vocabulary = JSON.parse(readFileSync(new URL('./ci-windows-operator/diagnostic-vocabulary.json', import.meta.url), 'utf8'));
  assert.deepEqual(Object.keys(vocabulary).sort(), ['bridgeStages', 'gates', 'operatorStages', 'phoneReasons']);
  for (const values of Object.values(vocabulary)) {
    assert.ok(values.length > 0 && values.length < 256);
    assert.equal(new Set(values).size, values.length);
    // Fixed codec names such as invalid_png_base64 contain digits. Runtime
    // admission still requires exact vocabulary membership, not this pattern.
    assert.ok(values.every(value => /^[a-z][a-z0-9_]{0,63}$/.test(value)));
  }
});

test('private failure topology accepts only complete bounded operator structure', () => {
  const header = 'CI consent topology summary: textNodes=1';
  const row = 'CI consent topology: type=Text id=1024 node=0123456789ABCDEF parent=FEDCBA9876543210 locationLabel=False locationLabelTrimmed=False combinedLocation=True hasFormat=False expectedPath=False closedPair=False conflictingPath=True nextType=None nextExpectedPath=False';
  const value = { status: 'failed', source: 'operator', stage: 'initial_consent', gate: 'conflicting_consent_path', topologyLines: [header, row] };
  const result = fixtureDiagnostic(value);
  assert.equal(result.topology.textNodes, 1);
  assert.equal(result.topology.rows[0].combinedLocation, true);
  assert.ok(!Object.hasOwn(result, 'topologyLines'));
  for (const invalid of [
    { ...value, source: 'bridge' }, { ...value, stage: 'startup' },
    { ...value, topologyLines: [header] }, { ...value, topologyLines: [header, row + ' raw=secret'] },
    { ...value, topologyLines: [header, row.replace('id=1024', 'id=private/path')] },
    { ...value, topologyLines: [header + '\n' + row] }, { ...value, topologyLines: Array(34).fill(header) },
    { ...value, topologyLines: ['CI consent topology summary: textNodes=257'] },
  ]) assert.equal(fixtureDiagnostic(invalid), null);
});

test('QR readiness retries only a closed zero-grid response before enrollment', async () => {
  let captures = 0, pauses = 0, clock = 0;
  await awaitQrEnrollment({
    capture: async () => { captures++; return { synthetic: true }; },
    enroll: async () => ({ state: captures < 3 ? 'qr_not_ready' : 'awaiting_comparison' }),
    now: () => clock, pause: async () => { pauses++; clock += 200; },
  });
  assert.equal(captures, 3);
  assert.equal(pauses, 2);
  for (const response of [{ state: 'failed' }, { state: 'enrollment_accepted' },
    { state: 'qr_not_ready', extra: 'forbidden' }]) {
    let attempted = 0;
    await assert.rejects(awaitQrEnrollment({
      capture: async () => { attempted++; return {}; }, enroll: async () => response,
      pause: async () => assert.fail('Non-presentation failure must not retry'),
    }));
    assert.equal(attempted, 1);
  }
});

test('QR readiness has both fixed attempt and monotonic time bounds', async () => {
  for (const tick of [0, 5000]) {
    let captures = 0, clock = 0;
    await assert.rejects(awaitQrEnrollment({
      capture: async () => { captures++; return {}; },
      enroll: async () => ({ state: 'qr_not_ready' }), now: () => clock,
      pause: async () => { clock += tick; },
    }), /readiness exhausted/);
    assert.equal(captures, tick === 0 ? 25 : 2);
  }
});

test('QR readiness does not restart a failed fixture or shorten authentication', async () => {
  let captures = 0;
  const terminal = new Error('Synthetic terminal failure');
  await assert.rejects(awaitQrEnrollment({
    capture: async () => { captures++; return {}; }, enroll: async () => { throw terminal; },
  }), error => error === terminal);
  assert.equal(captures, 1);
  let clock = 0;
  await awaitQrEnrollment({ capture: async () => ({}), now: () => clock,
    enroll: async () => { clock += 20000; return { state: 'awaiting_comparison' }; },
  });
});
