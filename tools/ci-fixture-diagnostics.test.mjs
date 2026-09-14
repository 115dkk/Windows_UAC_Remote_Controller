// SPDX-License-Identifier: GPL-2.0-or-later
// Pure diagnostic projection tests: no native calls or raw transcript artifacts.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { fixtureDiagnostic } from './ci-fixture-diagnostics.mjs';

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
    assert.ok(values.every(value => /^[a-z][a-z_]{0,63}$/.test(value)));
  }
});
