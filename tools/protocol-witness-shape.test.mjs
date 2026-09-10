// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { ORIGINAL, SHAPED, shapeWitness } from './protocol-witness-shape.mjs';

const source = readFileSync(new URL('../security/tamarin/RequestAuthorization.spthy', import.meta.url), 'utf8');
test('only the original existential witness is strengthened; rules and all-trace properties stay byte-identical', () => {
  const { normalized, candidate } = shapeWitness(source);
  assert.equal(candidate.replace(SHAPED, ORIGINAL), normalized);
  assert.ok(candidate.includes("& o < u & u < a\n"));
  assert.ok(candidate.includes("& (All d r b #x. SnapshotCaptured(pc, d, r, b) @x ==> #x = #c)"));
  assert.ok(candidate.includes("& (All d r ak dk #x. Enrolled(pc, d, r, ak, dk) @x ==> #x = #e)"));
  assert.equal(candidate.split('lemma ').length, normalized.split('lemma ').length);
});
test('different rules, properties, duplicate witnesses and oversized inputs are rejected', () => {
  for (const invalid of [
    source.replace('builtins: signing', 'builtins: signing, hashing'),
    source.replace('==> #i = #j', '==> #i < #j'),
    source + ORIGINAL,
    'x'.repeat(1024 * 1024 + 1),
  ]) assert.throws(() => shapeWitness(invalid));
});
test('CRLF normalization changes no model text beyond line endings', () => {
  assert.deepEqual(shapeWitness(source.replace(/\r?\n/g, '\r\n')), shapeWitness(source));
});
