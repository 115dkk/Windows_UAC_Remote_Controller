// SPDX-License-Identifier: GPL-2.0-or-later
// ROOT/CI only: exercise the actual analyzer on intentionally invalid fixtures.
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { isAbsolute, join, relative } from 'node:path';
import { scanWorkspace } from './rust-analyzer.mjs';

const temporaryRoot = realpathSync(tmpdir());
const fixtureRoot = mkdtempSync(join(temporaryRoot, 'uac-analyzer-gate-'));
const fixtures = [
  { name: 'clean', source: 'pub fn answer() -> u32 { 42 }\n', expected: true },
  { name: 'error', source: 'pub fn answer() -> u32 { "not a number" }\n', expected: false },
  { name: 'warning', source: 'pub fn answer() -> u32 { let unused_value = 42; 42 }\n', expected: false },
];

try {
  for (const fixture of fixtures) {
    const directory = join(fixtureRoot, fixture.name);
    mkdirSync(join(directory, 'src'), { recursive: true });
    writeFileSync(join(directory, 'Cargo.toml'),
      `[package]\nname = "analyzer-${fixture.name}"\nversion = "0.0.0"\nedition = "2024"\n[workspace]\n`);
    writeFileSync(join(directory, 'src/lib.rs'), fixture.source);
    const result = scanWorkspace(directory);
    process.stdout.write(`Fixture ${fixture.name}: analyzer_exit=${String(result.processStatus)}, diagnostics=${result.diagnostics.length}, gate_pass=${result.ok}\n`);
    for (const diagnostic of result.diagnostics) process.stdout.write(`${diagnostic}\n`);
    if (result.ok !== fixture.expected) process.stderr.write(result.output);
    assert.equal(result.ok, fixture.expected, `${fixture.name}: ${result.reasons.join('; ')}`);
    // Negative tests must fail because the real analyzer emitted a diagnostic,
    // not merely because a compiler, process or network dependency was missing.
    if (!fixture.expected) assert.ok(result.diagnostics.length > 0, 'missing real analyzer diagnostic');
  }
  process.stdout.write('Actual Rust Analyzer clean/error/warning gate fixtures passed.\n');
} finally {
  const resolved = realpathSync(fixtureRoot);
  const containment = relative(temporaryRoot, resolved);
  if (!containment.startsWith('uac-analyzer-gate-') || containment.includes('..') || isAbsolute(containment)) {
    throw new Error('Refusing to remove an unexpected temporary fixture directory.');
  }
  rmSync(resolved, { recursive: true });
}
