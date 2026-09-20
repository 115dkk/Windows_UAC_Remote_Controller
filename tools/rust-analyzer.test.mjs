// SPDX-License-Identifier: GPL-2.0-or-later
import assert from 'node:assert/strict';
import test from 'node:test';
import { buildAnalyzerEnvironment, classifyDiagnostics, pinnedToolchain } from './rust-analyzer.mjs';

const complete = 'diagnostic scan complete\n';
const clean = { status: 0, stdout: complete, stderr: '' };

test('an exact toolchain is pinned', () => {
  assert.match(pinnedToolchain(), /^\d+\.\d+\.\d+$/);
});

test('analyzer environment adds the explicit dev-debug codegen flag', () => {
  assert.deepEqual(buildAnalyzerEnvironment({}), { RUSTFLAGS: '-Cdebug-assertions=yes' });
  assert.deepEqual(buildAnalyzerEnvironment({ RUSTFLAGS: '' }), { RUSTFLAGS: '-Cdebug-assertions=yes' });
});

test('analyzer environment preserves unrelated variables and plain flags without mutating its input', () => {
  const incoming = Object.freeze({ PATH: '/synthetic/toolchain', RUSTFLAGS: '-D warnings -Ctarget-feature=+sse2', CONTROLLER_FIXTURE: 'example-only' });
  const environment = buildAnalyzerEnvironment(incoming);
  assert.notEqual(environment, incoming);
  assert.deepEqual(environment, {
    PATH: '/synthetic/toolchain',
    RUSTFLAGS: '-D warnings -Ctarget-feature=+sse2 -Cdebug-assertions=yes',
    CONTROLLER_FIXTURE: 'example-only',
  });
  assert.equal(incoming.RUSTFLAGS, '-D warnings -Ctarget-feature=+sse2');
});

test('plain flags are appended as an environment string without rewriting existing whitespace or quoting', () => {
  const existing = '  --cfg="controller_fixture" -D warnings  ';
  assert.equal(buildAnalyzerEnvironment({ RUSTFLAGS: existing }).RUSTFLAGS, `${existing} -Cdebug-assertions=yes`);
});

test('encoded flags retain Cargo precedence and append one unit-separated argument', () => {
  const incoming = Object.freeze({
    RUSTFLAGS: '-D warnings',
    CARGO_ENCODED_RUSTFLAGS: '-Dwarnings\u001f--cfg\u001fcontroller_fixture',
    PATH: '/synthetic/toolchain',
  });
  const environment = buildAnalyzerEnvironment(incoming);
  assert.equal(environment.RUSTFLAGS, incoming.RUSTFLAGS);
  assert.equal(environment.PATH, incoming.PATH);
  assert.deepEqual(environment.CARGO_ENCODED_RUSTFLAGS.split('\u001f'), [
    '-Dwarnings', '--cfg', 'controller_fixture', '-Cdebug-assertions=yes',
  ]);
  assert.equal(incoming.CARGO_ENCODED_RUSTFLAGS, '-Dwarnings\u001f--cfg\u001fcontroller_fixture');
});

test('an explicitly empty encoded value still takes precedence over plain flags', () => {
  const environment = buildAnalyzerEnvironment({ CARGO_ENCODED_RUSTFLAGS: '', RUSTFLAGS: '-D warnings' });
  assert.equal(environment.CARGO_ENCODED_RUSTFLAGS, '-Cdebug-assertions=yes');
  assert.equal(environment.RUSTFLAGS, '-D warnings');
});

test('undefined encoded flags use the plain branch and preserve the original entry', () => {
  assert.deepEqual(buildAnalyzerEnvironment({ CARGO_ENCODED_RUSTFLAGS: undefined, RUSTFLAGS: '-Dwarnings' }), {
    CARGO_ENCODED_RUSTFLAGS: undefined,
    RUSTFLAGS: '-Dwarnings -Cdebug-assertions=yes',
  });
});

test('the explicit dev-debug option is last without dropping conflicting flags or warning enforcement', () => {
  assert.equal(buildAnalyzerEnvironment({ RUSTFLAGS: '-Cdebug-assertions=no -Dwarnings' }).RUSTFLAGS,
    '-Cdebug-assertions=no -Dwarnings -Cdebug-assertions=yes');
  assert.equal(buildAnalyzerEnvironment({ CARGO_ENCODED_RUSTFLAGS: '-Cdebug-assertions=no\u001f-Dwarnings' }).CARGO_ENCODED_RUSTFLAGS,
    '-Cdebug-assertions=no\u001f-Dwarnings\u001f-Cdebug-assertions=yes');
});

test('Windows reuses existing case-insensitive environment names without duplicate keys', () => {
  const environment = buildAnalyzerEnvironment({ RustFlags: '-Dwarnings', Cargo_Encoded_Rustflags: '--cfg\u001fcontroller_fixture', Path: 'C:\\synthetic\\toolchain' }, 'win32');
  assert.deepEqual(environment, {
    RustFlags: '-Dwarnings',
    Cargo_Encoded_Rustflags: '--cfg\u001fcontroller_fixture\u001f-Cdebug-assertions=yes',
    Path: 'C:\\synthetic\\toolchain',
  });
  assert.deepEqual(buildAnalyzerEnvironment({ RustFlags: '-Dwarnings' }, 'win32'), {
    RustFlags: '-Dwarnings -Cdebug-assertions=yes',
  });
});

test('POSIX preserves differently cased variables without treating them as Cargo flag variables', () => {
  assert.deepEqual(buildAnalyzerEnvironment({ RustFlags: 'example-only', cargo_encoded_rustflags: 'example-only' }, 'linux'), {
    RustFlags: 'example-only',
    cargo_encoded_rustflags: 'example-only',
    RUSTFLAGS: '-Cdebug-assertions=yes',
  });
});

test('only a completed zero-diagnostic scan succeeds', () => {
  assert.equal(classifyDiagnostics(clean).ok, true);
});

for (const severity of ['Error', 'Warning', 'WeakWarning', 'UnknownFutureSeverity']) {
  test(`exit zero with ${severity} cannot turn CI green`, () => {
    const stdout = `at crate example, file /example/lib.rs: ${severity} diagnostic\n${complete}`;
    assert.equal(classifyDiagnostics({ ...clean, stdout }).ok, false);
  });
}

test('stderr diagnostics and ANSI escape sequences are not ignored', () => {
  const stderr = '\u001b[31mat crate example, file C:\\example.rs: Warning diagnostic\u001b[0m';
  assert.equal(classifyDiagnostics({ ...clean, stderr }).ok, false);
});

test('a Windows progress bar cannot hide the first diagnostic', () => {
  const stdout = `0/1 processing fixture\b\b   \b\bat crate example, file C:\\example.rs: Warning diagnostic\n${complete}`;
  const result = classifyDiagnostics({ ...clean, stdout });
  assert.equal(result.ok, false);
  assert.equal(result.diagnostics.length, 1);
});

test('only the exact inactive-cfg LSP hint is classified as configuration information', () => {
  const line = 'at crate example, file /example.rs: WeakWarning Ra("inactive-code", WeakWarning) from LineCol { line: 1, col: 0 } to LineCol { line: 2, col: 1 }: code is inactive due to #[cfg] directives: windows is enabled';
  const result = classifyDiagnostics({ ...clean, stdout: `${line}\n${complete}` });
  assert.equal(result.ok, true);
  assert.equal(result.configurationHints.length, 1);
  assert.equal(result.diagnostics.length, 0);
  for (const changed of [line.replace('WeakWarning Ra', 'Warning Ra'), line.replace('inactive-code', 'other-code'), line.replace('code is inactive', 'a problem is present')]) {
    assert.equal(classifyDiagnostics({ ...clean, stdout: `${changed}\n${complete}` }).ok, false);
  }
});

for (const stderr of ['warning: could not load a build script', 'ERROR missing sysroot', 'WARN proc-macro failure']) {
  test(`workspace loading problem fails: ${stderr}`, () => {
    assert.equal(classifyDiagnostics({ ...clean, stderr }).ok, false);
  });
}

test('missing completion, process error, nonzero status and signal all fail', () => {
  assert.equal(classifyDiagnostics({ ...clean, stdout: '' }).ok, false);
  assert.equal(classifyDiagnostics({ ...clean, error: new Error('ENOENT') }).ok, false);
  assert.equal(classifyDiagnostics({ ...clean, status: 1 }).ok, false);
  assert.equal(classifyDiagnostics({ ...clean, status: null }).ok, false);
  assert.equal(classifyDiagnostics({ ...clean, signal: 'SIGTERM' }).ok, false);
});
