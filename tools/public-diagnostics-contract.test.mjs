// SPDX-License-Identifier: GPL-2.0-or-later
// Source checks supplement, never replace, hosted native ACL/GUI proof.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
test('public output remains a fixed privileged-write path separate from the original journal', () => {
  const ffi = read('crates/windows-service-host/src/ffi/public_diagnostics.rs');
  assert.match(ffi, /UACRemoteController-Logs/u);
  assert.match(ffi, /D:P\(A;OICI;FA;;;SY\)\(A;OICI;FA;;;BA\)\(A;OICI;GRGX;;;BU\)/u);
  assert.ok(ffi.indexOf('inspect_open_handle') < ffi.indexOf('File::from_raw_handle'));
  assert.match(ffi, /FILE_FLAG_OPEN_REPARSE_POINT/u);
  assert.doesNotMatch(ffi, /CREATE_ALWAYS|TRUNCATE_EXISTING|FILE_SHARE_DELETE/u);
  const runtime = read('crates/windows-service-host/src/runtime.rs');
  assert.match(runtime, /JournalUnavailable\)\?;\s+crate::public_diagnostics::record/u);
});
test('folder handoff has no renderer-selected path, URL, executable or elevation', () => {
  const ffi = read('crates/windows-service-host/src/ffi/public_diagnostics.rs');
  assert.match(ffi, /pub\(crate\) fn open_folder\(\)/u);
  assert.match(ffi, /directory\(false\)/u);
  assert.match(ffi, /require_unelevated\(\)/u);
  assert.doesNotMatch(ffi, /w!\("runas"\)/u);
  assert.match(read('ui/src/bridge.ts'), /openDiagnosticsFolder: \(\) => native<void>\('open_diagnostics_folder'\)/u);
});
