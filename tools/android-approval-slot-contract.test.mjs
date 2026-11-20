// SPDX-License-Identifier: GPL-2.0-or-later
// Source contracts only. These tests never build an APK, start an Activity,
// reach a key store or touch a device; ROOT owns all executable validation.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const source = readFileSync(new URL(
  '../src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/ApplicationApprovalCoordinator.kt',
  import.meta.url), 'utf8').replace(/\r\n?/gu, '\n');

const between = (start, end) => {
  const from = source.indexOf(start);
  const to = source.indexOf(end, from + start.length);
  assert.ok(from >= 0 && to > from, `${start} .. ${end}`);
  return source.slice(from, to);
};
const workerPass = () => between('fun cleanupOnWorker()', 'fun hasPendingCleanup()');

// `expired` calls an absent deadline expired, and a PREPARING session has not
// read its deadline off the plan yet, so the phase has to be asked first or the
// pass cancels an approval in the window between the tap that claims the slot
// and the worker job that begins it. `advance` orders these two the same way.
test('an expired session is cancelled once, and never one that has not begun', () => {
  const pass = workerPass();
  assert.match(pass, /if \(!session\.prepared\.get\(\) && !session\.cancelled\.get\(\) && session\.phase\(\) != Phase\.PREPARING && expired\(session\)\)/u);
  assert.match(pass, /session\.expiryTraced\.compareAndSet\(false, true\)/u);
});
