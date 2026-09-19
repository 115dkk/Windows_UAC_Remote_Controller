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

// The slot one session holds is exactly what `canRequest` refuses on, so a pass
// that leaves early leaves the phone's approve button grey, with nothing on
// screen saying why, until the app is force-stopped. That symptom has now
// arrived twice from two different causes, and the second cause was a `return`
// added one line above the retry that exists to prevent the first.
test('the worker pass always reaches the retry that frees the approval slot', () => {
  const pass = workerPass();
  const exits = [...pass.matchAll(/\breturn\b/gu)];
  assert.equal(exits.length, 1, 'only the absent-session elvis may leave this function');
  assert.match(pass.slice(0, exits[0].index), /\?:\s*$/u);
  assert.ok(pass.indexOf('cleanupFailed.set(false)') < pass.indexOf('cleanup(session)'));
});

// `expired` calls an absent deadline expired, and a PREPARING session has not
// read its deadline off the plan yet, so the phase has to be asked first or the
// pass cancels an approval in the window between the tap that claims the slot
// and the worker job that begins it. `advance` orders these two the same way.
test('an expired session is cancelled once, and never one that has not begun', () => {
  const pass = workerPass();
  assert.match(pass, /if \(!session\.cancelled\.get\(\) && session\.phase\(\) != Phase\.PREPARING && expired\(session\)\)/u);
  assert.match(pass, /session\.expiryTraced\.compareAndSet\(false, true\)/u);
});

test('every guard that refuses a terminal cleanup names itself', () => {
  const body = between('private fun cleanup(session: Session)', 'if (!enqueue {');
  const guards = body.split('\n').filter((line) => /\breturn\b/u.test(line));
  assert.equal(guards.length, 5);
  for (const guard of guards) assert.match(guard, /refused\(session, CleanupRefusal\.[A-Z_]+\)/u);
  const used = new Set([...source.matchAll(/CleanupRefusal\.([A-Z_]+)/gu)].map(([, name]) => name));
  const declared = between('private enum class CleanupRefusal {', '}')
    .replace('private enum class CleanupRefusal {', '').split(',').map((name) => name.trim());
  assert.equal(declared.length, 5);
  for (const name of declared) assert.ok(used.has(name), name);
});
