// SPDX-License-Identifier: GPL-2.0-or-later
// Authored presentation-copy policy only, not a native/runtime behavior test.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path) => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');
const developerLabel = /서비스|UAC_permission|controller_service_|phone_service_/u;

test('Rust-authored presentation messages use consumer terms while issue codes remain internal', () => {
  for (const path of ['crates/controller-runtime/src/runtime.rs', 'crates/controller-runtime/src/unwired.rs', 'src-tauri/src/mobile/snapshot.rs']) {
    const source = read(path);
    const messages = [...source.matchAll(/(?:message:|issue\.message\s*=|next_action:\s*Some\()\s*"([^"\n]+)"/gu)].map((match) => match[1]);
    assert.ok(messages.length >= 4, path);
    for (const message of messages) assert.doesNotMatch(message, developerLabel, path);
    assert.match(source, /code:\s*"[a-z_]+"/u, 'stable internal issue identifiers are not renamed');
  }
});

test('Android notification values are consumer copy; stable resource names and the product name stay', () => {
  const source = read('src-tauri/gen/android/app/src/main/res/values-ko/strings.xml');
  const entries = [...source.matchAll(/<string name="([a-z0-9_]+)">([^<]+)<\/string>/gu)];
  assert.ok(entries.length > 0);
  assert.equal(entries.length, (source.match(/<string\s/gu) ?? []).length, 'every authored string value must be inspected');
  const values = new Map(entries.map((match) => [match[1], match[2]]));
  assert.equal(values.size, entries.length, 'resource names must be unique');
  for (const [, , value] of entries) assert.doesNotMatch(value, developerLabel);
  assert.equal(values.get('app_name'), 'UAC 원격 승인');
  assert.match(read('src-tauri/gen/android/app/src/main/res/values/strings.xml'), /<string name="app_name">UAC Remote Approval<\/string>/u);
  assert.equal(values.get('controller_service_title'), 'UAC 원격 승인');
  assert.equal(values.get('controller_service_ready'), '앱 설정을 사용할 수 있습니다.');
  assert.equal(values.get('controller_service_stopping'), '휴대폰 승인을 끄고 있습니다.');
  assert.equal(values.get('request_notification_summary'), '%1$s\\n%2$s', 'original program/path text is not rewritten');
  assert.deepEqual(['request_action_approve', 'request_action_deny', 'request_action_details'].map((name) => values.get(name)), ['승인', '거부', '자세히 보기']);
});
