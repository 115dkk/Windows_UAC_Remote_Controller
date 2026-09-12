// SPDX-License-Identifier: GPL-2.0-or-later
// Source inventory only. Never scans request/credential/user data or executes app code.
import { readFileSync, readdirSync } from 'node:fs';
import ts from 'typescript';

const messages = new Set();
const korean = /[가-힣]/u;
for (const name of readdirSync('ui/src')) {
  if (!/\.(?:ts|tsx)$/u.test(name) || /(?:\.test\.|^qa-|^i18n)/u.test(name)) continue;
  const source = ts.createSourceFile(name, readFileSync(`ui/src/${name}`, 'utf8'), ts.ScriptTarget.Latest, true);
  const visit = node => {
    if ((ts.isStringLiteral(node) || ts.isNoSubstitutionTemplateLiteral(node)) && korean.test(node.text)) messages.add(node.text);
    if (ts.isJsxText(node) && korean.test(node.text)) messages.add(node.text.replace(/\s+/gu, ' ').trim());
    ts.forEachChild(node, visit);
  };
  visit(source);
}
for (const path of [
  'crates/controller-runtime/src/runtime.rs', 'crates/controller-runtime/src/unwired.rs',
  'crates/controller-runtime/src/phone_requests.rs', 'crates/controller-runtime/src/phone_history.rs',
  'crates/controller-runtime/src/storage.rs', 'src-tauri/src/commands.rs', 'src-tauri/src/mobile.rs',
  'crates/windows-service-host/src/peer_runtime.rs',
  'crates/windows-service-host/src/ffi/pairing_client/renderer_ui.rs',
]) {
  const source = readFileSync(path, 'utf8').split('#[cfg(test)]\nmod tests')[0];
  for (const match of source.matchAll(/"((?:[^"\\]|\\.)*)"/gu)) {
    if (!korean.test(match[1])) continue;
    const value = match[1].replace(/\\n/gu, '\n').replace(/\\"/gu, '"').replace(/\\\\/gu, '\\');
    if (!value.includes('\\') && value.length <= 1200) messages.add(value);
  }
}
for (const message of [
  '앱 설정', '언어', '시스템 언어 사용', '표시 언어', '적용', '언어 설정을 저장하지 못했어요. 다시 시도해 주세요.',
  '시스템 언어에 맞춰 표시합니다. 지원하지 않는 언어는 영어로 표시합니다.',
  '언어를 바꿔도 PC 요청, 파일 경로와 연결 확인 숫자는 원문 그대로 표시합니다.',
  '시간대 {index}', '마지막 확인 시 {seconds}초 남음', '휴대폰 {id}',
  '숨은 방향 제어 문자를 눈에 보이게 표시했어요.',
  '작업 표시줄에 추가되지 않았어요.', '지금은 앱에서 작업 표시줄 고정을 마무리할 수 없어요.',
  '실행 중인 UAC 원격 승인 아이콘을 마우스 오른쪽 버튼으로 누르고 ‘작업 표시줄에 고정’을 선택할 수 있어요.',
]) messages.add(message);
process.stdout.write(JSON.stringify(Object.fromEntries([...messages].sort().map(value => [value, value])), null, 2));
