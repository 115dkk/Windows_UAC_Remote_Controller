// SPDX-License-Identifier: GPL-2.0-or-later
// Fills docs/RELEASE_NOTES_TEMPLATE.md for one release. Pure text work: no network, no build.
// Usage: node tools/release-notes.mjs <template.md> <SHA256SUMS.txt>
// Environment: VERSION, SIGNER_SHA256, SIGNER_SOURCE, GITHUB_SHA (all required).
import { readFileSync } from 'node:fs';

const CAPABILITIES = [
  ['Windows 설치 파일 빌드와 수동 실행 없는 페이로드 검사', '자동 검사 통과', 'CI가 설치 파일 안의 실행 파일 세 개를 바이트 단위로 확인합니다. 설치 자체는 실행하지 않습니다.'],
  ['Android APK 빌드, JVM 단위 테스트, 부팅 선언 검사', '자동 검사 통과', '실제 휴대폰 설치나 인증은 포함하지 않습니다.'],
  ['Android 에뮬레이터 수명주기(부팅, 재부팅, 앱 교체, 첫 잠금 해제, QR 스캐너 화면 열기)', '자동 검사 통과', 'x86_64 에뮬레이터 결과입니다. 실제 휴대폰 결과는 아닙니다.'],
  ['연결 규약의 기호 증명(Tamarin)', '자동 검사 통과', '규약 모델의 성질만 증명합니다. 구현이나 기기 보안을 증명하지 않습니다.'],
  ['호스팅 러너 실험실에서 서비스 시작, 감시 헬퍼 실행, 실제 UAC 창 관측', '자동 검사 통과', '소프트웨어 키 공급자를 쓰는 실험실 빌드에서 서비스가 실행 상태에 도달하고, 감시 헬퍼가 보안 데스크톱의 실제 consent.exe 창을 관측해 활동 기록에 남겼습니다. 관측까지이며 휴대폰으로 보내거나 창에 적용한 것은 아닙니다.'],
  ['PC 앱에서 짝지은 휴대폰 목록 확인, 기기 삭제, 중계 주소 설정', '실기 미검증', '코드는 들어 있으나 실제 PC에서 확인한 기록이 아직 없습니다.'],
  ['PC와 휴대폰의 QR 연결, 여섯 자리 비교, 등록', '실기 미검증', '설계와 코드는 들어 있으나 실제 PC와 휴대폰에서 성공한 기록이 아직 없습니다.'],
  ['실제 UAC 창을 휴대폰에서 승인 또는 거부', '실기 미검증', '실제 Windows PC에서 성공한 기록이 아직 없습니다. 이 판으로 승인이 된다고 기대하지 마세요.'],
  ['TPM 기반 서비스 키 시작', 'alpha.13 실기 확인', '2026-09-12 실제 개발 PC에서 alpha.13 설치와 서비스 재시작이 성공했습니다. 현재 판의 실제 휴대폰 원격 승인 시험과는 별도 결과입니다.'],
];

function required(name) {
  const value = process.env[name];
  if (!value || value.length > 256) throw new Error(`${name} is required for release notes`);
  return value;
}

function table(rows) {
  const header = '| 항목 | 상태 | 설명 |\n| --- | --- | --- |';
  return [header, ...rows.map(([item, status, note]) => `| ${item} | ${status} | ${note} |`)].join('\n');
}

const [templatePath, sumsPath] = process.argv.slice(2);
if (!templatePath || !sumsPath) throw new Error('Usage: node tools/release-notes.mjs <template.md> <SHA256SUMS.txt>');
const template = readFileSync(templatePath, 'utf8');
const sums = readFileSync(sumsPath, 'utf8').trim();
if (Buffer.byteLength(sums) > 4096 || !/^[a-f0-9]{64}  \S+(\n[a-f0-9]{64}  \S+)*$/u.test(sums)) throw new Error('SHA256SUMS.txt has an unexpected shape');
const values = {
  VERSION: required('VERSION'),
  SIGNER_SHA256: required('SIGNER_SHA256'),
  SIGNER_SOURCE: required('SIGNER_SOURCE'),
  COMMIT: required('GITHUB_SHA'),
  SHA256SUMS: sums,
  CAPABILITY_TABLE: table(CAPABILITIES),
};
if (!/^[a-f0-9]{64}$/u.test(values.SIGNER_SHA256)) throw new Error('SIGNER_SHA256 must be 64 lowercase hex characters');
let output = template;
for (const [key, value] of Object.entries(values)) output = output.replaceAll(`{{${key}}}`, value);
const leftover = /\{\{[A-Z_]+\}\}/u.exec(output);
if (leftover) throw new Error(`Unfilled placeholder ${leftover[0]}`);
process.stdout.write(output);
