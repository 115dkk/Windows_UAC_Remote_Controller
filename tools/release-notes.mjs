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
  ['호스팅 Windows 러너의 실제 QR 화면 → 소프트웨어 휴대폰 등록', '자동 검사 통과', '실제 PC 앱의 관리자 확인과 QR 화면 픽셀, 양쪽 비교 확인, 서비스 기기 등록을 검사합니다. 소프트웨어 키·인증서 픽스처를 사용하며 실제 Android 하드웨어 증거는 아닙니다.'],
  ['실제 UAC 요청 → 소프트웨어 휴대폰의 서명된 거절 → Windows 취소', '자동 검사 통과', '같은 요청의 서명·내용 다이제스트·거절 결과를 확인하고, 원래 Windows 요청이 ERROR_CANCELLED로 끝나며 시험 대상이 실행되지 않아야 통과합니다. 휴대폰 생체 인증이나 승인 동작은 포함하지 않습니다.'],
  ['PC 앱에서 짝지은 휴대폰 목록 확인, 기기 삭제, 중계 주소 설정', '실기 미검증', '코드는 들어 있으나 실제 PC에서 확인한 기록이 아직 없습니다.'],
  ['이번 판의 새 QR 연결, 여섯 자리 비교, 등록', '실물 재등록은 별도 시험', '기존 연결의 실제 요청 승인은 사용자 시험 완료입니다. 이번 판의 새 등록은 CI 실험실 결과와 실물 재등록 시험을 구분합니다.'],
  ['휴대폰 본인 확인과 실제 UAC 승인 수락', '사용자 시험 완료', '2026-09-19 사용자 보고로 기존 설치본의 본인 확인과 UAC 승인 수락을 확인했습니다. alpha.37 PC 설치의 원격 승인은 발행 후 별도 갱신 시험입니다.'],
  ['USB AOA 등록 보조 경로', '실기 미검증', '공개 연결 정보만 전달합니다. AOA 지원 기기와 호환 WinUSB 드라이버가 필요하며 실제 기기 조합 시험은 별도입니다.'],
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
