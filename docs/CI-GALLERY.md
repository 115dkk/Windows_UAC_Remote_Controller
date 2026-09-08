# CI 화면 갤러리

`UI gallery` 작업은 Windows와 Linux 실행기에서 같은 React 화면을 Chromium으로
렌더링한다. 생성된 스크린샷과 보고서는 실행의 Artifacts에 14일간 보관한다.
공개 저장소의 시험 데이터만 사용하며 실제 요청·명령어·기기 키·QR 비밀은 넣지 않는다.

## 실행 범위

- 고정한 Node와 Playwright 버전, 잠금 파일로 의존성을 설치한다.
- TypeScript·ESLint·화면 행동 테스트·제품 빌드를 먼저 실행한다.
- 별도 `qa.html` 진입점을 제품과 같은 최적화 빌드로 만든다.
- 시험 데이터임을 화면에 표시한 상태로 데스크톱·휴대폰 크기를 촬영한다.
- 스크린샷과 브라우저 결과를 최상위 에이전트가 검토한다.

이 갤러리는 **공유 React 클라이언트의 화면 증거**다. Windows 실행기의 Chromium은
설치된 Tauri/WebView2가 아니며, 휴대폰 너비의 Chromium은 Android 기기가 아니다.
실제 서비스 설치·Secure Desktop·휴대폰 인증·알림·패키징·통신 지연은 입증하지 않는다.
별도 갤러리 성공이 전체 Rust/Android 품질 검사의 성공으로 합쳐지지 않는다.

## 실행 명령

CI에서 `npm ci`, `node tools/ui-quality.mjs`, `npm run build:qa`,
`node node_modules/playwright/cli.js install --with-deps chromium`, `npm run gallery` 순서다.
이 작업을 실행하려고 로컬 앱/브라우저 권한을 변경하거나 로컬 화면 접근을 우회하지 않는다.

## 사용자가 맡는 실기 확인

2026-09-09 사용자 지시에 따라 실제 UAC 승인과 휴대폰 인증은 사용자가 나중에
직접 확인한다. 구현·자동 검사와 수동 인수 검증을 구분해 기록하며, 미확인 항목을
통과한 것으로 표시하지 않는다. 지금 필요하지 않은 UAC 창은 띄우지 않는다.
사용자가 제안한 즉시 승인 시간대에 수행하지 않은 승인을 나중에 허가된 것으로
간주하지 않는다. 마지막 아키텍처 리팩터링의 보고·승인은 기존 지시대로 ROOT가 맡는다.
