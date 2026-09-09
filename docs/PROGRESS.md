# 현재 구현과 검증

2026-09-09 · **개발 진행 중. 원격 UAC 승인기 전체가 완성된 상태는 아니다.**

## 9월 9일 저녁: 실제 서비스 설치와 남은 실행 오류

- 사용자에게 허가받은 UAC 실험 시간에 서비스 등록을 실행했다. 기본
  ProgramData 권한과 서비스 SID 길이 처리의 호환성 오류를 수정한 뒤
  **설치가 성공했고 부팅 시 자동 시작으로 등록됐다.** Windows 권한이나
  Secure Desktop 설정을 완화하지 않았다.
- 서비스 시작은 아직 실패한다. 마지막 실제 실행은 `e992290`의 서비스이며
  `0x80090030` (`NTE_DEVICE_NOT_READY`)를 반환하고 정지 상태다. 이 코드만으로
  TPM 고장이나 재부팅 후 해결을 단정할 수 없다. 어떤 암호화 작업에서
  실패했는지 구분할 진단 정보를 보완하고 있다. 설치 파일·이전 바이너리와
  실험 결과는 보존했으며 키나 등록 데이터를 삭제하지 않았다.
- 실제 UAC 창 관찰·원격 승인·자격 증명 입력은 실행하지 못했다. 읽기 전용
  보조 프로세스도 서비스 초기화가 끝나지 않아 활성화하지 않았다. 승인
  가능 시간이 끝난 뒤 추가 UAC나 보호된 설치 파일 변경은 하지 않았다.
- [`e992290` 품질 실행](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34351326442)의
  Windows·Linux·Android 코어 작업은 통과했다.
  [같은 소스의 APK 실행](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34351326416)도
  실제 Gradle 테스트와 빌드를 통과했다. 연결 보안 증명이 끝나기 전에
  후속 모델 수정을 올렸으므로 **전체 품질 실행 통과로 기록하지 않는다.**

### 부팅 시 시작과 연결 보안 CI

Android에는 기본 활성화된 부팅 수신기와 실제 포그라운드 서비스가 있다.
부팅 후 첫 잠금 해제 전에는 저장된 요청·키를 열지 않으며 인증 화면도
띄우지 않는다. 앱에서 서비스를 끄면 자동 시작도 끄고, 다시 시작하면
자동 시작을 켠다. 서비스 상태와 알림 설정을 따로 읽으므로 서비스가
꺼졌을 때도 다시 시작하는 화면을 표시한다. APK 선언·Kotlin 수명주기
테스트·Rust 연결부·화면 CI를 검사했지만 **실제 휴대폰 재부팅 시험은 남았다.**

CI는 고정된 Tamarin 1.12.0과 Maude 3.5.1을 실행한다. 연결 상대의 키 검증,
기밀성, 요청 결합·일회성 처리·등록 해제·취소·만료를 검사하며, 보호 장치를
제거한 모델에서 실제 공격 예제가 나오는지도 요구한다. 요청 모델의 증명
시간 초과가 남아 내부 상태 표현과 탐색 순서를 수정했고,
[`795dd9b` 실행](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34353029001)은
전체 실패로 끝났다. 연결 모델 4항목과 키 검사 제거 공격, 요청별 인증 결합
1항목은 완료했지만, 나머지 요청 8항목과 요청 공격 2개는 시간 초과였다.
필수 보조정리와 공격 검사는 줄이지 않았으며 별도 부분 증명 진단을 준비한다. 상징적 모델은
실제 키 보관·휴대폰 인증·Windows 동작이나 구현 전체를 증명하지 않는다.

### 저장 공간

실험에 앞서 사용자가 추가로 허가한 공간 확보 범위에서, 이 작업 전용
Rust 증분 빌드 캐시만 정리했다. C:의 실제 여유 공간은 약 **3.31GB 증가**했다.
소스·Git·키·설치물·검증 자료는 보존했고 E: 파일은 삭제하지 않았다.
이후 빌드는 증분 캐시를 끄고 가능한 작업을 CI로 옮겼다. 전체 구현·최종
리팩터링·검증 후에 하기로 한 C·E 드라이브 정리는 아직 수행하지 않았다.

### 후속 소스 검사: 요청 복구 전 휴대폰 키 확인

기존 단일 수신함 소유자에 전체 요청 복구용 키 사전 확인 경로를 추가했다.
저장소 잠금을 유지하고 복구 결과를 확정하기 전에 기존 키를 확인할 수 있다.
실패나 중단은 새 설치로 덮어쓰지 않으며, 기존 설정 전용 시작 조건도
바꾸지 않았다. ROOT의 Windows 호스트 테스트 123개와 fmt·Clippy가 통과했고
이 중 새 테스트 9개가 잠금·복구 순서·손상·실패·내구성 경계를 검사한다.
이는 향후 요청 수신 연결을 위한 준비이며 실제 휴대폰 알림·키 검증이나
Application의 수신 기능을 켠 결과는 아니다. 이 후속 변경의 별도 CI도 필요하다.

## 이전 검증 기준: `aba127f`

- [전체 품질 CI](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34326404942)의
  Windows·Linux·Android 코어 작업과 [APK 빌드](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34326404957)가
  통과했다. ROOT가 각 실행의 최종 종료 코드 0을 확인했다. Rustfmt, 전체
  Clippy 경고 0, Cargo 테스트, 실제 Rust Analyzer와 실패 판정 예제를 포함한다.
- 서비스 전용 Windows 등록부 저장과 휴대폰의 로컬 키 생성 의도·공개키
  기록·재열기 수명주기를 추가했다. 휴대폰 기록은 PC 등록 승인이 아니며,
  Application은 여전히 설정 전용이다. 불완전한 생성 기록이나 남은 키를
  새 설치로 덮어쓰지 않는다. 관련 결정은 [Windows 등록부](adr/0007-service-device-registry.md)와
  [휴대폰 키 수명주기](adr/0008-phone-local-key-lifecycle.md)에 있다.
- 실제 UAC·휴대폰 인증 수동 검증, 신뢰할 수 있는 QR 등록, 실제 요청·알림·
  승인 연결, PR/main 릴리스와 최종 보안 감사·리팩터링은 여전히 남았다.

### 검증된 소스 범위: Windows 창의 제한된 표시 내용

읽기 전용 보조 프로세스에서 같은 UIA 루트의 제목·보이는 정적 문구를
두 번 읽고 비교하도록 확장했다. 편집·값·비밀번호 하위 트리는 읽지 않는다.
런타임 식별자와 문구 일치는 원자적인 UAC 요청 식별이나 승인 권한이 아니다.
문구를 오류·Debug 기록에 넣지 않고, 입력 길이와 수신 버퍼·보조 프로세스
메모리를 제한한다. 위 CI에서 모델·통신·버퍼·범위 검사와 플랫폼 컴파일을
통과했지만, 실제 UAC 창을 읽거나 승인한 증거는 아니다.

### 검증된 소스 범위: 휴대폰 등록 정보와 수신 연결

같은 저장 트랜잭션에 PC·수신 기기·등록 개정 번호·휴대폰 키·PC 공개키의
대응 관계를 추가했다. 실제 TCP/TLS 수신 경로가 그 관계와 앱 소유자 수명을
유지하도록 연결했다. 연결 취소·재등록·앱 소유자 재시작 뒤 이전 메시지 거절을
포함한 실제 loopback 테스트 8개가 양쪽 호스트 CI에서 통과했다.
등록 절차 자체와 실제 알림·인증·서명 연결은
아직 남아 있다. 로컬 키나 저장된 관계가 존재한다고 이 기능들을 켜지 않는다.

### 검증된 소스 범위: 요청의 최초 수신 정보 보존

요청마다 최초 등록 세대를 저장하고, 복구·재전송 시 이를 다른 세대로
바꾸지 않도록 했다. 이전 형식에 수신 정보가 없으면 현재 PC의 키를 추측해
채우지 않는다. 등록이 바뀐 요청의 본문은 보류하되 만료·철회 결과는 유지한다.
이 변경과 복구·재등록·만료 철회 회귀 테스트는 위 검증에 포함된다.
저장된 수신 정보 자체가 실제 인증 허가는 아니다.

### 검증된 소스 범위: 요청별 휴대폰 인증과 서명

원래 요청과 연결된 일회성 승인 계획, Android의 실제 CryptoObject 인증
작업, 서명·취소·화면 수명주기 처리를 추가했다. 기존 Application
작업 스레드와 키 소유자를 함께 사용한다. 서명 결과는 전송 전 준비 상태로만
분류하며 Windows 승인 성공으로 기록하지 않는다. 위 기준 커밋에서 모델·
연결부 테스트와 APK 빌드를 통과했다. 실제 등록·요청 수신·알림 게시·전송 연결과
사용자의 실제 휴대폰 인증 확인이 남아 있으며 설정 전용 시작 조건도 유지한다.

### 현재 작성 중: 실제 연결의 전송과 휴대폰 통신 키

승인 서명을 실제 소켓 전송에 연결하고, 대기·분할 전송 중 등록 해제나
요청 철회·서비스 기준 변경을 감지해 중단하도록 했다. 휴대폰의 기존 통신
키를 사용하는 정형 TLS 서명 연결부도 추가했다. 전송 대기와 로컬 소켓 쓰기는
Windows 승인 결과와 구분한다. 이 변경은 위 기준 커밋 검증에 포함되지 않는다.
네이티브 연결 시작·알림 서비스와 PC 쪽 수신·실행 연결은 아직 남았다.

이 단계에서는 파일을 삭제하지 않았다. 이후 사용자가 허가한 실험 전
공간 확보와 전체 작업 종료 후 정리는 위의 저장 공간 항목에서 구분한다.

## 이전 화면·기록 검증 기준: `dac04a9`

- [전체 품질 CI](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34298828002)는
  Windows·Linux의 fmt, Clippy 경고 0, Cargo 테스트, 실제 Rust Analyzer와
  정상/오류/경고 판정 검사를 통과했다. Android Rust 코어와 Tauri 연결부
  Clippy도 통과했다. 과거 단계의 테스트 실패 수치를 현재 결과로 읽지 않는다.
- [Android 패키지 CI](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34298827988)는
  실제 arm64 디버그 APK를 만들었으며 Kotlin Gradle 테스트 47개가 통과했다.
  ROOT가 내려받은 APK의 SHA-256은
  `e35d6faf8ad06a8601232854c9b23e711ab882d92b628e75c2ecfcc30d4a4c91`이다.
  설치·시작·생체/PIN 인증을 실행한 결과는 아니다.
- 수신함과 표시용 기록을 한 저장 트랜잭션으로 묶었다. 기록 보관은 최대
  512건/30일이며, 기록을 지워도 요청 재전송 방지 상태는 지워지지 않는다.
  실제 Android Application 소유자에 기록 조회·삭제를 연결했지만, 등록과
  인증된 요청 수신이 미구현이므로 초기화는 계속 설정 전용 상태만 허용한다.
- Windows 읽기 전용 보조 프로세스의 제한된 실행·인증 통신·종료 소유자를
  작성하고 CI로 검사했다. 이 경로를 서비스에 활성화하거나 실제 UAC를
  조작하지 않았다. 실제 프롬프트 식별·승인 어댑터는 아직 없다.
- [화면 갤러리 CI](https://github.com/115dkk/Windows_UAC_Remote_Controller/actions/runs/34298827980)는
  Windows·Linux 각각 29개 시나리오/44개 이미지를 생성했다. ROOT가 새 기록
  화면을 양쪽에서 확인했다. [대표 화면 12장](gallery/2026-09-09/README.md)은
  합성 데이터를 실제 Chromium으로 렌더링한 것이며 Android 캡처가 아니다.

이 단계에 남았던 핵심은 소유자가 선택한 휴대폰만 등록하는 QR 절차, 영속 등록부,
실제 요청 수신·알림·요청별 인증, Windows 프롬프트에 대한 동작 적용이다.
일반 화면에서 복사한 QR이나 하드웨어 키 증명만으로 등록을 허용하지 않는다.
등록할 기기를 확인하는 보호된 화면·입력 절차는 아직 결정·실증이 필요하다.
실제 UAC 승인과 휴대폰 인증 수동 검증은 사용자에게 유보되어 있다.
PR/main 실행·자동 릴리스, 완료 후 보안 감사와 새 아키텍처 리팩터링도 남았다.

아래는 **이전 단계의 이력**이다. 각 단계의 ‘최신’·‘미해결’·실패 수치 및
아직 연결되지 않았다는 표현은 당시 범위이며, 현재 판정은 위 커밋과 실제
CI 링크를 기준으로 한다. 과거 실패와 미검증 기록은 삭제하지 않고 보존한다.

## Android Application 소유자·실제 소켓 경로

Android에 한 개의 Application 작업자와 Rust 정책 소유자를 연결했다. Android
Tauri에서 이전 AppRuntime을 여는 경로는 제거했으며 Windows 경로는 유지했다.
기존 설정은 Tauri의 실제 dataDir 위치에서 읽고, 중단·손상·키가 남은 상태를
새 설치로 덮어쓰지 않는다. 알림 정리가 실패하면 종료 재시도 의무를 유지한다.
요청·인증·알림 수신 서비스가 완성됐다는 뜻은 아니다.

- 실제 arm64 Rust 라이브러리·새 Kotlin ABI 생성 성공.
- 생성 ABI, Application 작업자와 네이티브 어댑터의 Kotlin `-Werror` 컴파일,
  순수 JVM 검사 25개 통과. Tauri Kotlin 플러그인·전체 APK 검증은 별도다.
- Android용 Tauri Rust Clippy 통과. 호스트 Tauri 검사 5개와 Android 바인딩
  검사 14개, 표시/설정 런타임 검사 32개가 통과했다.
- 테스트 전용 소켓 루프를 production SocketDriver로 교체했다. 실제 TCP·중계·
  상호 TLS 경로 및 단편화·역압력·취소·기한·종료 검사 총 37개 통과.
  스택 고갈은 큰 상태/버퍼의 힙 소유로 수정했다. 겹치는 기한 두 검사에서는
  원래 제한을 그대로 둔 채 TLS 기한을 따로 검사하도록 시험 시각을 구분했다.
- 전체 workspace Clippy `-D warnings` 통과. 전체 Cargo/Analyzer와 플랫폼별 CI는
  현재 코드로 갱신해야 한다. 기존 중계 EOF 실패를 해결했다고 주장하지 않는다.

현재 작업은 `codex/native-runtime`에서 이어간다. 세부 기록은
`.superloopy/evidence/android-application-kotlin-tests.txt`,
`android-owner-tauri-android-clippy.txt`, `socket-driver-all-root.txt`,
`native-owner-workspace-clippy-v2.txt`, `android-owner-bootstrap-review.md`에 있다.
실제 APK 빌드와 전체 CI 결과는 다음 확인 단계다. [결정 기록](adr/0005-android-application-policy-owner.md)

## CI 화면 확인으로 전환

사용자가 로컬 화면 승인을 놓친 상황을 설명하고 CI 갤러리 촬영을 지시했다.
로컬 앱/브라우저 접근을 다시 시도하지 않고 Windows·Linux CI에서 공유 React
클라이언트의 시험 화면을 촬영한다. 실제 UAC 승인과 휴대폰 인증은 사용자가
나중에 직접 확인하기로 했다. 이 수동 검증을 이미 통과한 것으로 표시하지
않으며, 이를 기다리느라 클라이언트 CI를 중단하지 않는다.

최상위가 실행한 화면 행동 테스트 21개, 빌드 분리 테스트 3개,
TypeScript·ESLint·제품/시험 빌드는 통과했다. 시험 출력은 고정 경로로 제한하며
제품 빌드에 시험 모듈이 섞이면 실패한다. 이어서 소스 `37890c7`의 실제 CI
실행 `34276434168`에서 Windows·Linux 각각 26개 시나리오가 통과했고 39장씩
촬영했다. ROOT가 다운로드해 대표 상태·경계 화면과 변경 이미지를 검토했다.
오류 예시가 빈 목록을 확정하던 모순과 촬영 도구의 오류 누락·결과 표시를 수정했다.

대표 원본 PNG 8장과 전체 갤러리 링크를 [이슈 #1](https://github.com/115dkk/Windows_UAC_Remote_Controller/issues/1)에 올렸다.
화면 코드·갤러리와 이미지 보관 커밋만 `codex/ci-ui-gallery`에 푸시했다.
main 병합·PR 생성·릴리스나 전체 Rust CI 성공은 아니다. 다른 Rust/Android 소스는
기존 로컬 작업 그대로 보존했다. 실제 CI·이미지 검토 기록은
`.superloopy/evidence/frontend/20260908T201702Z-ci-gallery/`에 있다.
이 브라우저 갤러리를 Tauri 설치·Secure Desktop·Android 인증의 증거로 쓰지 않는다.

## 최신 Android 연결 코드 단계

실제 arm64 Android Rust 라이브러리를 빌드하고, 그 라이브러리에서 Kotlin 연결
코드를 생성했다. 생성 코드와 Application 기반 네이티브 관측 어댑터는 Kotlin
1.9.25의 `-Werror` 컴파일을 통과했다. 네이티브 관측의 순수 테스트 12개,
Rust 연결부 호스트 테스트 5개, 빌드 도구 테스트 26개도 통과했다.

이 연결부는 **설정 전용 준비 단계**다. 요청 기록이 있는 저장소는 같은 잠금
안에서 먼저 거부하여 미구현 처리기가 만료 결과를 소모하지 않게 했다. 아직
Application/Service에 활성화하거나 기존 Tauri AppRuntime을 교체하지 않았다.
두 번째 Rust 라이브러리의 APK 배치, 시작 시 알림 정리, 요청·기록 처리기와
실제 인증 연결이 필요하다. Gradle 소스 생성/JNA 의존성은 선언했지만 전체
Gradle·APK 실행을 통과했다고 표시하지 않는다.

최신 전체 Rust 테스트는 **445개 통과·2개 실패**다. 중계의 연결 종료/기한
실패는 여전히 미해결이다. fmt·전체 Clippy·Android 대상 Clippy·실제 Rust
Analyzer는 통과했고 분석기의 조건부 컴파일 Hint 66개만 별도 기록했다.
호스트 전용 연결 코드 생성기는 호스트 전체 검사에 포함하며 Android 대상
검사에서만 Tauri 껍데기와 함께 명시적으로 제외한다. 실제 GitHub 실행은 아니다.

관련 기록: `.superloopy/evidence/android-binding-root-progress.md`,
`android-bindings-real-build-v3.txt`, `generated-native-controller-kotlin-v2.txt`,
`bindings-workspace-tests.txt`, `bindings-rust-analyzer.txt`.

## 최신 휴대폰 상태 저장·복구 단계

본문·명령어·개인키 없는 복구 형식, 중단 흔적을 남기는 파일 저장소,
저장 완료 후에만 결과를 반환하는 `DurableInbox`를 연결했다. 미처리 입력과
저장 완료된 폐기를 구분하며, 불확실한 저장이나 손상을 빈 상태로 초기화하지 않는다.

- 요청 코어 **54개**, 알림 복구 경계 **20개**, 저장소 **27개**, 실제 파일을
  사용하는 소유자 통합 **18개** 테스트가 최상위 실행으로 통과했다.
- 시간 밖 폐기 후 파일 재열기, 새 앱 실행을 깨운 요청, 원래 만료 시각 보존,
  재부팅·시계 불연속·복구 본문 재검증, 쓰기 실패 시 본문/표시 후보 차단을 확인했다.
- Rust 1.97의 표준 파일 잠금이 Android에서 지원되지 않는 문제를 확인했다.
  Android에서만 safe rustix API를 사용하도록 새 저장소와 기존 설정·기록 저장소를 수정했다.
- 전체 Clippy `-D warnings`, fmt와 실제 Rust Analyzer가 통과했다. 분석기 오류·경고는
  0개이며 조건부 컴파일 Hint 65개는 별도 기록했다. 실제 정상/오류/경고 판정 예제도 통과했다.
- Android 공통 Rust Clippy와 문서 테스트 6개가 통과했다. 백업 제외 XML은
  Android 빌드 도구로 리소스 컴파일만 확인했다. APK 포장·실기 동작 증거는 아니다.
- 최신 전체 Rust 테스트는 **438개 통과·3개 실패·제외 0개**다. 실패는 중계의
  대기 연결 종료, 반복 연결 세대 종료, 조기 입력 후 종료/기한 테스트다.
  기존 독립 Winsock 문제와 관련될 수 있으나 모든 실패의 원인이 같다고 단정하지 않는다.

따라서 G002/C001은 계속 fail이며 전체 제품은 미완료다. Windows 호스트의 파일
동기화 테스트를 Android의 전원 차단·디렉터리 동기화 증거로 쓰지 않았다.
실제 Android Application 소유자/바인딩, 알림·인증·등록 연결, 중단 저장소 복구와
기록 전달 보장은 남아 있다. [저장·복구 결정](adr/0004-phone-checkpoint-transactions.md)

최신 실행 기록은 `.superloopy/evidence/persistence-all-tests-root.txt`,
`persistence-workspace-clippy.txt`, `persistence-rust-analyzer-root.txt`,
`persistence-android-core.txt`, `durable-inbox-full-root.txt`에 있다.
아래 수치는 이전 단계의 기록이다.

## 최신 전송·안드로이드 소스 단계

현재 확장된 워크스페이스의 전체 품질 검사는 **실패**다. 슈퍼루피
G002/C001을 재실행해 fail로 갱신했다. 이전 단계의 통과 기록은 현재
중계·전송 코드까지 통과했다는 근거가 아니다. 현재 7개 목표 중 1개 완료,
14개 세부 기준 중 2개 통과이며 전체 제품은 미완료다.

- PC 서명 메시지·시각 대응(`service-protocol`), 상호 공개키 고정 TLS 1.3
  (`secure-channel`), 휴대폰 요청 수명주기(`phone-request-core`), 제한된
  프레임 운반(`framed-transport`), 불투명 TCP 중계(`relay-service`)를 추가했다.
- 새 클라이언트 연결 코드로 실제 로컬 중계와 상호 TLS를 거쳐 합성 PC 서명
  요청을 전달하는 통합 테스트가 통과했다. 클라이언트 연결·취소·기한·표식
  검사 5개도 통과했다. 인터넷·실제 기기·UAC 승인의 증거는 아니다.
- 휴대폰 요청 코어는 시계 오차에 따른 폐기 요청의 재등장 반례를 수정한 뒤
  42개 테스트와 Clippy가 통과했다. PC의 서명된 만료 확인 기록을 유지한다.
  프로세스 재시작 후 지속 저장·복원은 아직 구현하지 않았다.
- Windows의 연결 종료 테스트가 간헐적으로 실패한다. 중계/TLS/Tokio를
  제거한 독립 실험에서도 원시 Winsock 수준으로 재현했다. 원인은 미확정이며,
  제한 시간 연장·재시도·테스트 제외·시스템 설정 변경으로 통과시키지 않았다.
  별도 코드 감사에서 발견한 연결 인계 취소·상대편 조기 종료의 자원 수명주기
  결함 두 건은 수정했고, 최상위 실행 회귀 테스트 7개가 통과했다.
- UniFFI 0.32 실험은 Android 대상 `forbid(unsafe_code)` 유지 검사,
  실제 Android 공유 라이브러리 빌드와 Kotlin 바인딩 생성까지 통과했다.
  Kotlin/JNA의 실제 Android 실행은 입증하지 않는다.
- 새 Android 키 생성·검사 모듈은 Kotlin 1.9.25/API 36에서 `-Werror`
  컴파일과 순수 정책 테스트 10개를 통과했다. 승인·거절·연결용 키를 분리하고
  하드웨어 키와 승인용 요청별 인증 정책을 검사하는 소스다. 실제 키 생성,
  원격 인증서 검증, 승인 서명·생체/PIN 창, 등록 복구·폐기 처리는 아직 남았다.
- Android NDK 선택 도구 테스트 12개와 Android 공통 코어 Clippy를 추가 검증했다.
  최신 전체 품질 명령은 앞 단계의 중계 테스트에서 멈추므로 후속 분석기·라이선스
  단계까지 이번 전체 명령이 성공했다고 표시하지 않는다.
- 이후 개별 실행한 전체 Rust 테스트는 **362개 통과·2개 실패·제외 0개**였다.
  두 실패는 중계의 기다리는 연결 종료/기한 테스트다. 전체 Clippy, 문서 테스트
  6개, Android 공통 코어 Clippy는 통과했다. 실제 Rust Analyzer는 테스트의
  비동기 함수 호출에서 오류 3개로 실패했으나, 반환 Future의 Send 계약을
  컴파일러가 검증하도록 명시한 뒤 오류·경고 0개로 통과했다. 조건부 컴파일의
  inactive-code Hint 50개만 별도 기록하며 일반 진단은 제외하지 않았다.
  실제 정상/오류/경고 예제로 분석기의 실패 판정도 다시 확인했다.

기록: `.superloopy/evidence/G002-C001-capture.txt`,
`tcp-eof-investigation.md`, `transport-tcp-pipeline-v2.txt`,
`relay-client-contract-tests.txt`, `android-keystore-source-root-v3.txt`.
각 짧은 파일명은 같은 evidence 디렉터리 아래에 있다. 기존 앱/브라우저 검사
권한 거부와 APK 링크 권한 문제는 그대로이며 우회하지 않았다.

## 이전 Windows·화면 통합 단계의 기록

공통 코어 뒤에 Windows 서비스 호스트, TPM 키 소유자, 화면용 런타임,
React 화면과 Tauri Windows/Android 호스트를 추가했다. 서비스 설치·키 생성·
실제 승인·페어링·전송·휴대폰 인증의 종단간 동작이 입증됐다는 뜻은 아니다.

- 화면의 strict TypeScript, ESLint(경고 0), 행동 테스트 21개, production 빌드가 통과했다.
- 새 Windows 통합에서 Rust 테스트 195개, 문서 테스트 5개, fmt와 전체 Clippy `-D warnings`가 통과했다.
- 실제 Rust Analyzer는 최초 통합에서 Tauri 생성 코드의 진단 25개로 실패했다. CLI의 dev cfg 일치와 실제 아이콘 배열 길이 보강 후 오류·경고 0개로 통과했다. 다른 cfg의 `inactive-code` LSP Hint 44개만 별도 기록하며 일반 진단은 제외하지 않았다. 실제 정상/오류/경고 예제로 실패 판정도 확인했다.
- 9월 9일 통합 품질 명령은 종료 코드 0이다. 분석기 환경/판정 Node 테스트 22개, Android 공통 코어 Clippy, 라이선스 메타데이터 471개 패키지도 검사했다. 별도 Android Tauri 라이브러리 Clippy `-D warnings`가 통과했다. APK·Kotlin·실기 검증을 뜻하지 않는다.
- Windows 실행 파일과 Android aarch64 Rust 라이브러리를 빌드했다. Windows cdylib 링크에는 한국어 MSVC 진행 문구를 경고로 취급하는 도구 문제가 남아 있다.
- Android APK 포장은 Windows 파일 링크 권한 부족으로 중단됐다. OS 보안 설정을 바꾸거나 다른 포장 방식으로 우회하지 않았다. Kotlin 단독 컴파일/JVM 테스트도 Gradle 캐시 이동 실패로 시작 단계에서 멈췄다. 작성한 Kotlin 테스트 8개는 아직 실행되지 않았다.
- 실제 Windows 앱과 localhost 화면의 자동 검사 권한이 모두 거부됐다. 다른 도구로 우회하지 않았고 시각·접근성·네이티브 동작을 통과로 표시하지 않았다.

실패 기록은 `.superloopy/evidence/integration-quality-20260908-r2.txt`,
이후 통합 통과 기록은 `.superloopy/evidence/integration-quality-20260909-final.txt`,
정적 보안 지적의 수정/잔여 항목은
`.superloopy/evidence/controller-bridge-root-remediation.md`에 있다.
아래의 129개 테스트 및 첫 품질 검사 성공은 **이전 코어 단계의 기록**이며,
확장된 현재 워크스페이스 전체가 통과했다는 뜻이 아니다.

당시 슈퍼루피 G002/C001도 재실행 캡처 후 pass였으나, 위 최신 확장 검사에서
fail로 갱신했다. 실제 GitHub 실행, 설치물·네이티브 기능·화면·보안 종단간
검증을 이전 품질 수치로 대신하지 않는다.

## 반영한 사용자 결정

- 자격 증명형은 휴대폰에서 Windows 요구대로 입력하는 방법이 적절한지 평가한다. 적절하면 지원하고 무리가 있는 유형은 무시한다. Windows 인증을 앱 인증으로 대체하지 않는다.
- 이미 SYSTEM/커널이 침해된 경우는 위협 모델에서 제외한다. 일반 권한 악성코드가 이 서비스를 통해 상승하는 공격, 적대적 네트워크·중계, 미등록/폐기 기기는 계속 방어 대상이다.
- 모든 실행 검증은 최상위 에이전트가 했다. 구현·보안 감사 하위 에이전트는 코드/테스트 작성과 정적 검토만 했다.
- 마지막 `improve-codebase-architecture`의 승인자는 최상위 에이전트다. 새 리팩터링 에이전트의 후보 보고를 검토하고 승인한 안을 같은 에이전트에 되돌려 보낸 뒤 구현하게 한다. 사용자에게 밤중 승인을 요청하지 않는다.

## 구현된 범위

| 모듈 | 현재 기능 | 아직 입증하지 않는 것 |
| --- | --- | --- |
| approval-protocol | 고정 버전·목적별 P-256 서명, 엄격한 DER/바이너리 파서, 전체 요청 결합, 일반 앱/셸 이름·긴 Windows 문자열 | Windows 원본 요청 식별, 하드웨어 키 인증, 전송 암호화 |
| approval-core | 기기별 승인/거절 키, 등록 개정 번호, 폐기/교체, 단조 시계 만료, 중복 승인 방지, 한 번만 소비하는 승인 결과 | 권한 있는 서비스/QR 등록, 실제 Windows 승인 적용 |
| notification-policy | 요일/시간대, 자정 경계, 미설정 항상 허용, 기본 소리·진동·무음, 비활성 시간 폐기, 취소/만료·재전송 억제·용량 상한 | Android OS 알림, 인증, 앱 종료 후 내구성 |
| activity-journal | 파일 기반 구조화 기록, 기간·건수·용량 제한, 배타 잠금, 원자 교체, 명시적 손상 복구 | 서비스 디렉터리 ACL 설치, 권한 상태 저장, 변조 방지 감사 장부 |
| windows-observer | 현재 프로세스 세션과 데스크톱 분류를 한 번 읽는 진단 | UAC 탐지, Secure Desktop 입력·전환, 자격 증명 처리 |
| windows-service-host | 고정 서비스/설치 경로, 실제 SCM 설치·AutoStart 등록, 제한된 서비스 SID·디렉터리 정책, 종료 수명주기, 키 초기화 연결 | 정상 서비스 시작·종료, Secure Desktop 보조 프로세스 실행, 승인 |
| windows-identity | 서비스 전용 TPM P-256 키 생성/열기·사용 경계, 비추출 정책·DACL 검사 | 실제 TPM/KSP 동작과 제한된 서비스 토큰 호환성 |
| controller-runtime | 검증된 알림 설정 저장, 서비스 관찰/명시적 제어, 미확인 결과와 사용 불가 상태 분리 | 기기·요청·기록의 실제 소유자 연결, Windows AppData ACL 입증 |
| service-protocol / secure-channel | 서비스 서명 메시지·일회성 시각 탐침, 상호 공개키 고정 TLS 1.3, 제한된 운반 | 등록 키의 출처, 실제 TPM/휴대폰 키 연결, 인터넷 지연 |
| phone-request-core | 활성 요청 본문 제한, 원래 만료 기한과 서명된 PC 시각에 따른 재전송 억제 | 프로세스 재시작 내구성, Android OS 알림 |
| framed-transport / relay-service | 제한된 프레임·연결 수·버퍼·기한, 공개 중계 표식과 내부 인증 분리 | 실제 서비스 배포, 종료 실패의 해소, 모든 네이티브 연결 수명주기 |
| Tauri/React/Kotlin | 화면·명령 경계, 요청 적체 방지, Android 화면 잠금/알림 상태 관찰 코드 | 실제 앱 화면, APK·실기기, 생체/PIN 승인·OS 알림 |

보안 감사 후 등록 저장소 전체 교체로 개정 번호가 되돌아갈 수 있는 인터페이스를 좁혔다. 알림의 발급 시각 충돌과 식별자 Debug 출력을 보강했다. 프로그램 정보는 불변 공유 메모리로 보관해 대형 본문의 중복 복사를 줄인다. 상세 정적 검토는 `.superloopy/evidence/core-security-review.md`에 있다.

## 첫 코어 단계에서 최상위가 실행한 검증 (이전 기록)

당시 코어 통합 명령: `node tools/quality.mjs --extended`, 종료 코드 0.

- Windows Rust 단위/통합 테스트 **129개**, 문서/컴파일 계약 테스트 **4개** 통과.
- Rustfmt 검사, 전체 대상·기능 Clippy `-D warnings` 통과.
- 실제 Rust Analyzer 검사 통과. 실제 오류·경고 0개이며 다른 cfg 분기의 `inactive-code` LSP Hint 7개는 별도 기록한다. 일반 경고와 다른 진단은 실패 처리한다.
- 분석기 실패 판정 Node 테스트 **13개** 통과. 실제 분석기에 정상/오류/경고 파일을 넣어 정상만 허용함을 확인했다. 경고 예제의 분석기 자체 종료 코드는 0이었으나 검사 결과는 실패였다.
- `aarch64-linux-android` 대상 전체 Clippy `-D warnings` 통과. 이는 Android 기기 실행이 아니다.
- actionlint **1.7.12**로 워크플로 구문 검사 통과.
- 의존성을 포함한 **76개 패키지**의 라이선스 메타데이터를 기록했다. 프로젝트 크레이트는 GPL-2.0-or-later다. 배포 호환성·소스 제공 의무를 모두 검토했다는 뜻은 아니다.

슈퍼루피 명령 캡처:

- `.superloopy/evidence/G001-C001-capture.txt`: 프로토콜·승인 코어.
- `.superloopy/evidence/G001-C002-capture.txt`: 알림 일정·수명주기.
- `.superloopy/evidence/G002-C001-capture.txt`: 최종 확장 품질 검사.

원본 분석 출력과 라이선스 목록은 `target/quality/`에 있다. 이 디렉터리와 슈퍼루피 런타임 산출물은 Git에서 제외되어 있다.

## 첫 단계 Windows 실제 환경의 제한된 관찰

최상위가 `cargo run -p windows-observer --bin uac-observe --locked -- --once`를 실행했고 종료 코드 0이었다.

```text
platform=windows
process_session_id=1
thread_desktop=Default
input_desktop=Default
```

실제 UAC를 띄우거나 승인한 증거가 아니다. 이 과정에서 서비스 설치, 정책 변경, 데스크톱 전환, 화면 캡처, 입력 전송을 하지 않았다. 당시 관찰 모듈의 직접 작성한 unsafe 블록 **8개**는 Windows 전용 `src/ffi.rs`에 있다. 이후 서비스·키 크레이트에도 격리된 Windows FFI가 추가됐으며, 공통/Android/Tauri 소스는 unsafe를 금지한다. 종속/생성 코드 내부의 unsafe까지 0이라는 뜻은 아니다.

## 남은 필수 작업

1. 실제 UAC 요청 식별·최종 대상 결합과 자격 증명 입력 경로를 격리 환경에서 평가한다. Credential Provider의 기존 Windows 자격 증명 직렬화·자동 제출도 검토 후보이며, 앱 인증을 새 Windows 인증 방식으로 대체하는 별도 LSA 패키지를 뜻하지 않는다.
2. Windows 서비스·세션 보조 프로세스·TPM 키·ACL·매 QR 재발급 UAC·신뢰할 수 있는 페어링 절차.
3. 종단간 인증·암호화 전송 및 인터넷 중계/푸시, 재접속·기기 폐기·만료 신호.
4. Kotlin OS 연결, Android 요청별 인증·알림·일정 사전 검사·재시작 내구성·실기 지연 측정. SDK는 발견했지만 확인 시점에 연결된 adb 기기는 없었다.
5. 슈퍼루피 기반 Windows/Android Tauri React 화면과 플랫폼별 시각·접근성 검증.
6. 실제 GitHub CI 실행, main 연계 설치물 빌드·자동 릴리즈·서명·소스 제공.
7. 완성 결과의 보안 감사 및 **새 에이전트**를 통한 전체 아키텍처 리팩터링. 후보 보고 → 최상위 검토·승인 → 같은 에이전트에 승인안 재전달 → 구현 → 최상위 회귀 검증 순서로 진행한다.

실제 GitHub Actions 실행·커밋·푸시·PR·릴리즈는 아직 하지 않았다. 초기화권도 사용하지 않았다. 전체 목표와 슈퍼루피의 나머지 기준은 미완료로 유지한다.
