# 기술 부채 감사

종합 단계는 읽기 전용으로 진행해 본문을 반환했습니다. 이 파일은 주 세션이 그 본문을 저장소 기준 상대 경로로 바꿔 저장한 것입니다.

## Header

| 항목 | 값 |
|---|---|
| 저장소 | `115dkk/Windows_UAC_Remote_Controller` |
| 날짜 | 2026-11-20 |
| 커밋 | `cd72e8d0d607f68d526f1797d72120c3ddaeb83c` |
| 모드 | CI |
| 기준 보고서 | 없음 |
| 작성 방식 | readers **gpt-6-astra**, judges **Claude Opus 5.5**, synthesis **gpt-6-astra** |
| 검증 방식 | 제공된 9개 차원의 판정 합성, 주요 위치와 상위 5건의 소스·ADR 직접 대조 |
| 실행·측정 | **no code was run, no coverage was measured**. 제품 코드, 빌드, 테스트, 설치, 기기 실험, 성능 측정을 실행하지 않았습니다. |
| 제외 범위 | 지정된 빌드·의존성·개인 설정·첨부·실험·생성 코드와 제3자 구현 내부 |
| 구조 감사의 제한 | 종합 시점에 `ARCHITECTURE_AUDIT.md`가 파일로 저장돼 있지 않아 그 **Fine as is를 대조하지 못했습니다**. 두 보고서의 대조는 후속 작업으로 남습니다. |

## Executive summary

- **Critical 0 / High 1 / Medium 17 / Low 20**, 총 **38건**입니다. 모두 `NEW`입니다.
- 입력 40건 중 `confirmed` 또는 `confirmed_with_changes`는 39건입니다. 중복 2건을 합치고, 합성 중 직접 확인한 1건을 추가했습니다. `rejected` **0건**, `recorded_decision` **1건**, `Not judged` **0건**입니다.
- **TD-01**은 승인 코디네이터의 재시도·정리를 실행하는 회귀 테스트가 없다는 문제입니다. 승인 슬롯이 해제되지 않는 과거 증상의 재발을 문자열 검사만으로 막지 못합니다.
- **TD-02·TD-03**은 정상적인 유휴 처리에서도 발생합니다. 승인 처리 스레드에서 활동 기록을 동기식으로 다시 쓰고, 연결별 검증에서 같은 체크포인트와 Windows 신원 정보를 반복해서 구합니다. 지연이나 CPU 사용량은 측정하지 않았습니다.
- **TD-04·TD-06~TD-11**은 실패 원인이 사라지는 문제입니다. 서명된 결정의 거부, 서비스 내부 panic, 키 저장소 실패, 연결 종료, 관리 파이프 재생성 실패를 운영 진단에서 구별하기 어렵습니다.
- **TD-05**는 사용자에게 직접 영향을 주는 문서 누락입니다. 주요 사용 사례인 백그라운드 작업의 UAC 요청이 작업 표시줄에 대기하면 PC에서 직접 눌러야 하지만 README에는 이 제한이 없습니다.
- 문서 12건은 현재 계약과 어긋납니다. 특히 서비스 SID 유형, Android ABI, 표시 스키마, 리스 갱신 메시지와 실제 승인 기능의 구현 여부를 잘못 안내합니다.
- 노력 규모는 **S 32 / M 5 / L 1**입니다. 파일 크기만으로 권한 소유자를 나누거나, 기록된 보안·수명 결정을 바꾸도록 권하지 않습니다.

## Architectural mental model

Windows 서비스의 `ServiceSession`은 등록 정보, 승인 엔진, 원래 서비스 시계와 스레드에 귀속된 PC 키를 함께 소유합니다. 별도 감시 도우미가 실제 보안 데스크톱의 창을 관찰하고, 검증된 결정에 대해 같은 대상과 내용을 다시 확인한 뒤 버튼을 누릅니다. TLS 연결, 중계, 직접 접속 주소와 DNS-SD는 전달 수단입니다. 이들의 접속 성공이나 주소 정보가 승인 권한을 대신하지 않습니다. 활동 기록과 공개 진단도 권한 상태가 아닙니다.

Android에서는 Application 수명의 단일 작업자와 `MobileController`가 요청·저장·인증·핸들 정리를 소유합니다. Kotlin은 Android 인증과 알림, Activity 수명을 연결하고 Rust는 요청 및 결정의 유효성을 검사합니다. Tauri/React는 제한된 표시 데이터와 명령 의도를 전달합니다. 실제 승인 기능은 연결되어 있으므로, 이를 아직 없는 기능이라고 설명하는 도메인 문서와 일부 README는 현재 코드와 어긋납니다. 이번 감사가 현재 버전의 실기 동작을 다시 입증한 것은 아닙니다.

## Findings table

모든 항목은 정적 판단입니다. 실행 재현으로 확인한 항목은 없습니다. 테스트 부채와 중복 항목은 현재 제품 오동작을 확인했다는 뜻이 아닙니다.

| ID | Status | Category | File:Line | Severity | Effort | Description | Recommendation |
|---|---|---|---|---|---|---|---|
| TD-01 | NEW | Test debt | `tools/android-approval-slot-contract.test.mjs:25` | High | L | **승인 코디네이터의 재시도와 정리를 실행하는 회귀 테스트가 없습니다.** 현재 검사는 `return` 개수와 문자열 순서를 확인합니다. 개별 JVM 정책 테스트도 실제 코디네이터의 Busy 처리, 서명 보존, 작업 큐와 슬롯 해제를 실행하지 않습니다. | 코디네이터의 실제 상태 전이를 실행하면서 시간·작업 큐·네이티브 호출 결과를 제어하는 테스트를 추가하십시오. 같은 서명 재전달, 정리 실패 재시도, 만료 뒤 후속 승인 허용을 검사해야 합니다. |
| TD-02 | NEW | Performance and resources | `crates/windows-service-host/src/runtime.rs:416` | Medium | M | **활동 기록의 동기식 전체 파일 I/O가 승인 처리를 기다리게 합니다.** 새 활동이 없어도 약 1초마다 `recent`를 호출하고, 시각이 진행하면 전체 파일을 다시 쓰고 동기화합니다. 같은 스레드의 감시·결정 처리는 그 뒤에 실행됩니다. | 기록의 단일 소유권을 제한된 별도 작업자로 옮기고 서비스에는 최근 목록을 전달하십시오. 인라인 append도 함께 다루며 보존 기간, 시각 역행과 실패 보고 계약을 유지하십시오. |
| TD-03 | NEW | Performance and resources | `crates/windows-service-host/src/peer_runtime.rs:2490` | Medium | M | **연결별 검증이 같은 체크포인트와 Windows 신원 조회를 반복합니다.** 두 재검증을 끝까지 수행하는 처리에서는 연결 1개만 있어도 체크포인트 10개와 신원 확인 8회가 발생합니다. 키 작업 전후의 두 검증 자체는 ADR의 요구입니다. | 각 검증 시점 안에서 등록 정보·엔진 비교와 연결별 조회를 묶으십시오. 키 작업 전후 검증과 적용 직전 검증은 그대로 두고, 검증 결과를 다음 작업까지 재사용하지 마십시오. |
| TD-04 | NEW | Errors and observability | `crates/windows-service-host/src/runtime.rs:546` | Medium | S | **PC가 서명된 결정을 거부한 이유를 최종 처리에서 버립니다.** 코어의 `Expired`, `BindingMismatch`, `InvalidSignature` 등이 `DecisionRejected(error)`로 도착하지만 기본 분기에서 사라집니다. | 명시적인 분기에서 고정된 오류 분류만 진단에 기록하십시오. 요청·기기 식별자와 서명은 제외하고 반복 입력의 기록 빈도를 제한하십시오. |
| TD-05 | NEW | Documentation drift | `README.md:59` | Medium | S | **작업 표시줄에 대기하는 UAC 요청의 승인 제한이 없습니다.** 창 없는 백그라운드 셸의 상승 요청은 휴대폰에서 승인할 수 없고 PC에서 직접 눌러야 하는데, 문서는 해당 사용 사례에서도 승인 요청이 온다고 안내합니다. | 지원 제한·승인 절차·문제 해결에 ADR 0051의 제한을 반영하십시오. 대기 안내는 승인 요청이 아니며 검증된 원격 활성화 방법도 없음을 구분하십시오. |
| TD-06 | NEW | Errors and observability | `crates/windows-service-host/src/runtime.rs:653` | Medium | S | **서비스 종료 원인이 `WorkerFailed`로 합쳐지고 잡힌 panic도 `panicked=false`가 됩니다.** `PeerRuntimeError::Unwind`가 일반 오류로 변환되므로 서명·I/O·신원 실패와 구별되지 않습니다. | 변환 전에 고정된 원인 분류를 보존하고, 잡힌 panic과 반환 오류를 구분하십시오. panic 메시지나 원시 오류 문자열은 기록하지 마십시오. |
| TD-07 | NEW | Errors and observability | `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/AndroidNativePlatform.kt:454` | Medium | S | **Android 키 저장소의 오류·롤백 분류가 ABI 변환에서 사라집니다.** 키 소실, 무효화, 정책 불일치, 제공자 장애가 모두 `LocalKeysUnavailable`이 되어 반복 시작 실패의 원인을 구별하지 못합니다. | 현재 ABI와 화면 오류는 유지하고 변환 직전에 작업 종류·`DeviceKeyError`·`RollbackState`만 허용된 진단으로 남기십시오. |
| TD-08 | NEW | Errors and observability | `crates/relay-service/src/hosted.rs:99` | Medium | S | **내장 중계 작업자의 종료 결과를 버립니다.** `RelayReport`, `RelayError`, join의 panic 결과가 사라져 재시작에 성공하면 종료 원인과 일부 통계가 남지 않습니다. 남용 카운터 네 개는 이미 공유·기록하므로 제외합니다. | 실제 종료 때 결과를 서비스에 전달하고 정상 취소·오류·panic을 구분하십시오. 기존 재시작과 남용 카운터 처리는 유지하십시오. |
| TD-09 | NEW | Errors and observability | `crates/windows-service-host/src/peer_runtime.rs:2537` | Medium | M | **Windows 연결 작업자의 실패 원인을 회수 과정에서 잃습니다.** 드라이버 오류를 `Io`로 합친 뒤 `join().is_err()`만 검사해 `Ok(Err(...))`를 버립니다. 반복 단절의 TLS·시계·기한 오류를 구별할 수 없습니다. | 오류를 축약하기 전에 고정된 분류를 보존하고 정상 완료·반환 오류·panic을 따로 처리하십시오. 연결 하나의 실패로 서비스를 종료하지 않는 정책은 유지하십시오. |
| TD-10 | NEW | Errors and observability | `crates/android-bindings/src/intake.rs:1178` | Medium | M | **Android가 소켓 오류를 정상 종료와 함께 버립니다.** 서명 검증·TLS·기한 오류가 `Event(Err(_))`에서 없어지거나, abort 뒤 liveness 검사에서 먼저 제거됩니다. | `next_event` 결과를 받은 직후 고정된 오류 종류를 기록하십시오. 이후 큐 제거 여부와 무관하게 원인을 남기되 재시도와 연결별 종료 정책은 바꾸지 마십시오. |
| TD-11 | NEW | Errors and observability | `crates/windows-service-host/src/peer_runtime/management.rs:128` | Medium | S | **관리 파이프 재생성 실패를 보고하지 않습니다.** 실패는 private 필드에만 남고 재시도는 `Idle`을 반환합니다. 초기 실패도 일반 빌드에서는 상세 원인을 버립니다. ADR 0052의 한 번 보고한다는 계약을 지키지 않습니다. | 첫 실패·원인 변경·복구를 고정된 단계와 오류 코드로 보고하십시오. 250ms 재시도마다 같은 로그를 쓰지는 마십시오. |
| TD-12 | NEW | Architectural decay | `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/ApplicationPolicyActor.kt:54` | Medium | M | **정책 액터가 페어링 작업의 수명 관리까지 직접 담당합니다.** 취소됐지만 아직 종료되지 않은 ceremony의 polling 예산·콜백·핸들 보존·전체 종료 조건이 여러 구간에 흩어져 있습니다. 실행 결함을 입증한 항목은 아닙니다. | 기존 단일 worker와 controller 소유권 안에서 페어링 상태·poll·정리를 모으는 후보입니다. 없는 구조 보고서의 Fine as is를 확인하기 전에는 추출 결정을 확정하지 마십시오. |
| TD-13 | NEW | Documentation drift | `crates/windows-prompt-probe/README.md:3` | Medium | S | **실제 버튼을 누르는 크레이트를 읽기 전용으로 설명합니다.** watch 모드는 서비스의 `Apply`를 받아 UIA `Invoke`를 실행하지만 문서는 승인 어댑터와 Invoke가 없다고 합니다. 보안 검토에서 적용 기능을 빠뜨릴 수 있습니다. | `probe_once`의 읽기 전용 계약과 watch의 인증된 입력·대상 재검사·단일 Invoke·결과 관찰 계약을 구분하십시오. |
| TD-14 | NEW | Documentation drift | `crates/windows-service-host/README.md:234` | Medium | S | **서비스 README의 Restricted SID 요구가 구현과 반대입니다.** 문서대로 등록을 바꾸면 현재 제어 코드는 `ConfigurationConflict`를 반환합니다. | ADR 0028에 맞춰 Unrestricted SID와 일반 활성 그룹 검사를 설명하십시오. 유지되는 ACL·설치 파일 검증은 그대로 명시하십시오. |
| TD-15 | NEW | Documentation drift | `crates/android-bindings/README.md:5` | Medium | S | **폐기된 설정 전용 시작 계약과 ABI 7을 안내합니다.** 실제 ABI는 15이고 기존 요청 상태를 전체 복구합니다. 문서대로 연결하면 정상 체크포인트를 거부하거나 호환성 검사를 잘못 구현합니다. | ABI 15와 전체 복구 절차를 적고 설정 전용 제한은 폐기된 과거 계약으로 구분하십시오. |
| TD-16 | NEW | Documentation drift | `crates/controller-runtime/README.md:50` | Medium | S | **동작하는 관리 기능을 미구현으로, 스냅샷을 schema 1로 설명합니다.** Windows의 페어링·기기 삭제·기록 조회는 구현됐고 schema 4를 반환합니다. | API 표와 capability 조건을 현재 코드에 맞추십시오. 여전히 사용 불가인 `decide`와 `clear_activity`는 구분해야 합니다. |
| TD-17 | NEW | Documentation drift | `crates/service-protocol/README.md:17` | Medium | S | **리스 갱신 메시지와 새 시간 대응 계약이 빠져 있습니다.** 문서대로 만든 디코더는 정상 `Renewed` kind 4를 거부하고, 최초 시간 대응을 계속 쓰는 어댑터는 새 리스를 옛 만료에 묶습니다. | 이전·새 binding과 발급 시각, 같은 요청을 유지하는 조건을 문서화하십시오. 단순 재전송과 서명된 리스 갱신을 구분하십시오. |
| TD-18 | NEW | Documentation drift | `CONTEXT.md:79` | Medium | S | **도메인 문서가 실제 승인 연결을 미구현으로 안내합니다.** 코드에서는 페어링·중계·감시를 활성화하고 검증된 결정을 실제 창에 적용합니다. 후속 설계와 감사가 잘못된 전제로 시작하게 됩니다. | 현재 구현 범위를 수정하고, 구현 여부·과거 실기 증거·이번 버전에서 재검증하지 않은 항목을 구분하십시오. |
| TD-19 | NEW | Consistency / Architecture | `ui/src/useController.ts:250`, `ui/src/useController.ts:351` | Low | S | **늦은 조회·명령 완료가 숨긴 화면에 요청 본문을 복원합니다.** 일반 조회는 가시성을 보지 않고, 설정 열기는 시작 때의 `previous`를 복원합니다. 표시 기한이나 주기적 철회 전까지 본문이 다시 남습니다. | 새 스냅샷 게시에는 숨김 검사를 공통 적용하고, 결과만 갱신하는 완료 처리는 현재 상태를 사용하십시오. 대기 중 화면 숨김 회귀 테스트를 추가하십시오. |
| TD-20 | NEW | Consistency rot | `ui/src/useController.ts:434` | Low | S | **앱을 떠났다가 돌아오면 대기 중인 결정 의도가 살아납니다.** 조회 중 거부를 누르고 떠났다가 조회 완료 전에 돌아오면 완료 순간의 가시성 검사만 통과해 이전 거부를 전송합니다. ADR 0048의 취소 계약과 다릅니다. | 별도의 표시 세대나 취소 표식을 두고 모든 대기 뒤에 확인하십시오. 기존 `revision`을 올려 `readPending` 해제를 방해하는 방식은 피하십시오. |
| TD-21 | NEW | Architectural decay | `crates/windows-service-host/src/peer_runtime.rs:852` | Low | S | **응답 큐와 완료 대기열 갱신을 네 곳에서 반복합니다.** 현재 순서는 일치하지만 번호 할당·전송·실패 처리·FIFO 기록을 함께 바꿔야 하며, 한 곳이 어긋나면 정상 연결도 거부됩니다. | 비공개 enqueue 함수로 해당 묶음만 통합하십시오. 메시지별 서명·재검증·기한 검사와 후속 상태 갱신은 호출부에 남기십시오. |
| TD-22 | NEW | Type / Consistency | `crates/android-controller/src/peer_associations.rs:475` | Low | S | **중계 주소 검증이 저장할 수 없는 IPv6 정보를 허용합니다.** 신뢰된 Rust 호출자가 nonzero scope ID·flowinfo를 주면 생성은 성공하지만 저장·복원 뒤 0이 됩니다. 일반 QR 입력은 앞단에서 거부합니다. | 초대장의 표현 형식 제한과 맞추고, 비정규 주소 거부 및 허용 주소의 저장·복원 동등성을 검사하십시오. 저장 형식을 확장할 필요는 없습니다. |
| TD-23 | NEW | Type and contract | `crates/direct-network/src/igd/http.rs:170` | Low | S | **chunked HTTP 응답의 완료를 수신 루프가 판단하지 못합니다.** 공유기가 `Connection: close`를 무시하고 완전한 chunked 응답 뒤 연결을 유지하면 다음 read를 기다리다 제한 시간에 실패합니다. 디코더는 해당 형식을 지원합니다. | 완료·미완료·잘못된 framing을 구분하고 마지막 청크 뒤 EOF 없이 반환하십시오. 크기 제한과 중복 헤더 거부를 유지하십시오. |
| TD-24 | NEW | Test debt | `crates/windows-service-host/build.rs:59` | Low | S | **Android 서명자 설정 파서의 두 테스트가 Cargo 테스트 대상에 없습니다.** `build.rs`의 `cfg(test)` 안에만 있어 일반 테스트에서 수집·타입 검사되지 않습니다. | 파서를 공유 소스 모듈로 분리해 일반 테스트 대상에서도 포함하거나 명시적인 테스트 대상을 두십시오. |
| TD-25 | NEW | Test debt | `crates/windows-port-owner/tests/listener.rs:33` | Low | S | **자식 리스너 테스트가 해제한 포트를 다시 쓸 수 있다고 가정합니다.** 부모의 close와 자식의 bind 사이에 다른 프로세스가 포트를 잡으면 정상 코드도 테스트에 실패합니다. 실제 실패 이력은 확인하지 않았습니다. | 자식이 포트 0에 직접 바인딩하고 확보한 주소를 부모에게 알리게 하십시오. 기존 자식 수명 제한과 정리는 유지하십시오. |
| TD-26 | NEW | Test debt | `ui/src/RequestIntake.test.tsx:305` | Low | S | **표시 유효기간 테스트가 실제 실행 지연에 영향을 받습니다.** 1,500ms 리스에서 조기 조회 뒤 실제로 700ms를 더 기다리므로 추가 지연이 남은 여유를 넘으면 정상 만료 때문에 실패합니다. | 타이머와 `performance`를 함께 제어하고 조기 조회와 실제 만료를 따로 검사하십시오. |
| TD-27 | NEW | Dependency and config | `src-tauri/gen/android/app/build.gradle.kts:110` | Low | S | **Gradle이 Cargo 입력을 불완전하게 다시 나열합니다.** 로컬 증분 빌드에서 Rust 환경 옵션이나 누락된 설정·생성기 manifest만 바뀌면 Cargo 실행을 건너뛰고 이전 `.so`를 사용할 수 있습니다. 새 CI 러너의 재현된 실패는 아닙니다. | Exec를 항상 실행해 Cargo가 판단하게 하거나, 빠진 입력을 명시하십시오. 환경·설정만 바꾼 두 번째 빌드를 검증 대상으로 삼으십시오. |
| TD-28 | NEW | Dependency and config | `.github/workflows/windows-installer-options.yml:40` | Low | S | **수동 설치본 재검사가 현재 생산 실행을 모두 거부합니다.** 옛 브랜치의 push만 허용하지만 현재 생산 워크플로는 PR·dispatch로 실행됩니다. 일반 패키지 작업에는 같은 검사가 남아 있습니다. | 중복 수동 워크플로의 유지 여부를 정하십시오. 유지한다면 현재 신뢰 가능한 생산 실행과 검증 조건을 맞추되, 폐기된 push 트리거를 되살리지는 마십시오. |
| TD-29 | NEW | Dependency and config | `.github/workflows/release.yml:315` | Low | S | **게시 작업만 저장소의 Node 버전 고정을 적용하지 않습니다.** 별도 runner에서 두 Node 스크립트를 실행하면서 setup-node가 없어 이미지 기본 런타임을 사용합니다. 현재 실패를 관찰한 것은 아닙니다. | 같은 워크플로의 기존 SHA 고정 setup-node와 `.node-version`을 게시 작업에도 적용하십시오. |
| TD-30 | NEW | Performance and resources | `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/LanServiceDiscovery.kt:109` | Low | S | **해제 대기 중인 DNS-SD 콜백이 등록 상한에서 빠집니다.** 서비스 소실 때 `entries`에서 먼저 제거하므로 해제가 지연되거나 반복 실패하는 동안 새 등록이 들어옵니다. 정상 해제에서는 정리되며 무한 누적을 재현하지 않았습니다. | 활성 등록과 해제 대기 등록을 같은 상한에 포함하고, 해제 완료나 등록 부재가 확인된 뒤 슬롯을 반환하십시오. |
| TD-31 | NEW | Errors and observability | `crates/windows-service-host/src/peer_runtime/dialer.rs:273` | Low | S | **결과 큐가 가득 차면 성공한 연결을 버리고 재접속도 멈춥니다.** `delivered=true` 뒤 실패한 `try_send`를 무시하므로 소켓은 사라지고 release도 오지 않습니다. 큐 포화에는 서비스의 장시간 정체가 필요합니다. | 성공 결과를 전달한 뒤에만 delivered를 설정하십시오. Full에는 재시도를 예약하고 Disconnected를 구분하며, 소비하지 않는 실패 결과로 큐를 채우지 마십시오. |
| TD-32 | NEW | Security hygiene | `.github/workflows/release.yml:168` | Low | S | **릴리스 서명 단계가 저장소의 비밀정보 취급 관례와 다릅니다.** 비밀번호를 명령줄로 전달하고, 키 파일 생성 권한 제한과 실패 시 정리가 없습니다. 일회성 호스팅 runner 안의 문제이며 실제 유출은 확인하지 않았습니다. | 기존 실기 측정 워크플로처럼 `umask 077`, EXIT 정리, 환경변수 기반 비밀번호 인자를 사용하십시오. |
| TD-33 | NEW | Documentation drift | `docs/stable-release.md:26` | Low | S | **Windows 배포물도 서명한다고 안내합니다.** 실제 패키징은 서명 설정을 거부합니다. 사용자 README는 unsigned임을 정확히 안내하므로 유지보수 문서의 불일치입니다. | Android APK 서명과 Windows의 해시·페이로드 검사를 구분하고 Windows 코드 서명이 없음을 명시하십시오. |
| TD-34 | NEW | Documentation drift | `crates/approval-protocol/README.md:64` | Low | S | **문서가 실행 파일 경로를 필수라고 설명합니다.** 실제 생성자는 MSI·COM 상승·패키지 앱을 위해 빈 경로를 허용합니다. 문서대로 만든 별도 검증기는 정상 요청을 거부하게 됩니다. | 프로그램 이름만 필수이며 경로와 세부 내용은 비어도 된다고 수정하십시오. 없는 경로를 추정해 보충하지 않는다고 적으십시오. |
| TD-35 | NEW | Documentation drift | `crates/secure-channel/README.md:52` | Low | S | **TLS 문서가 ALPN v1만 허용한다고 안내합니다.** 현재 양쪽은 V3·V2·V1 순으로 제시하며 기능도 협상 결과에 따라 다릅니다. | 지원 순서와 `negotiated_protocol`, V2 이상 주소 교환·V3 대기 안내의 구분을 문서화하십시오. |
| TD-36 | NEW | Documentation drift | `docs/CI.md:227` | Low | S | **이미 존재하는 main 릴리스 자동화를 앞으로 할 일로 설명합니다.** 같은 문서의 현재 절차 및 실제 워크플로와 반대입니다. | 해당 절을 과거 기록으로 구분하거나 현재 절차와 실제 남은 검증 조건으로 교체하십시오. 새 파이프라인은 필요하지 않습니다. |
| TD-37 | NEW | Documentation drift | `crates/windows-service-host/README.md:35` | Low | S | **CLI 문서가 복구·중계·외부 연결 명령을 누락합니다.** 추가 인자를 조용히 버린다는 설명도 실제 `InvalidArguments` 거부와 다릅니다. | 현재 parse·help와 운영 명령 목록을 맞추고, 내부 페어링 진입점은 일반 운영 명령과 구분하십시오. |
| TD-38 | NEW | Architectural decay | `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/ApplicationPolicyActor.kt:486` | Low | S | **작업 큐 등록과 후처리 코드가 세 번 반복됩니다.** **added in synthesis**. 486·491·496행의 함수는 작업 실행, `resumeQueuedWork`, `cleanupIfStopped`, 제출 거부 처리가 같습니다. 공통 정리 규칙을 바꿀 때 세 곳을 함께 수정해야 합니다. 현재 동작 불일치는 없습니다. | 기존 함수 이름과 호출 계약은 유지하고 공통 비공개 구현에 위임하십시오. worker·큐·정리 순서는 바꾸지 마십시오. |

### 중복과 합성 보충

- 구조 차원의 숨김 본문 복원과 일관성 차원의 늦은 스냅샷 복원을 **TD-19**로 합쳤습니다.
- 일관성과 타입 차원의 IPv6 저장·복원 불일치를 **TD-22**로 합쳤습니다.
- 판정자가 추가로 지적한 동일 enqueue 구현을 직접 대조해 **TD-38**로 추가했습니다.
- 다음은 **added in synthesis**인 보충 근거입니다. 같은 결함의 추가 위치이므로 별도 행으로 세지 않았습니다.
  - **TD-02** — `crates/windows-service-host/src/runtime.rs:520`, `crates/windows-service-host/src/runtime.rs:527`의 연속 append도 같은 동기식 전체 파일 쓰기를 수행합니다.
  - **TD-06** — `crates/windows-service-host/src/runtime.rs:425`의 감시 오류도 `WorkerFailed`로 축약됩니다.
  - **TD-09** — `crates/windows-service-host/src/peer_runtime/dialer.rs:317`에서는 접속 오류가 `None`이 됩니다. 연결 스레드 panic은 `crates/windows-service-host/src/peer_runtime.rs:2538`의 `io_failed`에 합쳐져 종료 때 원인을 구별하지 못합니다.
  - **TD-15** — `crates/android-controller/README.md:228`도 전체 복구 함수가 Application 시작에 연결되지 않았다고 설명하지만, `crates/android-bindings/src/lib.rs:639`에서 호출합니다.
  - **TD-19** — `ui/src/useController.ts:344`, `ui/src/useController.ts:403`도 가시성 확인 없이 새 스냅샷을 게시합니다.
- 의존성 판정자의 CI 문서 지적은 **TD-36**과 중복입니다.

### Not judged

| 차원 | 항목 수 |
|---|---:|
| 없음. 제공된 9개 차원 모두 판정이 있습니다. | 0 |

## Top 5: 다른 것을 고치지 않더라도 우선할 항목

아래는 변경안과 후속 검증 조건입니다. 구현하거나 실행하지 않았습니다.

### 1. TD-01 — 승인 코디네이터의 재시도·정리 회귀 테스트

대상은 `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/ApplicationApprovalCoordinator.kt:295`의 `finish`, 328행의 `work`, 402행의 `cleanup`입니다.

1. 기존 `owner`·`enqueue` 주입 방식에 맞춰 예약·시계·네이티브 호출을 테스트에서 제어할 수 있게 하십시오. 새로운 controller나 executor, 공개 서명 API를 만들지 않습니다.
2. 실제 `finish → work의 Busy 재예약 → finish → cleanup`을 실행합니다. `finishApproval`이 한 번 Busy를 반환한 뒤 **같은 DER 바이트**를 다시 받는지, 인증과 서명이 각각 한 번만 실행됐는지 단언합니다.
3. `retireApproval`의 Busy와 wrapper close 실패를 따로 만듭니다. 전자는 정리 실패 예산을 소비하지 않아야 하고, 후자는 성공한 close를 반복하지 않고 실패한 단계부터 재개해야 합니다.
4. PREPARING 전후 만료와 cleanup 실패 후 만료를 검사합니다. 정리 완료 뒤 `canRequest`가 다음 요청을 받아야 하며 완료되지 않은 의무가 있으면 슬롯을 유지해야 합니다.

현재 코드는 `Application`, main `Handler`, 실제 `MainActivity`, 생성 UniFFI 핸들에 직접 의존합니다. 기존 JUnit 정책 테스트 하나를 늘리는 S 규모가 아니므로 **L**을 유지했습니다. 구조 보고서가 없는 만큼 대규모 추출을 전제하지 않습니다.

### 2. TD-02 — 승인 처리에서 활동 기록 I/O 분리

근거는 `crates/activity-journal/src/lib.rs:15`의 실행 계약, 129행의 `recent`, `crates/activity-journal/src/storage.rs:120`의 쓰기·동기화입니다.

1. 현재 `Journal` 하나를 제한된 기록 작업자가 소유하게 합니다. 서비스의 매초 조회와 모든 append·purge가 같은 작업자를 거치도록 하며, 두 번째 writer를 만들지 않습니다.
2. 서비스 반복 처리에서는 완료된 최근 목록만 받아 `observe_activity`에 전달합니다. 느린 저장소를 기다리느라 감시와 결정 처리가 멈추지 않게 합니다.
3. 매초의 무조건적인 전체 파일 조회를 없애는 변경은 별도로 검토합니다. 실제 조회·추가·만료 정리에 맞춰 갱신하되, 영속적인 시각 고수위와 재시작 후 만료된 기록이 다시 나타나지 않는 계약을 먼저 검사해야 합니다.
4. 종료 때 기록 작업자의 실제 완료와 디렉터리 핸들 수명을 유지합니다. 큐 포화·저장 실패로 승인 처리를 종료하지 않고, ADR 0052의 제한된 실패 보고를 보존합니다.

지연된 저장소, 큐 포화, 시계 역행, 종료 중 기록을 후속 테스트에 포함해야 합니다. 이번 감사에서는 쓰기량이나 승인 지연을 측정하지 않았습니다.

### 3. TD-03 — 재검증 한 번 안의 반복 조회 제거

대상은 `crates/windows-service-host/src/peer_runtime.rs:2480`과 `crates/windows-service-host/src/trust_registry.rs:91`입니다.

1. `revalidate_peers`가 방금 확인한 체크포인트를 버리지 않고 해당 호출 안에서 사용하게 합니다.
2. 기존 등록 정보 객체에서 여러 기기의 transport binding을 한 번의 검증된 내부 조회로 얻도록 합니다. `binding`이 기기마다 전체 체크포인트를 다시 만들게 두지 않습니다.
3. `crates/windows-service-host/src/peer_runtime.rs:1663`, `crates/windows-service-host/src/peer_runtime.rs:1671`의 **키 작업 전후 두 검증은 그대로 유지**합니다. 서비스 토큰 확인을 영구 캐시하거나 검증 결과를 권한 증표로 넘기지 않습니다.
4. 연결 0·1·32개에서 체크포인트 생성·신원 조회 횟수를 검사하고, 서명 전후 등록 변경과 적용 직전 연결 종료가 계속 거부되는지 확인합니다.

현재 횟수는 소스에서 계산한 값입니다. 초당 호출 수나 절감 효과를 실측 결과로 제시하지 않습니다.

### 4. TD-04 — 서명된 결정의 거부 원인 기록

수정 범위는 `crates/windows-service-host/src/runtime.rs:500`의 match와 `crates/windows-service-host/src/public_diagnostics.rs:18`의 고정 진단 형식입니다.

1. `SessionProgress::DecisionRejected(error)`를 명시적으로 처리합니다.
2. `crates/approval-core/src/lib.rs:717`의 `DecisionError`를 빠짐없이 고정 분류로 변환합니다. 원시 Display·Debug 문자열은 쓰지 않습니다.
3. 기존 기록 실패 보고와 같은 방식으로 오류 종류별 빈도를 제한합니다. 요청 ID, 기기 ID, 서명, 본문은 전달하지 않습니다.
4. 만료·binding 불일치·서명 불일치가 서로 다른 진단을 만들고, 반복 거부가 로그를 채우지 않으며, 거부된 결정이 Windows 적용에 도달하지 않는지 검사합니다.

연결을 종료하는 현재 정책과 승인 판단 자체는 바꾸지 않습니다.

### 5. TD-05 — 작업 표시줄 대기 제한을 사용자 문서에 반영

수정 대상은 `README.md:13`, `README.md:59`, `README.md:115`입니다.

1. 백그라운드 프로그램의 상승 요청이 작업 표시줄에서 대기할 수 있음을 지원 제한에 넣습니다.
2. 휴대폰의 대기 안내와 실제 승인 요청을 구분합니다. 대기 안내에는 승인·거부 기능이 없습니다.
3. 이 상태에서는 PC에서 작업 표시줄의 권한 요청을 직접 눌러야 한다고 안내합니다.
4. `docs/adr/0051-a-parked-uac-prompt-is-reported-not-approved.md:28`의 실패한 활성화 시도를 해결책처럼 제시하지 않습니다. 새로운 원격 활성화 방법이나 현재 버전의 실기 성공을 주장하지 않습니다.

## Quick wins

S 규모이면서 Medium 이상인 항목입니다.

- [ ] **TD-04** 서명된 결정의 거부 원인 기록
- [ ] **TD-05** 작업 표시줄 대기 제한 안내
- [ ] **TD-06** 서비스 종료 원인과 잡힌 panic 구분
- [ ] **TD-07** 키 저장소 오류·롤백 진단 보존
- [ ] **TD-08** 내장 중계 종료 결과 보존
- [ ] **TD-11** 관리 파이프 재생성 실패 보고
- [ ] **TD-13** 읽기 전용 probe와 실제 적용 watch 문서 구분
- [ ] **TD-14** 서비스 SID 문서 수정
- [ ] **TD-15** Android ABI·전체 복구 문서 수정
- [ ] **TD-16** 표시 스키마·관리 API 문서 수정
- [ ] **TD-17** 리스 갱신 와이어 계약 문서화
- [ ] **TD-18** 도메인 문서의 현재 구현 범위 수정

## Looks bad but is fine

| 대상 | 잘못된 것으로 판단하지 않은 이유와 근거 |
|---|---|
| **recorded_decision** — `crates/relay-service/tests/deadlines.rs:165` | 짧은 실제 시간 제한은 의도된 선택입니다. 같은 파일 2행은 실제 loopback·실제 Tokio 기한을 검사한다고 명시합니다. `.github/workflows/quality.yml:123`은 기한을 유지하면서 테스트 경쟁을 제한합니다. 가짜 시간으로 바꾸라는 원 발견은 부채 집계에서 제외했습니다. |
| `crates/windows-service-host/src/peer_runtime.rs:513` | 큰 `ServiceSession`이 등록 정보·엔진·키 작업자를 함께 소유하는 것은 수명 계약입니다. `docs/adr/0018-service-session-and-clock-ingress.md:9`와 35행은 단일 소유 및 실제 I/O 회수 후 해제를 정합니다. 파일 크기만으로 독립 서비스로 나누지 않습니다. |
| `crates/android-bindings/src/lib.rs:797`, `crates/android-bindings/src/lib.rs:819` | 즉시 Busy와 제한된 대기의 차이는 의도적입니다. `docs/adr/0048-a-busy-owner-does-not-cost-a-decision.md:48`은 결정 처리만 기다리게 하고 reactor·재진입 콜백은 즉시 거부하도록 정합니다. |
| `src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/AndroidNativePlatform.kt:454` | 화면에서 키 오류를 같은 사용 불가 상태로 표현하는 것은 `docs/adr/0008-phone-local-key-lifecycle.md:74`의 결정입니다. TD-07은 화면 오류를 세분화하라는 항목이 아니라 내부 진단 원인 소실을 지적합니다. |
| `crates/windows-service-host/src/runtime.rs:175` | 실행 중 활동 기록 쓰기 실패 때문에 서비스를 멈추지 않는 것은 `docs/adr/0052-one-peer-or-one-ceremony-does-not-stop-the-service.md:67`의 결정입니다. 권한 저장소까지 같은 방식으로 복구하는 것은 허용하지 않습니다. |
| `crates/windows-service-host/src/native.rs:734` | Unrestricted 서비스 SID는 빠뜨린 보호 설정이 아닙니다. `docs/adr/0028-unrestricted-service-sid-for-key-storage.md:35`는 키 저장을 위해 이를 채택하고 유지되는 ACL·신원 검사를 기록합니다. TD-14는 낡은 README만 다룹니다. |
| `crates/windows-service-host/src/peer_runtime.rs:1103` | Approved가 상승한 프로그램의 실행 성공을 입증하지 않는 것은 의도된 의미입니다. `docs/adr/0040-what-a-recorded-prompt-result-means.md:8`은 버튼을 누른 뒤 대상 창이 사라진 관찰로 정의합니다. |
| `Cargo.toml:63` | 릴리스의 심벌 테이블 보존은 UniFFI 생성기가 메타데이터를 읽기 위해 필요합니다. 해당 위치에 `strip = true`로 실제 생성이 실패한 이유가 기록되어 있습니다. |
| `crates/windows-service-host/src/public_diagnostics.rs:244` | 진단 파일의 잠금 경쟁·I/O 실패에서 해당 진단만 버리는 것은 명시된 비차단 계약입니다. 진단 쓰기 실패를 서비스 실패로 바꾸지 않습니다. |

## Open questions for the maintainer

다음은 집계하지 않았습니다. 판정자의 `missed` 중 직접 확정하지 않은 사항과 원 독자의 미해결 질문입니다.

1. **구조 감사의 보존 대상은 무엇입니까?**  
   `ARCHITECTURE_AUDIT.md`가 필요합니다. 판정자가 추가 지적한 큰 파일인 `crates/windows-service-host/src/peer_runtime/pairing.rs:1`, `crates/android-bindings/src/connectivity.rs:1`, `crates/android-bindings/src/lib.rs:1`, `src-tauri/src/mobile.rs:1`과 `ui/src/useController.ts:283`은 크기만으로 별도 결함을 만들지 않았습니다. 단일 소유권 안의 내부 정리가 이전 검토의 보존 결정과 양립하는지 확인해야 합니다.

2. **RetainedRequest 정리를 연기한 결정을 유지합니까?**  
   `.superloopy/evidence/20260919-finalization/architecture-candidates.md:30`에 기록된 연기와 `crates/phone-request-core/src/inbox.rs:49`의 현재 상태 표현을 재검토할 시점인지 확인이 필요합니다.

3. **Android의 controller-runtime 의존은 장기적인 패키지 구분입니까?**  
   `crates/android-bindings/Cargo.toml:25`의 의존은 정책 코덱 재사용에 쓰입니다. Windows 표시·직접 네트워크 코드까지 포함하는 패키지 의존을 계속 유지할지는 이번 합성에서 판단하지 않았습니다.

4. **주소 검증에서 공통인 표현 규칙과 용도별 정책을 어디서 구분합니까?**  
   판정자는 `crates/service-protocol/src/address.rs:255`, `crates/android-controller/src/routing_candidates.rs:140`, `crates/windows-service-host/src/contract.rs:285`, `crates/windows-service-host/src/trust_registry/model.rs:338`, `crates/service-protocol/src/pairing/invitation.rs:73`, `crates/controller-runtime/src/runtime.rs:1149`의 중복과 차이를 지적했습니다. loopback·link-local·unspecified 허용 여부까지 무조건 통합해서는 안 됩니다.

5. **RelayEndpoint는 검증된 값입니까, 이후 검증할 원시 좌표입니까?**  
   `crates/android-controller/src/peer_associations.rs:47`의 공개 필드로 생성자 검증을 건너뛸 수 있습니다. 이후 descriptor·저장 검증은 남아 있습니다. 이 타입 자체가 유효성을 보장해야 하는지 확인하기 전에는 권한 우회나 별도 실행 결함으로 집계하지 않았습니다.

6. **helper의 overlapped I/O 오류가 종료를 보장합니까?**  
   `crates/windows-prompt-probe/src/ffi/pipe_client.rs:594`의 완료 처리와 `crates/windows-service-host/src/ffi/overlapped_pipe.rs:247`의 보존 정책이 다릅니다. `bWait=true` 호출의 모든 실패가 저장소 해제를 허용한다는 근거를 확인해야 합니다. 실패를 발생시켜 검증하지 않았습니다.

7. **프론트엔드와 네이티브의 동일 스키마 배포를 어디서 보장합니까?**  
   `ui/src/bridge.ts:5`는 반환값을 실행 중 검사하지 않고 `ui/src/contracts.ts:155`의 스키마를 신뢰합니다. 실제 버전 불일치를 관찰하지 않았으므로 결함으로 집계하지 않았습니다.

8. **다른 소스 정규식 검사는 어떤 동작 테스트를 보조합니까?**  
   `tools/android-diagnostic-export-contract.test.mjs:11` 등에도 정확한 소스 형태를 고정하는 검사가 많습니다. 소스 검사의 존재 자체는 결함이 아닙니다. 각 검사가 대신하지 못하는 동작 테스트가 있는지는 별도 대조가 필요합니다.

9. **Android 전체 빌드의 lockfile·의존성 바이트 정책은 무엇입니까?**  
   `.github/workflows/release.yml:131`의 Tauri 호출에서 내부 Cargo의 `--locked` 보장을 확인하지 않았습니다. `src-tauri/gen/android/build.gradle.kts:2`와 `src-tauri/gen/android/app/build.gradle.kts:71`의 Maven 의존성에 대해 전이 의존성과 배포 바이트까지 고정해야 하는지도 미확정입니다.

10. **액션 고정 표는 전체 목록입니까, 당시 조사 기록입니까?**  
    `docs/CI.md:180`에는 날짜가 붙은 일부 액션만 있습니다. 판정자가 지적한 `.github/workflows/android-release-startup.yml:88`, `.github/workflows/windows-installer-options.yml:41`의 버전 기록 누락을 현재 문서 결함으로 볼지는 표의 역할을 확인해야 합니다.

11. **PC의 25ms 유휴 주기와 Android의 다중 연결 비용을 측정했습니까?**  
    `crates/windows-service-host/src/runtime.rs:548`의 간격은 Android용 ADR 0015의 결정과 별개입니다. `crates/framed-transport/src/socket.rs:618`의 소켓 대기와 함께 CPU·배터리 비용을 측정한 자료는 이번 감사에서 확인하지 못했습니다.

12. **DNS-SD 해제 대기를 서비스 처리 스레드에서 수행하는 이유가 있습니까?**  
    `crates/windows-service-host/src/peer_runtime/lan_announce.rs:41`에서 기존 공지를 제거하면 `crates/windows-dns-sd/src/ffi.rs:197`의 제한된 대기가 실행됩니다. 네이티브 메모리 보존 이유와 별개로, 이 대기를 승인 처리의 지연 예산에 포함했는지 확인해야 합니다.

13. **Android Rust 로그의 평생 64줄 상한은 후속 치명적 오류의 소실까지 의도합니까?**  
    `crates/android-log-sink/src/lib.rs:27`의 초기 기록 보존 의도는 명시돼 있습니다. `crates/android-bindings/src/intake.rs:790`의 복구 가능한 실패가 예산을 먼저 소진한 뒤 발생하는 panic·치명적 오류를 구분할 수 있어야 하는지는 정책 질문입니다.

14. **ADR 상태는 구현 상태입니까, 특정 실기 검증 완료 상태입니까?**  
    판정자는 `docs/adr/0045-repair-from-a-protected-copy.md:4`의 proposed와 0019·0020·0022·0023의 ROOT validation pending을 지적했습니다. 구현이나 과거 승인 성공이 모든 해당 검증을 완료했다는 뜻은 아니므로 자동으로 문서 부채로 분류하지 않았습니다.

15. **프로토콜 README의 미완료 통합 목록은 누구의 남은 작업입니까?**  
    `crates/service-protocol/README.md:89`는 QR 등록·창 캡처·휴대폰 정책 처리를 미완료로 나열합니다. 크레이트 자체의 비책임 범위를 설명하려는 것인지, 제품 상태를 설명하려는 것인지 명확히 해야 합니다. TD-17의 실제 와이어 계약 누락과는 구분했습니다.

16. **날짜가 있는 인수인계 문서는 현재 상태의 기준입니까?**  
    `docs/DEVELOPMENT_STATUS.md:1`과 최신 상태를 그 문서로 안내하는 `docs/PROGRESS.md:297`의 관계를 확인해야 합니다. 보존용 기록이라면 과거 내용을 지우기보다 안내 링크의 역할을 바로잡아야 합니다.

17. **Windows 게시자 서명은 아직 유효한 향후 출시 조건입니까?**  
    `docs/packaging-windows.md:254`의 조건과 현재 unsigned 배포를 어떻게 구분할지 확인이 필요합니다. TD-33은 현재 산출물을 서명됐다고 설명하는 문장만 다루며, 향후 출시 조건을 폐기하라고 권하지 않습니다.

## 수행·검증 결과

- 종합 단계의 파일 생성·수정·삭제는 **0건**입니다.
- 읽기 전용 `git log`로 위 커밋을 확인했습니다.
- 시작·종료 시 `git diff --stat HEAD` 출력은 비어 있었습니다.
- 빌드·lint·테스트·커버리지·설치·실기·성능 검증은 **실행하지 않았습니다**.
- 종합 시점에 아키텍처 보고서가 파일로 없었으므로 **Fine as is 준수 여부는 검증하지 못했습니다**.
