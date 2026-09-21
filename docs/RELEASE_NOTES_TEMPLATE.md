# UAC 원격 승인기 {{VERSION}}

## 이번 변경

{{CHANGES}}

## 설치

1. Windows 설치 파일을 실행하고 관리자 확인을 승인합니다.
2. Android APK는 기존 앱 위에 업데이트합니다. 앱 데이터를 지우거나 삭제한 뒤 설치할 필요는 없습니다.
3. 새 연결은 PC의 [휴대폰 관리]와 휴대폰의 [연결된 PC]에서 QR 또는 USB로 진행합니다.
4. 같은 네트워크에서는 PC의 내장 중계를 사용합니다. 외부 모바일망은 PC로 들어오는 경로나 별도 외부 중계가 필요합니다.

검증 결과와 기기별 확인 항목은 [이 버전의 검증 기록]({{VERIFICATION_URL}})에 정리했습니다. 같은 문서를 `release-verification.md` 파일로도 첨부합니다.

Android 서명 출처: `{{SIGNER_SOURCE}}`  
Android 서명 인증서 SHA-256: `{{SIGNER_SHA256}}`

## 체크섬

```text
{{SHA256SUMS}}
```

빌드 커밋: `{{COMMIT}}`
