# 휴대폰 승인 {{VERSION}} 프리릴리즈

이 판은 시험용 프리릴리즈입니다. 설치 파일과 APK를 만들었을 뿐, 실제 PC와 휴대폰에서
원격 승인이 동작했다는 증거는 아닙니다. 아래 표의 각 항목은 이 판에서 실제로 어디까지
검증했는지를 적은 것입니다.

## 내려받기

| 파일 | 용도 |
| --- | --- |
| `uac-remote-controller-windows-x64-setup.exe` | Windows 11 x64 설치 파일. 설치 때 관리자 확인이 한 번 필요합니다. |
| `uac-remote-controller-android-arm64.apk` | Android 11(API 30) 이상, arm64 휴대폰용 앱. |
| `uac-relay-windows-x64.exe`, `uac-relay-linux-x64` | 중계 서버. 같은 Wi-Fi에서 시험할 때는 PC에서, 4G/LTE로 시험할 때는 공개 주소가 있는 서버에서 실행합니다. |
| `SHA256SUMS.txt` | 위 파일들의 SHA-256. |

## 서명

- Android APK 서명 인증서 SHA-256: `{{SIGNER_SHA256}}` (출처: {{SIGNER_SOURCE}})
- Windows 설치 파일과 실행 파일은 코드 서명이 없습니다. SmartScreen 경고가 표시됩니다.

`ephemeral-this-run-only`라고 적혀 있으면 이 판을 만들 때 임시로 만든 서명 키입니다. 다음 판은
다른 키로 서명되므로 그대로 덮어 설치할 수 없고, 앱을 지운 뒤 설치해야 합니다.

## 검증 상태

{{CAPABILITY_TABLE}}

## 시작하기

1. Windows에 설치 파일을 실행하고 관리자 확인을 승인합니다. 설치가 끝나면 서비스가 부팅 때
   자동으로 시작되도록 등록됩니다.
2. 중계 서버를 실행합니다. 같은 Wi-Fi에서 시험하려면 PC에서 `uac-relay-windows-x64.exe --listen 0.0.0.0:7443`을
   실행하고, PC의 IP 주소를 확인합니다.
3. 관리자 권한 명령 프롬프트에서 `"C:\Program Files\휴대폰 승인\uac-service.exe" relay <IP>:7443`으로
   중계 서버 주소를 등록합니다.
4. 휴대폰에 APK를 설치하고 화면 잠금(PIN, 패턴, 비밀번호, 생체)을 설정합니다.
5. PC의 휴대폰 승인 앱에서 [휴대폰 연결]을 누르면 관리자 확인 뒤 QR이 보호된 화면에 표시됩니다.
   휴대폰 앱에서 [PC 연결 QR 읽기]로 QR을 읽고, 양쪽에 표시된 여섯 자리 숫자가 같은지 확인한 뒤
   양쪽에서 확인을 누릅니다.

## 체크섬

```text
{{SHA256SUMS}}
```

빌드 커밋: `{{COMMIT}}`
