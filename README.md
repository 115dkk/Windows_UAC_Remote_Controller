# Windows UAC Remote Controller

Windows에 표시되는 권한 요청을 연결된 Android 스마트폰에서 확인하고 승인·거절하는 프로그램을 준비하고 있습니다.

**2026-09-19, 실제 PC와 휴대폰에서 관리자 동의형 UAC의 원격 승인이 끝까지 동작했습니다.** 동의 창을 휴대폰에서 지문으로 승인하면 요청한 프로그램이 관리자 권한으로 실행됩니다. 아직 프리릴리즈입니다. 자격 증명형과 Windows Hello형 요청은 지원하지 않습니다.

Rust + Tauri를 우선 후보로 유지합니다. 자격 증명형은 스마트폰에서 Windows 요구대로 입력할 수 있는지 평가해 지원하고, 무리가 있는 유형은 무시합니다. 이미 SYSTEM/커널이 침해된 상황은 사용자 결정에 따라 위협 모델에서 제외합니다.

- [타당성 검토와 결정이 필요한 사항](docs/FEASIBILITY.md)
- [현재 구현과 최상위 검증 결과](docs/PROGRESS.md)
- [요구사항과 구현·검증 계획](docs/IMPLEMENTATION_PLAN.md)
- [초기 설계 보안 검토](docs/SECURITY_REVIEW.md)
- [라이선스 적용 고지](LICENSE-NOTICE.md)

`.node-version`의 Node로 `npm ci`를 실행한 뒤, 로컬 개발 검사는
`node tools/quality.mjs --extended`로 실행합니다. Android
Rust 대상 설치와 실제 기기 검증의 차이는 [CI 문서](docs/CI.md)를 참고하세요.

## 라이선스

SPDX-License-Identifier: GPL-2.0-or-later

This project is free software: you can redistribute it and/or modify it under
the terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or (at your option) any later version.

This project is distributed in the hope that it will be useful, but WITHOUT ANY
WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A
PARTICULAR PURPOSE. See [LICENSE](LICENSE) for the GNU General Public License,
version 2. Third-party material retains its own notices and license terms.
