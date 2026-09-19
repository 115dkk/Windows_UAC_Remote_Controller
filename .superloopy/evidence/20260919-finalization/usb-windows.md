# Windows USB public-invitation bootstrap — 2026-09-19

Status: implementation/static review complete; ROOT security audit, formatting, CI and physical compatibility checks pending. This worker ran no validation executables, tests, builds, lint or formatter.

## Approved integration

ROOT approved the existing authenticated Starter handoff seam, avoiding a second ad-hoc privileged pipe. `AppRuntime::begin_pairing_usb()` uses the same serialized service-readiness/admission path as QR; `PairingStarter::start_usb()` defaults to unavailable and Windows explicitly implements it. `PairingClient::into_usb_helper_launch()` is separate from the unchanged QR default.

The medium Starter opts into new fixed HelperLaunchedUsb frame kind 17. The service validates the original helper/renderer exactly as before. Once the canonical invitation exists, it sends RendererUsbInvitation (18) to the existing protected renderer and exactly one StarterUsbInvitation (19) to the original authenticated medium Starter. The Starter handoff rejects this frame for QR mode, helper role, wrong original pending ID, before binding, or after its first receipt. Invitation bytes are public bootstrap metadata, never authority.

The protected renderer displays USB waiting text and no QR modules/introduction. The native comparison screen, both local decisions, TLS pinning, attestation, signed frozen candidate, registry mutation and signed acceptance remain unchanged. In this first version the waiting screen is also on the existing protected desktop; there is no new desktop-switch or permission bypass.

## New reviewed boundary requiring independent audit

`crates/windows-service-host/src/ffi/usb_bootstrap.rs` owns all new WinUSB/SetupAPI FFI. The medium Starter spawns only the retained protected installation's `uac-service.exe usb-bootstrap`, hidden, with a bounded anonymous stdin pipe and discarded stdout/stderr. No invitation appears in arguments/files/logs. The child independently reuses `TokenFacts::observe`/Starter admission: exact medium integrity, no elevation or enabled Administrators group, non-SYSTEM interactive session, no UIAccess or AppContainer. USB APIs never execute inside SYSTEM/service or the elevated renderer.

Resource invariants: SetupAPI snapshots, registry key, file and WinUSB handles have one owner; WinUSB context frees before the underlying file; all buffers have fixed bounds/alignment and remain alive through synchronous calls. The child watchdog caps the whole process at 50 seconds, including stdin, registry/SetupAPI, control endpoint and bulk calls. Re-enumeration is separately capped at 20 seconds; bulk OUT timeout is 15 seconds. Cancellation kills only this retained owned unprivileged child; cleanup retains the original pairing owner until its exit is observed.

Enumeration reads present USB devices with the already-installed WinUSB service and their driver-declared DeviceInterfaceGUIDs. MTP-only devices without a compatible driver fail closed. There is no driver install/replacement, ADB client, associated-interface access, HID, arbitrary URL/path/command, or device payload upload. Exactly one enumerated interface is required both before and after AOA switching; multiple candidates fail rather than picking the first or broadcasting. Initial capability check is fixed vendor IN request 51, supported versions 1/2, then fixed strings via 52 and START 53. After re-enumeration only VID 18d1 PID 2d00/2d01, interface zero and exactly one bulk IN/one bulk OUT are accepted; only OUT carries the invitation.

AOA strings agreed with ROOT Android receiver: manufacturer `UAC Remote`, model `UAC Remote Approval`, version `1`, description `Public pairing invitation`. No URI/serial is supplied.

`usb_bootstrap_frame.rs` is unsafe-forbidden and crate-private. Exact frame: ASCII `UACUSB`, version byte 1, u16 big-endian canonical body length 345/357, canonical invitation bytes. Oversize, truncation, trailing bytes, wrong magic/version/length and invalid canonical invitation reject. Receiving these bytes does not introduce any authorization or signing API.

## Failure UX and source interfaces

- `PairingLaunchError::UsbUnavailable` maps to `PairingFailure::UsbUnavailable`, wire presentation failure `usb_unavailable`, issue `pairing_usb_unavailable`.
- Exact Korean message: `USB 연결을 사용할 수 없습니다. USB 드라이버와 케이블을 확인하거나 QR 코드로 연결하십시오.`
- Native source-copy keys: `USB 연결 대기`; `휴대폰에서 USB 연결을 허용하십시오. 연결 후 두 기기의 비교 코드를 확인하십시오.`
- ROOT owns locale translations, UI command/button/TS union, Android receiver and Android manifest.

## Verification plan and limitations

Existing `pairing_handoff` unit tests were extended with USB roundtrip/truncation/header/cross-shape checks and explicit original-Starter/role/mode/duplicate rejection. Canonical bootstrap encoding/decoding negatives share the real private codec; these are pure source-boundary tests, not USB/native proof. ROOT runs formatting, Clippy `-D warnings`, Rust Analyzer and exact-commit Windows/package/lab CI. Independent security reviewer must inspect the complete FFI and lifecycle boundary before release.

No physical Windows USB driver compatibility, AOA re-enumeration, Android accessory permission or end-to-end cable pairing has been executed here. Availability is intentionally limited to compatible already-installed WinUSB drivers; arbitrary MTP Android phones are not promised plug-and-play. Real phone acceptance remains a user trial. No cleanup or driver/config mutation was performed.

Primary references read for this implementation: [Android AOA 1.0](https://source.android.com/docs/core/interaction/accessories/aoa) (requests, IDs, metadata and separate ADB interface); [Microsoft WinUSB device communication](https://learn.microsoft.com/en-us/windows-hardware/drivers/usbcon/using-winusb-api-to-communicate-with-a-usb-device) (installed WinUSB interface enumeration and transfers). Native signatures were also inspected read-only in cached windows 0.62.2 generated bindings.
