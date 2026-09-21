# Final alpha.2 APK physical installation and recovery

Source: a1c5ae8d925486d13964cb3b38966d4979f39324 (v1.2.0-alpha.2).
Artifact: release-android-1.2.0-alpha.2 from release run35610136489, Android job
106367008860. Publication was still pending when this device check ran.

- APK SHA256:730dd43040bc9d9b8cee75253833ca266f736863147d9743edaa22ddd0245a68
- Signer SHA256:c975b78a34dd622d19c4af329e4f71bfa895693ff04db5116aa718fd9aa20c22
- CI signer source:repository-secret. ROOT's local SDK36 apksigner verification
  and file-hash comparison passed before installation.
- Ordinary adb install -r succeeded on the same physical SM-S948N,
  Android16/API36, WebView151.0.7922.202. No -g, downgrade, uninstall or key/data
  removal. versionName1.2.0-alpha.2, versionCode1002000.
- Before any explicit Activity launch, the replacement-installed service was
  attached/promoted, owner_phase=READY, reported_state=LOCAL_SETTINGS_READY,
  activation_state=ON, network callback_registered=true/reset_requests0.

ROOT repeated the bounded Wi-Fi trial on these exact final APK bytes. Original
Wi-Fi was enabled. After disabling and a2second observation wait: owner READY,
network reset_requests1. Wi-Fi was re-enabled in finally. After a3second
observation wait: wifi_on1, owner READY, network reset_requests2. Windows service
PID20508 remained Running/exit0 and had one Established TCP connection from the
paired phone LAN address. VPN and relay/pairing configuration were unchanged.
Both installation and the recovery script exited0.

This establishes same-signer in-place installation, automatic post-replacement
owner startup, actual default-network observation and TCP reconnection in this
configuration. It does not establish TLS/application readiness, mobile-WAN
approval, uninterrupted delivery or physical authentication latency. No new UAC
canary was sent after trial02; real user authentication readiness is still needed.

ROOT must compare this file hash with the actually published SHA256SUMS before
calling it the published artifact. The Windows installer was not executed on
the user's PC; its running measured service remains the installed1.0.0 version.

Publication follow-up: ROOT downloaded the published SHA256SUMS.txt after
release35610136489 attempt2 succeeded. The Android row matches these exact
installed bytes. Release published2026-09-21T14:38:03Z, non-draft prerelease.
