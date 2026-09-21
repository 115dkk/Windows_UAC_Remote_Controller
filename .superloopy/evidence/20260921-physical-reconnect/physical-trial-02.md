# Physical measurement candidate and trial02

## Installed candidate

ROOT downloaded restricted workflow35607953359 artifact10642008386. The native
watch exited0; build job106359597926 succeeded in8minutes. Artifact source is
c48598a637eb7352687550c0de3a450ce57e0096, not later a1c5ae8 syntax correction.

- APK SHA256: f75f413a42fac6b91ecca8fea33ba500b4a77a67c050f29db9da24fe4a9c3304
- Signer SHA256: c975b78a34dd622d19c4af329e4f71bfa895693ff04db5116aa718fd9aa20c22
- ROOT locally verified APK cryptographic signature with SDK36 apksigner and
  compared the downloaded file hash and source commit to the CI outputs.
- Ordinary adb install -r returned Success on the one authorized physical
  SM-S948N. No -g, downgrade, uninstall, app-data deletion or key mutation.
- Installed versionName1.2.0-alpha.2, versionCode1002000. Foreground owner READY,
  attached/promoted true, network callback_registered true, reset_requests0.
- Physical OS subsequently read as Android16/API36; selected System WebView is
  com.google.android.webview151.0.7922.202.
- Ordinary am start opened the existing MainActivity, WARM55ms. This is app
  launch timing, not authentication latency. Phone remained Dozing.

## Actual Windows request

ROOT launched the fixed system cmd.exe /d /c exit0 canary once. User was asked
to unlock the phone, select approve and complete actual OS authentication.

- startedUnixMillis1789999225336
- requestElapsedMillis122367.2223
- requestToProcessExitMillis:null; processExitCode:null; requestErrorCode:null
- windowsOutcome:unconfirmed
- phoneVerifiedRecords0; windowsAppliedRecords0
- controlledRemotePathObserved:false
- Current app-process closed metric reader returned no decision samples.

Public Windows events: observed1789999226016, notification_sent1789999226024,
cancelled1789999231098, observed1789999231194,
notification_sent1789999231207, cancelled1789999346805. Windows service remained
Running, PID20508, exit0. No unrelated request data or private journal was read.

No physical authentication latency is derived. The whole122second wait includes
an unconfirmed request and human interaction opportunity; it is not a valid
authentication or network-performance sample. Further canaries await actual
user readiness instead of repeatedly generating unanswered prompts.

## Physical default-network recovery trial

On this same installed candidate, ROOT verified original wifi_on1, temporarily
disabled Wi-Fi, and restored it in finally. VPN and paired state were unchanged.
No UAC request was in progress during the network trial.

| Observation | Wi-Fi | Native owner | Network reset requests |
| --- | --- | --- | --- |
| Before | 1 | READY | 0 |
| After disable,2second observation wait | 0 | READY | 1 |
| After restore,3second observation wait | 1 | READY | 2 |

After restoration the Windows PID20508 had one Established TCP connection from
the paired phone LAN address and its two local relay legs. The script exited0,
wifi_enable_restored=true. These are real phone default-network callback and TCP
reconnection observations, not native TLS/application readiness, mobile-WAN UAC
approval, uninterrupted delivery, radio performance or authentication latency.
The configured private-LAN destination still requires a routable external path
for mobile data. No VPN/firewall/router/public-host setting was changed.
