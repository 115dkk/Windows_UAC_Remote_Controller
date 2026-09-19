# Android USB bootstrap

Implementation, awaiting ROOT CI and physical-device proof.

- Separate zero-payload `open_pairing_usb` uses the same originating physical
  WebView/Activity admission, service readiness and native modal ownership as QR.
- No camera permission is requested. Optional `android.hardware.usb.accessory`
  retains install support for phones without AOA. No boot activity/USB launch.
- A single native AOA accessory matching fixed manufacturer/model/version is
  selected. Discovery and permission/read have one 30-second monotonic bound.
  Permission broadcasts are wakeups only: query OS permission for the retained
  accessory. No supplied broadcast flag/accessory is authority.
- Worker reads full-size USB packets (16 KiB) and accepts one 354/366-byte frame:
  UACUSB + version1 + u16 big-endian canonical-body length345/357. Oversize,
  truncated, unknown-header frames fail. Original Rust invitation parser retains
  semantic/canonical checking; received body is encoded internally into the
  exact existing QR-carrier prefix and never enters JS, files or logs.
- Enrollment, phone attestation, TLS pinning, SAS and both confirmations reuse
  the same actor/ticket/ceremony. USB reception grants no trust or approval.
- Cancellation closes the permission registration and stops the worker. Polls
  are bounded at200ms. The original modal slot remains owned until descriptor,
  actor and actual window release are all observed. Late callbacks cannot bind
  to a replacement Activity or continue an expired/cancelled ticket.

Synthetic frame tests cover exact lengths, all header bytes, prefix truncation,
trailing bytes and invalid counts; client test covers explicit USB entry. Native
AOA/Windows driver interoperability and phone authentication are unverified.

References consulted: Android USB accessory overview and AOSP AOA protocol docs.
