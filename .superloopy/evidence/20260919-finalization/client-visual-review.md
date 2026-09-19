# ROOT client visual review

Source commit: a2c192fe01fc0ba456d966e59fb66e621331f432.
Actual downloaded CI artifact: `ui-gallery-ubuntu-24.04-a2c192fe01fc0ba456d966e59fb66e621331f432`
from run35443323057. Overall initial gallery failed four obsolete no-service-word
assertions;137/141 cases passed. Assertion update does not change rendered source.
Final exact-commit gallery still required.

ROOT opened actual PNGs, not just success logs:

- desktop-running-980 overview: existing rail/card geometry retained, title is
  UAC 원격 승인기, advertising subtitle removed, observed service and readiness
  remain distinct; controls visible with no clipping.
- phone-empty-390 overview: 승인 요청 없음 and enabled connected-PC navigation
  on this synthetic ready-catalog case; no repeated connect-PC prompt.
- phone-connection-setup-dark-390 connection-guidance: QR and USB actions both
  readable within the existing card; formal Korean copy, dark-theme contrast and
  wrapping preserved. Lower service actions remain in the established scroll area.
  This fixture intentionally has unavailable device inventory and its bottom
  unavailable label is expected, unlike the now-wired actual ready catalogue.

This is browser-rendered client evidence with explicit synthetic banners. It is
not Windows native UAC, Android accessory permission, hardware attestation, or
real paired-device connectivity evidence. User-reported real-device acceptance
is separately recorded in user-acceptance.md.
