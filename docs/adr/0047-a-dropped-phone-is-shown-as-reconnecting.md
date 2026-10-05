<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0047: The PC shows a dropped phone as reconnecting

Status: implemented source with unit and gallery coverage. Not yet seen on a
real PC while the phone drops and comes back.

## Evidence

The user reported on 2026-10-05 that the PC app flips to "휴대폰 연결 안 됨"
from time to time and back. The phone already covers the same kind of drop
with a waiting row ("PC에 다시 연결하는 중", 60 s, `pcConnection.ts`), but the
PC only held "휴대폰 연결됨" for 10 s (`useConnectionDisplay`). Any drop longer
than that showed the red state, the relay line and the firewall paragraph, and
they disappeared again when the phone came back.

A four-minute sample of established connections on port 7443 the same
afternoon, at about 2 s intervals, saw one phone connection that never
dropped. The cadence of the reported drops is therefore not measured.

## Decision

`useConnectionDisplay` returns `connected`, `reconnecting` or `disconnected`
(or null when unknown). A phone observed connected and then missing, under the
same paired-device identity, is `reconnecting` until one deadline 60 s after
the first missing sample, the phone's own `RECONNECT_GRACE_MS`. Later samples
do not move the deadline, and recovery returns to `connected` at once.

While reconnecting, the status card shows a spinner with "휴대폰에 다시 연결하는
중" and none of the failure guidance (relay line, direct-connection guidance,
firewall paragraph). The paired-phones list shows "다시 연결하는 중" in the same
slot. After the deadline the existing "연결 안 됨" state and its guidance
appear.

The earlier 10 s hold showed "연결됨" for a phone that was not connected; the
reconnecting row states what is known instead.

A view that opens while the phone is already missing says "연결 안 됨" at once.
The phone's 60 s "connecting" row for a PC never seen in the session is not
ported: the PC has no dial of its own to wait for, and a phone that has not
connected since the app opened may have been away for hours.

The state is display only. Request admission, signing and commands still read
the raw snapshot.
