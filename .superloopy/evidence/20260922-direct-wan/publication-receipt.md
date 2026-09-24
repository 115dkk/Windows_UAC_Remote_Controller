# v1.3.0 publication receipt

Date: 2026-09-23. Author: ROOT.

Verified after publication, against the bytes GitHub actually stores.

## What was checked

Tag `v1.3.0` at `422497aafe5200821fe4cb1b12775987bb0ee6a9`, published
2026-09-22T23:48:24Z, `prerelease=false`, marked latest.

Every entry in the published `SHA256SUMS.txt` matches the digest GitHub reports
for the corresponding stored asset. Four of four, no mismatches.

| asset | sha256 |
| --- | --- |
| `uac-remote-controller-windows-x64-setup.exe` | `63832fa3a20808982c8f7351af3bfeed4c33be3740eef72820f7e39720a7e9fe` |
| `uac-remote-controller-android-arm64.apk` | `9ddfea3e8a4566394087589b438aa7b311bea8b9c3369ab4262598544ab06cf7` |
| `uac-relay-windows-x64.exe` | `57164034185465a8b416090fa9958df181e32bc7a89ea6feb50ac2535c5eadb7` |
| `uac-relay-linux-x64` | `6fed223bf404344c2174cbe41a4673df17d908882309e989fd7b4ee0d7747e1f` |

The Android signer source is `repository-secret`, not the ephemeral key a
prerelease may use, and the published certificate digest
`c975b78a34dd622d19c4af329e4f71bfa895693ff04db5116aa718fd9aa20c22` equals the
repository pin in `security/android-release-signer.sha256`. A stable tag
requires both; both hold.

The release body links the verification record at the exact build commit rather
than a moving branch.

## What this does not establish

Matching digests prove the published bytes are the bytes the release job
produced and recorded. They say nothing about product behaviour on any machine.

The cold-boot evidence for the reboot repair is still outstanding, and the
development PC still runs the earlier 1.0.0 service binary with the SCM recovery
contract applied by hand. Installing 1.3.0 is what puts the contract and the
fifteen named startup phases into the product itself; until a cold boot is
observed after that install, the first-attempt refusal remains unidentified.
