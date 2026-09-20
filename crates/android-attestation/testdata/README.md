# Public certificate fixtures

Certificate-only fixtures from Google's Android keyattestation repository at
commit `a48898a68337b920cbd368eab5824f696d7bbf3d` (retrieved 2026-09-10):

- sony-sdk33-factory.pem: `testdata/sony-xperia10-iii/sdk33/TEE_EC.pem`
- caiman-sdk36-rkp.pem: `testdata/caiman/sdk36/TEE_EC_RKP.pem`
- tegu-sdk36-tee-2026.pem: `testdata/tegu/sdk36/TEE_EC_2026_ROOT.pem`
- tegu-sdk36-strongbox-2026.pem: `testdata/tegu/sdk36/SB_EC_2026_ROOT.pem`

[Pinned upstream source](https://github.com/android/keyattestation/tree/a48898a68337b920cbd368eab5824f696d7bbf3d/testdata).
Upstream Apache-2.0 notice is retained in LICENSE-ANDROID-KEYATTESTATION. No private
key was retrieved. These test the chain layer and legacy/current issuer profiles;
their package/challenge/key policies are not this app's enrollment evidence.

RKP positive tests use an explicitly test-only instant within the public fixture's
issuer interval, plus separate before/expired negative tests. This is not a
production historical-time workaround. The public verifier uses the PC clock and
has no caller-supplied timestamp. Native Android keys/UAC/QR are not validated by
these fixtures. Production roots are the separate release-owned Google root file.
