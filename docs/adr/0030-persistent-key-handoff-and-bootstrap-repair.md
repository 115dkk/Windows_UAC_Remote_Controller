# ADR 0030: Persisted-key handoff and authorized bootstrap completion

The observed alpha12 service reached key finalization, then failed validation
and its compensating delete failed (E4000005). This exposed two lifecycle flaws:
validation used the creation handle before inspecting the reopened durable
object, and failed compensation hid the original error while leaving a key-only
bootstrap state that a reinstall could not finish.

The identity adapter now compares the creation public point with the reopened
key, validates every completed policy and exact P-256 blob on the reopened key,
and returns that reopened handle. Unvalidated material never leaves the adapter.
No policy is changed on an existing key. No persistent deletion is attempted on
failure or Drop; finalized/uncertain keys remain available for operator recovery.
The original fixed policy/Windows error reaches SCM rather than a secondary
cleanup error. This is not a diagnostic endpoint or a signing/provisioning bypass.

An elevated, protected installer may write an eight-byte bootstrap permit ONLY
when devices.journal is genuinely absent and the pinned private directory has
only known entries. Any present journal (including empty/corrupt) is preserved.
The normal service consumes and flushes that permit before key work. A valid
existing identity plus that consumed grant may CREATE_NEW the missing empty
registry; it cannot replace a file or enroll a phone. Without that grant, the
existing-key/missing-registry case still fails closed. A partial permit/journal
fails; consumption followed by a crash requires a fresh elevated reinstall.

This deliberately does not infer "never paired" from mere absence. Reinstall is
the administrator's recovery authorization; previously missing device records
are not reconstructed, and phones must be paired through the normal ceremony.
Present device records, keys and settings are never erased by this repair.
The permit is not a claim of atomicity across TPM and NTFS or power-loss proof.

Native completion remains subject to the actual CI-built installed service test.
TPM-only identity, protected SYSTEM/service DACL, no private export, P-256 curve
validation, native service context and Windows authentication remain mandatory.
