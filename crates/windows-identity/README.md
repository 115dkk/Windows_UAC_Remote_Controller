# windows-identity

Service-only Windows TPM PC-identity adapter. Status: **implemented_unverified**.
Source and pure tests have been authored; the implementation worker did not run
builds, tests, formatting, lint, Rust Analyzer, token queries or native key calls.
Root owns all validation. This is not evidence of working remote UAC or pairing.

## Trusted-host contract

`PcIdentityKey::open_existing_for_service()` opens only the fixed machine key
`UacRemoteController.PcIdentity.P256.v1`; it never creates or repairs it.
`create_for_service()` explicitly creates that key without overwrite.
`public_sec1()` returns only a validated 65-byte uncompressed P-256 public point.
`sign_digest_for_service(&[u8; 32])` produces verified low-S DER ECDSA from an
exact prehash. `close()` releases handles, not the persistent key.

`verify_service_context()` reuses the same native identity check without opening
or creating a key. It is a point-in-time observation, not a transferable grant;
the fixed trust-file adapter rechecks it for each operation.

Every open/create/export/sign entry checks the actual process token: LocalSystem
as its user and the enabled, non-deny-only SID obtained by native lookup of
`NT SERVICE\UacRemoteController`. Any thread impersonation is rejected. An
elevated administrator, a caller boolean or a service-name string is insufficient.
No alternate token, `RevertToSelf`, privilege adjustment or elevation is used.

Call only from the installed service's trusted Rust worker, outside the service
start callback. `windows-service-host::runtime` now opens the existing key and
creates only on `KeyNotFound` with an otherwise empty validated trust directory,
loads/initializes the matching registry before worker Ready, and
closes it on normal shutdown. This is authored integration, not a performed
service installation, key creation or successful native-OS test. No UI, IPC,
network listener, automatic pairing bootstrap, probe CLI or installer key API
is included. The future protocol adapter
must construct a reviewed PC-identity/TLS transcript; never forward untrusted
digests directly. This PC identity cannot sign Android approval decisions or
substitute for Windows authentication. Public key access is not pairing authority.

## Fixed security policy

- Only Microsoft Platform Crypto Provider, hardware implementation (optional
  hardware RNG), descriptor support and ECDSA P-256 support; no software/removable/
  unknown-provider fallback, no plaintext private-key file or DPAPI fallback.
- Key name, algorithm/group, 256-bit length, machine scope, signing-only usage
  and export policy zero are checked on actual native handles. The provider
  reference retrieved from the key is independently checked and freed.
- Protected DACL, SYSTEM owner/group, exactly two non-inherited allow ACEs:
  SYSTEM and this service SID, each with `GENERIC_ALL`. Service-SID administration
  rights support initialization/finalization/rollback under the host's planned
  `SERVICE_SID_TYPE_RESTRICTED` token. No other principal is admitted. No public
  policy-edit or deletion method is exposed.
- Only `ECCPUBLICBLOB` export exists: exact 72 bytes, ECDSA P-256 magic, 32-byte
  coordinates, validated curve point. CNG's fixed `r || s` is parsed and converted
  by RustCrypto `p256`, not a custom signature implementation.
- Only the private Windows `ffi` module may use unsafe. Owned handles cannot be
  cloned or moved across threads. Errors contain fixed labels and numeric codes;
  key/public-key/signature Debug output is redacted.

The descriptor parser intentionally accepts only the specified self-relative
layout and exact masks. Unexpected provider normalization or an unsupported
property is a failure, not evidence permitting a broader access policy.
Whether the Platform KSP returns this exact representation before finalization
and under the actual Restricted service token remains unverified. A secure but
different representation must be investigated by semantic policy review and
native evidence, not silently accepted or described as a working configuration.

## Creation, failure and concurrency

The unfinalized key must accept and return the non-export policy, signing-only
usage and protected descriptor **before** finalization. If those checks fail,
the handle is discarded without making a usable key. A provider that needs a
permissive finalized key before applying its ACL is unsupported by this path.

Finalization uses the silent flag without disabling validation. Actual policy
and public material are checked again, including a separately reopened handle.
Only successful finalization of this transaction's new key arms rollback.
Subsequent validation failure deletes that owned object; deletion failure is
reported as `CleanupFailed`. Drop has best-effort cleanup for unwind paths.

If finalization itself fails, `CreationStateUncertain` reports that persistence
cannot be proven. The adapter frees its handle but does not delete by name, retry
or overwrite: another concurrent creator might own the name. Existing keys are
never deleted or automatically repaired. An operator must investigate uncertain
creation/cleanup outcomes; a later open still requires all fixed policy checks.
Crash/power-loss atomicity is **not** established by this code.

## Root-only verification still required

Default tests contain only synthetic binary/public mathematical fixtures and API
shape checks. No native key integration test is supplied, ignored or otherwise;
`cargo test` cannot create/open/sign/delete an OS key through these tests.

On an explicitly authorized isolated Windows machine, root must separately verify:

1. LocalSystem + installed restricted service SID operation, and rejection of
   ordinary/elevated users, missing/disabled/deny-only service SID and all thread
   impersonation. Nonprivileged opening should stop before opening any KSP.
2. Platform KSP properties before finalize, protected owner/group/DACL persistence,
   exact native mask representation and service-SID permissions. Confirm actual
   hardware P-256 support without any fallback.
3. Explicit creation, reopen/restart/reboot stability, public/signature agreement,
   private-export denial, collision races, existing wrong-policy keys and policy
   tampering. Never change a production identity to manufacture a test fixture.
4. Failed configuration/finalization/rollback, handle allocation/release failures,
   crash/power-loss remnants and operator recovery without unintended rotation.
5. The future service/protocol boundary: no externally reachable generic signing,
   key management, enrollment or authorization path. Actual phone pairing, TLS,
   Android authentication and UAC application remain unimplemented/unproven here.

The threat model assumes an intact Windows OS and excludes already-compromised
SYSTEM/kernel, as the user specified. These exclusions do not excuse an
unelevated caller reaching a privileged signing or approval endpoint.

## Native contracts consulted

Read 2026-09-08 against cached `windows` 0.62.2 bindings and Microsoft documentation:
[key properties](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers),
[service SID lookup](https://learn.microsoft.com/en-us/windows/win32/api/winsvc/ns-winsvc-service_sid_info),
[create](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey),
[set property](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsetproperty),
[finalize](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptfinalizekey),
[delete ownership](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptdeletekey),
[public ECC blob](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob),
[sign](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptsignhash).

Original project code: GPL-2.0-or-later. Dependency licenses remain their own.
