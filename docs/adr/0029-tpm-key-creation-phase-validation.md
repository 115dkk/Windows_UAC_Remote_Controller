# ADR 0029: Validate TPM creation and completed identity separately

Status: accepted, subject to security review and CI/native execution evidence.

## Evidence

On 2026-09-12 the installed alpha9 service stopped with SCM diagnostic
`0xE1000009` (P256SigningKeyRequired), after the previous provider-open failure.
An explicitly approved, elevated hardware diagnostic opened only the Platform
Crypto Provider and a uniquely named **unfinalized** P-256 machine-key handle.
It never opened an existing key, finalized, signed, exported, deleted, cleared
the TPM or changed service configuration. Both handles closed successfully.

The actual PCP returned algorithm `ECDSA`, group `ECDSA`, length `0`, key type
`0`, signing-only usage `2`, and export policy `0`. TPM was present, ready,
enabled and activated; not locked out. RestartPending was true, but this did not
prevent the successful provider/creation/property calls. This is observation of
unfinished metadata, not completed key or service readiness evidence.

## Decision

Only the native adapter's uniquely owned `Creating` handle uses the unfinished
policy check. It was created with the fixed ECDSA_P256 algorithm, fixed production
name and MACHINE flag, never OVERWRITE. Its security properties and exact
protected SYSTEM/service DACL must still be set successfully and read back
before finalization. Unfinished length may be 0 or 256; scope may be 0 or MACHINE.
No other placeholder, usage, export policy, name or provider is admitted.

Completed and reopened handles still require length 256, MACHINE scope,
signing-only use, zero private export and the same protected DACL. PCP's
canonical `ECDSA` name is accepted alongside `ECDSA_P256`, with group `ECDSA`.
The name is not curve evidence: the exact ECS1 P-256 public blob, coordinate
size and RustCrypto curve-membership validation remain required before returning
the identity capability. Generic ECC blobs, ECDH and other curves remain rejected.

Finalization-uncertain handles are never published or retried. Existing keys are
never overwritten/deleted. The existing owned-transaction rollback and matching
public-key check on reopen are unchanged. No software-provider fallback or
authentication/SCM-readiness relaxation is introduced.

## Sources and limits

- [NCryptCreatePersistedKey](https://learn.microsoft.com/en-us/windows/win32/api/ncrypt/nf-ncrypt-ncryptcreatepersistedkey): creation is completed by a separate finalize call.
- [Key storage properties](https://learn.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers): algorithm, length, scope and security descriptor semantics.
- [ECC public blob](https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_ecckey_blob): curve-specific public blob discriminants.

Hosted CI has no physical TPM. Safe policy regression tests and the lab software
provider cannot establish that this machine's completed key/startup succeeds.
The Quality gate runs windows-identity tests separately without default/lab
features: the workspace all-features suite selects the lab provider and would
otherwise exclude the production-only unfinished policy regression test.
The operator's current UAC availability permits a separately announced native
follow-up using the CI-built production binary; record its actual result.
