// SPDX-License-Identifier: GPL-2.0-or-later
//! Pure API shape/redaction tests. Never opens tokens, providers or OS keys.

use windows_identity::{
    IdentityError, IdentityOperation, IdentityPolicy, IdentitySignature, PERSISTENT_KEY_NAME,
    PcIdentityKey, PcPublicKey, SERVICE_NAME,
};

#[test]
fn trusted_host_api_has_no_key_name_or_provider_parameters() {
    let open: fn() -> Result<PcIdentityKey, IdentityError> =
        PcIdentityKey::open_existing_for_service;
    let create: fn() -> Result<PcIdentityKey, IdentityError> = PcIdentityKey::create_for_service;
    let public: fn(&PcIdentityKey) -> Result<PcPublicKey, IdentityError> =
        PcIdentityKey::public_sec1;
    let sign: fn(&PcIdentityKey, &[u8; 32]) -> Result<IdentitySignature, IdentityError> =
        PcIdentityKey::sign_digest_for_service;
    let close: fn(PcIdentityKey) -> Result<(), IdentityError> = PcIdentityKey::close;
    let context: fn() -> Result<(), IdentityError> = windows_identity::verify_service_context;
    // Referencing function pointers does not call native code.
    let _ = (open, create, public, sign, close, context);
    assert_eq!(SERVICE_NAME, "UacRemoteController");
    assert_eq!(
        PERSISTENT_KEY_NAME,
        "UacRemoteController.PcIdentity.P256.v1"
    );
}

#[test]
fn diagnostic_errors_contain_fixed_metadata_only() {
    let error = IdentityError::WindowsCall {
        operation: IdentityOperation::ReadKeyPolicy,
        hresult: 0x80090016_u32 as i32,
    };
    assert_eq!(
        format!("{error}"),
        "Windows identity operation ReadKeyPolicy failed (HRESULT 0x80090016)"
    );
    let policy = IdentityError::Policy(IdentityPolicy::ProtectedServiceDaclRequired);
    assert_eq!(
        format!("{policy}"),
        "PC identity policy rejected: ProtectedServiceDaclRequired"
    );
    let cleanup = IdentityError::CleanupFailed {
        cause: Box::new(policy),
        hresult: 0x80090010_u32 as i32,
    };
    assert!(format!("{cleanup:?}").contains("ProtectedServiceDaclRequired"));
}

#[cfg(not(windows))]
#[test]
fn unsupported_platform_has_no_success_stub_or_fallback() {
    assert!(matches!(
        windows_identity::verify_service_context(),
        Err(IdentityError::UnsupportedPlatform)
    ));
    assert!(matches!(
        PcIdentityKey::open_existing_for_service(),
        Err(IdentityError::UnsupportedPlatform)
    ));
    assert!(matches!(
        PcIdentityKey::create_for_service(),
        Err(IdentityError::UnsupportedPlatform)
    ));
}
