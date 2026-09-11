// SPDX-License-Identifier: GPL-2.0-or-later
//! TPM-backed PC identity key storage for the installed trusted Windows service.
//!
//! This Rust adapter is not an IPC, UI, network, CLI or UAC-approval endpoint.
//! It never replaces Windows authentication, signs phone approval decisions,
//! exports private keys or falls back to a software key provider. The service
//! must keep identity signing inside its separately reviewed protocol boundary.

#![deny(unsafe_code)]

use std::fmt;

use thiserror::Error;

#[cfg(any(windows, test))]
mod codec;
#[cfg(any(windows, test))]
mod policy;

// Sole Windows-only unsafe boundary; handle ownership, allocation, pointer and
// privilege invariants are documented at every unsafe call in this module.
#[cfg(windows)]
#[allow(unsafe_code)]
mod ffi;

/// Fixed service identity. Callers cannot select a different account or key.
pub const SERVICE_NAME: &str = "UacRemoteController";
/// Versioned persistent machine-key name, not a path or caller-supplied label.
pub const PERSISTENT_KEY_NAME: &str = "UacRemoteController.PcIdentity.P256.v1";

/// Build-time identity provider profile. Only this value ships in a release.
#[cfg(not(feature = "lab-software-identity"))]
pub const IDENTITY_PROVIDER_PROFILE: &str = "platform-crypto-provider";
/// Lab-only profile (ADR 0027). Release packaging rejects a binary carrying it.
#[cfg(feature = "lab-software-identity")]
pub const IDENTITY_PROVIDER_PROFILE: &str = "lab-software-ksp-do-not-ship";

/// Lab builds only: the last key security descriptor the policy examined, so a
/// disposable runner can record what its software KSP actually returned when
/// the descriptor policy rejects it. Never compiled into a release binary.
#[cfg(feature = "lab-software-identity")]
pub mod lab {
    use std::sync::Mutex;

    static LAST_DESCRIPTOR: Mutex<Option<Vec<u8>>> = Mutex::new(None);

    pub(crate) fn record_descriptor(bytes: &[u8]) {
        if let Ok(mut slot) = LAST_DESCRIPTOR.lock() {
            *slot = Some(bytes.to_vec());
        }
    }

    pub fn take_descriptor() -> Option<Vec<u8>> {
        LAST_DESCRIPTOR.lock().ok().and_then(|mut slot| slot.take())
    }
}

/// Observe the current thread/process's fixed service identity without opening
/// or creating a key. This is a point-in-time check, not a transferable grant:
/// callers must recheck at each protected operation and must never impersonate
/// between the observation and use. No token or privilege is changed.
pub fn verify_service_context() -> Result<(), IdentityError> {
    #[cfg(windows)]
    {
        ffi::verify_service_context()
    }
    #[cfg(not(windows))]
    {
        Err(IdentityError::UnsupportedPlatform)
    }
}

/// An owned, deliberately non-Clone, thread-affine TPM key capability.
///
/// Opening, creating, public-key export and signing each check the real process
/// token for LocalSystem plus the enabled service SID. Thread impersonation is
/// rejected. An elevated administrator token by itself is not sufficient.
///
/// Keep this type in the installed service's trusted Rust worker, never in a
/// WebView, relay, public IPC handler or an arbitrary-digest signing endpoint.
/// Windows NCrypt APIs must not be invoked from the service-start callback.
///
/// No raw handle, arbitrary key name, private export or delete API is exposed.
///
/// ```compile_fail
/// fn cannot_get_raw_handle(key: windows_identity::PcIdentityKey) {
///     let _ = key.raw_handle();
/// }
/// ```
pub struct PcIdentityKey {
    #[cfg(windows)]
    inner: ffi::ServiceKey,
    #[cfg(not(windows))]
    _unconstructible: std::convert::Infallible,
}

impl PcIdentityKey {
    /// Open the fixed existing machine key, rejecting any unexpected provider,
    /// key policy or access descriptor. Never creates, repairs or rotates it.
    pub fn open_existing_for_service() -> Result<Self, IdentityError> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: ffi::ServiceKey::open_existing()?,
            })
        }
        #[cfg(not(windows))]
        {
            Err(IdentityError::UnsupportedPlatform)
        }
    }

    /// Explicitly create the fixed persistent TPM key, without overwrite.
    ///
    /// This is a real storage mutation when called by the authorized service.
    /// It is not called automatically by this crate, its tests or any CLI.
    /// Built-in policies and the protected DACL must be accepted and read back
    /// before finalization; persistence is checked again through a reopened key.
    /// A collision fails. It never treats an existing key as its own to delete.
    ///
    /// `CreationStateUncertain` requires operator attention: after a failed
    /// finalize the adapter cannot prove whether the provider persisted the key.
    /// It will not delete by name or silently retry/overwrite. `CleanupFailed`
    /// likewise explicitly reports a failed rollback of its own finalized key.
    pub fn create_for_service() -> Result<Self, IdentityError> {
        #[cfg(windows)]
        {
            Ok(Self {
                inner: ffi::ServiceKey::create()?,
            })
        }
        #[cfg(not(windows))]
        {
            Err(IdentityError::UnsupportedPlatform)
        }
    }

    /// Deliberately export only the validated public, uncompressed P-256 point.
    /// Possessing this value is not pairing authority or evidence of a UAC event.
    pub fn public_sec1(&self) -> Result<PcPublicKey, IdentityError> {
        #[cfg(windows)]
        {
            self.inner.public_sec1()
        }
        #[cfg(not(windows))]
        {
            Err(IdentityError::UnsupportedPlatform)
        }
    }

    /// Sign exactly one SHA-256 prehash inside the trusted service boundary.
    ///
    /// The caller must construct a reviewed, domain-separated PC-identity/TLS
    /// transcript. This low-level adapter deliberately does not invent a wire
    /// protocol or decide which remote messages are allowed to be signed. Never
    /// forward a UI/IPC/network-provided digest directly to it. It must not sign
    /// Android approval/denial messages and cannot authorize or apply UAC.
    ///
    /// The result is validated, low-S, strict ASN.1 DER ECDSA, verified against
    /// the key's public point before return. No digest is retained or logged.
    pub fn sign_digest_for_service(
        &self,
        digest: &[u8; 32],
    ) -> Result<IdentitySignature, IdentityError> {
        #[cfg(windows)]
        {
            self.inner.sign_digest(digest)
        }
        #[cfg(not(windows))]
        {
            let _ = digest;
            Err(IdentityError::UnsupportedPlatform)
        }
    }

    /// Release owned native handles and report normal-path release failures.
    /// Dropping also releases handles, but cannot report a failure to the caller.
    /// Neither operation deletes a successfully created persistent key.
    pub fn close(self) -> Result<(), IdentityError> {
        #[cfg(windows)]
        {
            self.inner.close()
        }
        #[cfg(not(windows))]
        {
            Err(IdentityError::UnsupportedPlatform)
        }
    }
}

impl fmt::Debug for PcIdentityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PcIdentityKey([redacted])")
    }
}

/// Validated public SEC1 bytes; Debug is redacted to avoid incidental logging.
#[derive(Clone, PartialEq, Eq)]
pub struct PcPublicKey([u8; 65]);

impl PcPublicKey {
    pub const fn as_sec1_bytes(&self) -> &[u8; 65] {
        &self.0
    }
}

impl fmt::Debug for PcPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PcPublicKey([redacted])")
    }
}

/// Strict DER signature. This is a PC identity signature, not UAC authorization.
#[derive(Clone, PartialEq, Eq)]
pub struct IdentitySignature(Vec<u8>);

impl IdentitySignature {
    pub fn as_der_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for IdentitySignature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentitySignature([redacted])")
    }
}

/// Fixed operation labels only; errors never contain OS messages or input data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityOperation {
    OpenProcessToken,
    OpenThreadToken,
    ReadProcessUser,
    ReadProcessGroups,
    LookupServiceSid,
    CloseToken,
    OpenProvider,
    ReadProviderPolicy,
    CheckAlgorithmSupport,
    OpenKey,
    CreateKey,
    ReadKeyPolicy,
    SetKeyPolicy,
    BuildSecurityDescriptor,
    FreeSecurityDescriptor,
    FinalizeKey,
    ExportPublicKey,
    SignDigest,
    CloseKey,
    CloseProvider,
}

/// No actual SID, descriptor, key name from the OS or property value is retained.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IdentityPolicy {
    LocalSystemRequired,
    ServiceSidRequired,
    ImpersonationForbidden,
    InvalidServiceSid,
    PlatformProviderRequired,
    HardwareProviderRequired,
    SecurityDescriptorsRequired,
    FixedKeyNameRequired,
    P256SigningKeyRequired,
    SigningOnlyRequired,
    NonExportableRequired,
    MachineKeyRequired,
    ProtectedServiceDaclRequired,
    ReopenedPublicKeyMismatch,
}

#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum IdentityEncodingError {
    #[error("invalid P-256 public blob length")]
    PublicBlobLength,
    #[error("not an ECDSA P-256 public blob")]
    PublicBlobMagic,
    #[error("invalid P-256 coordinate size")]
    PublicCoordinateSize,
    #[error("invalid P-256 public point")]
    PublicPoint,
    #[error("invalid CNG P-256 signature length")]
    SignatureLength,
    #[error("invalid ECDSA signature scalar")]
    SignatureScalar,
    #[error("signature does not verify against this PC identity")]
    SignatureVerification,
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("TPM-backed PC identity is supported only on Windows")]
    UnsupportedPlatform,
    #[error("PC identity policy rejected: {0:?}")]
    Policy(IdentityPolicy),
    #[error("the fixed PC identity key already exists; no overwrite was attempted")]
    KeyAlreadyExists,
    #[error("the fixed PC identity key does not exist; no key was created")]
    KeyNotFound,
    #[error("Windows identity operation {operation:?} failed (HRESULT {hresult:#010x})")]
    WindowsCall {
        operation: IdentityOperation,
        hresult: i32,
    },
    #[error("invalid bounded native result during {operation:?}")]
    MalformedNativeData { operation: IdentityOperation },
    #[error("PC identity encoding rejected: {0}")]
    Encoding(#[from] IdentityEncodingError),
    #[error(
        "key finalization failed; persistence is uncertain and no named deletion or retry was attempted (HRESULT {hresult:#010x})"
    )]
    CreationStateUncertain { hresult: i32 },
    #[error(
        "rollback of this newly finalized key failed (HRESULT {hresult:#010x}); original failure: {cause}"
    )]
    CleanupFailed { cause: Box<Self>, hresult: i32 },
    #[error("an owned identity handle was already released")]
    HandleAlreadyReleased,
}
