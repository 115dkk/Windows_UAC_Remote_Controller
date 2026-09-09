// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual client TLS identity backed by the Application's existing native key
//! owner. No foreign/public constructor can manufacture the signing request.
use crate::native_clock::native_callback;
use crate::{BridgeError, NativeLocalKeySet, NativePlatform};
use android_controller::{DurableInbox, NativePeerLease, PeerAssociationRef};
use secure_channel::{
    CertificateVerifyInput, CertificateVerifySignature, EndpointRole, PlatformTlsSigner,
    SignerError, TlsIdentity, TlsPublicKey,
};
use std::{
    fmt,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

static NEXT_BINDING: AtomicU64 = AtomicU64::new(1);

#[derive(uniffi::Object)]
pub struct NativeTransportBinding {
    reference: u64,
    lease: NativePeerLease,
    closed: AtomicBool,
    signing: AtomicBool,
    released: AtomicBool,
}
impl fmt::Debug for NativeTransportBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeTransportBinding([redacted])")
    }
}
#[uniffi::export]
impl NativeTransportBinding {
    /// Local map index only. Identity checks remain mandatory; this is not a key
    /// selector, crypto secret, persistent ID or paired-device capability.
    pub fn reference_id(&self) -> u64 {
        self.reference
    }
    pub fn local_keys(&self) -> Result<NativeLocalKeySet, BridgeError> {
        if self.is_closed() {
            return Err(BridgeError::NativeUnavailable);
        }
        Ok(NativeLocalKeySet::from_descriptor(self.lease.local_keys()))
    }
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire) || self.lease.is_revoked()
    }
    pub fn close_binding(&self) {
        self.closed.store(true, Ordering::Release);
    }
    pub fn same_binding(&self, other: Arc<NativeTransportBinding>) -> bool {
        std::ptr::eq(self, Arc::as_ptr(&other))
    }
}

/// Owned and one-shot, minted only while a real TLS engine supplies its validated
/// Client CertificateVerify input. Neither a byte array nor a boolean can mint it.
#[derive(uniffi::Object)]
pub struct NativeCertificateVerify {
    binding: Arc<NativeTransportBinding>,
    bytes: Box<[u8]>,
    taken: AtomicBool,
}
impl fmt::Debug for NativeCertificateVerify {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeCertificateVerify([redacted], client_tls_only)")
    }
}
#[uniffi::export]
impl NativeCertificateVerify {
    pub fn binding_id(&self) -> u64 {
        self.binding.reference
    }
    pub fn belongs_to(&self, binding: Arc<NativeTransportBinding>) -> bool {
        Arc::ptr_eq(&self.binding, &binding)
    }
    pub fn is_cancelled(&self) -> bool {
        self.binding.is_closed()
    }
    pub fn take_bytes(&self) -> Result<Vec<u8>, BridgeError> {
        if self.is_cancelled() || self.taken.swap(true, Ordering::AcqRel) {
            return Err(BridgeError::NativeUnavailable);
        }
        let bytes = self.bytes.to_vec();
        if self.is_cancelled() {
            return Err(BridgeError::NativeUnavailable);
        }
        Ok(bytes)
    }
}

/// Native Rust composition point, NOT an exported UniFFI/Tauri operation. The
/// same live inbox creates a downward lease before any native key callback.
/// Native app/actor callers must release their state mutex before calling this
/// factory (move exclusive owners out under their existing admission).
/// No pairing, address selection, socket dialing or startup task is performed.
pub fn native_client_transport_identity(
    owner: &mut DurableInbox,
    association: PeerAssociationRef,
    platform: Arc<dyn NativePlatform>,
) -> Result<TlsIdentity, BridgeError> {
    let lease = owner
        .lease_peer_association(association)
        .map_err(|_| BridgeError::LocalKeysUnavailable)?;
    prepare_identity((), lease, platform).map(|(_, identity)| identity)
}

/// Fixed Client identity preparation off owner admission. Carrier drops BEFORE
/// native lease/signer release on every failure; no generic signing input.
pub(crate) fn native_identity_with_socket(
    socket: tokio::net::TcpStream,
    lease: NativePeerLease,
    platform: Arc<dyn NativePlatform>,
) -> Result<(tokio::net::TcpStream, TlsIdentity), BridgeError> {
    prepare_identity(socket, lease, platform)
}
fn prepare_identity<C>(
    carrier: C,
    lease: NativePeerLease,
    platform: Arc<dyn NativePlatform>,
) -> Result<(C, TlsIdentity), BridgeError> {
    struct Owned<C> {
        carrier: Option<C>,
        lease: Option<NativePeerLease>,
        signer: Option<Arc<NativeClientSigner>>,
    }
    let mut owned = Owned {
        carrier: Some(carrier),
        lease: Some(lease),
        signer: None,
    };
    let reference = NEXT_BINDING
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            value.checked_add(1)
        })
        .map_err(|_| BridgeError::NativeUnavailable)?;
    let binding = Arc::new(NativeTransportBinding {
        reference,
        lease: owned.lease.take().ok_or(BridgeError::NativeUnavailable)?,
        closed: AtomicBool::new(false),
        signing: AtomicBool::new(false),
        released: AtomicBool::new(false),
    });
    // The adapter owns a release obligation BEFORE native publication. A failed
    // prepare may have partially published a holder in the retained platform.
    let signer = Arc::new(NativeClientSigner { binding, platform });
    owned.signer = Some(Arc::clone(&signer));
    native_callback(|| {
        signer
            .platform
            .prepare_transport_signer(Arc::clone(&signer.binding))
    })?;
    if signer.binding.is_closed() {
        return Err(BridgeError::NativeUnavailable);
    }
    let identity = TlsIdentity::from_trusted_host(EndpointRole::Client, signer)
        .map_err(|_| BridgeError::NativeUnavailable)?;
    Ok((
        owned.carrier.take().ok_or(BridgeError::NativeUnavailable)?,
        identity,
    ))
}

struct NativeClientSigner {
    binding: Arc<NativeTransportBinding>,
    platform: Arc<dyn NativePlatform>,
}
impl PlatformTlsSigner for NativeClientSigner {
    fn public_key(&self) -> Result<TlsPublicKey, SignerError> {
        if self.binding.is_closed() {
            return Err(SignerError::Unavailable);
        }
        Ok(self.binding.lease.local_keys().transport_key().clone())
    }
    fn sign_certificate_verify(
        &self,
        input: CertificateVerifyInput<'_>,
    ) -> Result<CertificateVerifySignature, SignerError> {
        if input.role() != EndpointRole::Client || !matches!(input.as_bytes().len(), 130 | 146) {
            self.binding.close_binding();
            return Err(SignerError::InvalidMessage);
        }
        if self.binding.is_closed() {
            return Err(SignerError::Unavailable);
        }
        if self
            .binding
            .signing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            self.binding.close_binding();
            return Err(SignerError::Rejected);
        }
        let mut active = SigningAdmission {
            binding: &self.binding,
            complete: false,
        };
        let request = Arc::new(NativeCertificateVerify {
            binding: Arc::clone(&self.binding),
            bytes: input.as_bytes().into(),
            taken: AtomicBool::new(false),
        });
        let der = native_callback(|| {
            self.platform
                .sign_client_certificate_verify(Arc::clone(&request))
        })
        .map_err(|_| SignerError::Unavailable)?;
        if self.binding.is_closed() || !request.taken.load(Ordering::Acquire) {
            return Err(SignerError::Rejected);
        }
        let signature = CertificateVerifySignature::from_der(&der)
            .map_err(|_| SignerError::InvalidSignature)?;
        // Existing BoundSigningKey immediately verifies this DER against the
        // captured TRANSPORT pin and the actual full input before TLS uses it.
        active.complete = true;
        Ok(signature)
    }
}
struct SigningAdmission<'a> {
    binding: &'a NativeTransportBinding,
    complete: bool,
}
impl Drop for SigningAdmission<'_> {
    fn drop(&mut self) {
        if !self.complete {
            self.binding.close_binding();
        }
        self.binding.signing.store(false, Ordering::Release);
    }
}
impl Drop for NativeClientSigner {
    fn drop(&mut self) {
        self.binding.close_binding();
        if !self.binding.released.swap(true, Ordering::AcqRel) {
            // At most ONE callback per binding. Kotlin retains any failed/partial
            // cleanup for its explicit owner-scoped cleanup path, not a loop of
            // newly allocated callback wrappers. No key aliases are removed.
            let _ = native_callback(|| {
                self.platform
                    .release_transport_signer(Arc::clone(&self.binding))
            });
        }
    }
}
