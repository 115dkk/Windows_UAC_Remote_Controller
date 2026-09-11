// SPDX-License-Identifier: GPL-2.0-or-later
//! Private Windows FFI boundary. No pointer, raw handle or token leaves here.
//!
//! All native objects are uniquely owned and !Send/!Sync. The process must be
//! LocalSystem with this service's enabled SID; an impersonating thread is
//! rejected rather than reverted or given another token. Provider/key properties
//! are queried from live handles, with fixed bounded buffers and no UI fallback.
//! Only a handle whose finalization succeeded in THIS create transaction may be
//! rolled back with NCryptDeleteKey. Opened/pre-existing keys are never deleted.

use std::{fmt, marker::PhantomData, mem, rc::Rc};

use windows::{
    Win32::{
        Foundation::{
            CloseHandle, ERROR_INSUFFICIENT_BUFFER, ERROR_NO_TOKEN, HANDLE, HLOCAL, LocalFree,
            NTE_BAD_KEYSET, NTE_EXISTS,
        },
        Security::{
            Authorization::{
                ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
            },
            Cryptography::{
                BCRYPT_ECCPUBLIC_BLOB, CERT_KEY_SPEC, NCRYPT_ALGORITHM_GROUP_PROPERTY,
                NCRYPT_ALGORITHM_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG, NCRYPT_ECDSA_P256_ALGORITHM,
                NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_FLAGS, NCRYPT_HANDLE,
                NCRYPT_IMPL_TYPE_PROPERTY, NCRYPT_KEY_HANDLE, NCRYPT_KEY_TYPE_PROPERTY,
                NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_LENGTH_PROPERTY, NCRYPT_MACHINE_KEY_FLAG,
                NCRYPT_NAME_PROPERTY, NCRYPT_PROV_HANDLE, NCRYPT_PROVIDER_HANDLE_PROPERTY,
                NCRYPT_SECURITY_DESCR_PROPERTY, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY,
                NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDeleteKey, NCryptExportKey,
                NCryptFinalizeKey, NCryptFreeObject, NCryptGetProperty, NCryptIsAlgSupported,
                NCryptOpenKey, NCryptOpenStorageProvider, NCryptSetProperty, NCryptSignHash,
            },
            DACL_SECURITY_INFORMATION, GROUP_SECURITY_INFORMATION, GetTokenInformation,
            LookupAccountNameW, OBJECT_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PSECURITY_DESCRIPTOR, PSID, SID_AND_ATTRIBUTES, SID_NAME_USE, SidTypeWellKnownGroup,
            TOKEN_GROUPS, TOKEN_INFORMATION_CLASS, TOKEN_QUERY, TOKEN_USER, TokenGroups, TokenUser,
        },
        System::Threading::{
            GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
        },
    },
    core::{Error as WindowsError, HRESULT, PCWSTR, PWSTR, w},
};

use crate::{
    IdentityError, IdentityOperation, IdentityPolicy, IdentitySignature, PcPublicKey,
    codec::{
        PUBLIC_BLOB_BYTES, RAW_SIGNATURE_BYTES, public_key_from_blob, signature_from_cng,
        verify_signature,
    },
    policy::{
        KeyLifecycle, MAX_DESCRIPTOR_BYTES, ObservedKeyPolicy, SYSTEM_SID, enabled_service_group,
        is_service_sid, service_sid_sddl, sid_prefix, validate_descriptor, validate_provider,
    },
};

// Exactly one provider name is compiled in. The lab feature exists because
// hosted CI runners have no TPM; it is never a runtime choice (ADR 0027).
#[cfg(feature = "lab-software-identity")]
use windows::Win32::Security::Cryptography::MS_KEY_STORAGE_PROVIDER as SELECTED_PROVIDER;
#[cfg(not(feature = "lab-software-identity"))]
use windows::Win32::Security::Cryptography::MS_PLATFORM_CRYPTO_PROVIDER as SELECTED_PROVIDER;

const KEY_NAME: PCWSTR = w!("UacRemoteController.PcIdentity.P256.v1");
const SERVICE_ACCOUNT: PCWSTR = w!("NT SERVICE\\UacRemoteController");
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const STRING_PROPERTY_BYTES: usize = 512;

pub(super) struct ServiceKey {
    // Fields drop in declaration order: the key must be released before provider.
    key: OwnedKey,
    provider: OwnedProvider,
}

impl ServiceKey {
    pub(super) fn open_existing() -> Result<Self, IdentityError> {
        let service_sid = authorize_service()?;
        let provider = OwnedProvider::open()?;
        provider.validate()?;
        let key = OwnedKey::open_existing(&provider)?;
        validate_key(&key, &service_sid)?;
        // Invalid public material also makes an otherwise correctly labelled key
        // unusable. No signing or private-key export is done during opening.
        export_public(&key)?;
        Ok(Self { key, provider })
    }

    pub(super) fn create() -> Result<Self, IdentityError> {
        let service_sid = authorize_service()?;
        let descriptor = OwnedDescriptor::new(&service_sid)?;
        let provider = OwnedProvider::open()?;
        provider.validate()?;
        let mut key = OwnedKey::create_new(&provider)?;
        let configuration = configure_unfinalized(&key, &descriptor, &service_sid);
        // Report normal-path LocalFree failures, too. No finalized key exists yet.
        let descriptor_release = descriptor.close();
        configuration?;
        descriptor_release?;
        reject_thread_impersonation()?;
        key.finalize()?;
        let validation = (|| {
            validate_key(&key, &service_sid)?;
            let original_public = export_public(&key)?;
            let reopened = OwnedKey::open_existing(&provider)?;
            validate_key(&reopened, &service_sid)?;
            let reopened_public = export_public(&reopened)?;
            reopened.close()?;
            if original_public != reopened_public {
                return Err(IdentityError::Policy(
                    IdentityPolicy::ReopenedPublicKeyMismatch,
                ));
            }
            Ok(())
        })();
        if let Err(cause) = validation {
            return Err(key.rollback(cause));
        }
        key.lifecycle = KeyLifecycle::Established;
        Ok(Self { key, provider })
    }

    pub(super) fn public_sec1(&self) -> Result<PcPublicKey, IdentityError> {
        let service_sid = authorize_service()?;
        validate_key(&self.key, &service_sid)?;
        export_public(&self.key)
    }

    pub(super) fn sign_digest(
        &self,
        digest: &[u8; 32],
    ) -> Result<IdentitySignature, IdentityError> {
        let service_sid = authorize_service()?;
        validate_key(&self.key, &service_sid)?;
        let public = export_public(&self.key)?;
        reject_thread_impersonation()?;
        let mut raw_signature = [0_u8; RAW_SIGNATURE_BYTES];
        let mut returned = 0_u32;
        // SAFETY: key is uniquely owned and borrowed live for this synchronous
        // call. Its TPM provider, private-export prohibition, signing-only use,
        // P-256 shape and protected service DACL were just checked. digest is an
        // initialized exact 32-byte read-only prehash, output is an exclusive
        // initialized 64-byte buffer, returned is separate aligned u32 storage.
        // No pointers are retained. ECDSA uses no RSA padding. SILENT denies UI.
        unsafe {
            NCryptSignHash(
                self.key.get()?,
                None,
                digest,
                Some(&mut raw_signature),
                &mut returned,
                NCRYPT_SILENT_FLAG,
            )
        }
        .map_err(|error| os_error(IdentityOperation::SignDigest, error))?;
        if returned as usize != RAW_SIGNATURE_BYTES {
            return Err(malformed(IdentityOperation::SignDigest));
        }
        let signature = signature_from_cng(&raw_signature)?;
        verify_signature(&public, digest, &signature)?;
        Ok(signature)
    }

    pub(super) fn close(self) -> Result<(), IdentityError> {
        let key_release = self.key.close();
        let provider_release = self.provider.close();
        key_release.and(provider_release)
    }
}

impl fmt::Debug for ServiceKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ServiceKey([redacted])")
    }
}

fn configure_unfinalized(
    key: &OwnedKey,
    descriptor: &OwnedDescriptor,
    service_sid: &[u8; 32],
) -> Result<(), IdentityError> {
    // Standard built-in key properties, set before finalize; never shadowed by
    // NCRYPT_PERSIST_ONLY_FLAG. Reopen validation checks actual persistence.
    set_property(key, NCRYPT_EXPORT_POLICY_PROPERTY, &0_u32.to_le_bytes(), 0)?;
    set_property(
        key,
        NCRYPT_KEY_USAGE_PROPERTY,
        &NCRYPT_ALLOW_SIGNING_FLAG.to_le_bytes(),
        0,
    )?;
    set_property(
        key,
        NCRYPT_SECURITY_DESCR_PROPERTY,
        descriptor.bytes(),
        descriptor_parts().0,
    )?;
    // Some providers may not support these pre-finalization checks. In that
    // case do NOT finalize first and repair permissions afterward: reject them.
    validate_key(key, service_sid)
}

fn validate_key(key: &OwnedKey, service_sid: &[u8; 32]) -> Result<(), IdentityError> {
    // The key's actual provider, not just the provider requested during open.
    // NCRYPT_PROVIDER_HANDLE_PROPERTY returns a reference the caller must free.
    let provider = key.provider()?;
    provider.validate()?;
    provider.close()?;
    let handle = NCRYPT_HANDLE(key.get()?.0);
    let operation = IdentityOperation::ReadKeyPolicy;
    let name = property_bytes::<STRING_PROPERTY_BYTES>(handle, NCRYPT_NAME_PROPERTY, 0, operation)?;
    let algorithm =
        property_bytes::<STRING_PROPERTY_BYTES>(handle, NCRYPT_ALGORITHM_PROPERTY, 0, operation)?;
    let algorithm_group = property_bytes::<STRING_PROPERTY_BYTES>(
        handle,
        NCRYPT_ALGORITHM_GROUP_PROPERTY,
        0,
        operation,
    )?;
    ObservedKeyPolicy {
        name: &name,
        algorithm: &algorithm,
        algorithm_group: &algorithm_group,
        length_bits: property_u32(handle, NCRYPT_LENGTH_PROPERTY, operation)?,
        usage: property_u32(handle, NCRYPT_KEY_USAGE_PROPERTY, operation)?,
        export: property_u32(handle, NCRYPT_EXPORT_POLICY_PROPERTY, operation)?,
        key_type: property_u32(handle, NCRYPT_KEY_TYPE_PROPERTY, operation)?,
    }
    .validate()?;
    let descriptor = property_bytes::<MAX_DESCRIPTOR_BYTES>(
        handle,
        NCRYPT_SECURITY_DESCR_PROPERTY,
        descriptor_parts().0,
        operation,
    )?;
    validate_descriptor(&descriptor, service_sid)
}

fn descriptor_parts() -> OBJECT_SECURITY_INFORMATION {
    OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION
}

fn export_public(key: &OwnedKey) -> Result<PcPublicKey, IdentityError> {
    let mut blob = [0_u8; PUBLIC_BLOB_BYTES];
    let mut returned = 0_u32;
    // SAFETY: the live borrowed key has been policy-validated by every call site.
    // This fixed blob type exports ONLY public ECC coordinates, never private or
    // opaque transport material. Output has exactly 72 initialized writable
    // bytes, returned is aligned separate u32 storage, and no pointers escape.
    unsafe {
        NCryptExportKey(
            key.get()?,
            None,
            BCRYPT_ECCPUBLIC_BLOB,
            None,
            Some(&mut blob),
            &mut returned,
            NCRYPT_SILENT_FLAG,
        )
    }
    .map_err(|error| os_error(IdentityOperation::ExportPublicKey, error))?;
    if returned as usize != PUBLIC_BLOB_BYTES {
        return Err(malformed(IdentityOperation::ExportPublicKey));
    }
    public_key_from_blob(&blob).map_err(Into::into)
}

fn property_bytes<const LIMIT: usize>(
    handle: NCRYPT_HANDLE,
    property: PCWSTR,
    flags: u32,
    operation: IdentityOperation,
) -> Result<Vec<u8>, IdentityError> {
    let mut buffer = [0_u8; LIMIT];
    let mut returned = 0_u32;
    // SAFETY: every caller supplies a borrowed live key/provider handle and a
    // static NUL-terminated property name. LIMIT is a private compile-time bound
    // (at most 4096, hence representable as DWORD), buffer is initialized and
    // exclusively writable; returned is separate initialized aligned storage.
    // Windows retains neither pointer. We request actual built-in values, never
    // PERSIST_ONLY overrides. Security-information bits are passed only for SD.
    unsafe {
        NCryptGetProperty(
            handle,
            property,
            Some(&mut buffer),
            &mut returned,
            OBJECT_SECURITY_INFORMATION(flags | NCRYPT_SILENT_FLAG.0),
        )
    }
    .map_err(|error| os_error(operation, error))?;
    let used = usize::try_from(returned).map_err(|_| malformed(operation))?;
    if used == 0 || used > LIMIT {
        return Err(malformed(operation));
    }
    Ok(buffer[..used].to_vec())
}

fn property_u32(
    handle: NCRYPT_HANDLE,
    property: PCWSTR,
    operation: IdentityOperation,
) -> Result<u32, IdentityError> {
    let bytes = property_bytes::<4>(handle, property, 0, operation)?;
    let value: [u8; 4] = bytes.try_into().map_err(|_| malformed(operation))?;
    Ok(u32::from_le_bytes(value))
}

fn set_property(
    key: &OwnedKey,
    property: PCWSTR,
    bytes: &[u8],
    flags: u32,
) -> Result<(), IdentityError> {
    if bytes.is_empty()
        || bytes.len() > MAX_DESCRIPTOR_BYTES
        || !key.lifecycle.permits_configuration()
    {
        return Err(malformed(IdentityOperation::SetKeyPolicy));
    }
    // SAFETY: call sites supply only this transaction's unfinalized owned key,
    // static property names and bounded initialized bytes valid synchronously.
    // Descriptor bytes remain in their native LocalAlloc owner during this call.
    // No pointer is retained, no caller input selects policy, and SILENT forbids
    // fallback UI. No code sets policies on a reopened/finalized live key.
    unsafe {
        NCryptSetProperty(
            NCRYPT_HANDLE(key.get()?.0),
            property,
            bytes,
            NCRYPT_FLAGS(flags | NCRYPT_SILENT_FLAG.0),
        )
    }
    .map_err(|error| os_error(IdentityOperation::SetKeyPolicy, error))
}

struct OwnedProvider {
    handle: Option<NCRYPT_PROV_HANDLE>,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl OwnedProvider {
    fn open() -> Result<Self, IdentityError> {
        let mut handle = NCRYPT_PROV_HANDLE::default();
        // SAFETY: one fixed provider name chosen at compile time (the Platform
        // Crypto Provider; the lab feature substitutes the Software KSP), zero
        // reserved flags, initialized aligned exclusive output. No caller-selected
        // KSP, runtime fallback or UI operation. Successful handle is owned once.
        unsafe { NCryptOpenStorageProvider(&mut handle, SELECTED_PROVIDER, 0) }
            .map_err(|error| os_error(IdentityOperation::OpenProvider, error))?;
        Self::from_acquired(handle, IdentityOperation::OpenProvider)
    }

    fn from_acquired(
        handle: NCRYPT_PROV_HANDLE,
        operation: IdentityOperation,
    ) -> Result<Self, IdentityError> {
        if handle.0 == 0 {
            return Err(malformed(operation));
        }
        Ok(Self {
            handle: Some(handle),
            _thread_affinity: PhantomData,
        })
    }

    fn get(&self) -> Result<NCRYPT_PROV_HANDLE, IdentityError> {
        self.handle.ok_or(IdentityError::HandleAlreadyReleased)
    }

    fn validate(&self) -> Result<(), IdentityError> {
        let handle = NCRYPT_HANDLE(self.get()?.0);
        let operation = IdentityOperation::ReadProviderPolicy;
        let name =
            property_bytes::<STRING_PROPERTY_BYTES>(handle, NCRYPT_NAME_PROPERTY, 0, operation)?;
        validate_provider(
            &name,
            property_u32(handle, NCRYPT_IMPL_TYPE_PROPERTY, operation)?,
            property_u32(handle, NCRYPT_SECURITY_DESCR_SUPPORT_PROPERTY, operation)?,
        )?;
        // SAFETY: provider is a live owned TPM KSP, algorithm is a fixed static
        // NUL-terminated string, flags zero as documented. Query only; no key
        // generation/signing/provider mutation is triggered by this capability check.
        unsafe { NCryptIsAlgSupported(self.get()?, NCRYPT_ECDSA_P256_ALGORITHM, 0) }
            .map_err(|error| os_error(IdentityOperation::CheckAlgorithmSupport, error))
    }

    fn close(mut self) -> Result<(), IdentityError> {
        let handle = self
            .handle
            .take()
            .ok_or(IdentityError::HandleAlreadyReleased)?;
        // SAFETY: this unique provider reference came from OpenStorageProvider or
        // the documented owned Provider Handle property. All borrows have ended.
        // Taking it first prevents double-free even when Windows reports failure.
        unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle.0)) }
            .map_err(|error| os_error(IdentityOperation::CloseProvider, error))
    }
}

impl Drop for OwnedProvider {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: sole remaining native provider reference, no active borrows.
            // Drop cannot return an error; abnormal/unwind release is best-effort.
            let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle.0)) };
        }
    }
}

struct OwnedKey {
    handle: Option<NCRYPT_KEY_HANDLE>,
    // Armed only AFTER successful finalization of a key created by this owner.
    // Failed finalization never grants authority to delete a colliding key.
    lifecycle: KeyLifecycle,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl OwnedKey {
    fn open_existing(provider: &OwnedProvider) -> Result<Self, IdentityError> {
        let mut handle = NCRYPT_KEY_HANDLE::default();
        // SAFETY: live provider, fixed static key name and zero legacy key spec.
        // Machine/SILENT flags select the machine namespace and forbid UI. The
        // initialized output receives a distinct owned reference; no creation.
        unsafe {
            NCryptOpenKey(
                provider.get()?,
                &mut handle,
                KEY_NAME,
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG | NCRYPT_SILENT_FLAG,
            )
        }
        .map_err(|error| {
            if error.code() == NTE_BAD_KEYSET {
                IdentityError::KeyNotFound
            } else {
                os_error(IdentityOperation::OpenKey, error)
            }
        })?;
        Self::from_acquired(handle, IdentityOperation::OpenKey)
    }

    fn create_new(provider: &OwnedProvider) -> Result<Self, IdentityError> {
        let mut handle = NCRYPT_KEY_HANDLE::default();
        // SAFETY: authorized caller, live validated TPM provider, fixed P-256
        // algorithm/key name, zero legacy spec, initialized aligned output. Only
        // documented MACHINE flag is used: NEVER OVERWRITE. This creates an
        // unfinalized handle, not a usable key; properties must precede finalize.
        // CreatePersistedKey documents no SILENT flag; all usable operations and
        // finalization do use SILENT. No PIN/UI policy is supplied or requested.
        unsafe {
            NCryptCreatePersistedKey(
                provider.get()?,
                &mut handle,
                NCRYPT_ECDSA_P256_ALGORITHM,
                KEY_NAME,
                CERT_KEY_SPEC(0),
                NCRYPT_MACHINE_KEY_FLAG,
            )
        }
        .map_err(|error| {
            if error.code() == NTE_EXISTS {
                IdentityError::KeyAlreadyExists
            } else {
                os_error(IdentityOperation::CreateKey, error)
            }
        })?;
        let mut key = Self::from_acquired(handle, IdentityOperation::CreateKey)?;
        key.lifecycle = KeyLifecycle::Creating;
        Ok(key)
    }

    fn from_acquired(
        handle: NCRYPT_KEY_HANDLE,
        operation: IdentityOperation,
    ) -> Result<Self, IdentityError> {
        if handle.0 == 0 {
            return Err(malformed(operation));
        }
        Ok(Self {
            handle: Some(handle),
            lifecycle: KeyLifecycle::Established,
            _thread_affinity: PhantomData,
        })
    }

    fn get(&self) -> Result<NCRYPT_KEY_HANDLE, IdentityError> {
        self.handle.ok_or(IdentityError::HandleAlreadyReleased)
    }

    fn provider(&self) -> Result<OwnedProvider, IdentityError> {
        let bytes = property_bytes::<{ mem::size_of::<usize>() }>(
            NCRYPT_HANDLE(self.get()?.0),
            NCRYPT_PROVIDER_HANDLE_PROPERTY,
            0,
            IdentityOperation::ReadKeyPolicy,
        )?;
        let bytes: [u8; mem::size_of::<usize>()] = bytes
            .try_into()
            .map_err(|_| malformed(IdentityOperation::ReadKeyPolicy))?;
        // Windows documents this property as an owned provider reference which
        // MUST be freed, even when it refers to the provider we already opened.
        OwnedProvider::from_acquired(
            NCRYPT_PROV_HANDLE(usize::from_le_bytes(bytes)),
            IdentityOperation::ReadKeyPolicy,
        )
    }

    fn finalize(&mut self) -> Result<(), IdentityError> {
        if !self.lifecycle.permits_configuration() {
            return Err(malformed(IdentityOperation::FinalizeKey));
        }
        self.lifecycle = KeyLifecycle::FinalizationUncertain;
        // SAFETY: only create() calls this after pre-finalization policy/DACL
        // validation. Owned handle is live; no validation-skipping, legacy-store,
        // export or fallback flags. SILENT makes any required UI a failure.
        unsafe { NCryptFinalizeKey(self.get()?, NCRYPT_SILENT_FLAG) }.map_err(|error| {
            // Do not arm deletion after failure: a concurrent create may own the
            // persisted name, and finalization failure has no transactional proof.
            IdentityError::CreationStateUncertain {
                hresult: error.code().0,
            }
        })?;
        self.lifecycle = KeyLifecycle::RollbackPending;
        Ok(())
    }

    fn rollback(mut self, cause: IdentityError) -> IdentityError {
        if !self.lifecycle.permits_rollback() {
            return cause;
        }
        let Some(handle) = self.handle else {
            return cause;
        };
        // SAFETY: this is solely the newly created handle whose finalization
        // succeeded in this transaction. No opened/pre-existing key ever arms
        // rollback. DeleteKey deletes this object and frees its handle on success;
        // on failure Windows permits FreeObject, performed by Drop below.
        match unsafe { NCryptDeleteKey(handle, NCRYPT_SILENT_FLAG.0) } {
            Ok(()) => {
                self.handle = None;
                self.lifecycle = KeyLifecycle::Established;
                cause
            }
            Err(error) => {
                // Do not retry deletion from Drop after an explicit failed attempt.
                self.lifecycle = KeyLifecycle::FinalizationUncertain;
                IdentityError::CleanupFailed {
                    cause: Box::new(cause),
                    hresult: error.code().0,
                }
            }
        }
    }

    fn close(mut self) -> Result<(), IdentityError> {
        if self.lifecycle.permits_rollback() {
            // A pending transaction must commit explicitly or roll back. An
            // accidental close must not silently persist an unvalidated new key.
            return Err(malformed(IdentityOperation::CloseKey));
        }
        let handle = self
            .handle
            .take()
            .ok_or(IdentityError::HandleAlreadyReleased)?;
        // SAFETY: the unique reference has no remaining borrows. This releases
        // only the handle, never its persisted key, and taking prevents double-free.
        unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle.0)) }
            .map_err(|error| os_error(IdentityOperation::CloseKey, error))
    }
}

impl Drop for OwnedKey {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            if self.lifecycle.permits_rollback() {
                // SAFETY: only a successfully finalized newly created key can
                // arm this guard. Unwinding before commit rolls back that object,
                // never an object opened by name. Successful deletion frees it.
                if unsafe { NCryptDeleteKey(handle, NCRYPT_SILENT_FLAG.0) }.is_ok() {
                    return;
                }
            }
            // SAFETY: unique native reference; DeleteKey either wasn't called or
            // failed (in which case documentation permits FreeObject). Unfinalized
            // handles are discarded without deleting a potentially colliding name.
            // Drop cannot report failure; successful callers may use explicit close.
            let _ = unsafe { NCryptFreeObject(NCRYPT_HANDLE(handle.0)) };
        }
    }
}

struct OwnedDescriptor {
    descriptor: Option<PSECURITY_DESCRIPTOR>,
    length: usize,
}

impl OwnedDescriptor {
    fn new(service_sid: &[u8; 32]) -> Result<Self, IdentityError> {
        let sddl: Vec<u16> = service_sid_sddl(service_sid)?
            .encode_utf16()
            .chain(std::iter::once(0))
            .collect();
        let mut descriptor = PSECURITY_DESCRIPTOR::default();
        let mut length = 0_u32;
        // SAFETY: NUL-terminated bounded SDDL is constructed only from fixed
        // syntax and native-validated numeric service SID data. Both output
        // pointers are initialized, aligned and exclusive for the synchronous
        // call. On success Windows allocates a self-relative descriptor with
        // LocalAlloc, immediately adopted by a unique LocalFree owner below.
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                PCWSTR(sddl.as_ptr()),
                SDDL_REVISION_1,
                &mut descriptor,
                Some(&mut length),
            )
        }
        .map_err(|error| os_error(IdentityOperation::BuildSecurityDescriptor, error))?;
        let owned = Self {
            descriptor: (!descriptor.0.is_null()).then_some(descriptor),
            length: length as usize,
        };
        if owned.descriptor.is_none() || owned.length < 20 || owned.length > MAX_DESCRIPTOR_BYTES {
            return Err(malformed(IdentityOperation::BuildSecurityDescriptor));
        }
        validate_descriptor(owned.bytes(), service_sid)?;
        Ok(owned)
    }

    fn bytes(&self) -> &[u8] {
        match self.descriptor {
            Some(descriptor) => {
                // SAFETY: constructor validated successful native allocation,
                // non-null pointer and returned size 20..=4096. Windows owns the
                // initialized self-relative layout; we keep its LocalAlloc owner
                // borrowed and never mutate or free it while this slice exists.
                unsafe { std::slice::from_raw_parts(descriptor.0.cast(), self.length) }
            }
            None => &[],
        }
    }

    fn close(mut self) -> Result<(), IdentityError> {
        let descriptor = self
            .descriptor
            .take()
            .ok_or(IdentityError::HandleAlreadyReleased)?;
        // SAFETY: pointer was allocated by ConvertStringSecurityDescriptor...W's
        // LocalAlloc contract. All slices/calls have ended; unique owner is taken
        // first. LocalFree returns NULL on success, non-NULL on release failure.
        let failed = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        if !failed.0.is_null() {
            // LocalFree preserves the last error on failure; capture now without
            // retrieving/localizing its message or printing the allocation.
            return Err(os_error(
                IdentityOperation::FreeSecurityDescriptor,
                WindowsError::from_thread(),
            ));
        }
        Ok(())
    }
}

impl Drop for OwnedDescriptor {
    fn drop(&mut self) {
        if let Some(descriptor) = self.descriptor.take() {
            // SAFETY: solely owned LocalAlloc pointer, no remaining byte borrows.
            // Abnormal/unwind cleanup cannot report failure and is best-effort.
            let _ = unsafe { LocalFree(Some(HLOCAL(descriptor.0))) };
        }
    }
}

pub(super) fn verify_service_context() -> Result<(), IdentityError> {
    authorize_service().map(|_| ())
}

fn authorize_service() -> Result<[u8; 32], IdentityError> {
    reject_thread_impersonation()?;
    let token = OwnedToken::process()?;
    let user = token_information(&token, TokenUser, IdentityOperation::ReadProcessUser)?;
    if user.bytes().len() < mem::size_of::<TOKEN_USER>() {
        return Err(malformed(IdentityOperation::ReadProcessUser));
    }
    // SAFETY: successful GetTokenInformation filled at least TOKEN_USER bytes.
    // read_unaligned copies its C-layout scalar/pointer fields without requiring
    // alignment or dereferencing the contained pointer. sid_at_pointer below
    // validates that pointer against this same owned buffer before reading bytes.
    let user_info = unsafe { std::ptr::read_unaligned(user.bytes().as_ptr().cast::<TOKEN_USER>()) };
    if user.sid_at_pointer(user_info.User.Sid)? != SYSTEM_SID {
        return Err(IdentityError::Policy(IdentityPolicy::LocalSystemRequired));
    }
    let service_sid = lookup_service_sid()?;
    let groups = token_information(&token, TokenGroups, IdentityOperation::ReadProcessGroups)?;
    if !has_enabled_service_group(&groups, &service_sid)? {
        return Err(IdentityError::Policy(IdentityPolicy::ServiceSidRequired));
    }
    token.close()?;
    // Reject a newly active impersonation context as well. No routine here
    // impersonates, reverts, duplicates a token or requests additional privilege.
    reject_thread_impersonation()?;
    Ok(service_sid)
}

fn reject_thread_impersonation() -> Result<(), IdentityError> {
    let mut handle = HANDLE::default();
    // SAFETY: GetCurrentThread returns a borrowed pseudo-handle that is never
    // closed. OpenThreadToken requests only QUERY; open-as-self uses process
    // access checking but does NOT replace/ignore the thread's effective identity.
    // Output is initialized aligned storage valid for the synchronous call.
    let result = unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, true, &mut handle) };
    match result {
        Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_TOKEN.0) => Ok(()),
        Err(error) => Err(os_error(IdentityOperation::OpenThreadToken, error)),
        Ok(()) => {
            OwnedToken::from_acquired(handle)?.close()?;
            Err(IdentityError::Policy(
                IdentityPolicy::ImpersonationForbidden,
            ))
        }
    }
}

fn lookup_service_sid() -> Result<[u8; 32], IdentityError> {
    let operation = IdentityOperation::LookupServiceSid;
    // The fixed service namespace has a 32-byte SID. cbSid may remain the
    // supplied capacity on successful lookup, so use that exact bounded shape.
    let mut sid = NativeBuffer::new(32, operation)?;
    let mut sid_length = 32_u32;
    let mut domain = [0xffff_u16; 64];
    let mut domain_length = 64_u32;
    let mut usage = SID_NAME_USE::default();
    // SAFETY: NULL system name means local lookup; fully-qualified service name
    // is static, with no caller/domain input. SID storage is usize-aligned and
    // has exactly 32 writable initialized bytes for this fixed service SID.
    // Domain is 64 writable UTF-16 units. Length/use outputs are aligned,
    // separate and initialized. No native pointer is retained after return.
    unsafe {
        LookupAccountNameW(
            PCWSTR::null(),
            SERVICE_ACCOUNT,
            Some(PSID(sid.as_mut_ptr())),
            &mut sid_length,
            Some(PWSTR(domain.as_mut_ptr())),
            &mut domain_length,
            &mut usage,
        )
    }
    .map_err(|error| os_error(operation, error))?;
    if sid_length != 32 || domain_length > 64 || usage != SidTypeWellKnownGroup {
        return Err(IdentityError::Policy(IdentityPolicy::InvalidServiceSid));
    }
    let domain_end = domain
        .iter()
        .position(|unit| *unit == 0)
        .ok_or(malformed(operation))?;
    let domain_name =
        String::from_utf16(&domain[..domain_end]).map_err(|_| malformed(operation))?;
    if !domain_name.eq_ignore_ascii_case("NT SERVICE") {
        return Err(IdentityError::Policy(IdentityPolicy::InvalidServiceSid));
    }
    let bytes = &sid.bytes()[..32];
    if !is_service_sid(bytes) {
        return Err(IdentityError::Policy(IdentityPolicy::InvalidServiceSid));
    }
    let mut result = [0_u8; 32];
    result.copy_from_slice(bytes);
    Ok(result)
}

fn has_enabled_service_group(
    buffer: &NativeBuffer,
    service_sid: &[u8; 32],
) -> Result<bool, IdentityError> {
    let operation = IdentityOperation::ReadProcessGroups;
    let bytes = buffer.bytes();
    let count_bytes: [u8; 4] = bytes
        .get(..4)
        .ok_or(malformed(operation))?
        .try_into()
        .map_err(|_| malformed(operation))?;
    let count =
        usize::try_from(u32::from_ne_bytes(count_bytes)).map_err(|_| malformed(operation))?;
    let start = mem::offset_of!(TOKEN_GROUPS, Groups);
    let size = mem::size_of::<SID_AND_ATTRIBUTES>();
    let end = count
        .checked_mul(size)
        .and_then(|length| start.checked_add(length))
        .ok_or(malformed(operation))?;
    let entries = bytes.get(start..end).ok_or(malformed(operation))?;
    let mut found = false;
    for entry in entries.chunks_exact(size) {
        // SAFETY: entry is exactly the Windows C-layout SID_AND_ATTRIBUTES size
        // inside this initialized token buffer. Unaligned copy reads only raw
        // scalar/pointer fields; SID pointers are never dereferenced directly.
        let attributes =
            unsafe { std::ptr::read_unaligned(entry.as_ptr().cast::<SID_AND_ATTRIBUTES>()) };
        if buffer.sid_at_pointer(attributes.Sid)? == service_sid
            && enabled_service_group(attributes.Attributes)
        {
            found = true;
        }
    }
    Ok(found)
}

struct OwnedToken {
    handle: Option<HANDLE>,
    _thread_affinity: PhantomData<Rc<()>>,
}

impl OwnedToken {
    fn process() -> Result<Self, IdentityError> {
        let mut handle = HANDLE::default();
        // SAFETY: current-process pseudo-handle is borrowed, never closed. QUERY
        // only, initialized aligned output. Returned real token handle is adopted
        // uniquely; no token manipulation/elevation/impersonation is requested.
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut handle) }
            .map_err(|error| os_error(IdentityOperation::OpenProcessToken, error))?;
        Self::from_acquired(handle)
    }

    fn from_acquired(handle: HANDLE) -> Result<Self, IdentityError> {
        if handle.is_invalid() {
            return Err(malformed(IdentityOperation::OpenProcessToken));
        }
        Ok(Self {
            handle: Some(handle),
            _thread_affinity: PhantomData,
        })
    }

    fn get(&self) -> Result<HANDLE, IdentityError> {
        self.handle.ok_or(IdentityError::HandleAlreadyReleased)
    }

    fn close(mut self) -> Result<(), IdentityError> {
        let handle = self
            .handle
            .take()
            .ok_or(IdentityError::HandleAlreadyReleased)?;
        // SAFETY: real uniquely owned token handle, not a process/thread pseudo
        // handle; all queries have returned. Taking first prevents double-close.
        unsafe { CloseHandle(handle) }
            .map_err(|error| os_error(IdentityOperation::CloseToken, error))
    }
}

impl Drop for OwnedToken {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            // SAFETY: sole remaining real token handle with no pending queries.
            // Drop is an abnormal-path best-effort release and cannot report errors.
            let _ = unsafe { CloseHandle(handle) };
        }
    }
}

struct NativeBuffer {
    words: Vec<usize>,
    length: usize,
    operation: IdentityOperation,
}

impl NativeBuffer {
    fn new(length: u32, operation: IdentityOperation) -> Result<Self, IdentityError> {
        let length = usize::try_from(length).map_err(|_| malformed(operation))?;
        if length == 0 || length > MAX_TOKEN_BYTES {
            return Err(malformed(operation));
        }
        Ok(Self {
            words: vec![0_usize; length.div_ceil(mem::size_of::<usize>())],
            length,
            operation,
        })
    }

    fn as_mut_ptr(&mut self) -> *mut std::ffi::c_void {
        self.words.as_mut_ptr().cast()
    }

    fn bytes(&self) -> &[u8] {
        // SAFETY: every word is initialized. Constructor allocates at least
        // length bytes and length is only reduced after native reads. Byte slices
        // may view usize storage without alignment restrictions; exclusive writes
        // only occur before borrowing this slice, and no reallocation occurs.
        unsafe { std::slice::from_raw_parts(self.words.as_ptr().cast(), self.length) }
    }

    fn sid_at_pointer(&self, sid: PSID) -> Result<&[u8], IdentityError> {
        // Compare pointer addresses only; never follow an arbitrary returned
        // pointer. The full SID must live inside this GetTokenInformation buffer.
        let base = self.words.as_ptr() as usize;
        let offset = (sid.0 as usize)
            .checked_sub(base)
            .ok_or(malformed(self.operation))?;
        self.bytes()
            .get(offset..)
            .and_then(sid_prefix)
            .ok_or(malformed(self.operation))
    }
}

fn token_information(
    token: &OwnedToken,
    class: TOKEN_INFORMATION_CLASS,
    operation: IdentityOperation,
) -> Result<NativeBuffer, IdentityError> {
    let mut length = 0_u32;
    // SAFETY: live QUERY token, private fixed information class, no output buffer
    // for the documented sizing query. length is initialized exclusive u32 data.
    let probe = unsafe { GetTokenInformation(token.get()?, class, None, 0, &mut length) };
    match probe {
        Err(error) if error.code() == HRESULT::from_win32(ERROR_INSUFFICIENT_BUFFER.0) => {}
        Err(error) => return Err(os_error(operation, error)),
        Ok(()) => return Err(malformed(operation)),
    }
    let mut buffer = NativeBuffer::new(length, operation)?;
    let mut returned = 0_u32;
    // SAFETY: live borrowed token, same info class. Storage is usize-aligned,
    // initialized, exclusive and allocated for at least length bytes (<=64KiB).
    // Windows writes at most the supplied byte count and retains no pointers to
    // the allocation; contained SID pointers remain valid only while it is owned.
    // A size-change race fails rather than using partial output or unbounded retry.
    unsafe {
        GetTokenInformation(
            token.get()?,
            class,
            Some(buffer.as_mut_ptr()),
            length,
            &mut returned,
        )
    }
    .map_err(|error| os_error(operation, error))?;
    if returned == 0 || returned > length {
        return Err(malformed(operation));
    }
    buffer.length = returned as usize;
    Ok(buffer)
}

fn os_error(operation: IdentityOperation, error: WindowsError) -> IdentityError {
    IdentityError::WindowsCall {
        operation,
        hresult: error.code().0,
    }
}

fn malformed(operation: IdentityOperation) -> IdentityError {
    IdentityError::MalformedNativeData { operation }
}
