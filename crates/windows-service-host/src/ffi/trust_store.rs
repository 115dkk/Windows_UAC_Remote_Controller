// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed service-only NTFS journal FILE adapter, not an enrollment/parser API.
//!
//! The same exclusive synchronous handle is validated and used for all data IO.
//! Parent/ancestor pins omit share-delete for its entire lifetime. A successful
//! flush is an OS file-flush acknowledgment, not hardware power-loss proof or
//! directory-entry durability. No truncate, repair, delete, rename or compaction.
use super::{
    OwnedHandle, Wide,
    filesystem::{
        create_private_directory, inspect_open_handle, open_checked, pin_program_data_root,
        require_ntfs,
    },
    security::{OwnServiceSid, require_elevated},
};
use crate::{
    INSTALLATION_FOLDER, ServiceError,
    policy::{self, ObjectPolicy},
};
use std::{
    cell::Cell,
    fmt,
    mem::{ManuallyDrop, size_of},
    net::SocketAddr,
    path::PathBuf,
    ptr,
    rc::Rc,
};
use windows::{
    Win32::{
        Foundation::{CloseHandle, ERROR_FILE_NOT_FOUND, ERROR_NO_MORE_FILES},
        Security::SECURITY_ATTRIBUTES,
        Storage::FileSystem::{
            CREATE_NEW, CreateFileW, FILE_ATTRIBUTE_ARCHIVE, FILE_ATTRIBUTE_NORMAL,
            FILE_ATTRIBUTE_NOT_CONTENT_INDEXED, FILE_BEGIN, FILE_END, FILE_FLAG_OPEN_REPARSE_POINT,
            FILE_FLAG_WRITE_THROUGH, FILE_FLAGS_AND_ATTRIBUTES, FILE_GENERIC_READ,
            FILE_GENERIC_WRITE, FILE_SHARE_MODE, FindClose, FindFirstFileW, FindNextFileW,
            FlushFileBuffers, GetFileSizeEx, MOVEFILE_REPLACE_EXISTING, MOVEFILE_WRITE_THROUGH,
            MoveFileExW, OPEN_EXISTING, ReadFile, SetFilePointerEx, WIN32_FIND_DATAW, WriteFile,
        },
    },
    core::HRESULT,
};

const DIRECTORY_NAME: &str = "trust";
const FILE_NAME: &str = "devices.journal";
const RELAY_FILE_NAME: &str = "relay-endpoint.v1";
const RELAY_STAGING_FILE_NAME: &str = "relay-endpoint.v1.staging";
const BOOTSTRAP_FILE_NAME: &str = "initial-registry-permit.v1";
const BOOTSTRAP_PENDING: &[u8; 8] = b"UACREG1P";
const BOOTSTRAP_CONSUMED: &[u8; 8] = b"UACREG1C";
const MAX_RELAY_FILE_BYTES: u64 = 48;
pub(crate) const MAX_TRUST_FILE_BYTES: u64 = 4 * 1024 * 1024;
const IO_CHUNK_BYTES: usize = 64 * 1024;
const MAX_DIRECTORY_ENTRIES: usize = 7;
type Poison = Rc<Cell<bool>>;

#[derive(Clone, Copy)]
enum AccessContext {
    Service,
    Elevated,
}

fn unavailable() -> ServiceError {
    ServiceError::RegistryUnavailable
}
fn service_context() -> Result<(), ServiceError> {
    windows_identity::verify_service_context().map_err(|_| ServiceError::IdentityUnavailable)
}

/// Only elevated installation creates this fixed directory. The product parent
/// was provisioned by install's preceding activity-storage step; it is never
/// created or repaired from the service-open path.
pub(crate) fn provision_trust_directory() -> Result<(), ServiceError> {
    require_elevated()?;
    let sid = OwnServiceSid::lookup()?;
    let mut trusted = policy::trusted_system_sids();
    trusted.push(sid.bytes());
    let descriptor = sid.private_descriptor()?;
    let (program_data, mut pins) = pin_program_data_root(&trusted)?;
    let result = (|| {
        let product = program_data.join(INSTALLATION_FOLDER);
        pins.push(open_checked(
            &product,
            true,
            ObjectPolicy::PrivateData,
            &trusted,
        )?);
        let directory = product.join(DIRECTORY_NAME);
        create_private_directory(&directory, &descriptor)?;
        let pin = open_checked(&directory, true, ObjectPolicy::PrivateData, &trusted)?;
        pins.push(pin);
        let pin = pins.last().ok_or_else(unavailable)?;
        let info = inspect_open_handle(pin, &directory, true, ObjectPolicy::PrivateData, &trusted)?;
        require_ntfs(pin, info.dwVolumeSerialNumber)?;
        Ok(())
    })();
    let poison = Rc::new(Cell::new(false));
    for pin in pins.into_iter().rev() {
        close_handle(pin, &poison);
    }
    if poison.get() {
        return Err(unavailable());
    }
    // No journal creation, listing, key creation or enrollment decision here.
    result
}

/// Native fixed private parent ownership, not evidence that enrollment is fresh.
/// No path/raw-handle getter, Clone, cross-thread unsafe Send/Sync or IPC export.
pub(crate) struct TrustDirectory {
    path: PathBuf,
    trusted: Vec<Vec<u8>>,
    sid: OwnServiceSid,
    pins: Vec<OwnedHandle>,
    poison: Poison,
    context: AccessContext,
}
impl fmt::Debug for TrustDirectory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TrustDirectory([redacted])")
    }
}
impl TrustDirectory {
    /// Explicit elevated reinstall may finish an interrupted first bootstrap.
    /// Existing (even corrupt/empty) journals are never replaced by this grant.
    pub(crate) fn authorize_missing_registry_bootstrap(&mut self) -> Result<(), ServiceError> {
        if !matches!(self.context, AccessContext::Elevated) {
            return Err(unavailable());
        }
        if !self.is_empty_registry_absent()? {
            return Ok(());
        }
        self.operate(|owner| {
            let file = match owner.open_named(BOOTSTRAP_FILE_NAME, false)? {
                Some(file) => {
                    owner.read_bootstrap_permit(&file)?;
                    file
                }
                None => owner
                    .open_named(BOOTSTRAP_FILE_NAME, true)?
                    .ok_or_else(unavailable)?,
            };
            owner.inspect_named_file(&file, BOOTSTRAP_FILE_NAME, 8)?;
            write_all_and_flush(&file, BOOTSTRAP_PENDING)?;
            if !owner.read_bootstrap_permit(&file)? {
                return Err(unavailable());
            }
            file.close()
        })
    }

    /// Consume before any registry creation. A crash after consumption requires
    /// a new elevated reinstall, not an automatic reset on a later boot.
    pub(crate) fn take_missing_registry_bootstrap(&mut self) -> Result<bool, ServiceError> {
        if !matches!(self.context, AccessContext::Service) {
            return Err(unavailable());
        }
        self.operate(|owner| {
            let Some(file) = owner.open_named(BOOTSTRAP_FILE_NAME, false)? else {
                return Ok(false);
            };
            let pending = owner.read_bootstrap_permit(&file)?;
            if pending {
                write_all_and_flush(&file, BOOTSTRAP_CONSUMED)?;
                if owner.read_bootstrap_permit(&file)? {
                    return Err(unavailable());
                }
            }
            file.close()?;
            Ok(pending)
        })
    }

    fn read_bootstrap_permit(&self, file: &TrustHandle) -> Result<bool, ServiceError> {
        let size = self.inspect_named_file(file, BOOTSTRAP_FILE_NAME, 8)?;
        let bytes = read_exact_bounded(file, size, 8)?;
        self.inspect_named_file(file, BOOTSTRAP_FILE_NAME, 8)?;
        parse_bootstrap_permit(&bytes).ok_or_else(unavailable)
    }

    pub(crate) fn open_for_service() -> Result<Self, ServiceError> {
        service_context()?;
        Self::open(AccessContext::Service)
    }

    pub(crate) fn open_for_elevated_configuration() -> Result<Self, ServiceError> {
        require_elevated()?;
        Self::open(AccessContext::Elevated)
    }

    fn open(context: AccessContext) -> Result<Self, ServiceError> {
        let sid = OwnServiceSid::lookup().map_err(|_| unavailable())?;
        let mut trusted = policy::trusted_system_sids();
        trusted.push(sid.bytes());
        let (program_data, pins) = pin_program_data_root(&trusted).map_err(|_| unavailable())?;
        let product = program_data.join(INSTALLATION_FOLDER);
        let mut owner = Self {
            path: product.join(DIRECTORY_NAME),
            trusted,
            sid,
            pins,
            poison: Rc::new(Cell::new(false)),
            context,
        };
        owner.pins.push(
            open_checked(&product, true, ObjectPolicy::PrivateData, &owner.trusted)
                .map_err(|_| ServiceError::RegistryProvisioningRequired)?,
        );
        owner.pins.push(
            open_checked(&owner.path, true, ObjectPolicy::PrivateData, &owner.trusted)
                .map_err(|_| ServiceError::RegistryProvisioningRequired)?,
        );
        let directory = owner.pins.last().ok_or_else(unavailable)?;
        let info = inspect_open_handle(
            directory,
            &owner.path,
            true,
            ObjectPolicy::PrivateData,
            &owner.trusted,
        )
        .map_err(|_| unavailable())?;
        // Establish the supported volume before reporting absent state or
        // allowing CREATE_NEW; absence on an unsupported filesystem is not fresh.
        require_ntfs(directory, info.dwVolumeSerialNumber)?;
        owner.check_context()?;
        Ok(owner)
    }
    fn check_context(&self) -> Result<(), ServiceError> {
        if self.poison.get() {
            return Err(unavailable());
        }
        let result = match self.context {
            AccessContext::Service => service_context(),
            AccessContext::Elevated => require_elevated(),
        };
        result.inspect_err(|_| self.poison.set(true))
    }
    fn operate<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        self.check_context()?;
        let result = action(self).and_then(|value| {
            self.check_context()?;
            Ok(value)
        });
        if result.is_err() {
            self.poison.set(true);
        }
        result
    }

    /// A narrow storage observation only. true means the exact journal was
    /// absent and the pinned directory contained only the optional relay file.
    /// It is NOT pairing/bootstrap authorization and cannot justify recreating a
    /// PC key. Unknown entries, a leftover staging file, access failures and
    /// races are errors, never absence.
    pub(crate) fn is_empty_registry_absent(&mut self) -> Result<bool, ServiceError> {
        self.operate(|owner| {
            if let Some(file) = owner.open_exact(false)? {
                owner.inspect_file(&file)?;
                file.close()?;
                return Ok(false);
            }
            owner.require_known_directory_entries(false)?;
            if let Some(file) = owner.open_named(RELAY_FILE_NAME, false)? {
                owner.inspect_named_file(&file, RELAY_FILE_NAME, MAX_RELAY_FILE_BYTES)?;
                file.close()?;
            }
            // Recheck exact absence after enumeration. CREATE_NEW remains the
            // independent no-overwrite gate; no observation grants mutation.
            if let Some(file) = owner.open_exact(false)? {
                owner.inspect_file(&file)?;
                file.close()?;
                return Err(unavailable());
            }
            Ok(true)
        })
    }

    /// Read by the enrollment orchestration before each invitation.
    pub(crate) fn read_relay_endpoint(&mut self) -> Result<Option<SocketAddr>, ServiceError> {
        self.operate(|owner| {
            owner.require_known_directory_entries(false)?;
            let Some(file) = owner.open_named(RELAY_FILE_NAME, false)? else {
                return Ok(None);
            };
            let size = owner.inspect_named_file(&file, RELAY_FILE_NAME, MAX_RELAY_FILE_BYTES)?;
            let bytes = read_exact_bounded(&file, size, MAX_RELAY_FILE_BYTES)?;
            owner.inspect_named_file(&file, RELAY_FILE_NAME, MAX_RELAY_FILE_BYTES)?;
            file.close()?;
            parse_relay_endpoint(&bytes).map(Some)
        })
    }

    pub(crate) fn write_relay_endpoint(
        &mut self,
        endpoint: SocketAddr,
    ) -> Result<(), ServiceError> {
        if !matches!(self.context, AccessContext::Elevated) {
            return Err(unavailable());
        }
        validate_relay_endpoint(endpoint)?;
        let bytes = format!("{endpoint}\n").into_bytes();
        if bytes.len() as u64 > MAX_RELAY_FILE_BYTES {
            return Err(unavailable());
        }
        self.operate(|owner| {
            owner.require_known_directory_entries(false)?;
            if owner.open_named(RELAY_STAGING_FILE_NAME, false)?.is_some() {
                return Err(unavailable());
            }
            let staging = owner
                .open_named(RELAY_STAGING_FILE_NAME, true)?
                .ok_or_else(unavailable)?;
            if owner.inspect_named_file(&staging, RELAY_STAGING_FILE_NAME, MAX_RELAY_FILE_BYTES)?
                != 0
            {
                return Err(unavailable());
            }
            write_all_and_flush(&staging, &bytes)?;
            owner.inspect_named_file(&staging, RELAY_STAGING_FILE_NAME, MAX_RELAY_FILE_BYTES)?;
            staging.close()?;

            let source =
                Wide::new(owner.named_path(RELAY_STAGING_FILE_NAME)).map_err(|_| unavailable())?;
            let destination =
                Wide::new(owner.named_path(RELAY_FILE_NAME)).map_err(|_| unavailable())?;
            // SAFETY: both names are fixed children of retained, checked,
            // non-reparse private parent pins. The source was CREATE_NEW with a
            // private descriptor, flushed, inspected and closed above. The fixed
            // destination is replaced on the same NTFS volume with write-through.
            unsafe {
                MoveFileExW(
                    source.ptr(),
                    destination.ptr(),
                    MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
                )
            }
            .map_err(|_| unavailable())?;

            let file = owner
                .open_named(RELAY_FILE_NAME, false)?
                .ok_or_else(unavailable)?;
            let size = owner.inspect_named_file(&file, RELAY_FILE_NAME, MAX_RELAY_FILE_BYTES)?;
            let stored = read_exact_bounded(&file, size, MAX_RELAY_FILE_BYTES)?;
            owner.inspect_named_file(&file, RELAY_FILE_NAME, MAX_RELAY_FILE_BYTES)?;
            file.close()?;
            if stored != bytes || parse_relay_endpoint(&stored)? != endpoint {
                return Err(unavailable());
            }
            owner.require_known_directory_entries(false)
        })
    }
    pub(crate) fn open_existing(mut self) -> Result<ServiceTrustFile, ServiceError> {
        let file = self.operate(|owner| {
            let file = owner.open_exact(false)?.ok_or_else(unavailable)?;
            owner.inspect_file(&file)?;
            Ok(file)
        })?;
        Ok(ServiceTrustFile {
            file,
            directory: self,
        })
    }
    /// Explicit no-overwrite creation only. A newly created empty file is not a
    /// registry initialization or enrollment grant. Failure may leave a file;
    /// no rollback-by-path or automatic retry is performed.
    pub(crate) fn create_new(mut self) -> Result<ServiceTrustFile, ServiceError> {
        let file = self.operate(|owner| {
            let file = owner.open_exact(true)?.ok_or_else(unavailable)?;
            if owner.inspect_file(&file)? != 0 {
                return Err(unavailable());
            }
            Ok(file)
        })?;
        Ok(ServiceTrustFile {
            file,
            directory: self,
        })
    }
    fn named_path(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }
    fn open_exact(&self, create: bool) -> Result<Option<TrustHandle>, ServiceError> {
        self.open_named(FILE_NAME, create)
    }
    fn open_named(&self, name: &str, create: bool) -> Result<Option<TrustHandle>, ServiceError> {
        let path = Wide::new(self.named_path(name)).map_err(|_| unavailable())?;
        let descriptor = if create {
            Some(self.sid.private_descriptor().map_err(|_| unavailable())?)
        } else {
            None
        };
        let attributes = descriptor.as_ref().map(|descriptor| SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.ptr().0,
            bInheritHandle: false.into(),
        });
        let (access, sharing, flags) = file_open_options();
        // SAFETY: fixed path under retained non-reparse private parent pins;
        // exclusive share0 and synchronous (no OVERLAPPED) read/write handle.
        // Final reparse points are opened, not followed. CREATE_NEW never opens
        // an existing alias and receives the private descriptor atomically.
        let result = unsafe {
            CreateFileW(
                path.ptr(),
                access,
                sharing,
                attributes.as_ref().map(ptr::from_ref),
                if create { CREATE_NEW } else { OPEN_EXISTING },
                flags,
                None,
            )
        };
        match result {
            Ok(handle) => Ok(Some(TrustHandle {
                handle: Some(OwnedHandle(handle)),
                poison: Rc::clone(&self.poison),
            })),
            Err(error)
                if !create && error.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) =>
            {
                Ok(None)
            }
            Err(_) => Err(unavailable()),
        }
    }
    fn inspect_file(&self, file: &TrustHandle) -> Result<u64, ServiceError> {
        self.inspect_named_file(file, FILE_NAME, MAX_TRUST_FILE_BYTES)
    }
    fn inspect_named_file(
        &self,
        file: &TrustHandle,
        name: &str,
        maximum: u64,
    ) -> Result<u64, ServiceError> {
        let handle = file.handle()?;
        let info = inspect_open_handle(
            handle,
            &self.named_path(name),
            false,
            ObjectPolicy::PrivateData,
            &self.trusted,
        )
        .map_err(|_| unavailable())?;
        if !regular_file_attributes(info.dwFileAttributes, info.nNumberOfLinks) {
            return Err(unavailable());
        }
        require_ntfs(handle, info.dwVolumeSerialNumber)?;
        let size = file_size(handle)?;
        let metadata_size = (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow);
        if size != metadata_size || size > maximum {
            return Err(unavailable());
        }
        Ok(size)
    }
    fn require_known_directory_entries(&self, allow_staging: bool) -> Result<(), ServiceError> {
        let pattern = Wide::new(self.path.join("*")).map_err(|_| unavailable())?;
        let mut data = WIN32_FIND_DATAW::default();
        // SAFETY: fixed wildcard below our pinned private directory only. No
        // entry paths are opened, followed, logged or used as trust identities.
        let raw = match unsafe { FindFirstFileW(pattern.ptr(), &mut data) } {
            Ok(raw) => raw,
            Err(error) if error.code() == HRESULT::from_win32(ERROR_FILE_NOT_FOUND.0) => {
                return Ok(());
            }
            Err(_) => return Err(unavailable()),
        };
        let search = SearchHandle {
            raw,
            poison: Rc::clone(&self.poison),
        };
        let result = (|| {
            for _ in 0..MAX_DIRECTORY_ENTRIES {
                let end = data
                    .cFileName
                    .iter()
                    .position(|unit| *unit == 0)
                    .ok_or_else(unavailable)?;
                let name = String::from_utf16(&data.cFileName[..end]).map_err(|_| unavailable())?;
                if name != "."
                    && name != ".."
                    && name != FILE_NAME
                    && name != RELAY_FILE_NAME
                    && name != BOOTSTRAP_FILE_NAME
                    && !(allow_staging && name == RELAY_STAGING_FILE_NAME)
                {
                    return Err(unavailable());
                }
                // SAFETY: live owned search handle and bounded initialized
                // native output. Only actual NO_MORE_FILES ends enumeration.
                match unsafe { FindNextFileW(search.raw, &mut data) } {
                    Ok(()) => (),
                    Err(error) if error.code() == HRESULT::from_win32(ERROR_NO_MORE_FILES.0) => {
                        return Ok(());
                    }
                    Err(_) => return Err(unavailable()),
                }
            }
            Err(unavailable())
        })();
        drop(search);
        if self.poison.get() {
            return Err(unavailable());
        }
        result
    }
}
impl Drop for TrustDirectory {
    fn drop(&mut self) {
        for pin in self.pins.drain(..).rev() {
            close_handle(pin, &self.poison);
        }
    }
}

/// Append-only file access, not a parser or authorization capability. A failed
/// read/write/flush/context/close latches poison; no operation resets it. Root's
/// durable registry owner must stop on errors and never reopen as fresh state.
pub(crate) struct ServiceTrustFile {
    file: TrustHandle,
    directory: TrustDirectory,
}
impl fmt::Debug for ServiceTrustFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ServiceTrustFile([redacted])")
    }
}
impl ServiceTrustFile {
    pub(crate) fn read_relay_endpoint(&mut self) -> Result<Option<SocketAddr>, ServiceError> {
        self.directory.read_relay_endpoint()
    }

    fn operate<T>(
        &mut self,
        action: impl FnOnce(&mut Self) -> Result<T, ServiceError>,
    ) -> Result<T, ServiceError> {
        self.directory.check_context()?;
        let result = action(self).and_then(|value| {
            self.directory.check_context()?;
            Ok(value)
        });
        if result.is_err() {
            self.directory.poison.set(true);
        }
        result
    }
    pub(crate) fn read_bounded(&mut self) -> Result<Vec<u8>, ServiceError> {
        self.operate(|owner| {
            let before = owner.directory.inspect_file(&owner.file)?;
            let handle = owner.file.handle()?;
            seek(handle, FILE_BEGIN, 0)?;
            // One extra byte detects growth; max allocation/read is4MiB+1.
            let limit = usize::try_from(before).map_err(|_| unavailable())? + 1;
            let mut bytes = Vec::with_capacity(limit);
            let mut buffer = [0u8; IO_CHUNK_BYTES];
            while bytes.len() < limit {
                let count = (limit - bytes.len()).min(buffer.len());
                let mut received = 0;
                // SAFETY: same owned exclusive synchronous file, initialized
                // bounded slice and scalar output; no native pointer escapes.
                unsafe {
                    ReadFile(
                        handle.0,
                        Some(&mut buffer[..count]),
                        Some(&mut received),
                        None,
                    )
                }
                .map_err(|_| unavailable())?;
                if received as usize > count {
                    return Err(unavailable());
                }
                if received == 0 {
                    break;
                }
                bytes.extend_from_slice(&buffer[..received as usize]);
            }
            let after = owner.directory.inspect_file(&owner.file)?;
            if !stable_read(before, bytes.len(), after) {
                return Err(unavailable());
            }
            // Empty/partial/malformed journal content is returned unchanged to
            // ROOT's parser. This adapter never treats empty as trusted/fresh.
            Ok(bytes)
        })
    }
    pub(crate) fn append_and_flush(
        &mut self,
        expected_len: u64,
        bytes: &[u8],
    ) -> Result<u64, ServiceError> {
        self.operate(|owner| {
            let target = appended_length(expected_len, bytes.len()).ok_or_else(unavailable)?;
            if owner.directory.inspect_file(&owner.file)? != expected_len {
                return Err(unavailable());
            }
            let handle = owner.file.handle()?;
            seek(handle, FILE_END, expected_len)?;
            let mut offset = 0;
            while offset < bytes.len() {
                let count = (bytes.len() - offset).min(IO_CHUNK_BYTES);
                let mut written = 0;
                // SAFETY: fixed owned synchronous handle at checked EOF, bounded
                // immutable caller-owned bytes and exclusive scalar output. The
                // API retains neither pointer. Partial writes advance once only.
                unsafe {
                    WriteFile(
                        handle.0,
                        Some(&bytes[offset..offset + count]),
                        Some(&mut written),
                        None,
                    )
                }
                .map_err(|_| unavailable())?;
                if written == 0 || written as usize > count {
                    return Err(unavailable());
                }
                offset += written as usize;
            }
            // SAFETY: same still-exclusive file; acknowledge only successful
            // full writes AND actual OS file flush. Empty appends still flush.
            unsafe { FlushFileBuffers(handle.0) }.map_err(|_| unavailable())?;
            if owner.directory.inspect_file(&owner.file)? != target {
                return Err(unavailable());
            }
            Ok(target)
        })
    }
    /// Consumes all file/parent ownership. Even a failed context check still
    /// closes owned resources; failure does not permit another operation or
    /// pretend that a partial append was rolled back. Drop is only a fallback.
    pub(crate) fn close(self) -> Result<(), ServiceError> {
        let poison = Rc::clone(&self.directory.poison);
        // Closing is downward-only even after poison. Still observe actual
        // context rather than skipping the per-operation check in that state.
        let context = service_context().inspect_err(|_| poison.set(true));
        drop(self);
        if poison.get() {
            return Err(unavailable());
        }
        context
    }
}

struct TrustHandle {
    handle: Option<OwnedHandle>,
    poison: Poison,
}
impl TrustHandle {
    fn handle(&self) -> Result<&OwnedHandle, ServiceError> {
        self.handle.as_ref().ok_or_else(unavailable)
    }
    fn close(self) -> Result<(), ServiceError> {
        let poison = Rc::clone(&self.poison);
        drop(self);
        if poison.get() {
            Err(unavailable())
        } else {
            Ok(())
        }
    }
}
impl Drop for TrustHandle {
    fn drop(&mut self) {
        if let Some(handle) = self.handle.take() {
            close_handle(handle, &self.poison);
        }
    }
}
fn close_handle(handle: OwnedHandle, poison: &Poison) {
    let handle = ManuallyDrop::new(handle);
    // SAFETY: exclusively owned real kernel handle, no asynchronous IO or borrows
    // remain. ManuallyDrop prevents the existing guard from closing it twice.
    // Failure is latched, not retried against a potentially recycled handle value.
    if unsafe { CloseHandle(handle.0) }.is_err() {
        poison.set(true);
    }
}
struct SearchHandle {
    raw: windows::Win32::Foundation::HANDLE,
    poison: Poison,
}
impl Drop for SearchHandle {
    fn drop(&mut self) {
        // SAFETY: uniquely owned FindFirstFile output, no remaining search calls;
        // FindClose (not CloseHandle) is its documented destructor.
        if unsafe { FindClose(self.raw) }.is_err() {
            self.poison.set(true);
        }
    }
}
fn file_size(handle: &OwnedHandle) -> Result<u64, ServiceError> {
    let mut size = 0;
    // SAFETY: live same file handle and initialized exclusive signed64 output.
    unsafe { GetFileSizeEx(handle.0, &mut size) }.map_err(|_| unavailable())?;
    u64::try_from(size).map_err(|_| unavailable())
}
fn seek(
    handle: &OwnedHandle,
    origin: windows::Win32::Storage::FileSystem::SET_FILE_POINTER_MOVE_METHOD,
    expected: u64,
) -> Result<(), ServiceError> {
    let mut offset = 0;
    // SAFETY: same exclusive synchronous handle; only fixed BEGIN0 or END0
    // positioning, never a caller-selected overwrite offset.
    unsafe { SetFilePointerEx(handle.0, 0, Some(&mut offset), origin) }
        .map_err(|_| unavailable())?;
    if u64::try_from(offset).ok() != Some(expected) {
        return Err(unavailable());
    }
    Ok(())
}
fn file_open_options() -> (u32, FILE_SHARE_MODE, FILE_FLAGS_AND_ATTRIBUTES) {
    (
        (FILE_GENERIC_READ | FILE_GENERIC_WRITE).0,
        FILE_SHARE_MODE(0),
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_WRITE_THROUGH,
    )
}
fn regular_file_attributes(attributes: u32, links: u32) -> bool {
    let allowed =
        (FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED).0;
    let normal_is_alone =
        attributes & FILE_ATTRIBUTE_NORMAL.0 == 0 || attributes == FILE_ATTRIBUTE_NORMAL.0;
    links == 1 && attributes != 0 && attributes & !allowed == 0 && normal_is_alone
}
fn appended_length(expected: u64, additional: usize) -> Option<u64> {
    if expected > MAX_TRUST_FILE_BYTES {
        return None;
    }
    let total = expected.checked_add(u64::try_from(additional).ok()?)?;
    (total <= MAX_TRUST_FILE_BYTES).then_some(total)
}
fn stable_read(before: u64, received: usize, after: u64) -> bool {
    before <= MAX_TRUST_FILE_BYTES
        && before == after
        && u64::try_from(received).ok() == Some(before)
}

/// Reads exactly `size` bytes (bounded by `maximum`) from the start of a
/// small protected configuration file. One extra byte detects growth.
fn read_exact_bounded(
    file: &TrustHandle,
    size: u64,
    maximum: u64,
) -> Result<Vec<u8>, ServiceError> {
    if size > maximum || maximum > MAX_TRUST_FILE_BYTES {
        return Err(unavailable());
    }
    let expected = usize::try_from(size).map_err(|_| unavailable())?;
    let handle = file.handle()?;
    seek(handle, FILE_BEGIN, 0)?;
    let limit = expected + 1;
    let mut bytes = Vec::with_capacity(limit);
    let mut buffer = [0u8; 64];
    while bytes.len() < limit {
        let count = (limit - bytes.len()).min(buffer.len());
        let mut received = 0;
        // SAFETY: same owned exclusive synchronous file, initialized bounded
        // slice and scalar output; no native pointer escapes.
        unsafe {
            ReadFile(
                handle.0,
                Some(&mut buffer[..count]),
                Some(&mut received),
                None,
            )
        }
        .map_err(|_| unavailable())?;
        if received as usize > count {
            return Err(unavailable());
        }
        if received == 0 {
            break;
        }
        bytes.extend_from_slice(&buffer[..received as usize]);
    }
    if bytes.len() != expected {
        return Err(unavailable());
    }
    Ok(bytes)
}

/// Writes an empty file or an exact-size fixed permit update; never truncates.
/// Partial writes advance once only; any failure poisons the owner.
fn write_all_and_flush(file: &TrustHandle, bytes: &[u8]) -> Result<(), ServiceError> {
    let handle = file.handle()?;
    let size = file_size(handle)?;
    if size != 0 && size != bytes.len() as u64 {
        return Err(unavailable());
    }
    seek(handle, FILE_BEGIN, 0)?;
    let mut offset = 0;
    while offset < bytes.len() {
        let count = (bytes.len() - offset).min(IO_CHUNK_BYTES);
        let mut written = 0;
        // SAFETY: fixed owned synchronous handle at offset zero of an empty or
        // exact-size file, bounded immutable caller-owned bytes and exclusive
        // scalar output. The API retains neither pointer.
        unsafe {
            WriteFile(
                handle.0,
                Some(&bytes[offset..offset + count]),
                Some(&mut written),
                None,
            )
        }
        .map_err(|_| unavailable())?;
        if written == 0 || written as usize > count {
            return Err(unavailable());
        }
        offset += written as usize;
    }
    // SAFETY: same still-exclusive file; acknowledge only an actual OS flush.
    unsafe { FlushFileBuffers(handle.0) }.map_err(|_| unavailable())
}

fn parse_bootstrap_permit(bytes: &[u8]) -> Option<bool> {
    match bytes {
        value if value == BOOTSTRAP_PENDING => Some(true),
        value if value == BOOTSTRAP_CONSUMED => Some(false),
        _ => None,
    }
}

#[cfg(test)]
mod bootstrap_tests {
    use super::*;

    #[test]
    fn only_the_exact_pending_permit_authorizes_one_bootstrap() {
        assert_eq!(parse_bootstrap_permit(BOOTSTRAP_PENDING), Some(true));
        assert_eq!(parse_bootstrap_permit(BOOTSTRAP_CONSUMED), Some(false));
        for bytes in [
            b"".as_slice(),
            b"UACREG1",
            b"UACREG1P\n",
            b"UACREG2P",
            b"UACREG1X",
        ] {
            assert_eq!(parse_bootstrap_permit(bytes), None);
        }
        assert_eq!(BOOTSTRAP_PENDING.len(), BOOTSTRAP_CONSUMED.len());
    }
}

/// The relay endpoint rules shared with the elevated CLI verb.
fn validate_relay_endpoint(endpoint: SocketAddr) -> Result<(), ServiceError> {
    crate::contract::validate_relay_endpoint(endpoint).map_err(|_| unavailable())
}

/// Accepts exactly the canonical `ip:port\n` spelling that the writer stores.
/// Anything else (whitespace, names, a second line, a non-canonical address)
/// is a corrupt or foreign file, reported as unavailable, never as absent.
fn parse_relay_endpoint(bytes: &[u8]) -> Result<SocketAddr, ServiceError> {
    if bytes.len() as u64 > MAX_RELAY_FILE_BYTES {
        return Err(unavailable());
    }
    let text = std::str::from_utf8(bytes).map_err(|_| unavailable())?;
    let line = text.strip_suffix('\n').ok_or_else(unavailable)?;
    if !line.is_ascii() || line.contains(char::is_whitespace) {
        return Err(unavailable());
    }
    let endpoint = line.parse::<SocketAddr>().map_err(|_| unavailable())?;
    validate_relay_endpoint(endpoint)?;
    if format!("{endpoint}\n").as_bytes() != bytes {
        return Err(unavailable());
    }
    Ok(endpoint)
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows::Win32::Storage::FileSystem::{
        DELETE, FILE_ATTRIBUTE_COMPRESSED, FILE_ATTRIBUTE_DIRECTORY, FILE_ATTRIBUTE_ENCRYPTED,
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ATTRIBUTE_SPARSE_FILE, FILE_FLAG_BACKUP_SEMANTICS,
        FILE_FLAG_DELETE_ON_CLOSE, FILE_FLAG_OVERLAPPED, FILE_READ_ATTRIBUTES, FILE_READ_DATA,
        FILE_WRITE_DATA, READ_CONTROL, WRITE_DAC, WRITE_OWNER,
    };

    // Pure flags/size policy only. Never open, provision, read, write or close a
    // real Windows file/service/token/key in these tests, on any host.
    #[test]
    fn exclusive_synchronous_same_handle_flags_do_not_allow_delete_or_acl_mutation() {
        let (access, sharing, flags) = file_open_options();
        assert_ne!(access & FILE_READ_DATA.0, 0);
        assert_ne!(access & FILE_WRITE_DATA.0, 0);
        assert_ne!(access & FILE_READ_ATTRIBUTES.0, 0);
        assert_ne!(access & READ_CONTROL.0, 0);
        assert_eq!(access & (DELETE | WRITE_DAC | WRITE_OWNER).0, 0);
        assert_eq!(sharing.0, 0);
        assert_ne!(flags.0 & FILE_FLAG_OPEN_REPARSE_POINT.0, 0);
        assert_ne!(flags.0 & FILE_FLAG_WRITE_THROUGH.0, 0);
        assert_eq!(
            flags.0
                & (FILE_FLAG_OVERLAPPED | FILE_FLAG_DELETE_ON_CLOSE | FILE_FLAG_BACKUP_SEMANTICS).0,
            0
        );
    }
    #[test]
    fn regular_file_profile_rejects_links_and_special_storage_attributes() {
        assert!(regular_file_attributes(FILE_ATTRIBUTE_NORMAL.0, 1));
        assert!(regular_file_attributes(
            (FILE_ATTRIBUTE_ARCHIVE | FILE_ATTRIBUTE_NOT_CONTENT_INDEXED).0,
            1
        ));
        assert!(!regular_file_attributes(
            (FILE_ATTRIBUTE_NORMAL | FILE_ATTRIBUTE_ARCHIVE).0,
            1
        ));
        for links in [0, 2, u32::MAX] {
            assert!(!regular_file_attributes(FILE_ATTRIBUTE_NORMAL.0, links));
        }
        for attributes in [
            0,
            u32::MAX,
            FILE_ATTRIBUTE_DIRECTORY.0,
            FILE_ATTRIBUTE_REPARSE_POINT.0,
            FILE_ATTRIBUTE_SPARSE_FILE.0,
            FILE_ATTRIBUTE_COMPRESSED.0,
            FILE_ATTRIBUTE_ENCRYPTED.0,
        ] {
            assert!(!regular_file_attributes(attributes, 1));
        }
    }
    #[test]
    fn append_bound_includes_empty_flush_without_overflow_or_growth_past_cap() {
        assert_eq!(appended_length(0, 0), Some(0));
        assert_eq!(
            appended_length(0, MAX_TRUST_FILE_BYTES as usize),
            Some(MAX_TRUST_FILE_BYTES)
        );
        assert_eq!(
            appended_length(MAX_TRUST_FILE_BYTES, 0),
            Some(MAX_TRUST_FILE_BYTES)
        );
        assert_eq!(appended_length(MAX_TRUST_FILE_BYTES, 1), None);
        assert_eq!(appended_length(MAX_TRUST_FILE_BYTES + 1, 0), None);
        assert_eq!(appended_length(u64::MAX, 1), None);
        assert_eq!(appended_length(1, usize::MAX), None);
    }
    #[test]
    fn reads_preserve_empty_content_but_reject_short_changed_and_oversize_results() {
        assert!(stable_read(0, 0, 0));
        assert!(stable_read(
            MAX_TRUST_FILE_BYTES,
            MAX_TRUST_FILE_BYTES as usize,
            MAX_TRUST_FILE_BYTES
        ));
        assert!(!stable_read(5, 4, 5));
        assert!(!stable_read(5, 6, 5));
        assert!(!stable_read(5, 5, 6));
        assert!(!stable_read(5, 5, 4));
        assert!(!stable_read(
            MAX_TRUST_FILE_BYTES + 1,
            MAX_TRUST_FILE_BYTES as usize + 1,
            MAX_TRUST_FILE_BYTES + 1
        ));
    }

    #[test]
    fn relay_endpoint_file_accepts_only_the_canonical_line() {
        let endpoint = parse_relay_endpoint(b"203.0.113.5:7443\n").unwrap();
        assert_eq!(endpoint.port(), 7443);
        assert!(parse_relay_endpoint(b"[2001:db8::1]:7443\n").is_ok());
        for bad in [
            &b""[..],
            b"203.0.113.5:7443",
            b"203.0.113.5:7443\r\n",
            b" 203.0.113.5:7443\n",
            b"203.0.113.5:7443\n\n",
            b"203.0.113.5:0\n",
            b"0.0.0.0:7443\n",
            b"relay.example:7443\n",
            b"[::ffff:203.0.113.5]:7443\n",
            b"[2001:0db8::1]:7443\n",
            b"203.0.113.5:7443\nx",
        ] {
            assert!(parse_relay_endpoint(bad).is_err(), "{bad:?}");
        }
        let long = format!("{}:7443\n", "1".repeat(60));
        assert!(parse_relay_endpoint(long.as_bytes()).is_err());
    }
}
