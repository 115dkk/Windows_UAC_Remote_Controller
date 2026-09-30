// SPDX-License-Identifier: GPL-2.0-or-later
//! Sole Windows FFI boundary. Every asynchronous request has a stable Arc
//! allocation and a callback-owned strong reference. A late/missing callback
//! retains its request and instance rather than permitting a use-after-free.

use crate::{AnnounceError, AnnouncementState, Names};
use std::{
    ffi::c_void,
    net::Ipv4Addr,
    sync::{Arc, Condvar, Mutex, MutexGuard},
    time::Duration,
};
use windows::{
    Win32::{
        Foundation::{
            DNS_REQUEST_PENDING, ERROR_CALL_NOT_IMPLEMENTED, ERROR_NOT_ENOUGH_MEMORY,
            ERROR_NOT_SUPPORTED, ERROR_PROC_NOT_FOUND, GetLastError,
        },
        NetworkManagement::Dns::{
            DNS_QUERY_REQUEST_VERSION1, DNS_SERVICE_INSTANCE, DNS_SERVICE_REGISTER_REQUEST,
            DnsServiceConstructInstance, DnsServiceDeRegister, DnsServiceFreeInstance,
            DnsServiceRegister,
        },
        System::SystemInformation::{ComputerNameDnsHostname, GetComputerNameExW},
    },
    core::{PCWSTR, PWSTR, w},
};

const DROP_WAIT: Duration = Duration::from_secs(2);

fn dns_host_name() -> Result<Vec<u16>, AnnounceError> {
    let mut length = 0;
    // SAFETY: a null buffer and zero size request the required UTF-16 capacity;
    // length is exclusively writable and no pointer is retained.
    let _ = unsafe { GetComputerNameExW(ComputerNameDnsHostname, None, &mut length) };
    if !(2..=32768).contains(&length) {
        return Err(AnnounceError::Unsupported);
    }
    let mut host = vec![0_u16; length as usize];
    // SAFETY: host has the requested writable UTF-16 capacity; length supplies
    // that capacity on entry and receives the count excluding NUL on success.
    unsafe {
        GetComputerNameExW(
            ComputerNameDnsHostname,
            Some(PWSTR(host.as_mut_ptr())),
            &mut length,
        )
    }
    .map_err(|_| AnnounceError::Unsupported)?;
    if length == 0 || length as usize >= host.len() {
        return Err(AnnounceError::Unsupported);
    }
    host.truncate(length as usize);
    // Preserve the OS's UTF-16 name without ASCII filtering or lossy conversion.
    // DNS Client already publishes this host; only the service association is new.
    host.extend(".local".encode_utf16().chain(Some(0)));
    Ok(host)
}

pub(super) struct Announcement {
    registration: Arc<Registration>,
}

#[derive(Default)]
struct Progress {
    result: Option<u32>,
    retired: bool,
    deregistered: bool,
}

struct Registration {
    request: DNS_SERVICE_REGISTER_REQUEST,
    instance: *mut DNS_SERVICE_INSTANCE,
    progress: Mutex<Progress>,
    changed: Condvar,
}

// SAFETY: request and instance have stable allocations and are not mutated by
// Rust after publication. Only DNSAPI borrows their pointers. Progress is the
// only Rust-shared mutable data and is protected by its mutex. The last Arc
// cannot free request/instance while either native operation owns a context.
unsafe impl Send for Registration {}
// SAFETY: the same immutable-request and mutex invariants permit shared access.
unsafe impl Sync for Registration {}

impl Registration {
    fn progress(&self) -> MutexGuard<'_, Progress> {
        self.progress
            .lock()
            .unwrap_or_else(|error| error.into_inner())
    }
}

impl Drop for Registration {
    fn drop(&mut self) {
        // SAFETY: this is the unique constructed instance; the last strong Arc
        // is gone only after both callbacks, or a synchronous register refusal.
        unsafe { DnsServiceFreeInstance(self.instance) };
    }
}

struct Deregistration {
    request: DNS_SERVICE_REGISTER_REQUEST,
    registration: Arc<Registration>,
}

// SAFETY: the immutable request points into the retained registration. Only
// DNSAPI uses those pointers; the callback signals progress through the mutex.
unsafe impl Send for Deregistration {}
// SAFETY: no Rust mutation of the request occurs after the Arc is published.
unsafe impl Sync for Deregistration {}

impl Announcement {
    pub(super) fn start(
        names: &Names,
        ipv4: Ipv4Addr,
        port: u16,
        interface_index: u32,
    ) -> Result<Self, AnnounceError> {
        let service: Vec<u16> = names.instance.encode_utf16().chain(Some(0)).collect();
        let host = dns_host_name()?;
        // IP4_ADDRESS stores the four network-order octets in memory, like
        // IN_ADDR. from_ne_bytes preserves them on little-endian Windows.
        let address = u32::from_ne_bytes(ipv4.octets());
        let keys = [w!("v")];
        let values = [w!("1")];
        // SAFETY: validated names are terminated UTF-16; address and one-element
        // TXT arrays are live for this synchronous allocating/copying call.
        // No IPv6 is supplied. The port/priority/weight are host-order WORDs.
        let instance = unsafe {
            DnsServiceConstructInstance(
                PCWSTR(service.as_ptr()),
                PCWSTR(host.as_ptr()),
                Some(&address),
                None,
                port,
                0,
                0,
                1,
                keys.as_ptr(),
                values.as_ptr(),
            )
        };
        if instance.is_null() {
            // SAFETY: reads only the current thread's last error immediately
            // after the allocation failure; no pointers or ownership involved.
            let code = unsafe { GetLastError() }.0;
            return Err(call_error(if code == 0 {
                ERROR_NOT_ENOUGH_MEMORY.0
            } else {
                code
            }));
        }
        let registration = Arc::new_cyclic(|weak: &std::sync::Weak<Registration>| Registration {
            request: DNS_SERVICE_REGISTER_REQUEST {
                Version: DNS_QUERY_REQUEST_VERSION1.0,
                InterfaceIndex: interface_index,
                pServiceInstance: instance,
                pRegisterCompletionCallback: Some(registered),
                pQueryContext: weak.as_ptr().cast_mut().cast(),
                ..Default::default()
            },
            instance,
            progress: Mutex::new(Progress::default()),
            changed: Condvar::new(),
        });
        let callback = Arc::into_raw(Arc::clone(&registration));
        // SAFETY: registration owns the stable request and constructed instance.
        // callback owns one strong reference until registered consumes it once.
        // The local Arc also protects a completion that occurs before return.
        let code = unsafe { DnsServiceRegister(&registration.request, None) };
        if code != DNS_REQUEST_PENDING as u32 {
            // SAFETY: a non-pending return did not schedule a callback. Reclaim
            // exactly the strong reference just transferred with into_raw.
            drop(unsafe { Arc::from_raw(callback) });
            return Err(call_error(code));
        }
        Ok(Self { registration })
    }

    pub(super) fn state(&self) -> AnnouncementState {
        match self.registration.progress().result {
            None => AnnouncementState::Pending,
            Some(0) => AnnouncementState::Registered,
            Some(code) => AnnouncementState::Failed(code),
        }
    }
}

impl Drop for Announcement {
    fn drop(&mut self) {
        let start_deregister = {
            let mut progress = self.registration.progress();
            progress.retired = true;
            progress.result == Some(0)
        };
        if start_deregister {
            deregister(Arc::clone(&self.registration));
        }
        // If registration is still pending, its callback observes retired and
        // initiates deregistration itself. The mutex makes those two paths
        // mutually exclusive, including a callback concurrent with Drop.
        let _ = self.registration.changed.wait_timeout_while(
            self.registration.progress(),
            DROP_WAIT,
            |progress| !progress.deregistered && progress.result.is_none_or(|code| code == 0),
        );
        // Do NOT reclaim a callback's raw Arc on timeout. It owns request and
        // instance until a late callback, or leaks them if DNSAPI never calls
        // back. Shutdown has a bounded wait; leaking these small allocations
        // is preferable to freeing memory that DNSAPI may still touch.
    }
}

fn call_error(code: u32) -> AnnounceError {
    if [
        ERROR_NOT_SUPPORTED.0,
        ERROR_CALL_NOT_IMPLEMENTED.0,
        ERROR_PROC_NOT_FOUND.0,
    ]
    .contains(&code)
    {
        AnnounceError::Unsupported
    } else {
        AnnounceError::Failed(code)
    }
}

unsafe extern "system" fn registered(
    status: u32,
    context: *const c_void,
    instance: *const DNS_SERVICE_INSTANCE,
) {
    // SAFETY: context is precisely the single into_raw strong reference passed
    // to this registration's one completion; the call site retains another Arc
    // until DnsServiceRegister returns, even for synchronous completion.
    let registration = unsafe { Arc::from_raw(context.cast::<Registration>()) };
    free_callback_instance(instance, registration.instance);
    let retired = {
        let mut progress = registration.progress();
        progress.result = Some(status);
        progress.retired
    };
    registration.changed.notify_all();
    if retired && status == 0 {
        deregister(registration);
    }
}

fn deregister(registration: Arc<Registration>) {
    let operation = Arc::new_cyclic(|weak: &std::sync::Weak<Deregistration>| Deregistration {
        request: DNS_SERVICE_REGISTER_REQUEST {
            pRegisterCompletionCallback: Some(deregistered),
            pQueryContext: weak.as_ptr().cast_mut().cast(),
            ..registration.request
        },
        registration,
    });
    let _callback = Arc::into_raw(Arc::clone(&operation));
    // SAFETY: a separate stable request owns its own callback context and keeps
    // the original registration/instance alive. pCancel must be null for this
    // API. A synchronous callback is protected by the local operation Arc.
    let code = unsafe { DnsServiceDeRegister(&operation.request, None) };
    if code != DNS_REQUEST_PENDING as u32 {
        // No completion was scheduled, but withdrawal was not confirmed either.
        // Intentionally retain the raw context and original instance. This also
        // leaves the original request valid for the process-bound registration.
        // Do not claim success or release native backing storage on this path.
    }
}

unsafe extern "system" fn deregistered(
    status: u32,
    context: *const c_void,
    instance: *const DNS_SERVICE_INSTANCE,
) {
    // SAFETY: this is the separate into_raw reference created by deregister;
    // DNSAPI invokes the completion once, transferring that ownership back.
    let operation = unsafe { Arc::from_raw(context.cast::<Deregistration>()) };
    free_callback_instance(instance, operation.registration.instance);
    if status == 0 {
        operation.registration.progress().deregistered = true;
        operation.registration.changed.notify_all();
    } else {
        // Completion failure is not proof the service was withdrawn. Preserve
        // its backing allocation for the remaining process lifetime.
        std::mem::forget(operation);
    }
}

fn free_callback_instance(
    instance: *const DNS_SERVICE_INSTANCE,
    original: *const DNS_SERVICE_INSTANCE,
) {
    if !instance.is_null() && instance != original {
        // SAFETY: DNSAPI transfers the callback instance to the application;
        // it is a copy, distinct from the constructed input we still own. The
        // identity guard also prevents double-free if an API returns the input.
        unsafe { DnsServiceFreeInstance(instance) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        net::UdpSocket,
        sync::atomic::{AtomicBool, Ordering},
        thread,
        time::Instant,
    };
    use windows::Win32::NetworkManagement::Dns::{
        DNS_QUERY_MULTICAST_ONLY, DNS_RECORDW, DNS_SERVICE_BROWSE_REQUEST,
        DNS_SERVICE_BROWSE_REQUEST_0, DNS_SERVICE_CANCEL, DNS_SERVICE_RESOLVE_REQUEST, DNS_TYPE_A,
        DNS_TYPE_PTR, DnsFree, DnsFreeRecordList, DnsQuery_W, DnsServiceBrowse,
        DnsServiceBrowseCancel, DnsServiceResolve, DnsServiceResolveCancel,
    };

    struct BrowseContext {
        instance: String,
        found: AtomicBool,
    }

    unsafe extern "system" fn browsed(
        status: u32,
        context: *const c_void,
        records: *const DNS_RECORDW,
    ) {
        // SAFETY: this ignored test retains the small context allocation until
        // process exit, including any final callback after browse cancellation.
        let context = unsafe { &*context.cast::<BrowseContext>() };
        let mut current = records;
        while !current.is_null() {
            // SAFETY: DNSAPI owns this valid linked list until the callback
            // frees it below; each next pointer is from that same allocation.
            let record = unsafe { &*current };
            if status == 0 && record.wType == DNS_TYPE_PTR.0 {
                // SAFETY: the tag selects the PTR member; the Unicode target is
                // terminated and remains valid for the life of the result list.
                let target = unsafe { record.Data.PTR.pNameHost.to_string() };
                if target.is_ok_and(|target| {
                    target
                        .trim_end_matches('.')
                        .eq_ignore_ascii_case(&context.instance)
                }) {
                    context.found.store(true, Ordering::Release);
                }
            }
            current = record.pNext;
        }
        if !records.is_null() {
            // SAFETY: the browse callback owns its returned list and releases
            // it once, after all names and records have gone out of use.
            unsafe { DnsFree(Some(records.cast()), DnsFreeRecordList) };
        }
    }

    fn browse(instance: String) -> bool {
        // Test-only bounded retention: BrowseCancel schedules another callback
        // but does not synchronously join callbacks. Keep context/request/cancel
        // until test-process exit, even when an assertion later fails.
        let context = Box::leak(Box::new(BrowseContext {
            instance,
            found: AtomicBool::new(false),
        }));
        let request = Box::leak(Box::new(DNS_SERVICE_BROWSE_REQUEST {
            Version: DNS_QUERY_REQUEST_VERSION1.0,
            QueryName: w!("_uacremote._tcp.local"),
            Anonymous: DNS_SERVICE_BROWSE_REQUEST_0 {
                pBrowseCallback: Some(browsed),
            },
            pQueryContext: (context as *const BrowseContext).cast_mut().cast(),
            ..Default::default()
        }));
        let cancel = Box::leak(Box::new(DNS_SERVICE_CANCEL::default()));
        // SAFETY: request, static query name, context and cancel all have stable
        // process-lifetime allocations. Only the API mutates the cancel handle.
        let code = unsafe { DnsServiceBrowse(request, cancel) };
        println!("browse start: {code}");
        assert_eq!(code, DNS_REQUEST_PENDING);
        let deadline = Instant::now() + Duration::from_secs(5);
        while !context.found.load(Ordering::Acquire) && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        let found = context.found.load(Ordering::Acquire);
        // SAFETY: this is the live cancellation handle supplied to Browse;
        // its allocation and all callback data survive the final callback.
        let code = unsafe { DnsServiceBrowseCancel(cancel) };
        println!("browse cancellation: {code}");
        assert_eq!(code, 0);
        found
    }

    struct ResolveContext {
        host: String,
        result: Mutex<Option<(u32, bool, Option<Ipv4Addr>)>>,
    }

    unsafe extern "system" fn resolved(
        status: u32,
        context: *const c_void,
        instance: *const DNS_SERVICE_INSTANCE,
    ) {
        // SAFETY: the test retains this context until process exit, so a late
        // result or cancellation callback cannot borrow freed test storage.
        let context = unsafe { &*context.cast::<ResolveContext>() };
        let mut matches = false;
        let mut address = None;
        if !instance.is_null() {
            // SAFETY: DNSAPI supplies a live instance owned by this callback.
            let value = unsafe { &*instance };
            // SAFETY: the returned instance owns its terminated hostname until
            // DnsServiceFreeInstance below; no pointer escapes this callback.
            let host_matches = unsafe { value.pszHostName.to_string() }.is_ok_and(|host| {
                host.trim_end_matches('.')
                    .eq_ignore_ascii_case(&context.host)
            });
            if !value.ip4Address.is_null() {
                // SAFETY: the checked non-null IPv4 pointer belongs to the live
                // instance supplied by DNSAPI and points to one IP4_ADDRESS.
                address = Some(Ipv4Addr::from(unsafe { *value.ip4Address }.to_ne_bytes()));
            }
            matches = status == 0 && value.wPort == 7443 && host_matches;
            // SAFETY: release exactly the instance transferred to this callback,
            // after copying the host/port/address comparisons into a bool.
            unsafe { DnsServiceFreeInstance(instance) };
        }
        *context
            .result
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some((status, matches, address));
    }

    fn resolve(names: &Names, host: String) -> Option<(u32, bool, Option<Ipv4Addr>)> {
        // As with browse, keep these small test allocations until process exit
        // rather than assuming cancellation synchronously joins callbacks.
        let context = Box::leak(Box::new(ResolveContext {
            host,
            result: Mutex::new(None),
        }));
        let name = Box::leak(
            names
                .instance
                .encode_utf16()
                .chain(Some(0))
                .collect::<Vec<_>>()
                .into_boxed_slice(),
        );
        let request = Box::leak(Box::new(DNS_SERVICE_RESOLVE_REQUEST {
            Version: DNS_QUERY_REQUEST_VERSION1.0,
            QueryName: windows::core::PWSTR(name.as_mut_ptr()),
            pResolveCompletionCallback: Some(resolved),
            pQueryContext: (context as *const ResolveContext).cast_mut().cast(),
            ..Default::default()
        }));
        let cancel = Box::leak(Box::new(DNS_SERVICE_CANCEL::default()));
        // SAFETY: all request/query/context/cancel allocations are stable and
        // retained across the asynchronous resolve and any late cancellation.
        let code = unsafe { DnsServiceResolve(request, cancel) };
        assert_eq!(code, DNS_REQUEST_PENDING);
        let deadline = Instant::now() + Duration::from_secs(5);
        let result = loop {
            let result = *context
                .result
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if result.is_some() || Instant::now() >= deadline {
                break result;
            }
            thread::sleep(Duration::from_millis(25));
        };
        if result.is_none() {
            // SAFETY: cancel is the live handle passed to this resolve; every
            // pointer it or the callback uses remains valid until process exit.
            let _ = unsafe { DnsServiceResolveCancel(cancel) };
        }
        result
    }

    fn host_addresses(host: &[u16]) -> Result<Vec<Ipv4Addr>, u32> {
        let mut records = std::ptr::null_mut();
        // SAFETY: host is terminated UTF-16 and this synchronous query retains
        // no input pointer. The initialized output owns a list to free below.
        let code = unsafe {
            DnsQuery_W(
                PCWSTR(host.as_ptr()),
                DNS_TYPE_A,
                DNS_QUERY_MULTICAST_ONLY,
                None,
                &mut records,
                None,
            )
        };
        let mut addresses = Vec::new();
        let mut current = records.cast::<DNS_RECORDW>();
        while !current.is_null() {
            // SAFETY: current is in DNSAPI's returned Unicode linked list,
            // retained until DnsFree; the tag selects the A union field.
            let record = unsafe { &*current };
            if record.wType == DNS_TYPE_A.0 {
                // SAFETY: checked A tag and live result allocation; copy only.
                addresses.push(Ipv4Addr::from(
                    unsafe { record.Data.A.IpAddress }.to_ne_bytes(),
                ));
            }
            current = record.pNext;
        }
        if !records.is_null() {
            // SAFETY: uniquely release the returned list after all row borrows.
            unsafe { DnsFree(Some(records.cast()), DnsFreeRecordList) };
        }
        if code.0 == 0 {
            Ok(addresses)
        } else {
            Err(code.0)
        }
    }

    #[test]
    fn ipv4_storage_preserves_network_octets() {
        let ip = Ipv4Addr::new(192, 168, 12, 34);
        assert_eq!(
            u32::from_ne_bytes(ip.octets()).to_ne_bytes(),
            [192, 168, 12, 34]
        );
    }

    #[test]
    fn unsupported_statuses_are_not_panics() {
        for code in [50, 120, 127] {
            assert!(matches!(call_error(code), AnnounceError::Unsupported));
        }
        assert!(matches!(call_error(5), AnnounceError::Failed(5)));
    }

    #[test]
    #[ignore = "uses this PC's LAN DNS-SD responder without elevation"]
    fn registers_and_is_visible_on_lan() {
        let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).unwrap();
        socket.connect((Ipv4Addr::new(192, 0, 2, 1), 9)).unwrap();
        let std::net::IpAddr::V4(ip) = socket.local_addr().unwrap().ip() else {
            panic!("no IPv4 route")
        };
        assert!(
            ip.is_private(),
            "the integration test requires an RFC1918 LAN"
        );
        let mut random = [0_u8; 10];
        getrandom::fill(&mut random).unwrap();
        let label = format!(
            "uacremote-{}",
            random
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        );
        let names = Names::new(&label, "_uacremote._tcp").unwrap();
        let announcement =
            crate::ServiceAnnouncement::start(&label, "_uacremote._tcp", ip, 7443, 0).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while announcement.state() == AnnouncementState::Pending && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(25));
        }
        println!("registration state: {:?}", announcement.state());
        assert_eq!(announcement.state(), AnnouncementState::Registered);
        let visible = browse(names.instance.clone());
        println!("DNS-SD PTR visibility: {visible}");
        assert!(
            visible,
            "registered instance was not returned by DNS-SD browse"
        );
        let host = dns_host_name().unwrap();
        let host_text = String::from_utf16(&host[..host.len() - 1]).unwrap();
        println!("instance: {}", names.instance);
        println!("SRV target: {host_text}:7443");
        let resolved = resolve(&names, host_text);
        println!("resolved status, host/port match, IPv4: {resolved:?}");
        let (status, matches, address) = resolved.expect("resolve timed out");
        let addresses = match address {
            Some(address) => vec![address],
            None => host_addresses(&host).expect("host A query failed"),
        };
        println!("resolved IPv4 addresses: {addresses:?}");
        assert!(!addresses.is_empty());
        for address in addresses {
            // An exact local bind succeeds only for addresses owned by this PC;
            // no listener or packet is sent, and no new dependency is needed.
            assert!(
                UdpSocket::bind((address, 0)).is_ok(),
                "resolved address is not owned by this PC: {address}"
            );
        }
        if std::env::var("UACREMOTE_DNSSD_HOLD").as_deref() == Ok("1") {
            println!("holding registration for network probe (15 seconds)");
            use std::io::Write;
            std::io::stdout().flush().unwrap();
            thread::sleep(Duration::from_secs(15));
        }
        let registration = Arc::clone(&announcement.inner.registration);
        drop(announcement);
        let deregistered = registration.progress().deregistered;
        println!("deregistration callback confirmed: {deregistered}");
        assert!(deregistered);
        assert_eq!(status, 0);
        assert!(
            matches,
            "resolved host or port differs from the registration"
        );
    }
}
