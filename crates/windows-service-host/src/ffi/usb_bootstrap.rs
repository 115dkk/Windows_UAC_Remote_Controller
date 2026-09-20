// SPDX-License-Identifier: GPL-2.0-or-later
//! Windows-only public invitation courier. USB is never an authentication path.
//! Runs ONLY in a separate interactive medium-integrity, non-admin process.
//! Each native allocation/handle is owned locally; no pointers cross threads.
//! No driver install, ADB, HID, device input, URLs, files or arbitrary commands.
use crate::usb_bootstrap_frame::{self, MAX_FRAME};
use crate::{PairingPeerRole, ffi::pairing_peer::TokenFacts};
use std::{
    collections::BTreeSet,
    io::{Read, Write},
    mem,
    os::windows::process::CommandExt,
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use windows::{
    Win32::{
        Devices::{DeviceAndDriverInstallation::*, Usb::*},
        Foundation::{CloseHandle, ERROR_NO_MORE_ITEMS, GENERIC_READ, GENERIC_WRITE, HANDLE},
        Storage::FileSystem::{
            CreateFileW, FILE_ATTRIBUTE_NORMAL, FILE_FLAG_OVERLAPPED, FILE_SHARE_READ,
            FILE_SHARE_WRITE, OPEN_EXISTING,
        },
        System::{
            Registry::{KEY_READ, REG_MULTI_SZ, REG_VALUE_TYPE, RegCloseKey, RegQueryValueExW},
            RemoteDesktop::ProcessIdToSessionId,
            Threading::{GetCurrentProcess, GetCurrentProcessId},
        },
    },
    core::{GUID, PCWSTR, w},
};

type Result<T> = std::result::Result<T, ()>;
const CHILD_LIMIT: Duration = Duration::from_secs(50);

pub(super) struct UsbBroker {
    child: Child,
}
impl UsbBroker {
    pub(super) fn start(executable: &Path, text: &str) -> Result<Self> {
        require_medium()?;
        let invitation = service_protocol::PairingInvitation::from_qr_text(text).map_err(|_| ())?;
        let frame = usb_bootstrap_frame::encode(&invitation)?;
        // `executable` is the existing Starter connection's retained/pinned
        // protected installation, not any caller/web/USB-provided path.
        let child = Command::new(executable)
            .arg("usb-bootstrap")
            .current_dir(executable.parent().ok_or(())?)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .creation_flags(0x0800_0000)
            .spawn()
            .map_err(|_| ())?;
        let mut owner = Self { child };
        let result = owner
            .child
            .stdin
            .take()
            .ok_or(())
            .and_then(|mut stdin| stdin.write_all(&frame).map_err(|_| ()));
        if result.is_err() {
            owner.cancel();
            return Err(());
        }
        Ok(owner)
    }
    pub(super) fn poll(&mut self) -> Result<()> {
        match self.child.try_wait().map_err(|_| ())? {
            Some(status) if !status.success() => Err(()),
            _ => Ok(()),
        }
    }
    pub(super) fn cancel(&mut self) {
        let _ = self.child.kill();
    }
    pub(super) fn drained(&mut self) -> bool {
        self.child.try_wait().ok().flatten().is_some()
    }
}
impl Drop for UsbBroker {
    fn drop(&mut self) {
        if !self.drained() {
            self.cancel();
        }
    }
}

fn require_medium() -> Result<()> {
    let mut session = 0;
    // SAFETY: current process pseudo-handle and initialized scalar outputs.
    unsafe { ProcessIdToSessionId(GetCurrentProcessId(), &mut session) }.map_err(|_| ())?;
    // Same observed primary-token admission as the existing medium Starter.
    let token = TokenFacts::observe(unsafe { GetCurrentProcess() }).map_err(|_| ())?;
    token
        .require(PairingPeerRole::Starter, session)
        .map_err(|_| ())
}

pub(crate) fn run() -> Result<()> {
    require_medium()?;
    // Process watchdog bounds stdin/SetupAPI/control endpoint calls too; no
    // native USB operation runs in the privileged service or renderer process.
    let _watchdog = thread::Builder::new()
        .name("usb-bootstrap-deadline".into())
        .spawn(|| {
            thread::sleep(CHILD_LIMIT);
            std::process::exit(124);
        })
        .map_err(|_| ())?;
    let mut frame = Vec::with_capacity(MAX_FRAME + 1);
    std::io::stdin()
        .lock()
        .take((MAX_FRAME + 1) as u64)
        .read_to_end(&mut frame)
        .map_err(|_| ())?;
    usb_bootstrap_frame::decode(&frame)?;
    transfer(&frame)
}

struct DeviceSet(HDEVINFO);
impl Drop for DeviceSet {
    fn drop(&mut self) {
        // SAFETY: one owned SetupAPI snapshot, no borrowed elements survive it.
        let _ = unsafe { SetupDiDestroyDeviceInfoList(self.0) };
    }
}
struct Device {
    file: HANDLE,
    usb: WINUSB_INTERFACE_HANDLE,
}
impl Drop for Device {
    fn drop(&mut self) {
        // SAFETY: WinUSB owns interface context, file remains live until freed.
        unsafe {
            let _ = WinUsb_Free(self.usb);
            let _ = CloseHandle(self.file);
        }
    }
}
fn terminated_text(bytes: &[u8]) -> Result<String> {
    if !bytes.len().is_multiple_of(2) {
        return Err(());
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|v| u16::from_le_bytes([v[0], v[1]]))
        .collect();
    let end = units.iter().position(|v| *v == 0).ok_or(())?;
    String::from_utf16(&units[..end]).map_err(|_| ())
}

// Enumerate only driver-declared WinUSB interface GUIDs. An MTP/composite device
// without a compatible installed function driver is not rebound or modified.
fn paths() -> Result<Vec<Vec<u16>>> {
    // SAFETY: fixed USB enumerator, read-only present-device snapshot.
    let set = DeviceSet(
        unsafe { SetupDiGetClassDevsW(None, w!("USB"), None, DIGCF_PRESENT | DIGCF_ALLCLASSES) }
            .map_err(|_| ())?,
    );
    let mut guids = BTreeSet::new();
    for index in 0..512 {
        let mut info = SP_DEVINFO_DATA {
            cbSize: mem::size_of::<SP_DEVINFO_DATA>() as u32,
            ..Default::default()
        };
        // SAFETY: initialized fixed output owned by this iteration.
        match unsafe { SetupDiEnumDeviceInfo(set.0, index, &mut info) } {
            Ok(()) => (),
            Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => {
                break;
            }
            Err(_) => return Err(()),
        }
        if index == 511 {
            return Err(());
        }
        let mut service = [0u8; 256];
        let mut size = 0;
        // SAFETY: bounded property buffer, no external allocation/pointer reuse.
        if unsafe {
            SetupDiGetDeviceRegistryPropertyW(
                set.0,
                &info,
                SPDRP_SERVICE,
                None,
                Some(&mut service),
                Some(&mut size),
            )
        }
        .is_err()
        {
            continue;
        }
        if size as usize > service.len()
            || !terminated_text(&service[..size as usize])?.eq_ignore_ascii_case("WinUSB")
        {
            continue;
        }
        // SAFETY: device's existing hardware key, read-only, never writes driver configuration.
        let key = unsafe {
            SetupDiOpenDevRegKey(set.0, &info, DICS_FLAG_GLOBAL.0, 0, DIREG_DEV, KEY_READ.0)
        }
        .map_err(|_| ())?;
        let mut data = [0u8; 4096];
        let mut count = data.len() as u32;
        let mut kind = REG_VALUE_TYPE::default();
        // SAFETY: fixed bounded destination and exact DeviceInterfaceGUIDs value.
        let read = unsafe {
            RegQueryValueExW(
                key,
                w!("DeviceInterfaceGUIDs"),
                None,
                Some(&mut kind),
                Some(data.as_mut_ptr()),
                Some(&mut count),
            )
        };
        // SAFETY: key ownership ends here, no retained registry pointers.
        let _ = unsafe { RegCloseKey(key) };
        if read.is_err()
            || kind != REG_MULTI_SZ
            || count as usize > data.len()
            || !count.is_multiple_of(2)
        {
            return Err(());
        }
        let units: Vec<u16> = data[..count as usize]
            .chunks_exact(2)
            .map(|v| u16::from_le_bytes([v[0], v[1]]))
            .collect();
        if !units.ends_with(&[0, 0]) {
            return Err(());
        }
        for item in units.split(|v| *v == 0).filter(|v| !v.is_empty()) {
            let text = String::from_utf16(item).map_err(|_| ())?;
            if text.len() != 38 || !text.starts_with('{') || !text.ends_with('}') {
                return Err(());
            }
            guids.insert(text);
            if guids.len() > 32 {
                return Err(());
            }
        }
    }
    let mut paths = BTreeSet::new();
    for text in guids {
        let guid = GUID::try_from(&text[1..text.len() - 1]).map_err(|_| ())?;
        // SAFETY: parsed fixed-length GUID, read-only present interface snapshot.
        let set = DeviceSet(
            unsafe {
                SetupDiGetClassDevsW(
                    Some(&guid),
                    PCWSTR::null(),
                    None,
                    DIGCF_PRESENT | DIGCF_DEVICEINTERFACE,
                )
            }
            .map_err(|_| ())?,
        );
        for index in 0..32 {
            let mut interface = SP_DEVICE_INTERFACE_DATA {
                cbSize: mem::size_of::<SP_DEVICE_INTERFACE_DATA>() as u32,
                ..Default::default()
            };
            // SAFETY: live set/GUID and initialized output.
            match unsafe { SetupDiEnumDeviceInterfaces(set.0, None, &guid, index, &mut interface) }
            {
                Ok(()) => (),
                Err(e) if e.code() == windows::core::HRESULT::from_win32(ERROR_NO_MORE_ITEMS.0) => {
                    break;
                }
                Err(_) => return Err(()),
            }
            if index == 31 {
                return Err(());
            }
            // Aligned u32 allocation; detail contains a DWORD then UTF-16 path.
            let mut detail = [0u32; 1024];
            let ptr = detail
                .as_mut_ptr()
                .cast::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>();
            // SAFETY: 4096-byte aligned storage, cbSize matches the native x64 ABI.
            unsafe {
                (*ptr).cbSize = mem::size_of::<SP_DEVICE_INTERFACE_DETAIL_DATA_W>() as u32;
            }
            let mut needed = 0;
            // SAFETY: fixed initialized storage outlives call; Windows bounds output.
            unsafe {
                SetupDiGetDeviceInterfaceDetailW(
                    set.0,
                    &interface,
                    Some(ptr),
                    4096,
                    Some(&mut needed),
                    None,
                )
            }
            .map_err(|_| ())?;
            if !(6..=4096).contains(&needed) {
                return Err(());
            }
            // SAFETY: path begins at native offset 4; only returned bytes read.
            let units = unsafe {
                std::slice::from_raw_parts(
                    detail.as_ptr().cast::<u16>().add(2),
                    (needed as usize - 4) / 2,
                )
            };
            let end = units.iter().position(|v| *v == 0).ok_or(())?;
            let mut path = units[..end].to_vec();
            path.push(0);
            paths.insert(path);
            if paths.len() > 32 {
                return Err(());
            }
        }
    }
    Ok(paths.into_iter().collect())
}

impl Device {
    fn open(path: &[u16]) -> Result<Self> {
        // SAFETY: device path comes only from the owned SetupAPI snapshot, NUL
        // terminated. OPEN_EXISTING cannot create a file or replace a driver.
        let file = unsafe {
            CreateFileW(
                PCWSTR(path.as_ptr()),
                GENERIC_READ.0 | GENERIC_WRITE.0,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
                None,
            )
        }
        .map_err(|_| ())?;
        let mut usb = WINUSB_INTERFACE_HANDLE::default();
        // SAFETY: file handle remains owned until interface teardown.
        if unsafe { WinUsb_Initialize(file, &mut usb) }.is_err() {
            unsafe {
                let _ = CloseHandle(file);
            }
            return Err(());
        }
        Ok(Self { file, usb })
    }
    fn accessory(&self) -> Result<bool> {
        let mut descriptor = [0u8; 18];
        let mut count = 0;
        // SAFETY: bounded standard device descriptor, no arbitrary device input parsing.
        unsafe { WinUsb_GetDescriptor(self.usb, 1, 0, 0, Some(&mut descriptor), &mut count) }
            .map_err(|_| ())?;
        if count != 18 || descriptor[0] != 18 || descriptor[1] != 1 {
            return Err(());
        }
        Ok(u16::from_le_bytes([descriptor[8], descriptor[9]]) == 0x18d1
            && [0x2d00, 0x2d01].contains(&u16::from_le_bytes([descriptor[10], descriptor[11]])))
    }
    fn control(&self, request_type: u8, request: u8, index: u16, data: &mut [u8]) -> Result<()> {
        let mut count = 0;
        let setup = WINUSB_SETUP_PACKET {
            RequestType: request_type,
            Request: request,
            Value: 0,
            Index: index,
            Length: data.len() as u16,
        };
        // SAFETY: only fixed AOA 51/52/53 calls use this private method; stack
        // buffer lives through synchronous transfer, process watchdog is active.
        unsafe { WinUsb_ControlTransfer(self.usb, setup, Some(data), Some(&mut count), None) }
            .map_err(|_| ())?;
        if count as usize != data.len() {
            return Err(());
        }
        Ok(())
    }
    fn start_accessory(&self) -> Result<()> {
        let mut protocol = [0u8; 2];
        self.control(0xc0, 51, 0, &mut protocol)?;
        if ![1, 2].contains(&u16::from_le_bytes(protocol)) {
            return Err(());
        }
        for (id, value) in [
            (0, b"UAC Remote\0".as_slice()),
            (1, b"UAC Remote Approval\0".as_slice()),
            (2, b"Public pairing invitation\0".as_slice()),
            (3, b"1\0".as_slice()),
        ] {
            self.control(0x40, 52, id, &mut value.to_vec())?;
        }
        self.control(0x40, 53, 0, &mut [])
    }
    fn send(&self, frame: &[u8]) -> Result<()> {
        let mut interface = USB_INTERFACE_DESCRIPTOR::default();
        // SAFETY: exact default WinUSB interface, never associated ADB interface.
        unsafe { WinUsb_QueryInterfaceSettings(self.usb, 0, &mut interface) }.map_err(|_| ())?;
        if interface.bInterfaceNumber != 0 || interface.bNumEndpoints != 2 {
            return Err(());
        }
        let mut output = None;
        let mut inputs = 0;
        for index in 0..interface.bNumEndpoints {
            let mut pipe = WINUSB_PIPE_INFORMATION::default();
            // SAFETY: bounded declared endpoint index and initialized output.
            unsafe { WinUsb_QueryPipe(self.usb, 0, index, &mut pipe) }.map_err(|_| ())?;
            if pipe.PipeType != UsbdPipeTypeBulk {
                return Err(());
            }
            if pipe.PipeId & 0x80 == 0 {
                if output.replace(pipe.PipeId).is_some() {
                    return Err(());
                }
            } else {
                inputs += 1;
            }
        }
        let pipe = output.ok_or(())?;
        if inputs != 1 {
            return Err(());
        }
        let timeout = 15000u32;
        // SAFETY: policy is a bounded u32 duration; only bulk OUT is used.
        unsafe {
            WinUsb_SetPipePolicy(
                self.usb,
                pipe,
                PIPE_TRANSFER_TIMEOUT,
                4,
                (&timeout as *const u32).cast(),
            )
        }
        .map_err(|_| ())?;
        let mut written = 0;
        // SAFETY: one fully validated fixed-size frame, synchronous operation.
        unsafe { WinUsb_WritePipe(self.usb, pipe, frame, Some(&mut written), None) }
            .map_err(|_| ())?;
        if written as usize != frame.len() {
            return Err(());
        }
        Ok(())
    }
}

fn transfer(frame: &[u8]) -> Result<()> {
    let candidates = paths()?;
    // Never choose the first of several devices or broadcast an invitation.
    if candidates.len() != 1 {
        return Err(());
    }
    let device = Device::open(&candidates[0])?;
    if device.accessory()? {
        return device.send(frame);
    }
    device.start_accessory()?;
    drop(device);
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        let candidates = paths()?;
        if candidates.len() > 1 {
            return Err(());
        }
        if let Some(path) = candidates.first() {
            let device = Device::open(path)?;
            if device.accessory()? {
                return device.send(frame);
            }
        }
        thread::sleep(Duration::from_millis(200));
    }
    Err(())
}
