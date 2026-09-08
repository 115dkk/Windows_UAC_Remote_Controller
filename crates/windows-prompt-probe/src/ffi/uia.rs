// SPDX-License-Identifier: GPL-2.0-or-later
//! Window-scoped UIA property reads only. No action-pattern interfaces exist here.
use super::{
    malformed, native_error,
    resources::{CleanupLog, record_cleanup},
    window_owner,
};
use crate::{NativeOperation, ProbeCounts, ProbeError, ProbeFailure, UIA_TIMEOUT_MILLIS, policy};
use std::{ffi::c_void, marker::PhantomData, mem::ManuallyDrop, rc::Rc, time::Instant};
use windows::{
    Win32::{
        Foundation::HWND,
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize,
            },
            Variant::{VARIANT, VT_BOOL, VariantClear},
        },
        UI::Accessibility::{
            CUIAutomation8, IUIAutomation, IUIAutomation2, IUIAutomationElement,
            IUIAutomationTreeWalker, UIA_ButtonControlTypeId,
            UIA_IsInvokePatternAvailablePropertyId,
            UIA_IsLegacyIAccessiblePatternAvailablePropertyId,
            UIA_IsValuePatternAvailablePropertyId, UIA_PROPERTY_ID,
        },
    },
    core::Interface,
};

struct Apartment {
    _thread: PhantomData<Rc<()>>,
}
impl Apartment {
    fn initialize() -> Result<Self, ProbeError> {
        // SAFETY: the freshly spawned windowless worker has not initialized COM.
        // Fixed MTA/null reserved arguments. S_OK/S_FALSE both create one matching
        // CoUninitialize obligation; failure does not create an apartment owner.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(|error| native_error(NativeOperation::ComInitialize, error))?;
        Ok(Self {
            _thread: PhantomData,
        })
    }
}
impl Drop for Apartment {
    fn drop(&mut self) {
        // SAFETY: unique successful initialization on this same worker. Every
        // scoped UIA interface and VARIANT is dropped before this owner. This
        // API has no error result; no COM object crosses thread/output boundaries.
        unsafe { CoUninitialize() };
    }
}

pub(super) fn inspect(
    hwnd: HWND,
    pid: u32,
    began: Instant,
    counts: &mut ProbeCounts,
    cleanup: &CleanupLog,
) -> Result<(), ProbeError> {
    policy::budget(began.elapsed())?;
    let _apartment = Apartment::initialize()?;
    // SAFETY: COM initialized MTA on this worker; fixed Windows UIA CLSID and
    // in-process activation only, no aggregation/server/user-selected class.
    // Returned interface references are RAII-owned entirely within this scope.
    let automation: IUIAutomation =
        unsafe { CoCreateInstance(&CUIAutomation8, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| native_error(NativeOperation::CreateAutomation, error))?;
    let timeouts: IUIAutomation2 = automation
        .cast()
        .map_err(|error| native_error(NativeOperation::ConfigureAutomationTimeout, error))?;
    // SAFETY: live UIA2 interface on its owning apartment; fixed finite timeout
    // scalars. Unsupported/failed configuration fails; no infinite default is
    // substituted. These settings do not replace the external process watchdog.
    unsafe { timeouts.SetConnectionTimeout(UIA_TIMEOUT_MILLIS) }
        .map_err(|error| native_error(NativeOperation::ConfigureAutomationTimeout, error))?;
    // SAFETY: same scoped UIA2 and fixed transaction timeout contract.
    unsafe { timeouts.SetTransactionTimeout(UIA_TIMEOUT_MILLIS) }
        .map_err(|error| native_error(NativeOperation::ConfigureAutomationTimeout, error))?;
    // SAFETY: exact retained/rechecked OS candidate HWND, never the desktop root
    // or caller-selected window. Ownership/liveness is rechecked after traversal.
    let root = unsafe { automation.ElementFromHandle(hwnd) }
        .map_err(|error| native_error(NativeOperation::ElementFromWindow, error))?;
    // SAFETY: live scoped UIA interface; obtains a read-only walker reference.
    let walker = unsafe { automation.RawViewWalker() }
        .map_err(|error| native_error(NativeOperation::TreeWalker, error))?;
    visit(&root, &walker, pid, 1, began, counts, cleanup)
}

fn visit(
    element: &IUIAutomationElement,
    walker: &IUIAutomationTreeWalker,
    pid: u32,
    depth: u8,
    began: Instant,
    counts: &mut ProbeCounts,
    cleanup: &CleanupLog,
) -> Result<(), ProbeError> {
    policy::budget(began.elapsed())?;
    policy::visit(counts, depth)?;
    // SAFETY: live scoped UIA element. Only fixed scalar capability/identity
    // properties are queried; no Name, Text, Value or password content is read.
    let owner = unsafe { element.CurrentProcessId() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    if u32::try_from(owner).ok() != Some(pid) {
        return Err(ProbeError::new(ProbeFailure::ProviderOwnerMismatch));
    }
    // SAFETY: fixed password FLAG read, not a value/pattern-content query.
    let password = unsafe { element.CurrentIsPassword() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    if password.as_bool() {
        counts.password_nodes_skipped += 1;
        // Do not inspect this node's other properties/patterns or its descendants.
        return Ok(());
    }
    // SAFETY: the same live element, fixed scalar properties only. None of these
    // calls activates a window, retrieves user content or invokes a pattern.
    let control_type = unsafe { element.CurrentControlType() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    // SAFETY: scoped interface; read-only enabled flag.
    let enabled = unsafe { element.CurrentIsEnabled() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    // SAFETY: scoped interface; read-only offscreen flag.
    let offscreen = unsafe { element.CurrentIsOffscreen() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    // SAFETY: reads an opaque HWND value only; it is not dereferenced or exposed.
    let native = unsafe { element.CurrentNativeWindowHandle() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    if !native.0.is_null() {
        if window_owner(native)?.1 != pid {
            return Err(ProbeError::new(ProbeFailure::ProviderOwnerMismatch));
        }
        counts.native_window_elements += 1;
    }
    counts.enabled_elements += u16::from(enabled.as_bool());
    counts.offscreen_elements += u16::from(offscreen.as_bool());
    counts.button_elements += u16::from(control_type == UIA_ButtonControlTypeId);
    counts.invoke_pattern_available += u16::from(pattern_available(
        element,
        UIA_IsInvokePatternAvailablePropertyId,
        cleanup,
    )?);
    counts.value_pattern_available += u16::from(pattern_available(
        element,
        UIA_IsValuePatternAvailablePropertyId,
        cleanup,
    )?);
    counts.legacy_accessible_pattern_available += u16::from(pattern_available(
        element,
        UIA_IsLegacyIAccessiblePatternAvailablePropertyId,
        cleanup,
    )?);
    policy::budget(began.elapsed())?;
    let mut child = walk(walker, element, Walk::FirstChild)?;
    while let Some(current) = child {
        visit(&current, walker, pid, depth + 1, began, counts, cleanup)?;
        policy::budget(began.elapsed())?;
        child = walk(walker, &current, Walk::NextSibling)?;
    }
    Ok(())
}

enum Walk {
    FirstChild,
    NextSibling,
}

fn walk(
    walker: &IUIAutomationTreeWalker,
    element: &IUIAutomationElement,
    direction: Walk,
) -> Result<Option<IUIAutomationElement>, ProbeError> {
    let mut output: *mut c_void = std::ptr::null_mut();
    // SAFETY: both live COM references belong to this initialized worker. The
    // exact generated vtable signatures take one initialized interface-out slot.
    // Calling the vtable preserves S_OK+NULL (normal end) separately from an
    // actual failing E_POINTER; the ergonomic binding would conflate the two.
    // Only successful non-null output is an AddRef-owned interface to adopt.
    let status = unsafe {
        let table = walker.vtable();
        match direction {
            Walk::FirstChild => {
                (table.GetFirstChildElement)(walker.as_raw(), element.as_raw(), &mut output)
            }
            Walk::NextSibling => {
                (table.GetNextSiblingElement)(walker.as_raw(), element.as_raw(), &mut output)
            }
        }
    };
    status
        .ok()
        .map_err(|error| native_error(NativeOperation::TreeWalker, error))?;
    if output.is_null() {
        return Ok(None);
    }
    // SAFETY: successful UIA out pointer owns one interface reference. Exactly
    // one wrapper adopts it; its Drop releases it before apartment/thread exit.
    Ok(Some(unsafe { IUIAutomationElement::from_raw(output) }))
}

struct PropertyValue<'a> {
    value: ManuallyDrop<VARIANT>,
    cleanup: &'a CleanupLog,
}
impl Drop for PropertyValue<'_> {
    fn drop(&mut self) {
        // SAFETY: unique VARIANT out slot initialized before the COM read. Its
        // contents are owned on both HRESULT paths, just as in the generated
        // binding's temporary. No field reference escapes and no clone is made.
        // ManuallyDrop prevents
        // windows' automatic Drop from clearing twice; failures are recorded.
        if let Err(error) = unsafe { VariantClear(&mut *self.value) } {
            record_cleanup(self.cleanup, NativeOperation::ClearProperty, error);
        }
    }
}

fn pattern_available(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
    cleanup: &CleanupLog,
) -> Result<bool, ProbeError> {
    // Own the initialized out slot before calling COM. The generated ergonomic
    // wrapper drops its temporary VARIANT on HRESULT failure and discards the
    // VariantClear result; this guard records cleanup failures on BOTH paths.
    let mut value = PropertyValue {
        value: ManuallyDrop::new(VARIANT::default()),
        cleanup,
    };
    // SAFETY: callers supply only the three fixed availability IDs above. The
    // live scoped interface and its exact generated vtable receive one exclusive
    // initialized VARIANT out slot, retained by the guard throughout the call.
    // No content/pattern action is requested. On success or failure the guarded
    // slot is cleared exactly once before its storage leaves this scope.
    let status = unsafe {
        (element.vtable().GetCurrentPropertyValueEx)(
            element.as_raw(),
            property,
            true.into(),
            &mut *value.value,
        )
    };
    status
        .ok()
        .map_err(|error| native_error(NativeOperation::PatternAvailability, error))?;
    if value.value.vt() != VT_BOOL {
        return Err(malformed(NativeOperation::PatternAvailability));
    }
    // SAFETY: vt was checked to exact VT_BOOL, so this union arm is initialized.
    // VARIANT_BOOL accepts only its documented false/true representations here.
    match unsafe { value.value.Anonymous.Anonymous.Anonymous.boolVal.0 } {
        0 => Ok(false),
        -1 => Ok(true),
        _ => Err(malformed(NativeOperation::PatternAvailability)),
    }
}
