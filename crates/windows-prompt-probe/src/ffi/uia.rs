// SPDX-License-Identifier: GPL-2.0-or-later
//! Two bounded same-root UIA observations. No action-pattern interfaces, edit/
//! value/password content, semantic request identity or surviving action target.
use super::{
    malformed, native_error,
    resources::{CleanupLog, record_cleanup},
    window_owner,
};
use crate::{
    LabelKind, MAX_PROMPT_CONTENT_UTF8_BYTES, MAX_PROMPT_FIELD_UTF16_UNITS, MAX_PROMPT_LABELS,
    MAX_RUNTIME_ID_VALUES, NativeOperation, ProbeCounts, ProbeError, ProbeFailure, ProbeReport,
    PromptContentObservation, PromptLabel, UIA_TIMEOUT_MILLIS, policy, prompt_text_from_utf16,
};
use std::{ffi::c_void, marker::PhantomData, mem::ManuallyDrop, rc::Rc, time::Instant};
use windows::{
    Win32::{
        Foundation::HWND,
        System::{
            Com::{
                CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
                CoUninitialize, SAFEARRAY,
            },
            Ole::{
                SafeArrayDestroy, SafeArrayGetDim, SafeArrayGetElement, SafeArrayGetElemsize,
                SafeArrayGetLBound, SafeArrayGetUBound, SafeArrayGetVartype,
            },
            Variant::{VARIANT, VT_BOOL, VT_BSTR, VT_I4, VariantClear},
        },
        UI::Accessibility::{
            CUIAutomation8, IUIAutomation, IUIAutomation2, IUIAutomationElement,
            IUIAutomationTreeWalker, UIA_ButtonControlTypeId as UIA_BUTTON_CONTROL_TYPE_ID,
            UIA_EditControlTypeId, UIA_HyperlinkControlTypeId as UIA_HYPERLINK_CONTROL_TYPE_ID,
            UIA_IsInvokePatternAvailablePropertyId,
            UIA_IsLegacyIAccessiblePatternAvailablePropertyId,
            UIA_IsValuePatternAvailablePropertyId, UIA_NamePropertyId, UIA_PROPERTY_ID,
            UIA_TextControlTypeId as UIA_TEXT_CONTROL_TYPE_ID, UIA_WindowControlTypeId,
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
    seed: ProbeCounts,
    cleanup: &CleanupLog,
    mut recheck: impl FnMut() -> Result<(), ProbeError>,
) -> Result<ProbeReport, ProbeError> {
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
    // Keep this SAME root reference, walker and apartment alive across both full
    // captures. Neither provider properties nor RuntimeId are an atomic/live
    // action identity. The trusted callback preserves candidate/desktop checks.
    recheck()?;
    let first = capture(&root, &walker, hwnd, pid, seed, began, cleanup)?;
    recheck()?;
    let second = capture(&root, &walker, hwnd, pid, seed, began, cleanup)?;
    recheck()?;
    policy::budget(began.elapsed())?;
    if first.counts() != second.counts() || first.content() != second.content() {
        return Err(ProbeError::new(ProbeFailure::ObservationChanged));
    }
    Ok(first)
}

struct Capture {
    counts: ProbeCounts,
    runtime_id: Option<Vec<i32>>,
    caption: Option<String>,
    labels: Vec<PromptLabel>,
    utf8_bytes: usize,
}
struct Traversal<'a> {
    walker: &'a IUIAutomationTreeWalker,
    root_hwnd: HWND,
    pid: u32,
    began: Instant,
    cleanup: &'a CleanupLog,
}
impl Capture {
    fn remaining(&self) -> usize {
        MAX_PROMPT_CONTENT_UTF8_BYTES - self.utf8_bytes
    }
    fn account(&mut self, text: &str) -> Result<(), ProbeError> {
        self.utf8_bytes = self
            .utf8_bytes
            .checked_add(text.len())
            .filter(|total| *total <= MAX_PROMPT_CONTENT_UTF8_BYTES)
            .ok_or_else(|| ProbeError::new(ProbeFailure::ContentLimit))?;
        Ok(())
    }
}

fn capture(
    root: &IUIAutomationElement,
    walker: &IUIAutomationTreeWalker,
    hwnd: HWND,
    pid: u32,
    seed: ProbeCounts,
    began: Instant,
    cleanup: &CleanupLog,
) -> Result<ProbeReport, ProbeError> {
    let mut observed = Capture {
        // These two fields are the original bounded desktop census, not a new
        // independent census. Every traversal count is freshly collected.
        counts: ProbeCounts {
            top_level_windows: seed.top_level_windows,
            qualified_candidates: seed.qualified_candidates,
            ..ProbeCounts::default()
        },
        runtime_id: None,
        caption: None,
        labels: Vec::with_capacity(MAX_PROMPT_LABELS),
        utf8_bytes: 0,
    };
    let traversal = Traversal {
        walker,
        root_hwnd: hwnd,
        pid,
        began,
        cleanup,
    };
    visit(root, 1, &mut observed, &traversal)?;
    let content = PromptContentObservation::from_parts(
        observed
            .runtime_id
            .ok_or_else(|| ProbeError::new(ProbeFailure::UnsupportedContent))?,
        observed
            .caption
            .ok_or_else(|| ProbeError::new(ProbeFailure::UnsupportedContent))?,
        observed.labels,
    )
    .map_err(|_| ProbeError::new(ProbeFailure::UnsupportedContent))?;
    ProbeReport::from_observation(observed.counts, content)
        .map_err(|_| ProbeError::new(ProbeFailure::UnsupportedContent))
}

fn visit(
    element: &IUIAutomationElement,
    depth: u8,
    observed: &mut Capture,
    traversal: &Traversal<'_>,
) -> Result<(), ProbeError> {
    let walker = traversal.walker;
    let root_hwnd = traversal.root_hwnd;
    let pid = traversal.pid;
    let began = traversal.began;
    let cleanup = traversal.cleanup;
    policy::budget(began.elapsed())?;
    let ordinal = observed.counts.elements;
    policy::visit(&mut observed.counts, depth)?;
    // SAFETY: live scoped UIA element. Only fixed scalar capability/identity
    // identity property first; no text is queried until exclusion guards pass.
    let owner = unsafe { element.CurrentProcessId() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    if u32::try_from(owner).ok() != Some(pid) {
        return Err(ProbeError::new(ProbeFailure::ProviderOwnerMismatch));
    }
    // SAFETY: fixed password FLAG read, not a value/pattern-content query.
    let password = unsafe { element.CurrentIsPassword() }
        .map_err(|error| native_error(NativeOperation::ElementProperty, error))?;
    if password.as_bool() {
        observed.counts.password_nodes_skipped += 1;
        // Do not inspect this node's other properties/patterns or its descendants.
        return Ok(());
    }
    // SAFETY: the same live element, fixed scalar properties only. None of these
    // calls activates a window, retrieves edit/value content or invokes a pattern.
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
        observed.counts.native_window_elements += 1;
    }
    observed.counts.enabled_elements += u16::from(enabled.as_bool());
    observed.counts.offscreen_elements += u16::from(offscreen.as_bool());
    observed.counts.button_elements += u16::from(control_type == UIA_BUTTON_CONTROL_TYPE_ID);
    observed.counts.invoke_pattern_available += u16::from(pattern_available(
        element,
        UIA_IsInvokePatternAvailablePropertyId,
        cleanup,
    )?);
    let has_value = pattern_available(element, UIA_IsValuePatternAvailablePropertyId, cleanup)?;
    observed.counts.value_pattern_available += u16::from(has_value);
    observed.counts.legacy_accessible_pattern_available += u16::from(pattern_available(
        element,
        UIA_IsLegacyIAccessiblePatternAvailablePropertyId,
        cleanup,
    )?);
    if control_type == UIA_EditControlTypeId || has_value {
        // Metadata flags above contain no value. Never read this node's Name or
        // any descendant text, including a Text/Button nested beneath an editor
        // or a provider advertising ValuePattern. No pattern object is obtained.
        return Ok(());
    }
    if depth == 1 {
        if control_type != UIA_WindowControlTypeId || native != root_hwnd || offscreen.as_bool() {
            return Err(ProbeError::new(ProbeFailure::UnsupportedContent));
        }
        observed.runtime_id = Some(runtime_id(element, cleanup)?);
        let caption = name(
            element,
            NativeOperation::Caption,
            observed.remaining(),
            cleanup,
        )?;
        observed.account(&caption)?;
        // A genuinely empty VT_BSTR caption is retained as empty, never filled
        // with a program/path/default title. Missing/wrong-typed property fails.
        observed.caption = Some(caption);
    } else if !offscreen.as_bool() {
        let kind = match control_type {
            UIA_TEXT_CONTROL_TYPE_ID => Some(LabelKind::Text),
            UIA_BUTTON_CONTROL_TYPE_ID => Some(LabelKind::Button),
            UIA_HYPERLINK_CONTROL_TYPE_ID => Some(LabelKind::Hyperlink),
            _ => None,
        };
        if let Some(kind) = kind {
            let text = name(
                element,
                NativeOperation::Label,
                observed.remaining(),
                cleanup,
            )?;
            // Actual empty producer text contributes no label. No trim,
            // deduplication, normalization, synthesized content or lossy decode.
            if !text.is_empty() {
                if observed.labels.len() == MAX_PROMPT_LABELS {
                    return Err(ProbeError::new(ProbeFailure::ContentLimit));
                }
                observed.account(&text)?;
                observed.labels.push(
                    PromptLabel::new(ordinal, depth, kind, enabled.as_bool(), text)
                        .map_err(|_| ProbeError::new(ProbeFailure::UnsupportedContent))?,
                );
            }
        }
    }
    policy::budget(began.elapsed())?;
    let mut child = walk(walker, element, Walk::FirstChild)?;
    while let Some(current) = child {
        visit(&current, depth + 1, observed, traversal)?;
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
    let value = read_property(
        element,
        property,
        NativeOperation::PatternAvailability,
        cleanup,
    )?;
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

fn read_property<'a>(
    element: &IUIAutomationElement,
    property: UIA_PROPERTY_ID,
    operation: NativeOperation,
    cleanup: &'a CleanupLog,
) -> Result<PropertyValue<'a>, ProbeError> {
    // Own the initialized out slot before calling COM. The generated ergonomic
    // wrapper drops its temporary VARIANT on HRESULT failure and discards the
    // VariantClear result; this guard records cleanup failures on BOTH paths.
    let mut value = PropertyValue {
        value: ManuallyDrop::new(VARIANT::default()),
        cleanup,
    };
    // SAFETY: private callers supply only the fixed Name or availability IDs. The
    // live scoped interface and its exact generated vtable receive one exclusive
    // initialized VARIANT out slot, retained by the guard throughout the call.
    // No edit/value read or pattern action is requested. On either HRESULT path the guarded
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
        .map_err(|error| native_error(operation, error))?;
    if status.0 != 0 {
        return Err(malformed(operation));
    }
    Ok(value)
}

fn name(
    element: &IUIAutomationElement,
    operation: NativeOperation,
    remaining: usize,
    cleanup: &CleanupLog,
) -> Result<String, ProbeError> {
    let value = read_property(element, UIA_NamePropertyId, operation, cleanup)?;
    if value.value.vt() != VT_BSTR {
        return Err(malformed(operation));
    }
    // SAFETY: exact VT_BSTR selects this initialized owned union arm. Borrow
    // through ManuallyDrop/BSTR's slice view; NEVER clone, move, from_raw or free
    // it independently. The PropertyValue remains alive until UTF8 has been
    // copied and VariantClear then owns the one release on every return path.
    let units: &[u16] = unsafe { &value.value.Anonymous.Anonymous.Anonymous.bstrVal };
    // Native/provider BSTR allocation happened BEFORE this size check. Only the
    // bounded client copy is constrained here; ROOT's helper job supplies its
    // process memory cap, not a promise about remote provider/server allocation.
    if units.len() > MAX_PROMPT_FIELD_UTF16_UNITS {
        return Err(ProbeError::new(ProbeFailure::ContentLimit));
    }
    let text = prompt_text_from_utf16(units)
        .map_err(|_| ProbeError::new(ProbeFailure::UnsupportedContent))?;
    if text.len() > remaining {
        return Err(ProbeError::new(ProbeFailure::ContentLimit));
    }
    Ok(text)
}

struct RuntimeArray<'a> {
    value: *mut SAFEARRAY,
    cleanup: &'a CleanupLog,
}
impl Drop for RuntimeArray<'_> {
    fn drop(&mut self) {
        let value = std::mem::replace(&mut self.value, std::ptr::null_mut());
        if !value.is_null() {
            // SAFETY: this is the uniquely owned SAFEARRAY out slot from the
            // root's GetRuntimeId call, on success OR failure if supplied. No
            // SafeArrayAccessData lock or borrowed element pointer escapes.
            // Destroy is attempted once; failure remains a cleanup obligation
            // in the probe result, never successful observation/another free.
            if let Err(error) = unsafe { SafeArrayDestroy(value) } {
                record_cleanup(self.cleanup, NativeOperation::ClearRuntimeId, error);
            }
        }
    }
}

fn runtime_id(
    element: &IUIAutomationElement,
    cleanup: &CleanupLog,
) -> Result<Vec<i32>, ProbeError> {
    // Adopt the initialized out slot before calling COM so an allocated result
    // cannot leak merely because GetRuntimeId subsequently returns failure.
    let mut array = RuntimeArray {
        value: std::ptr::null_mut(),
        cleanup,
    };
    // SAFETY: retained root COM reference on this MTA and one initialized,
    // exclusively borrowed SAFEARRAY-pointer out slot with its scope guard.
    let status = unsafe { (element.vtable().GetRuntimeId)(element.as_raw(), &mut array.value) };
    status
        .ok()
        .map_err(|error| native_error(NativeOperation::RuntimeId, error))?;
    if status.0 != 0 || array.value.is_null() {
        return Err(malformed(NativeOperation::RuntimeId));
    }
    // SAFETY: successful nonnull owned SAFEARRAY; scalar metadata queries only.
    if unsafe { SafeArrayGetDim(array.value) } != 1 {
        return Err(malformed(NativeOperation::RuntimeId));
    }
    // SAFETY: same live descriptor; no data dereference or caller type inference.
    let variant_type = unsafe { SafeArrayGetVartype(array.value) }
        .map_err(|error| native_error(NativeOperation::RuntimeId, error))?;
    // SAFETY: same live descriptor; confirm the output element buffer's size.
    let element_bytes = unsafe { SafeArrayGetElemsize(array.value) };
    if variant_type != VT_I4 || element_bytes as usize != std::mem::size_of::<i32>() {
        return Err(malformed(NativeOperation::RuntimeId));
    }
    // SAFETY: dimension1 was checked; each wrapper has an initialized scalar out.
    let lower = unsafe { SafeArrayGetLBound(array.value, 1) }
        .map_err(|error| native_error(NativeOperation::RuntimeId, error))?;
    // SAFETY: same validated one-dimensional owned array.
    let upper = unsafe { SafeArrayGetUBound(array.value, 1) }
        .map_err(|error| native_error(NativeOperation::RuntimeId, error))?;
    let count = runtime_length(lower, upper)?;
    let mut values = Vec::with_capacity(count);
    for offset in 0..count {
        let index = lower
            .checked_add(i32::try_from(offset).map_err(|_| malformed(NativeOperation::RuntimeId))?)
            .ok_or_else(|| malformed(NativeOperation::RuntimeId))?;
        let mut value = 0i32;
        // SAFETY: exact VT_I4/4-byte storage, index within the validated actual
        // lower/upper bounds (not an assumed zero lower bound). GetElement does
        // its own lock/unlock and copies a scalar; no array pointer escapes.
        unsafe { SafeArrayGetElement(array.value, &index, (&mut value as *mut i32).cast()) }
            .map_err(|error| native_error(NativeOperation::RuntimeId, error))?;
        values.push(value);
    }
    Ok(values)
}

fn runtime_length(lower: i32, upper: i32) -> Result<usize, ProbeError> {
    let count = i64::from(upper) - i64::from(lower) + 1;
    if count <= 0 {
        return Err(malformed(NativeOperation::RuntimeId));
    }
    if count > MAX_RUNTIME_ID_VALUES as i64 {
        return Err(ProbeError::new(ProbeFailure::ContentLimit));
    }
    usize::try_from(count).map_err(|_| malformed(NativeOperation::RuntimeId))
}

#[cfg(test)]
mod tests {
    use super::runtime_length;

    // Pure scalar range arithmetic only. No SAFEARRAY, BSTR, COM, probe or UI API.
    #[test]
    fn runtime_array_bounds_honor_nonzero_and_negative_lower_indices() {
        assert_eq!(runtime_length(7, 7).unwrap(), 1);
        assert_eq!(runtime_length(-9, -7).unwrap(), 3);
        assert_eq!(runtime_length(i32::MIN, i32::MIN + 31).unwrap(), 32);
        assert_eq!(runtime_length(i32::MAX - 31, i32::MAX).unwrap(), 32);
    }
    #[test]
    fn runtime_array_bounds_reject_empty_reversed_oversize_and_overflow_shaped_input() {
        assert!(runtime_length(1, 0).is_err());
        assert!(runtime_length(7, 5).is_err());
        assert!(runtime_length(0, 32).is_err());
        assert!(runtime_length(i32::MIN, i32::MAX).is_err());
    }
}
