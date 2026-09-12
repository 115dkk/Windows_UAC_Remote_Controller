// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed embedded-relay firewall lifecycle. No caller-supplied rule, program,
//! port or profile enters this boundary. Elevated installation ownership and
//! retained protected-file pins are required before accessing system COM.
#![allow(unsafe_code)]

use std::{marker::PhantomData, rc::Rc};
use windows::{
    Win32::{
        NetworkManagement::WindowsFirewall::{
            INetFwPolicy2, INetFwRule, NET_FW_ACTION_ALLOW, NET_FW_IP_PROTOCOL_TCP,
            NET_FW_PROFILE2_PRIVATE, NET_FW_RULE_DIR_IN, NetFwPolicy2, NetFwRule,
        },
        System::Com::{
            CLSCTX_INPROC_SERVER, COINIT_MULTITHREADED, CoCreateInstance, CoInitializeEx,
            CoUninitialize,
        },
    },
    core::BSTR,
};

use super::{require_elevated, validate_installation, win_error};
use crate::{SERVICE_NAME, ServiceError, ServiceOperation};

const RULE_NAME: &str = "dev.dkk115.uacremote.embedded-relay.v1";
const LOCAL_PORT: &str = "7443";

/// Must be dropped on this thread after every COM interface. A changed apartment
/// is an error, not permission to uninitialize someone else's apartment.
struct ComApartment(PhantomData<Rc<()>>);

impl ComApartment {
    fn enter(operation: ServiceOperation) -> Result<Self, ServiceError> {
        // SAFETY: no reserved pointer; this synchronous lifecycle owns one
        // successful COM initialization count (including S_FALSE) on this thread.
        unsafe { CoInitializeEx(None, COINIT_MULTITHREADED) }
            .ok()
            .map_err(|error| win_error(operation, error))?;
        Ok(Self(PhantomData))
    }
}

impl Drop for ComApartment {
    fn drop(&mut self) {
        // SAFETY: !Send/!Sync guard, exactly one matching successful init. Callers
        // declare this guard before interfaces so those release first on unwind.
        unsafe { CoUninitialize() };
    }
}

/// Install/update only this product's private-network TCP relay allowance.
/// The caller keeps service installation disabled until this succeeds.
pub(crate) fn provision_embedded_relay_firewall() -> Result<(), ServiceError> {
    require_elevated()?;
    let installation = validate_installation(true)?;
    let application = BSTR::from(
        installation
            .executable()
            .to_str()
            .ok_or(ServiceError::UnsafePath)?,
    );
    let operation = ServiceOperation::ConfigureFirewall;
    let _apartment = ComApartment::enter(operation)?;
    // SAFETY: fixed Windows firewall classes, no aggregation, elevated intact-OS
    // COM registration; interfaces and owned BSTRs remain on this apartment.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| win_error(operation, error))?;
    // SAFETY: policy is live in the initialized apartment; result owns its COM ref.
    let rules = unsafe { policy.Rules() }.map_err(|error| win_error(operation, error))?;
    // SAFETY: same fixed-class, same-apartment ownership as above.
    let rule: INetFwRule = unsafe { CoCreateInstance(&NetFwRule, None, CLSCTX_INPROC_SERVER) }
        .map_err(|error| win_error(operation, error))?;
    let name = BSTR::from(RULE_NAME);
    let service = BSTR::from(SERVICE_NAME);
    let port = BSTR::from(LOCAL_PORT);
    // SAFETY: all setters borrow owned BSTRs or pass fixed scalar constants.
    // Configure the detached object completely before publishing it. Protocol
    // precedes ports as required by INetFwRule; no transient broad rule is added.
    let configure = unsafe {
        (|| -> windows::core::Result<()> {
            rule.SetName(&name)?;
            rule.SetDescription(&BSTR::from(
                "UAC remote approval embedded relay (private networks)",
            ))?;
            rule.SetApplicationName(&application)?;
            rule.SetServiceName(&service)?;
            rule.SetProtocol(NET_FW_IP_PROTOCOL_TCP.0)?;
            rule.SetLocalPorts(&port)?;
            rule.SetDirection(NET_FW_RULE_DIR_IN)?;
            rule.SetProfiles(NET_FW_PROFILE2_PRIVATE.0)?;
            rule.SetInterfaceTypes(&BSTR::from("All"))?;
            rule.SetEdgeTraversal(false.into())?;
            rule.SetAction(NET_FW_ACTION_ALLOW)?;
            rule.SetEnabled(true.into())?;
            rules.Add(&rule)
        })()
    };
    configure.map_err(|error| win_error(operation, error))?;
    // SAFETY: fixed-name lookup in the same collection; fresh owned reference.
    let installed = unsafe { rules.Item(&name) }.map_err(|error| win_error(operation, error))?;
    // SAFETY: getters return owned strings/scalars; no pointers outlive COM refs.
    let matches = unsafe {
        (|| -> windows::core::Result<bool> {
            Ok(installed.ApplicationName()? == application
                && installed.ServiceName()? == service
                && installed.Protocol()? == NET_FW_IP_PROTOCOL_TCP.0
                && installed.LocalPorts()? == port
                && installed.Direction()? == NET_FW_RULE_DIR_IN
                && installed.Profiles()? == NET_FW_PROFILE2_PRIVATE.0
                && installed.InterfaceTypes()? == "All"
                && !installed.EdgeTraversal()?.as_bool()
                && installed.Action()? == NET_FW_ACTION_ALLOW
                && installed.Enabled()?.as_bool())
        })()
    }
    .map_err(|error| win_error(operation, error))?;
    if !matches {
        return Err(ServiceError::ConfigurationConflict);
    }
    Ok(())
}

/// Remove only this fixed rule. Windows documents absence as a successful no-op;
/// permission/COM failures propagate and are not mistaken for an absent rule.
pub(crate) fn remove_embedded_relay_firewall() -> Result<(), ServiceError> {
    require_elevated()?;
    let _installation = validate_installation(true)?;
    let operation = ServiceOperation::RemoveFirewall;
    let _apartment = ComApartment::enter(operation)?;
    // SAFETY: fixed system COM class, same-thread RAII lifetime as provisioning.
    let policy: INetFwPolicy2 =
        unsafe { CoCreateInstance(&NetFwPolicy2, None, CLSCTX_INPROC_SERVER) }
            .map_err(|error| win_error(operation, error))?;
    // SAFETY: live apartment-owned interface and fixed owned rule name only.
    let rules = unsafe { policy.Rules() }.map_err(|error| win_error(operation, error))?;
    // SAFETY: same owned rules reference; the only removal name is a constant.
    unsafe { rules.Remove(&BSTR::from(RULE_NAME)) }.map_err(|error| win_error(operation, error))
}
