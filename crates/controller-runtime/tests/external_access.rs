// SPDX-License-Identifier: GPL-2.0-or-later
//! The pinned presentation contract of the external-access tab: the view's
//! JSON shape and the exact input shapes the WebView may send.

use controller_runtime::{
    ExternalAccess, ExternalAccessFailure, ExternalAccessMode, ExternalAccessView,
    ExternalCandidateSource, MAX_EXTERNAL_ACCESS_JSON_BYTES, decode_external_access_json,
};
use serde_json::json;

fn view(mode: ExternalAccessMode) -> ExternalAccessView {
    ExternalAccessView {
        mode,
        external_port: None,
        fixed_address: None,
        external_address: None,
        source: None,
        lan_address: Some("192.168.1.50".into()),
        relay_port: 7443,
        failure: None,
    }
}

#[test]
fn view_serializes_camel_case_fields_and_snake_case_values_with_nulls() {
    let automatic = ExternalAccessView {
        failure: Some(ExternalAccessFailure::NoMappingProtocol),
        ..view(ExternalAccessMode::Automatic)
    };
    assert_eq!(
        serde_json::to_value(&automatic).unwrap(),
        json!({
            "mode": "automatic",
            "externalPort": null,
            "fixedAddress": null,
            "externalAddress": null,
            "source": null,
            "lanAddress": "192.168.1.50",
            "relayPort": 7443,
            "failure": "no_mapping_protocol"
        })
    );
    let forward = ExternalAccessView {
        external_port: Some(8443),
        external_address: Some("93.184.216.34:8443".into()),
        source: Some(ExternalCandidateSource::Stun),
        ..view(ExternalAccessMode::RouterForward)
    };
    assert_eq!(
        serde_json::to_value(&forward).unwrap(),
        json!({
            "mode": "router_forward",
            "externalPort": 8443,
            "fixedAddress": null,
            "externalAddress": "93.184.216.34:8443",
            "source": "stun",
            "lanAddress": "192.168.1.50",
            "relayPort": 7443,
            "failure": null
        })
    );
    let fixed = ExternalAccessView {
        fixed_address: Some("[2606:4700::1111]:7443".into()),
        external_address: Some("[2606:4700::1111]:7443".into()),
        source: Some(ExternalCandidateSource::Fixed),
        lan_address: None,
        ..view(ExternalAccessMode::Fixed)
    };
    assert_eq!(
        serde_json::to_value(&fixed).unwrap(),
        json!({
            "mode": "fixed",
            "externalPort": null,
            "fixedAddress": "[2606:4700::1111]:7443",
            "externalAddress": "[2606:4700::1111]:7443",
            "source": "fixed",
            "lanAddress": null,
            "relayPort": 7443,
            "failure": null
        })
    );
    for (source, text) in [
        (ExternalCandidateSource::Pcp, "pcp"),
        (ExternalCandidateSource::Upnp, "upnp"),
        (ExternalCandidateSource::Stun, "stun"),
        (ExternalCandidateSource::Fixed, "fixed"),
        (ExternalCandidateSource::PublicInterface, "public_interface"),
    ] {
        assert_eq!(serde_json::to_value(source).unwrap(), text);
    }
    for (failure, text) in [
        (
            ExternalAccessFailure::NoMappingProtocol,
            "no_mapping_protocol",
        ),
        (
            ExternalAccessFailure::PrivateExternalAddress,
            "private_external_address",
        ),
        (
            ExternalAccessFailure::PublicAddressUnavailable,
            "public_address_unavailable",
        ),
    ] {
        assert_eq!(serde_json::to_value(failure).unwrap(), text);
    }
    // Addresses stay out of ambient diagnostics.
    assert!(!format!("{fixed:?}").contains("2606"));
    assert!(!format!("{forward:?}").contains("192.168"));
}

#[test]
fn contradictory_views_are_dropped() {
    assert!(view(ExternalAccessMode::Automatic).checked().is_some());
    for bad in [
        ExternalAccessView {
            external_port: Some(7443),
            ..view(ExternalAccessMode::Automatic)
        },
        view(ExternalAccessMode::RouterForward),
        ExternalAccessView {
            external_port: Some(0),
            ..view(ExternalAccessMode::RouterForward)
        },
        view(ExternalAccessMode::Fixed),
        ExternalAccessView {
            external_address: Some("93.184.216.34:7443".into()),
            ..view(ExternalAccessMode::Automatic)
        },
        ExternalAccessView {
            source: Some(ExternalCandidateSource::Upnp),
            ..view(ExternalAccessMode::Automatic)
        },
        ExternalAccessView {
            external_address: Some("93.184.216.34:7443".into()),
            source: Some(ExternalCandidateSource::Upnp),
            failure: Some(ExternalAccessFailure::NoMappingProtocol),
            ..view(ExternalAccessMode::Automatic)
        },
        ExternalAccessView {
            relay_port: 0,
            ..view(ExternalAccessMode::Automatic)
        },
    ] {
        assert!(bad.checked().is_none());
    }
}

#[test]
fn input_accepts_exactly_the_three_shapes_and_validates_like_the_service() {
    assert_eq!(
        decode_external_access_json(br#"{"mode":"automatic"}"#),
        Ok(ExternalAccess::Automatic)
    );
    assert_eq!(
        decode_external_access_json(br#"{"mode":"router_forward","externalPort":8443}"#),
        Ok(ExternalAccess::RouterForward {
            external_port: 8443
        })
    );
    assert_eq!(
        decode_external_access_json(br#"{"externalPort":1,"mode":"router_forward"}"#),
        Ok(ExternalAccess::RouterForward { external_port: 1 })
    );
    assert_eq!(
        decode_external_access_json(br#"{"mode":"fixed","fixedAddress":"93.184.216.34:7443"}"#),
        Ok(ExternalAccess::Fixed {
            address: "93.184.216.34:7443".parse().unwrap()
        })
    );
    assert_eq!(
        decode_external_access_json(br#"{"mode":"fixed","fixedAddress":"[2606:4700::1111]:7443"}"#),
        Ok(ExternalAccess::Fixed {
            address: "[2606:4700::1111]:7443".parse().unwrap()
        })
    );
    for (bad, code) in [
        (
            &br#"{"mode":"automatic","externalPort":7443}"#[..],
            "invalid_external_access",
        ),
        (
            br#"{"mode":"automatic","extra":true}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"automatic","fixedAddress":null}"#,
            "invalid_external_access",
        ),
        (br#"{"mode":"router_forward"}"#, "invalid_external_access"),
        (
            br#"{"mode":"router_forward","externalPort":null}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"router_forward","externalPort":"7443"}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"router_forward","externalPort":7443.5}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"router_forward","externalPort":-1}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"router_forward","externalPort":65536}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"router_forward","externalPort":7443,"fixedAddress":"93.184.216.34:7443"}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"router_forward","external_port":7443}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"router_forward","externalPort":0}"#,
            "invalid_external_port",
        ),
        (br#"{"mode":"fixed"}"#, "invalid_external_access"),
        (
            br#"{"mode":"fixed","fixedAddress":"relay.example:7443"}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":"93.184.216.34"}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":" 93.184.216.34:7443"}"#,
            "invalid_external_access",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":"93.184.216.34:0"}"#,
            "invalid_external_address",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":"192.168.1.20:7443"}"#,
            "invalid_external_address",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":"203.0.113.7:7443"}"#,
            "invalid_external_address",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":"[2001:db8::1]:7443"}"#,
            "invalid_external_address",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":"[fe80::1]:7443"}"#,
            "invalid_external_address",
        ),
        (
            br#"{"mode":"fixed","fixedAddress":"93.184.216.34:7443","externalPort":1}"#,
            "invalid_external_access",
        ),
        (br#"{"mode":"dmz"}"#, "invalid_external_access"),
        (br#"{"mode":"Automatic"}"#, "invalid_external_access"),
        (br#"{}"#, "invalid_external_access"),
        (br#""automatic""#, "invalid_external_access"),
        (b"", "invalid_external_access"),
    ] {
        let text = String::from_utf8_lossy(bad);
        let result = decode_external_access_json(bad);
        assert_eq!(result.expect_err(&text).code, code, "{text}");
    }
    let oversized = format!(
        r#"{{"mode":"automatic"}}{}"#,
        " ".repeat(MAX_EXTERNAL_ACCESS_JSON_BYTES)
    );
    assert_eq!(
        decode_external_access_json(oversized.as_bytes())
            .unwrap_err()
            .code,
        "invalid_external_access"
    );
}
