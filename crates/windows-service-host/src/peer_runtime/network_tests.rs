// SPDX-License-Identifier: GPL-2.0-or-later
//! Network-owner tests use controlled workers, never the router or service store.
use super::network::*;
use super::{PeerRuntimeError, ServicePeerCarrier};
use crate::management_protocol::{DirectConnectionState, ManagementResponse};
use direct_network::{CandidateSource, DirectGatewayState, ExternalAccess};
use std::{
    cell::RefCell,
    io,
    net::{SocketAddr, SocketAddrV4},
    rc::Rc,
    time::{Duration, Instant},
};

const LAN: &str = "192.168.1.50:7443";
const EXTERNAL: &str = "93.184.216.34:8443";
fn address(value: &str) -> SocketAddr {
    value.parse().unwrap()
}
fn gateway(access: ExternalAccess) -> GatewayReading {
    GatewayReading {
        access,
        state: DirectGatewayState::MappedCandidate,
        candidates: vec![address(LAN), address(EXTERNAL)],
        validity_seconds: 60,
        external: Some(address(EXTERNAL)),
        source: Some(CandidateSource::Fixed),
        failure: None,
    }
}
struct Control {
    trace: Vec<String>,
    drain: [bool; 3],
    fail_relay: bool,
    fail_dialer: bool,
    fail_gateway: bool,
    fail_store: bool,
    running: bool,
    endpoint: Option<SocketAddr>,
    next_id: usize,
    snapshot_reads: usize,
    abuse: relay_service::RelayAbuseCounters,
}
impl Default for Control {
    fn default() -> Self {
        Self {
            trace: Vec::new(),
            drain: [true; 3],
            fail_relay: false,
            fail_dialer: false,
            fail_gateway: false,
            fail_store: false,
            running: true,
            endpoint: Some(address(LAN)),
            next_id: 0,
            snapshot_reads: 0,
            abuse: relay_service::RelayAbuseCounters::default(),
        }
    }
}
type Shared = Rc<RefCell<Control>>;
#[derive(Clone)]
struct FakePlatform(Shared);
struct FakeWorker {
    control: Shared,
    kind: usize,
    id: usize,
    drained: bool,
    exit_taken: bool,
    access: ExternalAccess,
}
const NAMES: [&str; 3] = ["dialer", "gateway", "relay"];
impl FakeWorker {
    fn new(control: &Shared, kind: usize, access: ExternalAccess) -> Self {
        let id = {
            let mut c = control.borrow_mut();
            c.next_id += 1;
            c.next_id
        };
        Self {
            control: control.clone(),
            kind,
            id,
            drained: false,
            exit_taken: false,
            access,
        }
    }
    fn trace(&self, action: &str) {
        self.control
            .borrow_mut()
            .trace
            .push(format!("{action}-{}", NAMES[self.kind]));
    }
}
impl Drop for FakeWorker {
    fn drop(&mut self) {
        self.trace("drop");
    }
}
impl Worker for FakeWorker {
    fn cancel(&mut self) {
        self.trace("cancel");
    }
    fn drain(&mut self) -> bool {
        self.trace("drain");
        self.drained = self.control.borrow().drain[self.kind];
        self.drained
    }
    fn remaining_owners(&self) -> usize {
        usize::from(!self.drained)
    }
}
impl Dialer for FakeWorker {
    fn poll(
        &mut self,
        _: &[(
            approval_protocol::DeviceId,
            SocketAddr,
            relay_service::RouteId,
        )],
        _: Instant,
    ) -> Vec<ServicePeerCarrier> {
        Vec::new()
    }
    fn release(&mut self, _: approval_protocol::DeviceId) {}
}
impl Relay for FakeWorker {
    fn is_running(&self) -> bool {
        !self.drained && self.control.borrow().running
    }
    fn supports_ipv6(&self) -> bool {
        true
    }
    fn abuse_counters(&self) -> relay_service::RelayAbuseCounters {
        self.control.borrow().abuse
    }
    fn take_exit(&mut self) -> Option<relay_service::HostedRelayExit> {
        if !self.drained || self.exit_taken {
            return None;
        }
        self.exit_taken = true;
        self.control
            .borrow_mut()
            .trace
            .push(format!("exit-{}", self.id));
        Some(relay_service::HostedRelayExit::Panicked)
    }
}
impl Gateway for FakeWorker {
    fn access(&self) -> ExternalAccess {
        self.access
    }
    fn snapshot(&self) -> GatewayReading {
        self.control.borrow_mut().snapshot_reads += 1;
        gateway(self.access)
    }
}
impl Platform for FakePlatform {
    type Dialer = FakeWorker;
    type Relay = FakeWorker;
    type Gateway = FakeWorker;
    fn start_dialer(&mut self, _: Option<SocketAddr>) -> Result<FakeWorker, PeerRuntimeError> {
        self.0.borrow_mut().trace.push("start-dialer".into());
        if self.0.borrow().fail_dialer {
            return Err(PeerRuntimeError::Io);
        }
        Ok(FakeWorker::new(&self.0, 0, ExternalAccess::Automatic))
    }
    fn start_relay(&mut self) -> io::Result<FakeWorker> {
        self.0.borrow_mut().trace.push("start-relay".into());
        if self.0.borrow().fail_relay {
            return Err(io::ErrorKind::AddrInUse.into());
        }
        self.0.borrow_mut().running = true;
        Ok(FakeWorker::new(&self.0, 2, ExternalAccess::Automatic))
    }
    fn start_gateway(&mut self, _: SocketAddr, access: ExternalAccess) -> Option<FakeWorker> {
        self.0.borrow_mut().trace.push("start-gateway".into());
        let failed = self.0.borrow().fail_gateway;
        (!failed).then(|| FakeWorker::new(&self.0, 1, access))
    }
    fn local_endpoint(&self) -> Option<SocketAddr> {
        self.0.borrow().endpoint
    }
    fn store_relay(&mut self, _: Option<SocketAddr>) -> Result<(), PeerRuntimeError> {
        self.0.borrow_mut().trace.push("store-relay".into());
        if self.0.borrow().fail_store {
            Err(PeerRuntimeError::Registry)
        } else {
            Ok(())
        }
    }
    fn store_external(&mut self, _: crate::external_access::ExternalAccessSetting) -> bool {
        self.0.borrow_mut().trace.push("store-external".into());
        !self.0.borrow().fail_store
    }
    fn poll_lan(&mut self, _: Option<SocketAddrV4>, _: Instant) {
        self.0.borrow_mut().trace.push("poll-lan".into());
    }
    fn drop_lan(&mut self) {
        self.0.borrow_mut().trace.push("drop-lan".into());
    }
    fn listener_owner(&self) -> Option<windows_port_owner::ListenerOwner> {
        None
    }
    fn record(&mut self, event: crate::public_diagnostics::Event) {
        let kind = serde_json::to_value(event).unwrap()["kind"]
            .as_str()
            .unwrap()
            .to_owned();
        self.0.borrow_mut().trace.push(format!("record-{kind}"));
    }
}
fn invalidator(control: &Shared) -> impl FnMut(Invalidation) + use<> {
    let control = control.clone();
    move |action| {
        control
            .borrow_mut()
            .trace
            .push(format!("invalidate-{action:?}"))
    }
}
fn active() -> (Network<FakePlatform>, Shared, Instant) {
    let control = Rc::new(RefCell::new(Control::default()));
    let now = Instant::now();
    let mut owner = Network::new(FakePlatform(control.clone()), now);
    owner
        .configure_after_ready(None, now, &mut invalidator(&control))
        .unwrap();
    control.borrow_mut().trace.clear();
    (owner, control, now)
}
fn assert_order(trace: &[String], expected: &[&str]) {
    let mut next = 0;
    for event in trace {
        if next < expected.len() && event == expected[next] {
            next += 1;
        }
    }
    assert_eq!(
        next,
        expected.len(),
        "missing ordered events {expected:?} in {trace:?}"
    );
}
fn finish(owner: &mut Network<FakePlatform>, control: &Shared) {
    control.borrow_mut().drain = [true; 3];
    owner.prepare_shutdown();
    owner.begin_shutdown();
    owner.drain_shutdown();
    assert_eq!(owner.remaining_owners(), 0);
}

#[test]
fn replacement_stores_withdraws_drains_starts_then_answers() {
    let (mut owner, control, now) = active();
    owner
        .request_relay(Some(address(EXTERNAL)), &mut invalidator(&control))
        .unwrap();
    assert_eq!(owner.observe().management_snapshot().2, None);
    assert!(owner.replacement_pending());
    let reply = owner
        .poll_replacement(now, &mut invalidator(&control))
        .unwrap();
    assert_eq!(reply, Some(ConfigurationResult::Ready));
    control.borrow_mut().trace.push("answer".into());
    assert_order(
        &control.borrow().trace,
        &[
            "store-relay",
            "cancel-gateway",
            "drop-lan",
            "invalidate-Peers",
            "cancel-dialer",
            "invalidate-Ceremony",
            "cancel-relay",
            "drain-dialer",
            "drop-dialer",
            "drain-gateway",
            "drop-gateway",
            "drain-relay",
            "record-relay_worker_stopped",
            "drop-relay",
            "start-dialer",
            "answer",
        ],
    );
    assert!(!owner.replacement_pending());
    assert_eq!(
        owner.observe().management_snapshot().2,
        Some(address(EXTERNAL))
    );
    finish(&mut owner, &control);
}

#[test]
fn pending_replacement_refuses_another_request_and_retains_each_undrained_owner() {
    let (mut owner, control, now) = active();
    control.borrow_mut().drain = [false; 3];
    owner
        .request_relay(Some(address(EXTERNAL)), &mut invalidator(&control))
        .unwrap();
    assert_eq!(
        owner.request_relay(None, &mut invalidator(&control)),
        Err(PeerRuntimeError::Protocol)
    );
    for (index, name) in NAMES.iter().enumerate() {
        control.borrow_mut().trace.clear();
        assert_eq!(
            owner
                .poll_replacement(now, &mut invalidator(&control))
                .unwrap(),
            None
        );
        assert!(owner.replacement_pending());
        let trace = control.borrow().trace.clone();
        assert!(trace.iter().any(|s| s == &format!("drain-{name}")));
        assert!(!trace.iter().any(|s| s.starts_with("start-")));
        assert!(!trace.iter().any(|s| s.starts_with("store-")));

        control.borrow_mut().drain[index] = true;
    }
    assert_eq!(
        owner
            .poll_replacement(now, &mut invalidator(&control))
            .unwrap(),
        Some(ConfigurationResult::Ready)
    );
    finish(&mut owner, &control);
}

#[test]
fn uncertain_relay_store_is_fatal_before_withdrawal_and_external_store_refuses_without_change() {
    let (mut owner, control, now) = active();
    control.borrow_mut().fail_store = true;
    assert_eq!(
        owner.request_relay(Some(address(EXTERNAL)), &mut invalidator(&control)),
        Err(PeerRuntimeError::Registry)
    );
    assert_eq!(control.borrow().trace, ["store-relay"]);
    assert_eq!(owner.observe().management_snapshot().2, Some(address(LAN)));
    assert!(!owner.replacement_pending());
    assert!(matches!(
        owner.set_external(
            ExternalAccess::Fixed {
                address: address(EXTERNAL)
            },
            now
        ),
        ConfigurationResult::Unavailable
    ));
    assert_eq!(owner.observe().access, ExternalAccess::Automatic);
    assert_eq!(owner.observe().management_snapshot().2, Some(address(LAN)));
    finish(&mut owner, &control);
}

#[test]
fn failed_embedded_replacement_does_not_restore_address_and_retries_after_one_second() {
    let (mut owner, control, now) = active();
    owner
        .request_relay(None, &mut invalidator(&control))
        .unwrap();
    control.borrow_mut().fail_relay = true;
    assert!(matches!(
        owner
            .poll_replacement(now, &mut invalidator(&control))
            .unwrap(),
        Some(ConfigurationResult::Unavailable)
    ));
    assert_eq!(owner.observe().management_snapshot().2, None);
    control.borrow_mut().trace.clear();
    owner
        .poll(now + Duration::from_millis(999), &mut invalidator(&control))
        .unwrap();
    assert!(!control.borrow().trace.iter().any(|s| s == "start-relay"));
    control.borrow_mut().fail_relay = false;
    owner
        .poll(now + Duration::from_secs(1), &mut invalidator(&control))
        .unwrap();
    assert_eq!(owner.observe().management_snapshot().2, Some(address(LAN)));
    finish(&mut owner, &control);
}

#[test]
fn external_change_keeps_relay_and_drains_mapping_obligation_before_starting_another_gateway() {
    let (mut owner, control, now) = active();
    let mode = ExternalAccess::Fixed {
        address: address(EXTERNAL),
    };
    assert_eq!(owner.set_external(mode, now), ConfigurationResult::Ready);
    assert_eq!(owner.observe().management_snapshot().2, Some(address(LAN)));
    control.borrow_mut().drain[1] = false;
    owner.poll(now, &mut invalidator(&control)).unwrap();
    let observed = owner.observe();
    assert_eq!(observed.internal, None);
    assert!(observed.gateway.is_some());
    assert_eq!(observed.management_snapshot().2, Some(address(LAN)));
    assert!(
        !control
            .borrow()
            .trace
            .iter()
            .any(|s| s == "invalidate-Peers")
    );
    control.borrow_mut().drain[1] = true;
    owner
        .poll(now + Duration::from_secs(5), &mut invalidator(&control))
        .unwrap();
    assert_eq!(owner.observe().gateway.unwrap().access, mode);
    assert_order(
        &control.borrow().trace,
        &[
            "store-external",
            "drain-gateway",
            "start-gateway",
            "poll-lan",
        ],
    );
    finish(&mut owner, &control);
}

#[test]
fn each_relay_drain_path_records_the_original_worker_once() {
    for path in 0..4 {
        let (mut owner, control, now) = active();
        match path {
            0 => {
                // replacement
                owner
                    .request_relay(Some(address(EXTERNAL)), &mut invalidator(&control))
                    .unwrap();
                owner
                    .poll_replacement(now, &mut invalidator(&control))
                    .unwrap();
                owner
                    .poll_replacement(now, &mut invalidator(&control))
                    .unwrap();
            }
            1 => {
                // failed listener/restart, including the second withdrawal
                control.borrow_mut().running = false;
                control.borrow_mut().fail_relay = true;
                owner
                    .poll(now + Duration::from_secs(5), &mut invalidator(&control))
                    .unwrap();
                owner
                    .poll(now + Duration::from_secs(6), &mut invalidator(&control))
                    .unwrap();
                assert_order(
                    &control.borrow().trace,
                    &[
                        "invalidate-Peers",
                        "drain-relay",
                        "record-relay_worker_stopped",
                        "invalidate-Peers",
                        "start-relay",
                    ],
                );
            }
            _ => {
                // explicit shutdown and ServiceSession's Drop cleanup use the same drain operation
                owner.prepare_shutdown();
                control
                    .borrow_mut()
                    .trace
                    .push("shutdown-ceremony-and-management".into());
                owner.begin_shutdown();
                owner.drain_shutdown();
                owner.drain_shutdown();
                assert_order(
                    &control.borrow().trace,
                    &[
                        "shutdown-ceremony-and-management",
                        "cancel-gateway",
                        "drop-lan",
                        "cancel-relay",
                        "cancel-dialer",
                        "drain-gateway",
                        "drain-relay",
                        "record-relay_worker_stopped",
                        "drain-dialer",
                    ],
                );
            }
        }
        assert_eq!(
            control
                .borrow()
                .trace
                .iter()
                .filter(|s| s.as_str() == "record-relay_worker_stopped")
                .count(),
            1,
            "path {path}"
        );
        finish(&mut owner, &control);
    }
}

#[test]
fn seven_consumers_use_one_observation_but_keep_their_different_predicates() {
    let (mut owner, control, _) = active();
    let baseline = owner.observe();
    for case in 0..10 {
        let mut observed = baseline.clone();
        match case {
            1 => observed.closing = true,
            2 => observed.pending = true,
            3 => observed.embedded = false,
            4 => observed.running = false,
            5 => observed.internal = None,
            6 => observed.gateway.as_mut().unwrap().validity_seconds = 0,
            7 => {
                observed.gateway.as_mut().unwrap().access = ExternalAccess::Fixed {
                    address: address(EXTERNAL),
                }
            }
            8 => observed.gateway = None,
            9 => observed.relay = Some(address("[fd00::1]:7443")),
            _ => {}
        }
        let management = observed.management_snapshot();
        assert_eq!(
            management.1,
            !matches!(case, 3 | 4),
            "management listening {case}"
        );
        assert_eq!(
            management.2.is_some(),
            case != 4,
            "management address {case}"
        );
        let ManagementResponse::DirectStatus {
            relay_listening, ..
        } = observed.direct_status()
        else {
            panic!()
        };
        assert_eq!(
            relay_listening,
            !matches!(case, 1..=4),
            "direct listening {case}"
        );
        let ManagementResponse::ExternalStatus { external, .. } = observed.external_status() else {
            panic!()
        };
        assert_eq!(
            external.is_some(),
            !matches!(case, 1 | 5 | 7 | 8),
            "external {case}"
        );
        let expected_direct = match case {
            1 | 2 => DirectConnectionState::Stopped,
            3 => DirectConnectionState::Unknown,
            4 => DirectConnectionState::Unavailable,
            0 | 7 => DirectConnectionState::Candidate,
            _ => DirectConnectionState::Discovering,
        };
        assert!(
            matches!(observed.direct_status(), ManagementResponse::DirectStatus { state, .. } if state == expected_direct)
        );
        assert_eq!(
            observed.invitation_addresses(None).is_ok(),
            case != 4,
            "invitation {case}"
        );
        assert_eq!(
            !observed.signed_candidates().0.is_empty(),
            matches!(case, 0 | 7),
            "signed candidates {case}"
        );
        assert_eq!(
            observed.accepts_address_query(address(LAN)),
            !matches!(case, 2 | 4),
            "query {case}"
        );
        assert_eq!(
            observed.lan_announcement().is_some(),
            !matches!(case, 1 | 3 | 4 | 9),
            "LAN {case}"
        );
    }
    assert!(matches!(
        baseline.direct_status(),
        ManagementResponse::DirectStatus {
            state: DirectConnectionState::Candidate,
            ..
        }
    ));
    finish(&mut owner, &control);
}

#[test]
fn consumer_projections_do_not_reread_the_gateway_or_relay() {
    let (mut owner, control, _) = active();
    control.borrow_mut().snapshot_reads = 0;
    let observation = owner.observe();
    assert_eq!(control.borrow().snapshot_reads, 1);
    control.borrow_mut().running = false;
    assert!(observation.management_snapshot().1);
    assert!(observation.invitation_addresses(None).is_ok());
    assert!(!observation.signed_candidates().0.is_empty());
    assert!(observation.accepts_address_query(address(LAN)));
    assert!(observation.lan_announcement().is_some());
    observation.direct_status();
    observation.external_status();
    assert_eq!(control.borrow().snapshot_reads, 1);
    assert!(!owner.observe().management_snapshot().1);
    assert_eq!(control.borrow().snapshot_reads, 2);
    finish(&mut owner, &control);
}

#[test]
fn candidate_bounds_ipv6_filter_and_invitation_primary_remain_distinct() {
    let (mut owner, control, _) = active();
    let mut observed = owner.observe();
    observed.ipv6 = false;
    let reading = observed.gateway.as_mut().unwrap();
    reading.validity_seconds = u32::MAX;
    reading.candidates = vec![
        address("[2606:4700::1111]:8443"),
        address(LAN),
        address(EXTERNAL),
    ];
    let (candidates, seconds) = observed.signed_candidates();
    assert_eq!(candidates, [address(LAN), address(EXTERNAL)]);
    assert_eq!(seconds, service_protocol::MAX_ADDRESS_VALIDITY_SECONDS);
    assert_eq!(
        observed.invitation_addresses(None).unwrap().alternatives,
        [address(EXTERNAL)]
    );
    assert!(
        observed
            .invitation_addresses(Some(address(EXTERNAL)))
            .is_err()
    );
    observed.running = false;
    assert!(observed.invitation_addresses(Some(address(LAN))).is_ok());
    assert!(observed.invitation_addresses(None).is_err());
    observed.running = true;
    observed.gateway.as_mut().unwrap().candidates =
        vec![address(EXTERNAL); service_protocol::MAX_ADDRESS_CANDIDATES + 2];
    assert_eq!(
        observed.signed_candidates().0.len(),
        service_protocol::MAX_ADDRESS_CANDIDATES
    );
    assert_eq!(
        observed
            .invitation_addresses(None)
            .unwrap()
            .alternatives
            .len(),
        service_protocol::MAX_ADDRESS_CANDIDATES - 1
    );
    observed.gateway.as_mut().unwrap().candidates.clear();
    assert_eq!(observed.signed_candidates(), (Vec::new(), 0));
    for relay in [
        None,
        Some(address("127.0.0.1:7443")),
        Some(address(EXTERNAL)),
        Some(address("169.254.1.2:7443")),
        Some(address("[fd00::1]:7443")),
    ] {
        observed.relay = relay;
        assert_eq!(observed.lan_announcement(), None);
    }
    observed.relay = None;
    assert!(observed.invitation_addresses(None).is_err());
    assert!(!observed.accepts_address_query(address(LAN)));
    observed.embedded = false;
    observed.relay = Some(address(EXTERNAL));
    assert!(!observed.accepts_address_query(address(LAN)));
    assert!(observed.accepts_address_query(address(EXTERNAL)));
    finish(&mut owner, &control);
}

#[test]
fn direct_states_and_external_metadata_preserve_their_original_filters() {
    let (mut owner, control, _) = active();
    let base = owner.observe();
    for (gateway_state, expected) in [
        (
            DirectGatewayState::PublicIpv4Candidate,
            DirectConnectionState::Candidate,
        ),
        (
            DirectGatewayState::MappedCandidate,
            DirectConnectionState::Candidate,
        ),
        (
            DirectGatewayState::Ipv6Candidate,
            DirectConnectionState::Candidate,
        ),
        (DirectGatewayState::LanOnly, DirectConnectionState::LanOnly),
        (
            DirectGatewayState::Discovering,
            DirectConnectionState::Discovering,
        ),
        (
            DirectGatewayState::Stopped,
            DirectConnectionState::Unavailable,
        ),
        (
            DirectGatewayState::Unavailable,
            DirectConnectionState::Unavailable,
        ),
    ] {
        let mut observed = base.clone();
        observed.gateway.as_mut().unwrap().state = gateway_state;
        assert!(
            matches!(observed.direct_status(), ManagementResponse::DirectStatus { state, .. } if state == expected)
        );
        // A snapshot's state is not an additional signed-candidate predicate.
        assert!(!observed.signed_candidates().0.is_empty());
    }
    let mut observed = base;
    observed.gateway.as_mut().unwrap().candidates = vec![address(LAN)];
    assert!(matches!(
        observed.direct_status(),
        ManagementResponse::DirectStatus {
            state: DirectConnectionState::LanOnly,
            ..
        }
    ));
    observed.gateway.as_mut().unwrap().source = None;
    assert!(matches!(
        observed.external_status(),
        ManagementResponse::ExternalStatus {
            external: None,
            source: None,
            lan: Some(_),
            ..
        }
    ));
    observed.gateway.as_mut().unwrap().source = Some(CandidateSource::Fixed);
    observed.gateway.as_mut().unwrap().external = Some(address("127.0.0.1:0"));
    assert!(matches!(
        observed.external_status(),
        ManagementResponse::ExternalStatus {
            external: None,
            source: None,
            ..
        }
    ));
    observed.forward_origin = Some("192.168.1.49".parse().unwrap());
    assert!(matches!(
        observed.external_status(),
        ManagementResponse::ExternalStatus {
            forward_origin: None,
            ..
        }
    ));
    observed.access = ExternalAccess::RouterForward {
        external_port: 8443,
    };
    assert!(matches!(
        observed.external_status(),
        ManagementResponse::ExternalStatus {
            forward_origin: Some(_),
            external: None,
            ..
        }
    ));
    finish(&mut owner, &control);
}

#[test]
fn dialer_start_failure_retains_selected_address_but_not_the_old_address() {
    let (mut owner, control, now) = active();
    owner
        .request_relay(Some(address(EXTERNAL)), &mut invalidator(&control))
        .unwrap();
    control.borrow_mut().fail_dialer = true;
    assert_eq!(
        owner.poll_replacement(now, &mut invalidator(&control)),
        Err(PeerRuntimeError::Io)
    );
    assert_eq!(
        owner.observe().management_snapshot().2,
        Some(address(EXTERNAL))
    );
    assert!(!owner.has_dialer());
    assert!(!owner.replacement_pending());
    assert_order(
        &control.borrow().trace,
        &[
            "drain-dialer",
            "drain-gateway",
            "drain-relay",
            "record-relay_worker_stopped",
            "drop-relay",
            "start-dialer",
        ],
    );
    finish(&mut owner, &control);
}

#[test]
fn stopped_listener_retains_its_worker_until_drain_and_gateway_start_failure_does_not_withdraw_relay()
 {
    let (mut owner, control, now) = active();
    control.borrow_mut().running = false;
    control.borrow_mut().drain[2] = false;
    owner
        .poll(now + Duration::from_secs(5), &mut invalidator(&control))
        .unwrap();
    assert!(
        !control
            .borrow()
            .trace
            .iter()
            .any(|s| s == "drop-relay" || s == "start-relay" || s == "record-relay_worker_stopped")
    );
    assert_eq!(owner.observe().management_snapshot().2, None);
    control.borrow_mut().drain[2] = true;
    control.borrow_mut().fail_gateway = true;
    // The old listener remains stopped; the replacement is live once started.
    owner
        .poll(now + Duration::from_secs(10), &mut invalidator(&control))
        .unwrap();
    assert_order(
        &control.borrow().trace,
        &[
            "drain-relay",
            "record-relay_worker_stopped",
            "drop-relay",
            "start-relay",
        ],
    );
    control.borrow_mut().running = true;
    owner
        .poll(now + Duration::from_secs(15), &mut invalidator(&control))
        .unwrap();
    assert_eq!(owner.observe().management_snapshot().2, Some(address(LAN)));
    assert!(owner.observe().gateway.is_none());
    control.borrow_mut().fail_gateway = false;
    owner
        .poll(now + Duration::from_secs(20), &mut invalidator(&control))
        .unwrap();
    assert!(owner.observe().gateway.is_some());
    finish(&mut owner, &control);
}

#[test]
fn shutdown_keeps_a_pending_old_dialer_and_gateway_until_their_drains_complete() {
    let (mut owner, control, _) = active();
    owner
        .request_relay(Some(address(EXTERNAL)), &mut invalidator(&control))
        .unwrap();
    control.borrow_mut().drain = [false; 3];
    owner.prepare_shutdown();
    owner.begin_shutdown();
    owner.drain_shutdown();
    assert_eq!(owner.remaining_owners(), 3);
    assert!(owner.replacement_pending());
    assert!(owner.observe().gateway.is_some());
    assert_eq!(owner.observe().internal, None);
    assert!(
        !control
            .borrow()
            .trace
            .iter()
            .any(|s| s == "drop-gateway" || s == "drop-relay" || s == "drop-dialer")
    );
    finish(&mut owner, &control);
    assert!(!owner.replacement_pending());
}

#[test]
fn listener_fault_clears_on_external_mode_and_on_shutdown() {
    for shutdown in [false, true] {
        let control = Rc::new(RefCell::new(Control {
            fail_relay: true,
            ..Control::default()
        }));
        let now = Instant::now();
        let mut owner = Network::new(FakePlatform(control.clone()), now);
        owner
            .configure_after_ready(None, now, &mut invalidator(&control))
            .unwrap();
        assert!(matches!(
            owner.listener_status(),
            ManagementResponse::ListenerStatus { fault: Some(_), .. }
        ));
        if shutdown {
            owner.prepare_shutdown();
        } else {
            owner
                .configure_after_ready(Some(address(EXTERNAL)), now, &mut invalidator(&control))
                .unwrap();
        }
        assert!(matches!(
            owner.listener_status(),
            ManagementResponse::ListenerStatus { fault: None, .. }
        ));
        assert_eq!(
            control
                .borrow()
                .trace
                .iter()
                .filter(|s| s.as_str() == "record-relay_listener_changed")
                .count(),
            2
        );
        finish(&mut owner, &control);
    }
}

#[test]
fn abuse_observation_stays_after_lan_poll_and_is_rate_limited() {
    let (mut owner, control, now) = active();
    control.borrow_mut().abuse.evicted_pairs = 1;
    owner
        .poll(now + Duration::from_secs(5), &mut invalidator(&control))
        .unwrap();
    assert_order(&control.borrow().trace, &["poll-lan", "record-relay_abuse"]);
    control.borrow_mut().abuse.evicted_pairs = 2;
    owner
        .poll(now + Duration::from_secs(60), &mut invalidator(&control))
        .unwrap();
    assert_eq!(
        control
            .borrow()
            .trace
            .iter()
            .filter(|s| s.as_str() == "record-relay_abuse")
            .count(),
        1
    );
    owner
        .poll(now + Duration::from_secs(65), &mut invalidator(&control))
        .unwrap();
    assert_eq!(
        control
            .borrow()
            .trace
            .iter()
            .filter(|s| s.as_str() == "record-relay_abuse")
            .count(),
        2
    );
    finish(&mut owner, &control);
}

#[test]
fn legacy_forward_origin_adoption_retries_after_a_minute_without_replacing_the_relay() {
    let (mut owner, control, now) = active();
    owner.use_external_access(crate::external_access::ExternalAccessSetting {
        access: ExternalAccess::RouterForward {
            external_port: 8443,
        },
        forward_origin: None,
    });
    control.borrow_mut().fail_store = true;
    owner
        .poll(now + Duration::from_secs(5), &mut invalidator(&control))
        .unwrap();
    owner
        .poll(now + Duration::from_secs(60), &mut invalidator(&control))
        .unwrap();
    assert_eq!(
        control
            .borrow()
            .trace
            .iter()
            .filter(|s| s.as_str() == "store-external")
            .count(),
        1
    );
    assert_eq!(owner.observe().forward_origin, None);
    control.borrow_mut().fail_store = false;
    owner
        .poll(now + Duration::from_secs(65), &mut invalidator(&control))
        .unwrap();
    assert_eq!(
        control
            .borrow()
            .trace
            .iter()
            .filter(|s| s.as_str() == "store-external")
            .count(),
        2
    );
    assert_eq!(
        owner.observe().forward_origin,
        Some("192.168.1.50".parse().unwrap())
    );
    assert_eq!(owner.observe().management_snapshot().2, Some(address(LAN)));
    assert!(
        !control
            .borrow()
            .trace
            .iter()
            .any(|s| s == "invalidate-Peers")
    );
    finish(&mut owner, &control);
}
