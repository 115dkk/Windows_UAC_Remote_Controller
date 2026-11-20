// SPDX-License-Identifier: GPL-2.0-or-later
//! Unsigned LAN routing hints, independent of paired address advertisements.
//! A discovered address still requires the phone's existing pinned TLS checks.
use std::{
    collections::BTreeSet,
    net::SocketAddrV4,
    time::{Duration, Instant},
};
use windows_dns_sd::{AnnounceError, AnnouncementState, ServiceAnnouncement};

const RETRY: Duration = Duration::from_secs(60);

pub(super) struct LanAnnouncement<A = ServiceAnnouncement> {
    active: Option<(SocketAddrV4, A)>,
    retry_at: Option<Instant>,
    // Deduplicate for the session, including endpoint changes and recovery.
    // These are OS error codes and local endpoints, never remote input.
    reported: BTreeSet<(SocketAddrV4, u32)>,
}

impl<A> Default for LanAnnouncement<A> {
    fn default() -> Self {
        Self {
            active: None,
            retry_at: None,
            reported: BTreeSet::new(),
        }
    }
}

impl<A> LanAnnouncement<A> {
    fn poll(
        &mut self,
        desired: Option<SocketAddrV4>,
        now: Instant,
        state: impl Fn(&A) -> AnnouncementState,
        start: impl FnOnce(SocketAddrV4) -> Result<A, AnnounceError>,
    ) -> Option<u32> {
        if self.active.as_ref().map(|(endpoint, _)| *endpoint) != desired {
            self.active = None;
        }
        let endpoint = desired?;
        if let Some((_, announcement)) = &self.active {
            return match state(announcement) {
                AnnouncementState::Failed(code) => {
                    self.active = None;
                    self.failed(endpoint, code, now)
                }
                AnnouncementState::Pending | AnnouncementState::Registered => None,
            };
        }
        if self.retry_at.is_some_and(|at| now < at) {
            return None;
        }
        match start(endpoint) {
            Ok(announcement) => {
                self.active = Some((endpoint, announcement));
                None
            }
            Err(error) => self.failed(endpoint, error_code(error), now),
        }
    }

    fn failed(&mut self, endpoint: SocketAddrV4, code: u32, now: Instant) -> Option<u32> {
        self.retry_at = Some(now + RETRY);
        self.reported.insert((endpoint, code)).then_some(code)
    }
}

fn error_code(error: AnnounceError) -> u32 {
    match error {
        AnnounceError::InvalidName => 87, // ERROR_INVALID_PARAMETER
        AnnounceError::Unsupported => 50, // ERROR_NOT_SUPPORTED
        AnnounceError::Failed(code) => code,
    }
}

impl LanAnnouncement {
    pub(super) fn withdraw(&mut self) {
        self.active = None;
    }

    pub(super) fn poll_endpoint(
        &mut self,
        label: &str,
        desired: Option<SocketAddrV4>,
        now: Instant,
    ) {
        if let Some(code) = self.poll(desired, now, ServiceAnnouncement::state, |endpoint| {
            // ipconfig exposes Ipv6IfIndex, not IPv4 IfIndex; 0 asks DNSAPI to
            // consider all adapters rather than substituting the wrong index.
            ServiceAnnouncement::start(
                label,
                service_protocol::LAN_SERVICE_TYPE,
                *endpoint.ip(),
                endpoint.port(),
                0,
            )
        }) {
            crate::public_diagnostics::record(
                crate::public_diagnostics::Event::LanAnnounceFailed { code },
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{cell::Cell, rc::Rc};

    struct Fixture {
        state: AnnouncementState,
        dropped: Rc<Cell<usize>>,
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.dropped.set(self.dropped.get() + 1);
        }
    }
    fn endpoint(last: u8) -> SocketAddrV4 {
        SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, last), 7443)
    }

    #[test]
    fn endpoint_changes_drop_before_start_and_withdrawal_drops() {
        let mut owner = LanAnnouncement::default();
        let dropped = Rc::new(Cell::new(0));
        let now = Instant::now();
        let state = |fixture: &Fixture| fixture.state;
        owner.poll(Some(endpoint(2)), now, state, |_| {
            Ok(Fixture {
                state: AnnouncementState::Pending,
                dropped: dropped.clone(),
            })
        });
        owner.poll(Some(endpoint(2)), now, state, |_| {
            panic!("same pending endpoint restarted")
        });
        owner.poll(Some(endpoint(3)), now, state, |_| {
            assert_eq!(dropped.get(), 1);
            Ok(Fixture {
                state: AnnouncementState::Registered,
                dropped: dropped.clone(),
            })
        });
        owner.poll(Some(endpoint(3)), now, state, |_| {
            panic!("same registered endpoint restarted")
        });
        owner.poll(None, now, state, |_| {
            panic!("withdrawal started registration")
        });
        assert_eq!(dropped.get(), 2);
    }

    #[test]
    fn failures_are_deduplicated_and_retries_wait_sixty_seconds() {
        let mut owner = LanAnnouncement::<AnnouncementState>::default();
        let now = Instant::now();
        assert_eq!(
            owner.poll(
                Some(endpoint(2)),
                now,
                |state| *state,
                |_| Err(AnnounceError::Failed(5))
            ),
            Some(5)
        );
        assert_eq!(
            owner.poll(
                Some(endpoint(2)),
                now + RETRY - Duration::from_nanos(1),
                |state| *state,
                |_| panic!("early retry")
            ),
            None
        );
        assert_eq!(
            owner.poll(
                Some(endpoint(2)),
                now + RETRY,
                |state| *state,
                |_| Err(AnnounceError::Failed(5))
            ),
            None
        );
        assert_eq!(
            owner.poll(
                Some(endpoint(2)),
                now + RETRY * 2,
                |state| *state,
                |_| Ok(AnnouncementState::Failed(9))
            ),
            None
        );
        assert_eq!(
            owner.poll(
                Some(endpoint(2)),
                now + RETRY * 2,
                |state| *state,
                |_| panic!("async failure retried immediately")
            ),
            Some(9)
        );
        assert_eq!(
            owner.poll(
                Some(endpoint(2)),
                now + RETRY * 3,
                |state| *state,
                |_| Ok(AnnouncementState::Registered)
            ),
            None
        );
        owner.poll(
            None,
            now + RETRY * 3,
            |state| *state,
            |_| panic!("withdrawal"),
        );
        assert_eq!(
            owner.poll(
                Some(endpoint(2)),
                now + RETRY * 3,
                |state| *state,
                |_| Err(AnnounceError::Failed(5))
            ),
            None
        );
        assert_eq!(
            owner.poll(
                Some(endpoint(3)),
                now + RETRY * 4,
                |state| *state,
                |_| Err(AnnounceError::Failed(5))
            ),
            Some(5)
        );
    }
}
