// SPDX-License-Identifier: GPL-2.0-or-later
//! Actual native time observations, not renderer time or authentication data.
use crate::{BridgeError, NativeClock, NativePlatform, map_clock};
use framed_transport::{SocketClock, SocketClockUnavailable};
use phone_request_core::{InboxClock, PhoneBootId};
use std::{
    cell::Cell,
    fmt,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

#[cfg(not(target_os = "android"))]
thread_local! { static CALLBACK_DEPTH: Cell<u32> = const { Cell::new(0) }; }
// Android uses lazy OS TLS. Rust1.97's OS macro wraps even a const block in a
// non-const initializer, triggering Clippy on that generated function. Default
// is genuinely runtime initialization with the same zero u32, not a lint bypass
// or an alternate reentry policy. No allow/expect or hand-written TLS/unsafe.
#[cfg(target_os = "android")]
thread_local! { static CALLBACK_DEPTH: Cell<u32> = Cell::default(); }
pub(crate) fn callback_active() -> bool {
    CALLBACK_DEPTH.with(|depth| depth.get() != 0)
}
pub(crate) fn native_callback<T>(call: impl FnOnce() -> T) -> T {
    struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            CALLBACK_DEPTH.with(|depth| depth.set(depth.get() - 1));
        }
    }
    CALLBACK_DEPTH.with(|depth| {
        depth.set(
            depth
                .get()
                .checked_add(1)
                .expect("bounded native callback depth"),
        )
    });
    let _guard = Guard;
    call()
}

/// Native adapter samples stable zone/time-epoch bookends and derives the local
/// fields from the SAME wall_after value. This carries no authority to approve.
#[derive(Clone, Copy, uniffi::Record)]
pub struct NativePresentationClock {
    pub boot_count: u32,
    pub elapsed_before_nanos: u64,
    pub elapsed_after_nanos: u64,
    pub wall_before_millis: u64,
    pub wall_after_millis: u64,
    pub weekday: u8,
    pub minute: u16,
    pub millis_within_minute: u16,
    pub time_epoch: u64,
}
impl fmt::Debug for NativePresentationClock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativePresentationClock(native_bookends)")
    }
}
#[derive(Clone, Copy)]
pub(crate) struct PresentationTime {
    pub boot: PhoneBootId,
    pub clock: InboxClock,
    pub time_epoch: u64,
    pub minute_cutoff: u64,
}
pub(crate) fn validate(observed: NativePresentationClock) -> Result<PresentationTime, BridgeError> {
    let span = observed
        .elapsed_after_nanos
        .checked_sub(observed.elapsed_before_nanos)
        .filter(|span| *span <= 100_000_000)
        .ok_or(BridgeError::InvalidObservation)?;
    let wall_span = observed
        .wall_after_millis
        .checked_sub(observed.wall_before_millis)
        .and_then(|millis| millis.checked_mul(1_000_000))
        .ok_or(BridgeError::InvalidObservation)?;
    if observed.time_epoch == 0
        || observed.millis_within_minute >= 60_000
        || observed.wall_after_millis > i64::MAX as u64
        || span.abs_diff(wall_span) > 2_000_000
    {
        return Err(BridgeError::InvalidObservation);
    }
    let (boot, clock) = map_clock(NativeClock {
        boot_count: observed.boot_count,
        monotonic_nanos: observed.elapsed_after_nanos,
        weekday: observed.weekday,
        minute: observed.minute,
    })?;
    let remaining = 60_000_u64 - u64::from(observed.millis_within_minute) - 1;
    let minute_cutoff = observed
        .elapsed_before_nanos
        .checked_add(remaining * 1_000_000)
        .ok_or(BridgeError::InvalidObservation)?;
    Ok(PresentationTime {
        boot,
        clock,
        time_epoch: observed.time_epoch,
        minute_cutoff,
    })
}

/// One immutable coordinate; Instant is NEVER an Android continuing-time fallback.
#[derive(Clone, Copy)]
pub(crate) struct ProjectionAnchor {
    coordinate: Instant,
    boot: PhoneBootId,
    native: u64,
}
impl ProjectionAnchor {
    pub(crate) fn capture(
        platform: &dyn NativePlatform,
        boot: PhoneBootId,
    ) -> Result<Self, BridgeError> {
        let coordinate = Instant::now();
        let observed = validate(native_callback(|| platform.presentation_clock())?)?;
        if observed.boot != boot {
            return Err(BridgeError::InvalidObservation);
        }
        Ok(Self {
            coordinate,
            boot,
            native: observed.clock.phone_monotonic_nanos(),
        })
    }
    pub(crate) fn clock(self, platform: Arc<dyn NativePlatform>) -> Arc<NativeSocketClock> {
        Arc::new(NativeSocketClock {
            anchor: self,
            platform,
            floor: AtomicU64::new(self.native),
        })
    }
}
/// ONE instance per socket. Never shares the business owner's serialized floor.
pub(crate) struct NativeSocketClock {
    anchor: ProjectionAnchor,
    platform: Arc<dyn NativePlatform>,
    floor: AtomicU64,
}
impl SocketClock for NativeSocketClock {
    fn now(&self) -> Result<Instant, SocketClockUnavailable> {
        let sample = native_callback(|| self.platform.presentation_clock())
            .map_err(|_| SocketClockUnavailable)?;
        let sample = validate(sample).map_err(|_| SocketClockUnavailable)?;
        let now = sample.clock.phone_monotonic_nanos();
        if sample.boot != self.anchor.boot {
            return Err(SocketClockUnavailable);
        }
        self.floor
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |floor| {
                (now >= floor).then_some(now)
            })
            .map_err(|_| SocketClockUnavailable)?;
        self.anchor
            .coordinate
            .checked_add(Duration::from_nanos(
                now.checked_sub(self.anchor.native)
                    .ok_or(SocketClockUnavailable)?,
            ))
            .ok_or(SocketClockUnavailable)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn sample() -> NativePresentationClock {
        NativePresentationClock {
            boot_count: 5,
            elapsed_before_nanos: 1_000_000_000,
            elapsed_after_nanos: 1_000_100_000,
            wall_before_millis: 1_700_000_000_000,
            wall_after_millis: 1_700_000_000_000,
            weekday: 0,
            minute: 600,
            millis_within_minute: 59_950,
            time_epoch: 1,
        }
    }
    #[test]
    fn precise_bookends_preserve_last_allowed_minute_without_a_new_sixty_second_ttl() {
        let value = validate(sample()).unwrap();
        assert_eq!(value.minute_cutoff, 1_049_000_000);
        assert!(value.minute_cutoff > value.clock.phone_monotonic_nanos());
        assert!(value.minute_cutoff - value.clock.phone_monotonic_nanos() < 50_000_000);
    }
    #[test]
    fn malformed_temporal_bookends_fail_without_clamping_or_unknown_defaults() {
        for index in 0..6 {
            let mut value = sample();
            match index {
                0 => value.elapsed_after_nanos = value.elapsed_before_nanos - 1,
                1 => value.elapsed_after_nanos = value.elapsed_before_nanos + 100_000_001,
                2 => value.wall_after_millis -= 1,
                3 => value.wall_after_millis += 10,
                4 => value.time_epoch = 0,
                _ => value.millis_within_minute = 60_000,
            }
            assert!(matches!(
                validate(value),
                Err(BridgeError::InvalidObservation)
            ));
        }
    }
    #[test]
    fn callback_depth_is_scoped_and_resets_even_after_unwind() {
        assert!(!callback_active());
        let result = std::panic::catch_unwind(|| {
            native_callback(|| {
                assert!(callback_active());
                native_callback(|| assert!(callback_active()));
                panic!("synthetic callback unwind");
            })
        });
        assert!(result.is_err());
        assert!(!callback_active());
    }
}
