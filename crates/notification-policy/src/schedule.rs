// SPDX-License-Identifier: GPL-2.0-or-later

use std::fmt;

use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use thiserror::Error;

/// Maximum number of windows in both constructed and deserialized schedules.
pub const MAX_SCHEDULE_WINDOWS: usize = 32;
const MINUTES_PER_DAY: u16 = 1440;

/// The OS adapter determines this using the current phone timezone, not the PC's.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Weekday {
    Monday,
    Tuesday,
    Wednesday,
    Thursday,
    Friday,
    Saturday,
    Sunday,
}

impl Weekday {
    const fn bit(self) -> u8 {
        1 << (self as u8)
    }

    const fn previous(self) -> Self {
        match self {
            Self::Monday => Self::Sunday,
            Self::Tuesday => Self::Monday,
            Self::Wednesday => Self::Tuesday,
            Self::Thursday => Self::Wednesday,
            Self::Friday => Self::Thursday,
            Self::Saturday => Self::Friday,
            Self::Sunday => Self::Saturday,
        }
    }
}

/// Nonempty seven-bit mask; bit 0 is Monday and bit 6 is Sunday.
///
/// Deserialization uses the same validation as [`DayMask::new`].
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "u8", into = "u8")]
pub struct DayMask(u8);

impl DayMask {
    pub const ALL: Self = Self(0x7f);

    pub fn new(bits: u8) -> Result<Self, ScheduleError> {
        if bits == 0 || bits & !Self::ALL.0 != 0 {
            return Err(ScheduleError::InvalidDays(bits));
        }
        Ok(Self(bits))
    }

    pub fn from_days(days: &[Weekday]) -> Result<Self, ScheduleError> {
        Self::new(days.iter().fold(0, |bits, day| bits | day.bit()))
    }

    pub const fn contains(self, day: Weekday) -> bool {
        self.0 & day.bit() != 0
    }

    pub const fn bits(self) -> u8 {
        self.0
    }
}

impl TryFrom<u8> for DayMask {
    type Error = ScheduleError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<DayMask> for u8 {
    fn from(value: DayMask) -> Self {
        value.bits()
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum ScheduleError {
    #[error("weekday mask must have at least one day and no bits outside the seven weekdays")]
    InvalidDays(u8),
    #[error("local minute must be between 0 and 1439")]
    InvalidLocalMinute(u16),
    #[error("window start must be between 0 and 1439 and end between 0 and 1440")]
    InvalidWindowMinutes,
    #[error("equal start and end are empty; use 0..1440 for an all-day window")]
    EmptyWindow,
    #[error("a weekly schedule must have at least one window; use Never to disable it")]
    EmptySchedule,
    #[error("a weekly schedule may have at most 32 windows")]
    TooManyWindows,
}

/// A validated phone-local observation. Minute 1440 is not an observation.
///
/// DST skipped minutes never match because the OS never reports them. Repeated
/// minutes are evaluated identically on both occurrences; monotonic expiration
/// still advances and suppression markers prevent replay. Changing the phone's
/// timezone changes subsequent evaluations immediately. No time is queued for
/// the next window, including a window skipped by a timezone or DST transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LocalTime {
    weekday: Weekday,
    minute: u16,
}

impl LocalTime {
    pub fn new(weekday: Weekday, minute: u16) -> Result<Self, ScheduleError> {
        if minute >= MINUTES_PER_DAY {
            return Err(ScheduleError::InvalidLocalMinute(minute));
        }
        Ok(Self { weekday, minute })
    }

    pub const fn weekday(self) -> Weekday {
        self.weekday
    }

    pub const fn minute(self) -> u16 {
        self.minute
    }
}

/// End-exclusive local window attached to its starting weekday(s).
///
/// Monday 1320..120 means Monday 22:00 through Tuesday 02:00, exclusive.
/// 0..1440 is all day; equal endpoints never mean all day. An end of 0 is
/// allowed for a window ending exactly at the following midnight.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(try_from = "WindowDefinition")]
pub struct TimeWindow {
    days: DayMask,
    start_minute: u16,
    end_minute: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WindowDefinition {
    days: DayMask,
    start_minute: u16,
    end_minute: u16,
}

impl TimeWindow {
    pub fn new(days: DayMask, start_minute: u16, end_minute: u16) -> Result<Self, ScheduleError> {
        if start_minute >= MINUTES_PER_DAY || end_minute > MINUTES_PER_DAY {
            return Err(ScheduleError::InvalidWindowMinutes);
        }
        if start_minute == end_minute {
            return Err(ScheduleError::EmptyWindow);
        }
        Ok(Self {
            days,
            start_minute,
            end_minute,
        })
    }

    pub const fn days(self) -> DayMask {
        self.days
    }

    pub const fn start_minute(self) -> u16 {
        self.start_minute
    }

    pub const fn end_minute(self) -> u16 {
        self.end_minute
    }

    pub fn contains(self, local: LocalTime) -> bool {
        if self.start_minute < self.end_minute {
            return self.days.contains(local.weekday)
                && local.minute >= self.start_minute
                && local.minute < self.end_minute;
        }
        (self.days.contains(local.weekday) && local.minute >= self.start_minute)
            || (self.days.contains(local.weekday.previous()) && local.minute < self.end_minute)
    }
}

impl TryFrom<WindowDefinition> for TimeWindow {
    type Error = ScheduleError;

    fn try_from(value: WindowDefinition) -> Result<Self, Self::Error> {
        Self::new(value.days, value.start_minute, value.end_minute)
    }
}

/// Nonempty bounded collection. Overlapping windows form a union.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct WeeklySchedule(Vec<TimeWindow>);

impl WeeklySchedule {
    /// Consumes at most 33 items, rejecting excessive or infinite iterators.
    pub fn new(windows: impl IntoIterator<Item = TimeWindow>) -> Result<Self, ScheduleError> {
        let mut bounded = Vec::with_capacity(MAX_SCHEDULE_WINDOWS);
        for window in windows {
            if bounded.len() == MAX_SCHEDULE_WINDOWS {
                return Err(ScheduleError::TooManyWindows);
            }
            bounded.push(window);
        }
        if bounded.is_empty() {
            return Err(ScheduleError::EmptySchedule);
        }
        Ok(Self(bounded))
    }

    pub fn windows(&self) -> &[TimeWindow] {
        &self.0
    }

    pub fn allows(&self, local: LocalTime) -> bool {
        self.0.iter().any(|window| window.contains(local))
    }
}

impl<'de> Deserialize<'de> for WeeklySchedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct BoundedWindows;

        impl<'de> Visitor<'de> for BoundedWindows {
            type Value = WeeklySchedule;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("between 1 and 32 validated time windows")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut windows = Vec::with_capacity(MAX_SCHEDULE_WINDOWS);
                while let Some(window) = sequence.next_element::<TimeWindow>()? {
                    if windows.len() == MAX_SCHEDULE_WINDOWS {
                        return Err(de::Error::custom(ScheduleError::TooManyWindows));
                    }
                    windows.push(window);
                }
                WeeklySchedule::new(windows).map_err(de::Error::custom)
            }
        }

        deserializer.deserialize_seq(BoundedWindows)
    }
}

/// `Always` is the unconfigured default; explicit `Never` remains disabled.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(tag = "mode", content = "windows", rename_all = "snake_case")]
pub enum Schedule {
    #[default]
    Always,
    Never,
    Weekly(WeeklySchedule),
}

impl<'de> Deserialize<'de> for Schedule {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(field_identifier, rename_all = "snake_case")]
        enum Field {
            Mode,
            Windows,
        }

        #[derive(Deserialize)]
        #[serde(rename_all = "snake_case")]
        enum Mode {
            Always,
            Never,
            Weekly,
        }

        struct ScheduleVisitor;

        impl<'de> Visitor<'de> for ScheduleVisitor {
            type Value = Schedule;

            fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str("a schedule mode with bounded windows only for weekly mode")
            }

            fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut mode = None;
                let mut windows = None;
                while let Some(field) = map.next_key::<Field>()? {
                    match field {
                        Field::Mode => {
                            if mode.is_some() {
                                return Err(de::Error::duplicate_field("mode"));
                            }
                            mode = Some(map.next_value::<Mode>()?);
                        }
                        Field::Windows => {
                            if windows.is_some() {
                                return Err(de::Error::duplicate_field("windows"));
                            }
                            // Decode immediately with the bounded visitor, even
                            // when windows precede mode in a persisted object.
                            windows = Some(map.next_value::<WeeklySchedule>()?);
                        }
                    }
                }
                match mode.ok_or_else(|| de::Error::missing_field("mode"))? {
                    Mode::Weekly => windows
                        .map(Schedule::Weekly)
                        .ok_or_else(|| de::Error::missing_field("windows")),
                    Mode::Always | Mode::Never if windows.is_some() => {
                        Err(de::Error::custom("only weekly mode may contain windows"))
                    }
                    Mode::Always => Ok(Schedule::Always),
                    Mode::Never => Ok(Schedule::Never),
                }
            }
        }

        deserializer.deserialize_map(ScheduleVisitor)
    }
}

impl Schedule {
    pub fn allows(&self, local: LocalTime) -> bool {
        match self {
            Self::Always => true,
            Self::Never => false,
            Self::Weekly(weekly) => weekly.allows(local),
        }
    }
}

/// Requested OS alert behavior. The adapter must not silently substitute modes.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AlertMode {
    #[default]
    Sound,
    VibrateOnly,
    Silent,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(from = "PolicyDefinition")]
pub struct NotificationPolicy {
    schedule: Schedule,
    alert: AlertMode,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyDefinition {
    #[serde(default)]
    schedule: Option<Schedule>,
    #[serde(default)]
    alert: AlertMode,
}

impl NotificationPolicy {
    pub fn new(schedule: Option<Schedule>, alert: AlertMode) -> Self {
        Self {
            schedule: schedule.unwrap_or_default(),
            alert,
        }
    }

    pub const fn alert(&self) -> AlertMode {
        self.alert
    }

    pub const fn schedule(&self) -> &Schedule {
        &self.schedule
    }

    pub fn allows(&self, local: LocalTime) -> bool {
        self.schedule.allows(local)
    }
}

impl From<PolicyDefinition> for NotificationPolicy {
    fn from(value: PolicyDefinition) -> Self {
        Self::new(value.schedule, value.alert)
    }
}
