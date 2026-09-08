// SPDX-License-Identifier: GPL-2.0-or-later

use notification_policy::{
    AlertMode, DayMask, LocalTime, MAX_SCHEDULE_WINDOWS, NotificationPolicy, Schedule,
    ScheduleError, TimeWindow, Weekday, WeeklySchedule,
};

fn local(day: Weekday, minute: u16) -> LocalTime {
    LocalTime::new(day, minute).unwrap()
}

fn window(days: &[Weekday], start: u16, end: u16) -> TimeWindow {
    TimeWindow::new(DayMask::from_days(days).unwrap(), start, end).unwrap()
}

#[test]
fn absent_schedule_is_always_and_explicit_never_stays_disabled() {
    let now = local(Weekday::Sunday, 1439);
    let defaults = NotificationPolicy::default();
    assert_eq!(defaults.schedule(), &Schedule::Always);
    assert!(defaults.allows(now));
    assert_eq!(defaults.alert(), AlertMode::Sound);
    let absent = NotificationPolicy::new(None, AlertMode::Sound);
    assert!(absent.allows(now));
    let disabled = NotificationPolicy::new(Some(Schedule::Never), AlertMode::VibrateOnly);
    assert!(!disabled.allows(now));

    for persisted in [r#"{}"#, r#"{"schedule":null}"#] {
        let restored: NotificationPolicy = serde_json::from_str(persisted).unwrap();
        assert_eq!(restored, defaults);
    }
    let restored: NotificationPolicy =
        serde_json::from_str(r#"{"schedule":{"mode":"never"},"alert":"vibrate_only"}"#).unwrap();
    assert_eq!(restored, disabled);
}

#[test]
fn all_alert_modes_round_trip_without_substitution() {
    for (mode, name) in [
        (AlertMode::Sound, "sound"),
        (AlertMode::VibrateOnly, "vibrate_only"),
        (AlertMode::Silent, "silent"),
    ] {
        let policy = NotificationPolicy::new(None, mode);
        let json = serde_json::to_string(&policy).unwrap();
        assert!(json.contains(name));
        assert_eq!(
            serde_json::from_str::<NotificationPolicy>(&json).unwrap(),
            policy
        );
    }
    assert!(serde_json::from_str::<AlertMode>(r#""automatic""#).is_err());
}

#[test]
fn weekday_mask_is_nonempty_and_has_only_seven_days() {
    assert_eq!(DayMask::new(0), Err(ScheduleError::InvalidDays(0)));
    assert_eq!(DayMask::new(128), Err(ScheduleError::InvalidDays(128)));
    assert_eq!(DayMask::new(255), Err(ScheduleError::InvalidDays(255)));
    assert!(DayMask::from_days(&[]).is_err());
    assert_eq!(DayMask::ALL.bits(), 127);
    let weekdays = DayMask::from_days(&[Weekday::Monday, Weekday::Friday]).unwrap();
    assert_eq!(weekdays.bits(), 17);
    assert!(weekdays.contains(Weekday::Monday));
    assert!(!weekdays.contains(Weekday::Sunday));
    for invalid in ["0", "128", "255", "256", "-1", "null"] {
        assert!(serde_json::from_str::<DayMask>(invalid).is_err());
    }
    assert_eq!(
        serde_json::from_str::<DayMask>("127").unwrap(),
        DayMask::ALL
    );
}

#[test]
fn ordinary_window_includes_start_but_excludes_end_and_other_weekdays() {
    let period = window(&[Weekday::Monday], 9 * 60, 17 * 60);
    assert!(!period.contains(local(Weekday::Monday, 539)));
    assert!(period.contains(local(Weekday::Monday, 540)));
    assert!(period.contains(local(Weekday::Monday, 1019)));
    assert!(!period.contains(local(Weekday::Monday, 1020)));
    assert!(!period.contains(local(Weekday::Tuesday, 600)));
    assert_eq!(period.start_minute(), 540);
    assert_eq!(period.end_minute(), 1020);
    assert_eq!(period.days().bits(), 1);
}

#[test]
fn midnight_crossing_belongs_to_the_start_day() {
    let period = window(&[Weekday::Monday], 22 * 60, 2 * 60);
    assert!(!period.contains(local(Weekday::Monday, 119)));
    assert!(!period.contains(local(Weekday::Monday, 1319)));
    assert!(period.contains(local(Weekday::Monday, 1320)));
    assert!(period.contains(local(Weekday::Monday, 1439)));
    assert!(period.contains(local(Weekday::Tuesday, 0)));
    assert!(period.contains(local(Weekday::Tuesday, 119)));
    assert!(!period.contains(local(Weekday::Tuesday, 120)));
    assert!(!period.contains(local(Weekday::Tuesday, 1320)));
}

#[test]
fn sunday_night_wraps_the_week_and_midnight_end_does_not_include_next_day() {
    let sunday = window(&[Weekday::Sunday], 1380, 60);
    assert!(sunday.contains(local(Weekday::Sunday, 1380)));
    assert!(sunday.contains(local(Weekday::Monday, 59)));
    assert!(!sunday.contains(local(Weekday::Monday, 60)));
    let midnight = window(&[Weekday::Friday], 1320, 0);
    assert!(midnight.contains(local(Weekday::Friday, 1439)));
    assert!(!midnight.contains(local(Weekday::Saturday, 0)));
}

#[test]
fn explicit_all_day_and_union_of_overlapping_windows() {
    let all_day = TimeWindow::new(DayMask::ALL, 0, 1440).unwrap();
    for day in [Weekday::Monday, Weekday::Sunday] {
        assert!(all_day.contains(local(day, 0)));
        assert!(all_day.contains(local(day, 1439)));
    }
    let weekly = WeeklySchedule::new([
        window(&[Weekday::Wednesday], 540, 660),
        window(&[Weekday::Wednesday], 630, 780),
    ])
    .unwrap();
    for minute in 540..780 {
        assert!(weekly.allows(local(Weekday::Wednesday, minute)));
    }
    assert!(!weekly.allows(local(Weekday::Wednesday, 539)));
    assert!(!weekly.allows(local(Weekday::Wednesday, 780)));
    assert_eq!(weekly.windows().len(), 2);
}

#[test]
fn invalid_minutes_and_empty_windows_are_rejected() {
    for (start, end) in [(1440, 1440), (1441, 100), (0, 1441), (65535, 65535)] {
        assert_eq!(
            TimeWindow::new(DayMask::ALL, start, end),
            Err(ScheduleError::InvalidWindowMinutes)
        );
    }
    for minute in [0, 600, 1439] {
        assert_eq!(
            TimeWindow::new(DayMask::ALL, minute, minute),
            Err(ScheduleError::EmptyWindow)
        );
    }
    assert!(LocalTime::new(Weekday::Monday, 1440).is_err());
    assert!(LocalTime::new(Weekday::Monday, u16::MAX).is_err());
    assert_eq!(local(Weekday::Thursday, 123).weekday(), Weekday::Thursday);
    assert_eq!(local(Weekday::Thursday, 123).minute(), 123);
}

#[test]
fn schedule_construction_bounds_even_an_infinite_iterator() {
    assert_eq!(WeeklySchedule::new([]), Err(ScheduleError::EmptySchedule));
    let all_day = TimeWindow::new(DayMask::ALL, 0, 1440).unwrap();
    let maximum = WeeklySchedule::new(std::iter::repeat_n(all_day, MAX_SCHEDULE_WINDOWS));
    assert!(maximum.is_ok());
    assert_eq!(
        WeeklySchedule::new(std::iter::repeat(all_day)),
        Err(ScheduleError::TooManyWindows)
    );
}

#[test]
fn malformed_persisted_windows_cannot_bypass_validation() {
    for invalid in [
        r#"{"days":0,"start_minute":0,"end_minute":1440}"#,
        r#"{"days":128,"start_minute":0,"end_minute":1440}"#,
        r#"{"days":1,"start_minute":0,"end_minute":0}"#,
        r#"{"days":1,"start_minute":1440,"end_minute":100}"#,
        r#"{"days":1,"start_minute":0,"end_minute":1441}"#,
        r#"{"days":1,"start_minute":-1,"end_minute":1}"#,
        r#"{"days":1,"start_minute":0,"end_minute":1,"extra":true}"#,
    ] {
        assert!(
            serde_json::from_str::<TimeWindow>(invalid).is_err(),
            "{invalid}"
        );
    }
}

#[test]
fn malformed_schedule_modes_and_duplicate_fields_fail_closed() {
    for invalid in [
        r#"{}"#,
        r#"{"mode":"weekly","windows":[]}"#,
        r#"{"mode":"weekly"}"#,
        r#"{"mode":"unknown"}"#,
        r#"{"mode":"never","enabled":true}"#,
        r#"{"mode":"never","mode":"always"}"#,
        r#"{"mode":"always","windows":[{"days":1,"start_minute":0,"end_minute":1440}]}"#,
        r#"{"mode":"weekly","windows":[{"days":1,"start_minute":0,"end_minute":1440}],"windows":[{"days":1,"start_minute":0,"end_minute":1440}]}"#,
    ] {
        assert!(
            serde_json::from_str::<Schedule>(invalid).is_err(),
            "{invalid}"
        );
    }
    for invalid in [
        r#"{"schedule":{"mode":"weekly","windows":[]}}"#,
        r#"{"schedule":{"mode":"never"},"schedule":{"mode":"always"}}"#,
        r#"{"schedule":{"mode":"never"},"ignored":true}"#,
        r#"{"alert":null}"#,
    ] {
        assert!(serde_json::from_str::<NotificationPolicy>(invalid).is_err());
    }
}

#[test]
fn deserialization_limits_windows_regardless_of_object_field_order() {
    let definition = r#"{"days":127,"start_minute":0,"end_minute":1440}"#;
    let allowed = vec![definition; MAX_SCHEDULE_WINDOWS].join(",");
    let excessive = vec![definition; MAX_SCHEDULE_WINDOWS + 1].join(",");
    for json in [
        format!(r#"{{"mode":"weekly","windows":[{allowed}]}}"#),
        format!(r#"{{"windows":[{allowed}],"mode":"weekly"}}"#),
    ] {
        let schedule: Schedule = serde_json::from_str(&json).unwrap();
        assert!(schedule.allows(local(Weekday::Monday, 0)));
    }
    for json in [
        format!(r#"{{"mode":"weekly","windows":[{excessive}]}}"#),
        format!(r#"{{"windows":[{excessive}],"mode":"weekly"}}"#),
    ] {
        assert!(serde_json::from_str::<Schedule>(&json).is_err());
    }
}

#[test]
fn schedule_round_trip_preserves_night_window_semantics() {
    let original = NotificationPolicy::new(
        Some(Schedule::Weekly(
            WeeklySchedule::new([window(&[Weekday::Monday], 1320, 120)]).unwrap(),
        )),
        AlertMode::VibrateOnly,
    );
    let encoded = serde_json::to_string(&original).unwrap();
    let restored: NotificationPolicy = serde_json::from_str(&encoded).unwrap();
    assert_eq!(restored, original);
    assert!(restored.allows(local(Weekday::Tuesday, 119)));
    assert!(!restored.allows(local(Weekday::Tuesday, 120)));
}
