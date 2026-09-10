//! Process-exit and exact-attachment routing only, not native creation or service authority.
//! The production platform input is compile-time `cfg!(target_os = "android")`;
//! this module is private and is not reachable through a command or JNI API.

/// `None` is Tauri's implicit last-window/user-interaction exit request. Every
/// explicit exit or restart carries `Some(code)`, including an explicit zero.
pub(crate) const fn prevent_implicit_exit(android: bool, code: Option<i32>) -> bool {
    android && code.is_none()
}

#[cfg(any(target_os = "android", test))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum AttachmentAction {
    Discard,
    WaitForWindowDestruction,
    Attach,
}

/// Private pure routing only. Production observations come from the original
/// native lease and Tauri manager, never a renderer-supplied liveness boolean.
#[cfg(any(target_os = "android", test))]
pub(crate) const fn attachment_action(
    stopped: bool,
    physical_live: bool,
    needs_window: bool,
    main_exists: bool,
) -> AttachmentAction {
    if stopped || !physical_live || !needs_window {
        AttachmentAction::Discard
    } else if main_exists {
        AttachmentAction::WaitForWindowDestruction
    } else {
        AttachmentAction::Attach
    }
}

#[cfg(test)]
mod tests {
    use super::{AttachmentAction, attachment_action, prevent_implicit_exit};

    #[test]
    fn new_physical_activity_waits_for_actual_old_logical_window_removal() {
        assert_eq!(
            attachment_action(false, true, true, true),
            AttachmentAction::WaitForWindowDestruction
        );
        assert_eq!(
            attachment_action(false, true, true, false),
            AttachmentAction::Attach
        );
    }

    #[test]
    fn destroyed_consumed_or_explicitly_stopped_leases_never_attach() {
        for main_exists in [false, true] {
            assert_eq!(
                attachment_action(false, false, true, main_exists),
                AttachmentAction::Discard
            );
            assert_eq!(
                attachment_action(false, true, false, main_exists),
                AttachmentAction::Discard
            );
            assert_eq!(
                attachment_action(true, true, true, main_exists),
                AttachmentAction::Discard
            );
        }
    }

    #[test]
    fn configuration_recreation_does_not_create_a_second_logical_window() {
        assert_eq!(
            attachment_action(false, true, false, true),
            AttachmentAction::Discard
        );
        assert_eq!(
            attachment_action(false, true, false, false),
            AttachmentAction::Discard
        );
    }

    #[test]
    fn only_android_implicit_window_exit_is_prevented() {
        assert!(prevent_implicit_exit(true, None));
        assert!(!prevent_implicit_exit(false, None));
    }

    #[test]
    fn explicit_exit_codes_and_restart_are_preserved_on_every_platform() {
        for android in [false, true] {
            for code in [i32::MIN, -1, 0, 1, tauri::RESTART_EXIT_CODE, i32::MAX] {
                assert!(!prevent_implicit_exit(android, Some(code)));
            }
        }
    }

    #[test]
    fn policy_is_stateless_and_never_converts_explicit_exit_to_implicit() {
        assert!(prevent_implicit_exit(true, None));
        assert!(!prevent_implicit_exit(true, Some(0)));
        assert!(prevent_implicit_exit(true, None));
        assert!(!prevent_implicit_exit(false, Some(0)));
    }
}
