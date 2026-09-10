//! Process-exit policy only, not Activity/window creation or service authority.
//! The production platform input is compile-time `cfg!(target_os = "android")`;
//! this module is private and is not reachable through a command or JNI API.

/// `None` is Tauri's implicit last-window/user-interaction exit request. Every
/// explicit exit or restart carries `Some(code)`, including an explicit zero.
pub(crate) const fn prevent_implicit_exit(android: bool, code: Option<i32>) -> bool {
    android && code.is_none()
}

#[cfg(test)]
mod tests {
    use super::prevent_implicit_exit;

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
