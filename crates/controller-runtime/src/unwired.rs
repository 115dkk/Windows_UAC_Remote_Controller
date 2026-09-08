// SPDX-License-Identifier: GPL-2.0-or-later
//! Stable error translation shared by desktop and the native Android shell.
use crate::AppIssue;

#[derive(Clone, Copy, Debug)]
pub enum UnwiredCapability {
    Pairing,
    Unpairing,
    Decisions,
    Activity,
}

impl UnwiredCapability {
    pub const fn issue(self) -> AppIssue {
        match self {
            Self::Pairing => AppIssue {
                code: "pairing_unavailable",
                message: "기기 연결 기능이 아직 연결되지 않아 등록을 시작할 수 없습니다.",
                next_action: Some("기기 연결을 지원하는 앱 버전에서 다시 시도해 주세요."),
            },
            Self::Unpairing => AppIssue {
                code: "unpair_unavailable",
                message: "연결된 기기 정보를 읽거나 연결을 해제할 수 없습니다.",
                next_action: Some("기기 관리 기능이 연결된 앱 버전에서 다시 시도해 주세요."),
            },
            Self::Decisions => AppIssue {
                code: "decisions_unavailable",
                message: "Windows 요청을 처리하는 기능이 아직 연결되지 않았습니다.",
                next_action: Some("PC에서 Windows 요청을 직접 확인해 주세요."),
            },
            Self::Activity => AppIssue {
                code: "activity_unavailable",
                message: "서비스 기록을 읽거나 지우는 기능이 아직 연결되지 않았습니다.",
                next_action: Some("기록 조회를 지원하는 앱 버전에서 다시 확인해 주세요."),
            },
        }
    }
}
