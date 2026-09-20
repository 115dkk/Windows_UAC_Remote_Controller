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
                message: "이 버전에서는 기기 등록을 시작할 수 없습니다.",
                next_action: Some("기기 연결을 지원하는 앱 버전에서 다시 시도해 주세요."),
            },
            Self::Unpairing => AppIssue {
                code: "unpair_unavailable",
                message: "연결된 기기 정보를 읽거나 연결을 해제할 수 없습니다.",
                next_action: Some("기기 관리를 지원하는 앱 버전에서 다시 시도해 주세요."),
            },
            Self::Decisions => AppIssue {
                code: "decisions_unavailable",
                message: "이 버전에서는 휴대폰으로 PC의 요청을 승인하거나 거부할 수 없습니다.",
                next_action: Some("PC에서 Windows 요청을 직접 확인해 주세요."),
            },
            Self::Activity => AppIssue {
                code: "activity_unavailable",
                message: "이 버전에서는 휴대폰 승인 기록을 읽거나 지울 수 없습니다.",
                next_action: Some("기록 조회를 지원하는 앱 버전에서 다시 확인해 주세요."),
            },
        }
    }
}
