// SPDX-License-Identifier: GPL-2.0-or-later
//! Fixed presentation copy only. No protocol, authentication or original request
//! data is accepted as a translation catalog or used to select authority.
#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, sync::OnceLock};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(usize)]
pub enum Locale {
    Ko,
    En,
    Fr,
    De,
    Ja,
    ZhHans,
    ZhHant,
    Es,
    PtBr,
    PtPt,
    Ar,
}

impl Locale {
    pub const ALL: [Self; 11] = [
        Self::Ko,
        Self::En,
        Self::Fr,
        Self::De,
        Self::Ja,
        Self::ZhHans,
        Self::ZhHant,
        Self::Es,
        Self::PtBr,
        Self::PtPt,
        Self::Ar,
    ];

    pub const fn tag(self) -> &'static str {
        match self {
            Self::Ko => "ko",
            Self::En => "en",
            Self::Fr => "fr",
            Self::De => "de",
            Self::Ja => "ja",
            Self::ZhHans => "zh-Hans",
            Self::ZhHant => "zh-Hant",
            Self::Es => "es",
            Self::PtBr => "pt-BR",
            Self::PtPt => "pt-PT",
            Self::Ar => "ar",
        }
    }

    pub const fn is_rtl(self) -> bool {
        matches!(self, Self::Ar)
    }

    pub fn from_preference(tag: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|locale| locale.tag() == tag)
    }

    /// Normalize an OS language tag, not an explicit stored preference. An
    /// explicit Chinese script takes precedence over its regional default.
    pub fn from_system_tag(tag: &str) -> Option<Self> {
        if tag.is_empty()
            || tag.len() > 128
            || !tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        {
            return None;
        }
        let parts: Vec<_> = tag.split('-').collect();
        if parts.iter().any(|part| part.is_empty()) {
            return None;
        }
        let language = parts.first()?.to_ascii_lowercase();
        // Unicode/private-use extension subtags are not scripts or territories.
        let base = || parts.iter().skip(1).take_while(|part| part.len() != 1);
        let script = base()
            .find(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphabetic()))
            .map(|p| p.to_ascii_lowercase());
        let region = base()
            .find(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_alphabetic()))
            .map(|p| p.to_ascii_uppercase());
        match language.as_str() {
            "zh" => Some(
                if script.as_deref() == Some("hant")
                    || (script.as_deref() != Some("hans")
                        && matches!(region.as_deref(), Some("TW" | "HK" | "MO")))
                {
                    Self::ZhHant
                } else {
                    Self::ZhHans
                },
            ),
            "pt" => Some(if region.as_deref() == Some("PT") {
                Self::PtPt
            } else {
                Self::PtBr
            }),
            _ => Self::from_preference(&language),
        }
    }

    pub fn from_system_locales(locales: &[String]) -> Self {
        locales
            .iter()
            .find_map(|tag| Self::from_system_tag(tag))
            .unwrap_or(Self::En)
    }
}

pub fn valid_preference(preference: &str) -> bool {
    preference == "system" || Locale::from_preference(preference).is_some()
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LanguageSettings {
    pub preference: String,
    pub system_locales: Vec<String>,
}

impl LanguageSettings {
    pub fn effective_locale(&self) -> Locale {
        Locale::from_preference(&self.preference)
            .unwrap_or_else(|| Locale::from_system_locales(&self.system_locales))
    }
}

type Catalog = BTreeMap<String, String>;
static CATALOGS: OnceLock<[Catalog; 11]> = OnceLock::new();

fn catalogs() -> &'static [Catalog; 11] {
    CATALOGS.get_or_init(|| {
        [
            include_str!("../../../locales/ko.json"),
            include_str!("../../../locales/en.json"),
            include_str!("../../../locales/fr.json"),
            include_str!("../../../locales/de.json"),
            include_str!("../../../locales/ja.json"),
            include_str!("../../../locales/zh-Hans.json"),
            include_str!("../../../locales/zh-Hant.json"),
            include_str!("../../../locales/es.json"),
            include_str!("../../../locales/pt-BR.json"),
            include_str!("../../../locales/pt-PT.json"),
            include_str!("../../../locales/ar.json"),
        ]
        .map(|json| serde_json::from_str(json).expect("bundled translation catalog must be valid"))
    })
}

/// Only call for authored fixed-copy keys. Missing localized entries use the
/// bundled English catalog; unknown keys are returned literally, not interpreted.
pub fn tr(locale: Locale, source: &str) -> &str {
    let catalogs = catalogs();
    catalogs[locale as usize]
        .get(source)
        .or_else(|| catalogs[Locale::En as usize].get(source))
        .map_or(source, String::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_allowlist_is_canonical_and_system_mapping_is_deliberate() {
        assert!(valid_preference("system"));
        for locale in Locale::ALL {
            assert!(valid_preference(locale.tag()));
        }
        for value in ["", "EN", "zh", "pt", "fr-FR", "../en", "ar\u{202e}"] {
            assert!(!valid_preference(value));
        }
        for (tag, expected) in [
            ("fr-CA", Locale::Fr),
            ("zh", Locale::ZhHans),
            ("zh-TW", Locale::ZhHant),
            ("zh-HK", Locale::ZhHant),
            ("zh-Hans-TW", Locale::ZhHans),
            ("zh-Hant-CN", Locale::ZhHant),
            ("zh-u-nu-hant", Locale::ZhHans),
            ("pt", Locale::PtBr),
            ("pt-AO", Locale::PtBr),
            ("pt-PT", Locale::PtPt),
            ("ar-EG", Locale::Ar),
        ] {
            assert_eq!(Locale::from_system_tag(tag), Some(expected));
        }
        assert_eq!(
            Locale::from_system_locales(&["ru-RU".into(), "de-AT".into()]),
            Locale::De
        );
        assert_eq!(Locale::from_system_locales(&["ru-RU".into()]), Locale::En);
    }

    #[test]
    fn bundled_catalogs_cover_every_authored_english_key() {
        let catalogs = catalogs();
        let english = &catalogs[Locale::En as usize];
        assert!(!english.is_empty());
        for locale in Locale::ALL {
            assert_eq!(
                catalogs[locale as usize].len(),
                english.len(),
                "{}",
                locale.tag()
            );
            for key in english.keys() {
                assert!(
                    catalogs[locale as usize]
                        .get(key)
                        .is_some_and(|value| !value.trim().is_empty()),
                    "{}: {key}",
                    locale.tag()
                );
            }
        }
        assert_eq!(tr(Locale::En, "UAC 원격 승인"), "UAC Remote Approval");
    }
}
