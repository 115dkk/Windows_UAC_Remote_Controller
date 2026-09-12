<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0032: Presentation localization and directional-text boundaries

Status: implementation, 2026-09-13.

## Decision

Korean remains supported. Add English, French, German, Japanese, simplified and
traditional Chinese, Spanish, Brazilian and European Portuguese, and Modern
Standard Arabic. Supported system language preferences are matched in order;
unmatched languages fall back to English. Explicit Chinese script takes priority
over territory. Language selection belongs in a secondary app-settings dialog,
not a new primary navigation tab or a first-launch question. Language autonyms
remain recognizable even after an accidental selection.

Windows stores a fixed allowlisted presentation preference under the current
user's HKCU. Android33+ uses the platform's per-app locale; Android30–32 stores
only the language choice in device-protected preferences. This does not expose
credential-encrypted policy, key or request data before unlock. The protected
Windows pairing renderer freezes the approving Windows account's locale per
ceremony; alternate-administrator elevation does not authorize reading another
user's hive or passing a new authority value through the pairing protocol.

The WebView and protected Windows UI share fixed-copy catalogs. Korean source
literals are lookup keys, not strings extracted from requests. Translation is
called only at authored presentation sinks. Android uses native resource
qualifiers and the same locale policy. Original program names, command lines,
file paths, identifiers and six-digit comparison codes are not translated.
Persistent installation/service/storage identities are not renamed by locale.

## Bidirectional display security

The audit finding is confirmed: approval-protocol's existing text validation
checks length/empty policy and NUL, and Android BidiFormatter alone retains an
embedded directional override. This can spoof filenames in Korean/LTR contexts
too; Arabic support adds another mixing context, not the underlying capability.

Do not normalize or reject such protocol text: its original canonical UTF-8 bytes
remain inputs to request digests/signatures. Presentation escapes U+061C,
U+200E/U+200F, U+202A–U+202E, U+2066–U+2069 and deprecated U+206A–U+206F into visible
ASCII tokens such as `[U+202E]`. Preserve ordinary Arabic text, ZWJ and ZWNJ.
WebView technical text gets LTR isolated paragraphs, never `dir=auto` or
`unicode-bidi:plaintext`. All original DTOs, callbacks and protocol data remain
unchanged. A displayed warning distinguishes escaped controls from ordinary
text. Native notifications escape before BidiFormatter wrapping; if full escaped
text exceeds the notification budget, or the source projection has already
elided its name/path, show a details instruction and omit its
Approve action rather than silently truncating the visible filename tail.

References: [UAX9](https://www.unicode.org/reports/tr9/),
[Unicode security considerations](https://www.unicode.org/reports/tr36/).

## Typography

Keep IBM Plex Sans KR for Korean and bundle pinned Noto Sans, Noto Sans Arabic,
Noto Sans JP/SC/TC for locale-appropriate UI glyphs. Fonts are served locally with
their OFL notices; there is no runtime font CDN. Generate renamed static native
faces for GDI, whose variable-font selection is not the web's font-axis interface.
Android scanner uses bundled native faces; OS-owned notification/authentication
templates retain OS typography. Glyph maps are checked in CI and actual client
and native installer pixels are separately reviewed. This does not promise
universal Unicode coverage or certify physical phone authentication.
