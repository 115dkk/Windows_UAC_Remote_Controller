# SPDX-License-Identifier: GPL-2.0-or-later
"""CI glyph/license/hash coverage for shipped fonts; not native shaping proof."""
from pathlib import Path
import hashlib
import json
import re
import unicodedata
import xml.etree.ElementTree as ET
from fontTools.ttLib import TTFont

root = Path(__file__).resolve().parent.parent
mapping = {"ko":"KR", "en":"", "fr":"", "de":"", "ja":"JP", "zh-Hans":"SC", "zh-Hant":"TC", "es":"", "pt-BR":"", "pt-PT":"", "ar":"Arabic"}
def cmap(path):
    with TTFont(path) as font:
        return set(font.getBestCmap())
records = json.loads((root / "assets/fonts/native/manifest.json").read_text(encoding="utf-8"))
# Inspect each surface's actual authored copy. The GDI pairing window does not
# render web-only instructions; WebView uses an explicitly bundled fallback chain.
renderer = (root / "crates/windows-service-host/src/ffi/pairing_client/renderer_ui.rs").read_text(encoding="utf-8")
native_keys = {value for value in re.findall(r'"([^"\n]+)"', renderer) if re.search(r'[가-힣]', value)}
assert len(native_keys) >= 8, "Protected renderer copy extraction must not be empty"
web_css = (root / "ui/src/i18n.css").read_text(encoding="utf-8")
web_faces = [root / "ui/public/fonts/ibm-plex-sans-kr/IBMPlexSansKR-Regular.woff2"]
for suffix in ("", "Arabic", "JP", "SC", "TC"):
    assert f'"Noto Sans{(" " + suffix) if suffix else ""}"' in web_css
    web_faces.append(root / f"ui/public/fonts/noto/NotoSans{suffix}.ttf")
web_coverage = set().union(*(cmap(path) for path in web_faces))

def codepoints(values):
    return {ord(char) for value in values for char in value if not unicodedata.category(char).startswith("C") and not char.isspace()}
for item in records:
    path = root / item["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path
    with TTFont(path) as font:
        assert "fvar" not in font, "Native GDI must receive static faces"
        assert font["OS/2"].usWeightClass == item["weight"]
        assert any(record.toUnicode() == item["family"] for record in font["name"].names if record.nameID in (1,16)), path
for locale, suffix in mapping.items():
    catalog = json.loads((root / f"locales/{locale}.json").read_text(encoding="utf-8"))
    required = codepoints(catalog.values())
    assert native_keys <= catalog.keys(), f"{locale}: untranslated protected-renderer copy"
    native_required = codepoints([catalog[key] for key in native_keys] + ["0123456789"])
    qualifier = {"en":"values", "ko":"values-ko", "zh-Hans":"values-b+zh+Hans", "zh-Hant":"values-b+zh+Hant", "pt-BR":"values-pt-rBR", "pt-PT":"values-pt-rPT"}.get(locale, f"values-{locale}")
    resources = ET.parse(root / f"src-tauri/gen/android/app/src/main/res/{qualifier}/strings.xml")
    scanner_copy = [node.text or "" for node in resources.findall("string") if node.attrib["name"].startswith("pairing_scanner_")]
    assert len(scanner_copy) >= 30, f"{locale}: incomplete scanner copy"
    scanner_required = codepoints(scanner_copy + ["0123456789"])
    native = root / f"assets/fonts/native/UACSans{suffix}-Regular.ttf"
    for weight in ("Regular", "Bold"):
        missing = native_required - cmap(root / f"assets/fonts/native/UACSans{suffix}-{weight}.ttf")
        assert not missing, f"{locale} native {weight} missing: {[hex(value) for value in sorted(missing)]}"
    assert not (required - web_coverage), f"{locale} bundled web fallback glyph coverage"
    assert not (scanner_required - cmap(native)), f"{locale} native scanner glyph coverage"
    resource = {"":"noto_sans", "Arabic":"noto_sans_arabic", "JP":"noto_sans_jp", "SC":"noto_sans_sc", "TC":"noto_sans_tc", "KR":"noto_sans_kr"}[suffix]
    assert native.read_bytes() == (root / f"src-tauri/gen/android/app/src/main/res/font/{resource}.ttf").read_bytes()
    license_text = (root / f"assets/fonts/native/UACSans{suffix}-OFL.txt").read_text(encoding="utf-8")
    assert "SIL OPEN FONT LICENSE" in license_text and "Copyright" in license_text
    print(f"PASS {locale}: web {len(required)} / GDI {len(native_required)} authored codepoints, Android copy, OFL")
print("Glyph coverage does not establish native shaping, visual readability, or universal Unicode coverage.")
