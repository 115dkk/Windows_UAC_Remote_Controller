# SPDX-License-Identifier: GPL-2.0-or-later
"""CI glyph/license/hash coverage for shipped fonts; not native shaping proof."""
from pathlib import Path
import hashlib
import json
import unicodedata
from fontTools.ttLib import TTFont

root = Path(__file__).resolve().parent.parent
mapping = {"ko":"KR", "en":"", "fr":"", "de":"", "ja":"JP", "zh-Hans":"SC", "zh-Hant":"TC", "es":"", "pt-BR":"", "pt-PT":"", "ar":"Arabic"}
def cmap(path):
    with TTFont(path) as font:
        return set(font.getBestCmap())
records = json.loads((root / "assets/fonts/native/manifest.json").read_text(encoding="utf-8"))
for item in records:
    path = root / item["path"]
    assert hashlib.sha256(path.read_bytes()).hexdigest() == item["sha256"], path
    with TTFont(path) as font:
        assert "fvar" not in font, "Native GDI must receive static faces"
        assert font["OS/2"].usWeightClass == item["weight"]
        assert any(record.toUnicode() == item["family"] for record in font["name"].names if record.nameID in (1,16)), path
for locale, suffix in mapping.items():
    catalog = json.loads((root / f"locales/{locale}.json").read_text(encoding="utf-8"))
    required = {ord(char) for value in catalog.values() for char in value if not unicodedata.category(char).startswith("C") and not char.isspace()}
    native = root / f"assets/fonts/native/UACSans{suffix}-Regular.ttf"
    missing = required - cmap(native)
    assert not missing, f"{locale} native missing: {[hex(value) for value in sorted(missing)]}"
    web = root / ("ui/public/fonts/ibm-plex-sans-kr/IBMPlexSansKR-Regular.woff2" if locale == "ko" else f"ui/public/fonts/noto/NotoSans{suffix}.ttf")
    assert not (required - cmap(web)), f"{locale} web glyph coverage"
    resource = {"":"noto_sans", "Arabic":"noto_sans_arabic", "JP":"noto_sans_jp", "SC":"noto_sans_sc", "TC":"noto_sans_tc", "KR":"noto_sans_kr"}[suffix]
    assert native.read_bytes() == (root / f"src-tauri/gen/android/app/src/main/res/font/{resource}.ttf").read_bytes()
    license_text = (root / f"assets/fonts/native/UACSans{suffix}-OFL.txt").read_text(encoding="utf-8")
    assert "SIL OPEN FONT LICENSE" in license_text and "Copyright" in license_text
    print(f"PASS {locale}: {len(required)} authored codepoints, native/web cmap and Android copy, OFL")
print("Glyph coverage does not establish native shaping, visual readability, or universal Unicode coverage.")
