# SPDX-License-Identifier: GPL-2.0-or-later
"""Asset generation only: deterministic static native faces, no app/device QA.

Original Google Fonts / IBM files and OFL notices remain unchanged. Derived
native faces get project-specific family names; glyph coverage is not subset.
"""
from pathlib import Path
import hashlib
import json
import shutil
from fontTools.ttLib import TTFont
from fontTools.varLib.instancer import instantiateVariableFont

root = Path(__file__).resolve().parent.parent
target = root / "assets/fonts/native"
android = root / "src-tauri/gen/android/app/src/main/res/font"
licenses = root / "src-tauri/gen/android/app/src/main/assets/font-licenses"
for directory in (target, android, licenses):
    directory.mkdir(parents=True, exist_ok=True)
manifest = []
families = [("", "noto_sans"), ("Arabic", "noto_sans_arabic"), ("JP", "noto_sans_jp"), ("SC", "noto_sans_sc"), ("TC", "noto_sans_tc"), ("KR", "noto_sans_kr")]
for suffix, resource in families:
    license_path = root / ("ui/public/fonts/ibm-plex-sans-kr/LICENSE.txt" if suffix == "KR" else f"ui/public/fonts/noto/NotoSans{suffix}-OFL.txt")
    shutil.copyfile(license_path, target / f"UACSans{suffix}-OFL.txt")
    shutil.copyfile(license_path, licenses / f"UACSans{suffix}-OFL.txt")
    for weight, style in ((400, "Regular"), (700, "Bold")):
        source = root / (f"ui/public/fonts/ibm-plex-sans-kr/IBMPlexSansKR-{style}.woff2" if suffix == "KR" else f"ui/public/fonts/noto/NotoSans{suffix}.ttf")
        font = TTFont(source, recalcTimestamp=False)
        if "fvar" in font:
            axes = {axis.axisTag: axis.defaultValue for axis in font["fvar"].axes}
            axes["wght"] = weight
            instantiateVariableFont(font, axes, inplace=True)
        font.flavor = None
        family = "UAC Sans" + (f" {suffix}" if suffix else "")
        names = {1: family, 2: style, 3: f"UAC-i18n-{family}-{style}", 4: f"{family} {style}", 6: f"UACSans{suffix}-{style}", 16: family, 17: style}
        for entry in font["name"].names:
            if entry.nameID in names:
                entry.string = names[entry.nameID].encode(entry.getEncoding(), errors="replace")
        if "CFF " in font:
            font["CFF "].cff.fontNames = [names[6]]
            for top in font["CFF "].cff.topDictIndex:
                top.FamilyName = family
                top.FullName = names[4]
        font["OS/2"].usWeightClass = weight
        font["OS/2"].fsSelection = (font["OS/2"].fsSelection & ~0x61) | (0x20 if weight == 700 else 0x40)
        font["head"].macStyle = (font["head"].macStyle & ~3) | (1 if weight == 700 else 0)
        destination = target / f"UACSans{suffix}-{style}.ttf"
        font.save(destination)
        font.close()
        if weight == 400:
            shutil.copyfile(destination, android / f"{resource}.ttf")
        manifest.append({"path": destination.relative_to(root).as_posix(), "source": source.relative_to(root).as_posix(), "family": family, "weight": weight, "sha256": hashlib.sha256(destination.read_bytes()).hexdigest(), "bytes": destination.stat().st_size})
print(json.dumps(manifest, indent=2))
