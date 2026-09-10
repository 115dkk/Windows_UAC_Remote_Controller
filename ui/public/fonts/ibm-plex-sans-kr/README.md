# IBM Plex Sans KR — offline client fonts

These four **unmodified complete hinted WOFF2** files are from the official
[IBM Plex Sans KR 1.1.0 package release](https://github.com/IBM/plex/releases/tag/@ibm%2Fplex-sans-kr@1.1.0),
pinned to commit `1da12f02587b630c07e92692d21492d722f53614`.
[Upstream directory](https://github.com/IBM/plex/tree/1da12f02587b630c07e92692d21492d722f53614/packages/plex-sans-kr/fonts/complete/woff2/hinted).

The normal Regular/Medium/SemiBold/Bold cuts map to CSS 400/500/600/700. The
client loads `/fonts/ibm-plex-sans-kr/IBMPlexSansKR-<cut>.woff2` from its own
package, without a CDN, installed-font preference, npm package or telemetry.
`DESIGN.md` owns typography; `ui/src/styles.css` applies it to both shells.
Path/command monospace stacks, OS chrome, SystemUI and authentication fonts
are intentionally unchanged.

`manifest.json` records ROOT-supplied SHA-256/size pins and the separate
2026-09-10 fontTools 4.63 / Brotli 1.2 inspection: each file has 12,183 cmap
entries, all 11,172 modern Hangul syllables and 95 printable ASCII characters;
decimal digits each advance 600 of 1,000 units. The Node packaging contract
does not decode these glyphs. The observation does not prove Jamo shaping,
all scripts, legibility, clipping or native rendering. ROOT owns actual
Chromium/WebView visual review; gallery CDP evidence identifies fonts actually
used by selected visible synthetic client text, not an OS authentication UI.

Font files remain **SIL OFL 1.1**, copyright IBM, Reserved Font Name **Plex**.
Keep `LICENSE.txt` with redistribution. Its notice text is unchanged; only
line endings and trailing whitespace follow repository conventions, with both
source and bundled hashes recorded in the manifest. Fonts are not relicensed
under the application's GPL. No source-font conversion, subset or glyph edits
were made. File hashes identify the exact bundled files, not mutable release
URLs. The source contract checks original/built copies without a network fetch.
