// SPDX-License-Identifier: GPL-2.0-or-later
// Exact ROOT-verified original notice applicability for47 packages /30 assets.
// No SPDX-template lookup, wildcard package matching, target filtering or waiver.
// ROOT owns the imported assets/index; this code reads/validates them, never fetches.
const REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index';
export const UPSTREAM_SOURCE_INDEX = 'third-party/notices/rust/sources.json';
const INDEX_SCOPE = 'Exact upstream original notice assets; package applicability and distribution completeness are separate';

function tuples(names, version, license) {
  return names.map((name) => Object.freeze({ name, version, license }));
}
function group(id, repository, revision, consumers, files, coverage = 'original-license-materials', limitations = []) {
  return Object.freeze({ id, repository, revision, consumers: Object.freeze(consumers), coverage, limitations: Object.freeze(limitations),
    sources: Object.freeze(files.map(([name, bytes, sha256, details = {}]) => {
      const origin = details.origin ?? 'upstream-repository';
      const upstreamSourcePath = origin === 'referenced-license-document' ? null : details.upstreamSourcePath ?? name;
      return Object.freeze({
        id: `${id}/${name}`, sourcePath: `third-party/notices/rust/${id}/${name}`, origin,
        upstreamSourcePath, upstreamUrl: details.upstreamUrl ?? `https://raw.githubusercontent.com/${repository}/${revision}/${upstreamSourcePath}`,
        documentVersion: details.documentVersion ?? null, referencedBySourceId: details.referencedBySourceId ?? null,
        bytes, sha256, kind: details.kind ?? (name === 'AUTHORS' || name === 'COPYRIGHT.md' ? 'attribution' : 'text'),
      });
    })),
  });
}
// ROOT verified both UNIC revisions independently. Equal pins do not merge their
// separately imported paths/URLs or claim the revisions are interchangeable.
const UNIC_FILES = Object.freeze([
  ['LICENSE-MIT', 1023, '23f18e03dc49df91622fe2a76176497404e46ced8a715d9d2b67a7446571cca3'],
  ['LICENSE-APACHE', 10847, 'a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2'],
  ['COPYRIGHT.md', 608, 'f5c342c49f3ac804f3e8e7bb62a8040a44c50d47bb36902b1abd13f66a1adf8b'],
  ['AUTHORS', 664, '2748c1a1fba7616917c61d455e8d715ab952671ead63f2026ad0124410596b09'],
].map(Object.freeze));
const OBJC_TRIO = 'Zlib OR Apache-2.0 OR MIT';
const OBJC_EXPLANATION = Object.freeze([
  ['LICENSE.md', 1339, '7f976f7e9cb2d87df7230606feb932c3f21ac0e664045a775b600046ff850c54', Object.freeze({ kind: 'attribution' })],
].map(Object.freeze));
const OBJC_LIMITATIONS = ['full-license-terms-not-collected', 'apple-sdk-distribution-uncertainty-unresolved', 'no-license-option-selected', 'g002-legal-completion-not-proven'];
const EFI_LIMITATIONS = ['not-all-alternative-license-terms-collected', 'no-license-option-selected', 'g002-legal-completion-not-proven'];
export const UPSTREAM_NOTICE_GROUPS = Object.freeze([
  group('uniffi-5c7b73906358', 'mozilla/uniffi-rs', '5c7b73906358e1a7acdc1bdc7bf5cd86fb27e44c',
    tuples(['uniffi', 'uniffi_bindgen', 'uniffi_core', 'uniffi_internal_macros', 'uniffi_macros', 'uniffi_meta', 'uniffi_pipeline', 'uniffi_udl'], '0.32.0', 'MPL-2.0'),
    [['LICENSE', 16725, '1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5']]),
  group('ndk-49bbbba16c58', 'rust-mobile/ndk', '49bbbba16c58ff63cb8a0ad0eca5a9fb7ecaec25',
    [...tuples(['ndk'], '0.9.0', 'MIT OR Apache-2.0'), ...tuples(['ndk-sys'], '0.6.0+11769913', 'MIT OR Apache-2.0')],
    [['LICENSE-MIT', 1036, '508a77d2e7b51d98adeed32648ad124b7b30241a8e70b2e72c99f92d8e5874d1'],
      ['LICENSE-APACHE', 11357, 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4']]),
  group('unic-5878605364af', 'open-i18n/rust-unic', '5878605364af97a3358368a6eaef02104af2e016',
    tuples(['unic-char-property', 'unic-char-range', 'unic-common', 'unic-ucd-version'], '0.9.0', 'MIT/Apache-2.0'), UNIC_FILES),
  group('unic-8a6ce83063d9', 'open-i18n/rust-unic', '8a6ce83063d90b91ae2ce59eddb803edd393fca9',
    tuples(['unic-ucd-ident'], '0.9.0', 'MIT/Apache-2.0'), UNIC_FILES),
  group('defmt-4a8cdb44891e', 'knurling-rs/defmt', '4a8cdb44891ed57b8ff5a023b6bec7137c48708f',
    tuples(['defmt-parser'], '1.0.0', 'MIT OR Apache-2.0'),
    [['LICENSE-MIT', 1053, '2710a622a896bba67356913d4d0492cab5465f61b2ecce6d880aeb483834fb50'],
      ['LICENSE-APACHE', 10850, '8173d5c29b4f956d532781d2b86e4e30f83e6b7878dce18c919451d6ba707c90']]),
  group('dlopen2-cc80e4a0a90', 'OpenByteDev/dlopen2', 'cc80e4a0a90d499b677fdf7743699b4b3a43a989',
    [...tuples(['dlopen2'], '0.8.2', 'MIT'), ...tuples(['dlopen2_derive'], '0.4.3', 'MIT')],
    [['LICENSE', 1184, '39fa265207450e77c62e90c5594a06c085b655d8374c7ced4bf7894b6bd95dd2']]),
  group('jni-sys-64d77b7a5f11', 'jni-rs/jni-sys', '64d77b7a5f119d7b55b4e2c169a4668067ff59e6',
    tuples(['jni-sys-macros'], '0.4.1', 'MIT OR Apache-2.0'),
    [['LICENSE-MIT', 1071, '1d85bd754b04ceec93e98e890edd1fa3c6a22e81bcb32135806beeccefa51cd1'],
      ['LICENSE-APACHE', 11358, 'c6596eb7be8581c18be736c846fb9173b69eccf6ef94c5135893ec56bd92ba08']]),
  group('webview2-b74dc5e2b394', 'wravery/webview2-rs', 'b74dc5e2b394044bea5191052868ce7a106c202c',
    tuples(['webview2-com', 'webview2-com-sys'], '0.38.2', 'MIT'),
    [['LICENSE', 1067, '0dcf41516e608bbcb6cdc5229feb7b86fe4a643b85e7df251133c93408fdac73']]),
  group('webview2-dffa41a8a46d', 'wravery/webview2-rs', 'dffa41a8a46d3f5565eefbff2de57d38d399f158',
    tuples(['webview2-com-macros'], '0.8.1', 'MIT'),
    [['LICENSE', 1067, '0dcf41516e608bbcb6cdc5229feb7b86fe4a643b85e7df251133c93408fdac73']]),
  group('libappindicator-eafd1e3682a1', 'tauri-apps/libappindicator-rs', 'eafd1e3682a1247f595410266091e9684021cb6f',
    tuples(['libappindicator-sys'], '0.9.0', 'Apache-2.0 OR MIT'),
    [['LICENSE-MIT', 1109, 'eb227437252b2a7a9c1fc342c93ade1f3d7ce38cc6dd754f613db07d53ceff0b'],
      ['LICENSE-APACHE', 10847, 'a60eea817514531668d7e00765731449fe14d059d3249e0bc93b36de45f759f2']]),
  group('selectors-635e1a19d029', 'servo/stylo', '635e1a19d02960588a00e189bd4bd5bdb150ec3d',
    tuples(['selectors'], '0.36.1', 'MPL-2.0'),
    [['lib.rs', 643, 'd54c6e13e9e952dac17d209171df8657e3cae93beaddace4906150cdec8d02e9', { kind: 'attribution', upstreamSourcePath: 'selectors/lib.rs' }],
      ['MPL-2.0.txt', 16726, '3f3d9e0024b1921b067d6f7f88deb4a60cbe7a78e76c64e3f1d7fc3b779b9d04', { origin: 'referenced-license-document', upstreamUrl: 'https://www.mozilla.org/media/MPL/2.0/index.txt', documentVersion: 'MPL-2.0', referencedBySourceId: 'selectors-635e1a19d029/lib.rs' }]],
    'header-and-referenced-license-document', ['referenced-document-is-not-a-repository-file']),
  group('objc2-b4167b582b2f', 'madsmtm/objc2', 'b4167b582b2f75f9a1be75495c41b765344fd03c',
    tuples(['block2'], '0.6.2', 'MIT'), OBJC_EXPLANATION, 'upstream-license-explanation', OBJC_LIMITATIONS),
  group('objc2-8852b424193c', 'madsmtm/objc2', '8852b424193ca41602281b3d7540d7c8ed51e49a',
    [...tuples(['objc2'], '0.6.4', 'MIT'), ...tuples(['dispatch2'], '0.3.1', OBJC_TRIO)], OBJC_EXPLANATION, 'upstream-license-explanation', OBJC_LIMITATIONS),
  group('objc2-8d214f547736', 'madsmtm/objc2', '8d214f5477365ffcbcbb7de058c86ed9a518efb7',
    [...tuples(['objc2-encode'], '4.1.0', 'MIT'), ...tuples(['objc2-exception-helper'], '0.1.1', OBJC_TRIO)], OBJC_EXPLANATION, 'upstream-license-explanation', OBJC_LIMITATIONS),
  group('objc2-7b1abfd750a2', 'madsmtm/objc2', '7b1abfd750a2cacaea71d6a56ecfb83cb7de560b',
    [...tuples(['objc2-app-kit', 'objc2-cloud-kit', 'objc2-core-data', 'objc2-core-foundation', 'objc2-core-graphics', 'objc2-core-image', 'objc2-core-location', 'objc2-core-text', 'objc2-io-surface', 'objc2-quartz-core', 'objc2-ui-kit', 'objc2-user-notifications', 'objc2-web-kit'], '0.3.2', OBJC_TRIO),
      ...tuples(['objc2-foundation'], '0.3.2', 'MIT')], OBJC_EXPLANATION, 'upstream-license-explanation', OBJC_LIMITATIONS),
  group('r-efi-97b55bed1c2c', 'r-efi/r-efi', '97b55bed1c2c91dcbf787674849f05337ff80b33',
    tuples(['r-efi'], '5.3.0', 'MIT OR Apache-2.0 OR LGPL-2.1-or-later'),
    [['AUTHORS', 3693, 'ff92bed461f50338dd703a9ba9aee496a425957873df1d91192776e4bdf5dda7', { kind: 'text' }]],
    'original-mixed-license-notice', EFI_LIMITATIONS),
  group('r-efi-7e1b0322d31d', 'r-efi/r-efi', '7e1b0322d31d625f81a5656096330934f9cd835d',
    tuples(['r-efi'], '6.0.0', 'MIT OR Apache-2.0 OR LGPL-2.1-or-later'),
    [['AUTHORS', 3733, 'd027e91dbc9cdbb2f1190068e498bd6b61cff022b6a032b191021ba658d96111', { kind: 'text' }]],
    'original-mixed-license-notice', EFI_LIMITATIONS),
  // These old archives have no VCS record. ROOT compared every original file,
  // including import libraries, with this historical source; none is fabricated.
  group('winapi-9497609ef44c', 'retep998/winapi-rs', '9497609ef44cc9bcd16cd2411c0ee6ccaf5483aa',
    tuples(['winapi-i686-pc-windows-gnu', 'winapi-x86_64-pc-windows-gnu'], '0.4.0', 'MIT/Apache-2.0'),
    [['LICENSE-MIT', 1068, '5b19674a1db628a475850a131956ed49521b744e3dda8f5a94141f9aba681219'],
      ['LICENSE-APACHE', 11357, 'b40930bbcf80744c86c46a12bc9da056641d722716c378f5659b9e555ef833e1']],
    'original-license-materials', ['no-archived-vcs-record', 'root-verified-original-file-association']),
]);
export const UPSTREAM_SOURCE_PINS = Object.freeze(UPSTREAM_NOTICE_GROUPS.flatMap((value) => value.sources));
export const MAX_UPSTREAM_CONSUMERS = 47;
export const MAX_UPSTREAM_GROUP_FILES = 4;

export function upstreamNoticeGroup(row, kind) {
  if (kind !== 'registry' || row?.workspace !== false || row.source !== REGISTRY) return null;
  return UPSTREAM_NOTICE_GROUPS.find((value) => value.consumers.some((tuple) => tuple.name === row.name && tuple.version === row.version && tuple.license === row.license)) ?? null;
}
export function isUpstreamMaterialOrigin(origin) {
  return origin === 'upstream-repository' || origin === 'referenced-license-document';
}
export function upstreamPinForSourcePath(path) {
  return UPSTREAM_SOURCE_PINS.find((pin) => pin.sourcePath === path) ?? null;
}
export function matchesUpstreamMaterial(material, pin) {
  return pin != null && material?.origin === pin.origin && material.sourcePath === pin.sourcePath
    && material.kind === pin.kind && material.bytes === pin.bytes && material.sha256 === pin.sha256;
}
export function isApprovedUpstreamIndex(index) {
  if (index === null || typeof index !== 'object' || Array.isArray(index)
    || Object.keys(index).sort().join() !== 'schemaVersion,scope,sources' || index.schemaVersion !== 1 || index.scope !== INDEX_SCOPE
    || !Array.isArray(index.sources) || index.sources.length !== UPSTREAM_SOURCE_PINS.length) return false;
  const seen = new Set();
  return index.sources.every((value) => {
    if (value === null || typeof value !== 'object' || Array.isArray(value) || Object.keys(value).sort().join() !== 'bytes,id,sha256,sourcePath,upstreamUrl') return false;
    const pin = UPSTREAM_SOURCE_PINS.find((item) => item.id === value.id);
    if (!pin || seen.has(value.id) || value.sourcePath !== pin.sourcePath || value.upstreamUrl !== pin.upstreamUrl
      || value.bytes !== pin.bytes || value.sha256 !== pin.sha256) return false;
    seen.add(value.id);
    return true;
  });
}
