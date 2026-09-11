// SPDX-License-Identifier: GPL-2.0-or-later
// Exact ROOT-verified original-repository notice applicability for15 packages.
// No SPDX-template lookup, wildcard package matching, target filtering or waiver.
// ROOT owns the imported assets/index; this code reads/validates them, never fetches.
const REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index';
export const UPSTREAM_SOURCE_INDEX = 'third-party/notices/rust/sources.json';
const INDEX_SCOPE = 'Exact upstream original notice assets; package applicability and distribution completeness are separate';

function group(id, repository, revision, names, version, license, files) {
  return Object.freeze({ id, repository, revision, names: Object.freeze(names), version, license,
    sources: Object.freeze(files.map(([name, bytes, sha256]) => Object.freeze({
      id: `${id}/${name}`, sourcePath: `third-party/notices/rust/${id}/${name}`,
      upstreamSourcePath: name, upstreamUrl: `https://raw.githubusercontent.com/${repository}/${revision}/${name}`,
      bytes, sha256, kind: name === 'AUTHORS' || name === 'COPYRIGHT.md' ? 'attribution' : 'text',
    }))),
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
export const UPSTREAM_NOTICE_GROUPS = Object.freeze([
  group('uniffi-5c7b73906358', 'mozilla/uniffi-rs', '5c7b73906358e1a7acdc1bdc7bf5cd86fb27e44c',
    ['uniffi', 'uniffi_bindgen', 'uniffi_core', 'uniffi_internal_macros', 'uniffi_macros', 'uniffi_meta', 'uniffi_pipeline', 'uniffi_udl'], '0.32.0', 'MPL-2.0',
    [['LICENSE', 16725, '1f256ecad192880510e84ad60474eab7589218784b9a50bc7ceee34c2b91f1d5']]),
  group('ndk-49bbbba16c58', 'rust-mobile/ndk', '49bbbba16c58ff63cb8a0ad0eca5a9fb7ecaec25',
    ['ndk'], '0.9.0', 'MIT OR Apache-2.0',
    [['LICENSE-MIT', 1036, '508a77d2e7b51d98adeed32648ad124b7b30241a8e70b2e72c99f92d8e5874d1'],
      ['LICENSE-APACHE', 11357, 'c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4']]),
  group('unic-5878605364af', 'open-i18n/rust-unic', '5878605364af97a3358368a6eaef02104af2e016',
    ['unic-char-property', 'unic-char-range', 'unic-common', 'unic-ucd-version'], '0.9.0', 'MIT/Apache-2.0', UNIC_FILES),
  group('unic-8a6ce83063d9', 'open-i18n/rust-unic', '8a6ce83063d90b91ae2ce59eddb803edd393fca9',
    ['unic-ucd-ident'], '0.9.0', 'MIT/Apache-2.0', UNIC_FILES),
]);
export const UPSTREAM_SOURCE_PINS = Object.freeze(UPSTREAM_NOTICE_GROUPS.flatMap((value) => value.sources));
export const MAX_UPSTREAM_CONSUMERS = 15;
export const MAX_UPSTREAM_GROUP_FILES = 4;

export function upstreamNoticeGroup(row, kind) {
  if (kind !== 'registry' || row?.workspace !== false || row.source !== REGISTRY) return null;
  // ndk-sys shares the NDK group but retains its own exact semver build metadata.
  if (row.name === 'ndk-sys' && row.version === '0.6.0+11769913' && row.license === 'MIT OR Apache-2.0') return UPSTREAM_NOTICE_GROUPS[1];
  return UPSTREAM_NOTICE_GROUPS.find((value) => value.names.includes(row.name) && value.version === row.version && value.license === row.license) ?? null;
}
export function upstreamPinForSourcePath(path) {
  return UPSTREAM_SOURCE_PINS.find((pin) => pin.sourcePath === path) ?? null;
}
export function matchesUpstreamMaterial(material, pin) {
  return pin != null && material?.origin === 'upstream-repository' && material.sourcePath === pin.sourcePath
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
