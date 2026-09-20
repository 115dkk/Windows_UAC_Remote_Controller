// SPDX-License-Identifier: GPL-2.0-or-later
// ONE ROOT-reviewed source relationship, not a generic SPDX fallback/waiver.
// ROOT compared the consumer-commit upstream LICENSE with the provider's actual
// archived LICENSE byte-for-byte. The crates have DIFFERENT source commits:
// consumer ae42d22078b98549e987d2f03d12df7b984fde47 (alloc-stdlib subdirectory),
// provider 6032b6a9b20e03737135c55a0270ccffcc1438ef. No common-commit claim.
const REGISTRY = 'registry+https://github.com/rust-lang/crates.io-index';
export const ALLOC_STDLIB_SHARED_NOTICE = Object.freeze({
  id: 'alloc-stdlib-0.2.4-reviewed-dropbox-notice-v1',
  consumer: Object.freeze({ name: 'alloc-stdlib', version: '0.2.4', source: REGISTRY, license: 'BSD-3-Clause' }),
  provider: Object.freeze({ name: 'alloc-no-stdlib', version: '2.0.4', source: REGISTRY, license: 'BSD-3-Clause' }),
  sourcePath: 'LICENSE',
  bytes: 1483,
  sha256: 'c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae',
  upstreamNoticeUrl: 'https://raw.githubusercontent.com/dropbox/rust-alloc-no-stdlib/ae42d22078b98549e987d2f03d12df7b984fde47/LICENSE',
});

function matches(row, tuple, kind) {
  return kind === 'registry' && row?.workspace === false && row.name === tuple.name
    && row.version === tuple.version && row.source === tuple.source && row.license === tuple.license;
}
export function isReviewedSharedNoticeConsumer(row, kind) {
  return matches(row, ALLOC_STDLIB_SHARED_NOTICE.consumer, kind);
}
export function isReviewedSharedNoticeProvider(row, kind) {
  return matches(row, ALLOC_STDLIB_SHARED_NOTICE.provider, kind);
}
export function matchesReviewedSharedNoticeBytes(material) {
  return material?.kind === 'text' && material.sourcePath === ALLOC_STDLIB_SHARED_NOTICE.sourcePath
    && material.bytes === ALLOC_STDLIB_SHARED_NOTICE.bytes && material.sha256 === ALLOC_STDLIB_SHARED_NOTICE.sha256;
}
