// SPDX-License-Identifier: GPL-2.0-or-later
import type { GalleryCase } from './cases';
import type { GalleryLocale } from './i18n-cases';

export interface NetworkCase extends GalleryCase { readonly locale: GalleryLocale }
function row(id: string, fixture: string, width: number, locale: GalleryLocale = 'ko', options: {
  readonly large?: boolean; readonly colorScheme?: 'light' | 'dark'; readonly forcedColors?: 'none' | 'active';
} = {}): NetworkCase {
  return { id, fixture, locale, viewport: { width, height: 900 }, action: 'overview',
    colorScheme: options.colorScheme ?? 'light', forcedColors: options.forcedColors ?? 'none',
    ...(options.large ? { rootTextSizePercent: 200 as const } : {}) };
}

// Client-only synthetic external-access views with documentation addresses.
// No router mapping, STUN reply, reachable address or native save is shown.
export const networkCases: readonly NetworkCase[] = [
  row('network-auto-no-mapping-980', 'desktop-network-auto-no-mapping', 980),
  row('network-auto-upnp-dark-980', 'desktop-network-auto-upnp', 980, 'ko', { colorScheme: 'dark' }),
  row('network-forward-stun-980', 'desktop-network-forward-stun', 980),
  // Longest Latin copy, CJK and RTL. The other variants share these lengths and
  // every locale's text is checked by the client tests; this keeps the run short.
  ...(['ko', 'en', 'fr', 'de', 'pt-PT', 'ja', 'zh-Hans', 'ar'] as const)
    .map(locale => row(`network-forward-unavailable-${locale}-760`, 'desktop-network-forward-unavailable', 760, locale)),
  row('network-forward-unavailable-narrow-390', 'desktop-network-forward-unavailable', 390),
  ...(['ko', 'de', 'ar'] as const).map(locale => row(`network-forward-unavailable-${locale}-text-200`, 'desktop-network-forward-unavailable', 760, locale, { large: true })),
  row('network-fixed-760', 'desktop-network-fixed', 760),
  row('network-fixed-forced-760', 'desktop-network-fixed', 760, 'ko', { forcedColors: 'active' }),
  row('network-phone-relay-first-760', 'desktop-pairing-relay-first', 760),
];
