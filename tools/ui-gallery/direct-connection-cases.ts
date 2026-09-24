// SPDX-License-Identifier: GPL-2.0-or-later
import type { GalleryCase } from './cases';
import { galleryLocales } from './i18n-cases';
import type { GalleryLocale } from './i18n-cases';

export interface DirectConnectionCase extends GalleryCase { readonly locale: GalleryLocale }
function row(id: string, fixture: string, width: number, locale: GalleryLocale = 'ko', large = false): DirectConnectionCase {
  return { id, fixture, locale, viewport: { width, height: 900 }, action: 'overview',
    colorScheme: 'light', forcedColors: 'none', ...(large ? { rootTextSizePercent: 200 as const } : {}) };
}

// Client-only synthetic observations; no firewall dialog, Internet or UAC proof.
export const directConnectionCases: readonly DirectConnectionCase[] = [
  ...galleryLocales.map(locale => row(`direct-candidate-${locale}-760`, 'desktop-relay-wan-candidate', 760, locale)),
  row('direct-candidate-narrow-390', 'desktop-relay-wan-candidate', 390),
  ...(['ko', 'de', 'ar'] as const).map(locale => row(`direct-candidate-${locale}-text-200`, 'desktop-relay-wan-candidate', 760, locale, true)),
  row('direct-lan-only-760', 'desktop-relay-wan-lan', 760),
  row('direct-unavailable-760', 'desktop-relay-wan-unavailable', 760),
  row('direct-stale-760', 'desktop-relay-wan-stale', 760),
  row('direct-phone-recovery-320', 'phone-disconnected', 320),
  row('direct-phone-recovery-text-200', 'phone-disconnected', 390, 'ko', true),
];
