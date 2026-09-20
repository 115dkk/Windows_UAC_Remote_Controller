// SPDX-License-Identifier: GPL-2.0-or-later
import type { GalleryCase } from './cases';
import { galleryLocales } from './i18n-cases';
import type { GalleryLocale } from './i18n-cases';

export interface HeaderCase extends GalleryCase { readonly locale: GalleryLocale }
function phone(locale: GalleryLocale, width: number, large = false): HeaderCase {
  return { id: `header-${locale}-${width}-${large ? 'large' : 'normal'}`, locale,
    fixture: 'phone-pending', viewport: { width, height: 900 }, action: 'overview',
    colorScheme: 'dark', forcedColors: 'none', ...(large ? { rootTextSizePercent: 200 as const } : {}) };
}
export const headerCases: readonly HeaderCase[] = [
  ...galleryLocales.map(locale => phone(locale, 390)),
  ...(['ko', 'de', 'ar'] as const).flatMap(locale => [phone(locale, 320), phone(locale, 390, true), phone(locale, 320, true)]),
  ...(['ko', 'fr', 'ar'] as const).map(locale => ({ id: `header-${locale}-desktop`, locale,
    fixture: 'desktop-pairing-ready', viewport: { width: 980, height: 820 }, action: 'overview' as const,
    colorScheme: 'light' as const, forcedColors: 'none' as const })),
];
