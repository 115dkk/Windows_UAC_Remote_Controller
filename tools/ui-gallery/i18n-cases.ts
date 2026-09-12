// SPDX-License-Identifier: GPL-2.0-or-later
// Data-only declarations shared by test registration and the strict reporter.
import type { GalleryCase } from './cases';

export const galleryLocales = ['ko', 'en', 'fr', 'de', 'ja', 'zh-Hans', 'zh-Hant', 'es', 'pt-BR', 'pt-PT', 'ar'] as const;
export type GalleryLocale = typeof galleryLocales[number];
export interface I18nGalleryCase extends GalleryCase {
  readonly locale: GalleryLocale;
  readonly i18nKind: 'desktop' | 'phone' | 'settings' | 'history' | 'bidi';
}

function row(locale: GalleryLocale, i18nKind: I18nGalleryCase['i18nKind'], suffix: string,
  fixture: string, width: number, height: number): I18nGalleryCase {
  return { id: `i18n-${locale}-${suffix}`, locale, i18nKind, fixture,
    viewport: { width, height }, colorScheme: 'light', forcedColors: 'none', action: 'overview' };
}

export const i18nDesktopCases = galleryLocales.map(locale => row(locale, 'desktop', 'desktop', 'desktop-pairing-ready', 980, 820));
export const i18nPhoneCases = galleryLocales.map(locale => row(locale, 'phone', 'phone', 'phone-pending', 390, 900));
const expansionLocales = ['fr', 'de', 'ar'] as const;
export const i18nSettingsCases = expansionLocales.map(locale => row(locale, 'settings', 'settings-320', 'phone-pending', 320, 740));
export const i18nHistoryCases = expansionLocales.map(locale => row(locale, 'history', 'history-390', 'phone-history', 390, 844));
export const i18nBidiCase = row('ar', 'bidi', 'bidi-original-details', 'phone-bidi', 390, 900);
export const i18nGalleryCases: readonly I18nGalleryCase[] = [
  ...i18nDesktopCases, ...i18nPhoneCases, ...i18nSettingsCases, ...i18nHistoryCases, i18nBidiCase,
];
