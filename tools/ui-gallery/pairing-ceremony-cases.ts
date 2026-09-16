// SPDX-License-Identifier: GPL-2.0-or-later
import type { GalleryCase } from './cases';
import { galleryLocales } from './i18n-cases';
import type { GalleryLocale } from './i18n-cases';

export interface CeremonyCase extends GalleryCase { readonly locale: GalleryLocale }

// CLIENT/SYNTHETIC drawing of the native Windows pairing ceremony. The real
// screens are GDI on a private desktop; these carry no invitation and prove no
// native paint. The widths are the ones the layout test also walks: the lab
// runner's display, the common laptop, and an ordinary desktop.
function ceremony(screen: 'introduction' | 'invitation' | 'comparison', width: number, height: number,
  locale: GalleryLocale = 'ko', forcedColors: 'none' | 'active' = 'none'): CeremonyCase {
  return {
    id: `pairing-ceremony-${screen}-${locale}-${String(width)}x${String(height)}${forcedColors === 'active' ? '-forced' : ''}`,
    fixture: `pairing-ceremony-${screen}`, locale,
    viewport: { width, height }, action: 'overview', colorScheme: 'light', forcedColors,
  };
}

export const pairingCeremonyCases: readonly CeremonyCase[] = [
  ceremony('introduction', 1280, 800),
  ceremony('invitation', 1280, 800),
  ceremony('comparison', 1280, 800),
  // The longest button labels in the catalogue. These two are why the row is
  // 240 wide and 72 tall rather than 184 by 60.
  ceremony('comparison', 1280, 800, 'fr'),
  ceremony('comparison', 1280, 800, 'pt-PT'),
  ceremony('comparison', 1024, 768, 'de'),
  ceremony('introduction', 1024, 768),
  ceremony('invitation', 1024, 768),
  ceremony('invitation', 1280, 720),
  ceremony('introduction', 1280, 800, 'ko', 'active'),
  ...(['de', 'ar'] as GalleryLocale[]).flatMap(locale => [
    ceremony('introduction', 1280, 800, locale),
    ceremony('invitation', 1280, 800, locale),
  ]),
  ...galleryLocales.filter(locale => !['ko', 'de', 'ar'].includes(locale))
    .map(locale => ceremony('introduction', 1280, 800, locale)),
];
