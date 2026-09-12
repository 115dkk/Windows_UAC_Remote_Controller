// SPDX-License-Identifier: GPL-2.0-or-later
import { galleryCases } from './cases';
import type { GalleryCase } from './cases';
import { i18nGalleryCases } from './i18n-cases';
import { headerCases } from './header-cases';

// CLIENT/SYNTHETIC launch controls only. No camera preview, permission UI, QR or
// native read result is rendered by this gallery adapter.
export const scannerLaunchCases: readonly GalleryCase[] = [
  { id: 'client-scanner-launch-390', fixture: 'phone-scanner-launch', viewport: { width: 390, height: 844 }, colorScheme: 'light', forcedColors: 'none', action: 'overview' },
  { id: 'client-scanner-launch-unavailable-320', fixture: 'phone-scanner-unavailable-catalog', viewport: { width: 320, height: 740 }, colorScheme: 'light', forcedColors: 'none', action: 'overview' },
  { id: 'client-scanner-launch-landscape-844', fixture: 'phone-scanner-launch', viewport: { width: 844, height: 390 }, colorScheme: 'dark', forcedColors: 'none', action: 'overview' },
  { id: 'client-scanner-launch-text-size-200-390', fixture: 'phone-scanner-launch', viewport: { width: 390, height: 844 }, colorScheme: 'light', forcedColors: 'none', action: 'overview', rootTextSizePercent: 200 },
  { id: 'client-scanner-launch-error-320', fixture: 'phone-scanner-launch-error', viewport: { width: 320, height: 740 }, colorScheme: 'light', forcedColors: 'none', action: 'overview' },
];

export const declaredGalleryCases = [...galleryCases, ...scannerLaunchCases, ...i18nGalleryCases, ...headerCases];
