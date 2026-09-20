// SPDX-License-Identifier: GPL-2.0-or-later
import type { GalleryCase } from './cases';

function phone(id: string, fixture: string, width = 390, height = 844,
  action: GalleryCase['action'] = 'overview', colorScheme: GalleryCase['colorScheme'] = 'light'): GalleryCase {
  return { id, fixture, viewport: { width, height }, action, colorScheme, forcedColors: 'none' };
}

/** Synthetic browser/client states; these are not native service/boot evidence. */
export const phoneServiceGalleryCases: readonly GalleryCase[] = [
  phone('phone-service-stopped-390', 'phone-service-stopped'),
  phone('phone-service-preparing-390', 'phone-service-preparing'),
  phone('phone-service-ready-390', 'phone-service-ready', 390, 844, 'dialog'),
  phone('phone-service-waiting-unlock-390', 'phone-service-waiting-unlock'),
  phone('phone-service-cleanup-390', 'phone-service-cleanup'),
  phone('phone-service-unavailable-390', 'phone-service-unavailable'),
  phone('phone-service-error-390', 'phone-service-error'),
  phone('phone-service-stopped-narrow-320', 'phone-service-stopped', 320, 740),
  phone('phone-service-ready-landscape-dark-844', 'phone-service-ready', 844, 390, 'dialog', 'dark'),
];
