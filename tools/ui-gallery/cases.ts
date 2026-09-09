// SPDX-License-Identifier: GPL-2.0-or-later
import { phoneServiceGalleryCases } from './phone-service-cases';
export type GalleryAction = 'overview' | 'details' | 'long-details' | 'schedule' | 'dialog' | 'draft' | 'deny' | 'notification-settings';
export interface GalleryCase {
  readonly id: string;
  readonly fixture: string;
  readonly viewport: { readonly width: number; readonly height: number };
  readonly colorScheme: 'light' | 'dark';
  readonly forcedColors: 'none' | 'active';
  readonly action: GalleryAction;
}

function row(id: string, fixture: string, width: number, height: number,
  action: GalleryAction = 'overview', colorScheme: 'light' | 'dark' = 'light',
  forcedColors: 'none' | 'active' = 'none'): GalleryCase {
  return { id, fixture, viewport: { width, height }, action, colorScheme, forcedColors };
}

// CSS: 52rem=832px padding, 42rem=672px rail/top navigation, 24rem=384px
// phone padding, 20rem=320px stacked actions. These are CLIENT viewports only.
export const galleryCases: readonly GalleryCase[] = [
  row('desktop-empty-980', 'desktop-empty', 980, 740),
  row('desktop-unavailable-minimum-760', 'desktop-unavailable', 760, 580),
  row('desktop-running-980', 'desktop-running', 980, 740),
  row('desktop-running-dark-1280', 'desktop-running', 1280, 900, 'overview', 'dark'),
  row('desktop-devices-768', 'desktop-devices', 768, 900),
  row('desktop-devices-narrow-390', 'desktop-devices', 390, 844),
  row('desktop-history-980', 'desktop-history', 980, 740),
  row('desktop-top-nav-boundary-672', 'desktop-empty', 672, 760),
  row('desktop-rail-boundary-673', 'desktop-empty', 673, 760),
  row('phone-empty-390', 'phone-empty', 390, 844),
  row('phone-history-390', 'phone-history', 390, 844),
  row('phone-history-empty-390', 'phone-history-empty', 390, 844),
  row('phone-unavailable-390', 'phone-unavailable', 390, 844),
  row('phone-pending-390', 'phone-pending', 390, 844),
  row('phone-terminal-390', 'phone-terminal', 390, 844, 'details'),
  row('phone-pending-landscape-844', 'phone-pending', 844, 390),
  row('phone-details-dark-390', 'phone-pending', 390, 844, 'details', 'dark'),
  row('phone-hostile-long-text-390', 'phone-long-request', 390, 844, 'long-details'),
  row('phone-weekly-schedule-390', 'phone-settings', 390, 844, 'schedule'),
  row('phone-padding-boundary-384', 'phone-settings', 384, 844, 'schedule'),
  row('phone-stacked-boundary-320', 'phone-settings', 320, 740, 'schedule'),
  row('phone-deny-keyboard-simulated-390', 'phone-pending', 390, 844, 'deny'),
  row('phone-lock-missing-390', 'phone-lock-missing', 390, 844),
  row('phone-lock-unknown-390', 'phone-lock-unknown', 390, 844),
  row('phone-notifications-denied-390', 'phone-notifications-denied', 390, 844, 'notification-settings'),
  row('phone-notifications-narrow-320', 'phone-notifications-denied', 320, 740, 'notification-settings'),
  row('phone-owner-error-390', 'errors', 390, 844),
  row('desktop-dialog-keyboard-forced-colors-760', 'desktop-devices', 760, 580, 'dialog', 'light', 'active'),
  row('phone-draft-keyboard-cancel-390', 'phone-settings', 390, 844, 'draft'),
  ...phoneServiceGalleryCases,
];
