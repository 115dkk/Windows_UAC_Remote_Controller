// SPDX-License-Identifier: GPL-2.0-or-later
import type { GalleryCase } from './cases';
import type { GalleryLocale } from './i18n-cases';

export type FeedbackKind = 'decision' | 'connection' | 'firewall';
export interface FeedbackCase extends GalleryCase {
  readonly locale: GalleryLocale;
  readonly kind: FeedbackKind;
  /** Client clock jump after the first observation; synthetic elapsed time only. */
  readonly clockMillis?: readonly number[];
  readonly motion?: true;
}
function row(kind: FeedbackKind, id: string, fixture: string, width: number, options: {
  readonly locale?: GalleryLocale; readonly height?: number; readonly large?: boolean; readonly colorScheme?: 'light' | 'dark';
  readonly forcedColors?: 'none' | 'active'; readonly clockMillis?: readonly number[]; readonly motion?: true;
} = {}): FeedbackCase {
  return { id, kind, fixture, locale: options.locale ?? 'ko', viewport: { width, height: options.height ?? 844 }, action: 'overview',
    colorScheme: options.colorScheme ?? 'light', forcedColors: options.forcedColors ?? 'none',
    ...(options.large ? { rootTextSizePercent: 200 as const } : {}),
    ...(options.clockMillis ? { clockMillis: options.clockMillis } : {}), ...(options.motion ? { motion: true as const } : {}) };
}

export const decisionPhases = ['authenticating', 'preparing', 'sending', 'awaiting-pc', 'authentication-cancelled',
  'approved', 'denied', 'failed', 'cancelled', 'expired', 'pc-completed', 'local-unconfirmed'] as const;
const past = 61_000;

// CLIENT/SYNTHETIC decision receipts and connection states. No native decision,
// PC result, dial, firewall prompt or elapsed real time is represented.
export const feedbackCases: readonly FeedbackCase[] = [
  ...decisionPhases.map(phase => row('decision', `decision-${phase}-390`, `phone-decision-${phase}`, 390)),
  row('decision', 'decision-approved-dark-390', 'phone-decision-approved', 390, { colorScheme: 'dark' }),
  row('decision', 'decision-failed-forced-320', 'phone-decision-failed', 320, { forcedColors: 'active' }),
  row('decision', 'decision-awaiting-pc-text-200-390', 'phone-decision-awaiting-pc', 390, { large: true, height: 1000 }),
  row('decision', 'decision-local-unconfirmed-de-320', 'phone-decision-local-unconfirmed', 320, { locale: 'de' }),
  row('decision', 'decision-cancelled-ar-390', 'phone-decision-cancelled', 390, { locale: 'ar' }),
  row('decision', 'decision-reissued-390', 'phone-decision-reissued', 390),
  row('decision', 'decision-reissued-de-320', 'phone-decision-reissued', 320, { locale: 'de' }),
  row('connection', 'connection-connecting-390', 'phone-connection-connecting', 390),
  row('connection', 'connection-connecting-motion-390', 'phone-connection-connecting', 390, { motion: true }),
  row('connection', 'connection-reconnecting-390', 'phone-connection-reconnecting', 390),
  row('connection', 'connection-refused-390', 'phone-connection-refused', 390, { clockMillis: [past] }),
  row('connection', 'connection-no-answer-390', 'phone-connection-no-answer', 390, { clockMillis: [past] }),
  row('connection', 'connection-unreachable-390', 'phone-connection-unreachable', 390, { clockMillis: [past] }),
  row('connection', 'connection-unreachable-route-390', 'phone-connection-unreachable-route', 390, { clockMillis: [past] }),
  row('connection', 'connection-unknown-390', 'phone-disconnected', 390, { clockMillis: [past] }),
  row('connection', 'connection-dialing-390', 'phone-connection-dialing', 390, { clockMillis: [past, 60_000] }),
  row('connection', 'connection-unreachable-dark-320', 'phone-connection-unreachable', 320, { colorScheme: 'dark', clockMillis: [past] }),
  row('connection', 'connection-unreachable-text-200-390', 'phone-connection-unreachable', 390, { large: true, height: 1000, clockMillis: [past] }),
  row('connection', 'connection-unreachable-de-320', 'phone-connection-unreachable', 320, { locale: 'de', clockMillis: [past] }),
  row('connection', 'connection-unreachable-ar-390', 'phone-connection-unreachable', 390, { locale: 'ar', clockMillis: [past] }),
  row('firewall', 'firewall-paired-offline-980', 'desktop-status-phone-offline', 980, { height: 900 }),
  row('firewall', 'firewall-paired-offline-network-760', 'desktop-network-auto-no-mapping', 760, { height: 900 }),
  row('firewall', 'firewall-connected-980', 'desktop-connected', 980, { height: 900 }),
  row('firewall', 'firewall-unpaired-network-760', 'desktop-relay-listening', 760, { height: 900 }),
];
