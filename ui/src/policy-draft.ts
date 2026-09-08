// SPDX-License-Identifier: GPL-2.0-or-later
import type { AlertMode, NotificationPolicy, Schedule } from './contracts';
import { ko } from './messages.ko';

export interface WindowDraft { readonly id: string; readonly days: number; readonly start: string; readonly end: string; readonly endOfDay: boolean }
export interface PolicyDraft { readonly mode: Schedule['mode']; readonly alert: AlertMode; readonly windows: readonly WindowDraft[] }
export interface DraftErrors { readonly summary?: string; readonly windows: Readonly<Record<string, { days?: string; time?: string }>> }

function minuteToTime(minute: number): string {
  return `${String(Math.floor(minute / 60)).padStart(2, '0')}:${String(minute % 60).padStart(2, '0')}`;
}

export function timeToMinute(time: string): number | null {
  if (!/^([01]\d|2[0-3]):[0-5]\d$/.test(time)) return null;
  const [hours, minutes] = time.split(':');
  return Number(hours) * 60 + Number(minutes);
}

export function draftFromPolicy(policy: NotificationPolicy): PolicyDraft {
  return { mode: policy.schedule.mode, alert: policy.alert, windows: policy.schedule.mode === 'weekly'
    ? policy.schedule.windows.map((window, index) => ({ id: `saved-${String(index)}`, days: window.days, start: minuteToTime(window.start_minute), end: minuteToTime(window.end_minute === 1440 ? 0 : window.end_minute), endOfDay: window.end_minute === 1440 })) : [] };
}

// Format feedback only: overlap, schedule semantics, applicability and persistence belong to Rust.
export function parseDraft(draft: PolicyDraft): { policy: NotificationPolicy | null; errors: DraftErrors } {
  if (draft.mode !== 'weekly') return { policy: { schedule: { mode: draft.mode }, alert: draft.alert }, errors: { windows: {} } };
  const errors: Record<string, { days?: string; time?: string }> = {};
  const windows = draft.windows.flatMap((window) => {
    const start = timeToMinute(window.start);
    const end = window.endOfDay ? 1440 : timeToMinute(window.end);
    const windowErrors: { days?: string; time?: string } = {};
    if (!window.days) windowErrors.days = ko.daysRequired;
    if (start === null || end === null) windowErrors.time = ko.timeRequired;
    if (Object.keys(windowErrors).length) errors[window.id] = windowErrors;
    return start !== null && end !== null ? [{ days: window.days, start_minute: start, end_minute: end }] : [];
  });
  if (!draft.windows.length) return { policy: null, errors: { summary: ko.windowRequired, windows: {} } };
  if (Object.keys(errors).length) return { policy: null, errors: { windows: errors } };
  return { policy: { schedule: { mode: 'weekly', windows }, alert: draft.alert }, errors: { windows: {} } };
}

export function samePolicy(first: NotificationPolicy, second: NotificationPolicy): boolean {
  if (first.alert !== second.alert || first.schedule.mode !== second.schedule.mode) return false;
  if (first.schedule.mode !== 'weekly' || second.schedule.mode !== 'weekly') return true;
  const secondWindows = second.schedule.windows;
  return first.schedule.windows.length === secondWindows.length && first.schedule.windows.every((window, index) => {
    const other = secondWindows[index];
    return other?.days === window.days && other.start_minute === window.start_minute && other.end_minute === window.end_minute;
  });
}
