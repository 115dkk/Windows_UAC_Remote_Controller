// SPDX-License-Identifier: GPL-2.0-or-later
import { useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { AlertMode, NotificationPolicy, Schedule } from './contracts';
import { Icon } from './icons';
import { alertModeText, ko, timeWindowLabel, weekdayOptions } from './messages.ko';
import { draftFromPolicy, parseDraft, samePolicy, timeToMinute } from './policy-draft';
import type { DraftErrors, PolicyDraft, WindowDraft } from './policy-draft';

export function PolicyEditor({ policy, available, unavailableTitle = ko.policyUnavailableTitle, unavailableBody = ko.policyUnavailableBody, disabled, saving, onSave }: {
  policy: NotificationPolicy | null; available: boolean; unavailableTitle?: string; unavailableBody?: string; disabled: boolean; saving: boolean;
  onSave: (policy: NotificationPolicy) => Promise<NotificationPolicy | null>;
}) {
  // A null draft follows refreshed native settings. A real draft never gets overwritten by a refresh.
  const [draft, setDraft] = useState<PolicyDraft | null>(null);
  const [errors, setErrors] = useState<DraftErrors>({ windows: {} });
  const [notice, setNotice] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const nextId = useRef(0);
  const composing = useRef(false);
  const submitLock = useRef(false);
  const form = useRef<HTMLFormElement>(null);
  const id = useId();
  const value = draft ?? (policy === null ? null : draftFromPolicy(policy));
  const parsed = value === null ? null : parseDraft(value);
  const dirty = parsed !== null && (parsed.policy === null || policy === null || !samePolicy(parsed.policy, policy));
  const busy = saving || submitting;

  function edit(next: PolicyDraft) {
    setDraft(next);
    setNotice(null);
    setErrors({ windows: {} });
  }
  function freshWindow(): WindowDraft {
    return { id: `draft-${String(nextId.current++)}`, days: 0, start: '09:00', end: '18:00', endOfDay: false };
  }
  function selectMode(mode: Schedule['mode']) {
    if (value === null) return;
    edit({ ...value, mode, windows: mode === 'weekly' && !value.windows.length ? [freshWindow()] : value.windows });
  }
  function changeWindow(windowId: string, patch: Partial<WindowDraft>) {
    if (value === null) return;
    edit({ ...value, windows: value.windows.map((window) => window.id === windowId ? { ...window, ...patch } : window) });
  }
  async function saveDraft() {
    if (disabled || !available || policy === null || value === null || submitLock.current || !dirty || composing.current) return;
    const result = parseDraft(value);
    setErrors(result.errors);
    if (!result.policy) {
      queueMicrotask(() => form.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    submitLock.current = true;
    setSubmitting(true);
    setNotice(null);
    try {
      const confirmed = await onSave(result.policy);
      if (confirmed && samePolicy(confirmed, result.policy)) {
        setDraft(null);
        setNotice(ko.saved);
      } else if (confirmed) {
        setNotice(ko.saveFailure);
      }
    } catch {
      // Injected/test bridges may throw too. Never expose exception text or discard the draft.
      setNotice(ko.saveFailure);
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (!composing.current) void saveDraft();
  }

  // Stay mounted across transient unavailability, but render no stale/default
  // policy controls. The memory-only draft remains until this client is closed.
  if (policy === null || !available || value === null) return <section className="notice-box" role="status" aria-labelledby={`${id}-unavailable`}>
    <Icon name="clock" /><div><h2 id={`${id}-unavailable`}>{unavailableTitle}</h2><p>{unavailableBody}</p>{draft !== null && <p className="supporting-text">{ko.policyDraftKept}</p>}</div>
  </section>;

  return <form ref={form} className="policy-form" onSubmit={submit} noValidate
    onCompositionStart={() => { composing.current = true; }} onCompositionEnd={() => { composing.current = false; }}
    onKeyDown={(event) => { if (event.key === 'Enter' && (event.nativeEvent.isComposing || composing.current)) event.preventDefault(); }}>
    <fieldset className="surface form-section" disabled={busy}>
      <legend>{ko.scheduleWhen}</legend>
      <div className="schedule-modes">{([
        ['always', ko.always, ko.alwaysDescription], ['never', ko.never, ko.neverDescription], ['weekly', ko.weekly, ko.weeklyDescription],
      ] as const).map(([mode, label, description]) => <label key={mode} className={`radio-option ${value.mode === mode ? 'selected' : ''}`}><input type="radio" name={`${id}-schedule`} value={mode} checked={value.mode === mode} aria-labelledby={`${id}-schedule-${mode}-title`} aria-describedby={`${id}-schedule-${mode}-description`} onChange={() => selectMode(mode)} /><span><span id={`${id}-schedule-${mode}-title`} className="option-title">{label}</span><span id={`${id}-schedule-${mode}-description`} className="option-description">{description}</span></span></label>)}</div>
      {value.mode === 'weekly' && <div className="weekly-windows">
        {value.windows.map((window, index) => {
          const windowErrors = errors.windows[window.id];
          const start = timeToMinute(window.start);
          const end = window.endOfDay ? 1440 : timeToMinute(window.end);
          const nextDay = start !== null && end !== null && end < start;
          const fieldId = `${id}-${window.id}`;
          return <fieldset className="time-window" key={window.id}><legend>{timeWindowLabel(index)}</legend>
            <div className="window-heading"><span>{ko.weekdays}</span><button type="button" className="button quiet" aria-label={`${timeWindowLabel(index)} ${ko.removeWindow}`} onClick={() => edit({ ...value, windows: value.windows.filter((item) => item.id !== window.id) })}>{ko.removeWindow}</button></div>
            <div className="weekday-list" role="group" aria-label={`${timeWindowLabel(index)} ${ko.weekdays}`}>{weekdayOptions.map((day) => <label className={`weekday-chip ${window.days & day.bit ? 'selected' : ''}`} key={day.bit}><input type="checkbox" aria-label={day.label} checked={Boolean(window.days & day.bit)} aria-invalid={Boolean(windowErrors?.days)} aria-describedby={windowErrors?.days ? `${fieldId}-days-error` : undefined} onChange={() => changeWindow(window.id, { days: window.days ^ day.bit })} /><span>{day.short}</span></label>)}</div>
            {windowErrors?.days && <p className="field-error" id={`${fieldId}-days-error`}>{windowErrors.days}</p>}
            <div className="time-fields"><label htmlFor={`${fieldId}-start`}><span>{ko.startTime}</span><input id={`${fieldId}-start`} type="time" step="60" value={window.start} aria-invalid={Boolean(windowErrors?.time)} aria-describedby={windowErrors?.time ? `${fieldId}-time-error` : undefined} onChange={(event) => changeWindow(window.id, { start: event.target.value })} /></label><span className="time-separator" aria-hidden="true">—</span><label htmlFor={`${fieldId}-end`}><span>{ko.endTime}</span><input id={`${fieldId}-end`} type="time" step="60" value={window.endOfDay ? '00:00' : window.end} disabled={window.endOfDay} aria-invalid={Boolean(windowErrors?.time)} aria-describedby={windowErrors?.time ? `${fieldId}-time-error` : nextDay ? `${fieldId}-next-day` : undefined} onChange={(event) => changeWindow(window.id, { end: event.target.value })} /></label></div>
            <label className="end-of-day"><input type="checkbox" checked={window.endOfDay} onChange={(event) => changeWindow(window.id, { endOfDay: event.target.checked })} /><span>{ko.endOfDay}</span></label>
            {nextDay && <p className="next-day supporting-text" id={`${fieldId}-next-day`}>{ko.nextDay}</p>}
            {windowErrors?.time && <p className="field-error" id={`${fieldId}-time-error`}>{windowErrors.time}</p>}
          </fieldset>;
        })}
        {errors.summary && <p className="field-error" role="alert">{errors.summary}</p>}
        <button type="button" className="button secondary add-window" onClick={() => edit({ ...value, windows: [...value.windows, freshWindow()] })}><Icon name="plus" />{ko.addWindow}</button>
        <p className="supporting-text schedule-boundary">{ko.scheduleBoundary}</p>
      </div>}
    </fieldset>
    <fieldset className="surface form-section" disabled={busy}><legend>{ko.alertMode}</legend><div className="alert-modes">{(['sound', 'vibrate_only', 'silent'] as const).map((mode: AlertMode) => <label className={`alert-option ${value.alert === mode ? 'selected' : ''}`} key={mode}><input type="radio" name={`${id}-alert`} checked={value.alert === mode} aria-labelledby={`${id}-alert-${mode}-title`} aria-describedby={`${id}-alert-description`} onChange={() => edit({ ...value, alert: mode })} /><span id={`${id}-alert-${mode}-title`}>{alertModeText[mode]}</span></label>)}</div><p id={`${id}-alert-description`} className="supporting-text">{ko.alertDescription}</p></fieldset>
    <div className="policy-footer"><p className="draft-status" role="status" aria-live="polite">{notice ?? (dirty ? ko.dirty : '')}</p><div className="form-actions"><button type="button" className="button secondary" disabled={!dirty || busy} onClick={() => { setDraft(null); setErrors({ windows: {} }); setNotice(ko.cancelledDraft); }}>{ko.cancel}</button><button type="submit" className="button primary" disabled={!dirty || disabled || busy}>{busy ? ko.saving : ko.save}</button></div></div>
  </form>;
}
