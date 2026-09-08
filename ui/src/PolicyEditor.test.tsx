// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic DOM tests only. Rust schedule policy and native persistence require separate proof.
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, NotificationPolicy } from './contracts';
import { ko } from './messages.ko';
import { PolicyEditor } from './PolicyEditor';
import { draftFromPolicy, parseDraft, samePolicy, timeToMinute } from './policy-draft';
import { createQaBridge, exampleSnapshot } from './qa-fixtures';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}

const defaultPolicy: NotificationPolicy = { schedule: { mode: 'always' }, alert: 'sound' };

describe('notification policy editor', () => {
  it('shows native Always/default, distinguishes Never, and announces only confirmed saving', async () => {
    const user = userEvent.setup();
    const pending = deferred<NotificationPolicy | null>();
    const save = vi.fn(() => pending.promise);
    const view = render(<PolicyEditor policy={defaultPolicy} disabled={false} saving={false} onSave={save} />);
    expect(screen.getByRole('radio', { name: ko.always })).toBeChecked();
    expect(screen.getByRole('radio', { name: ko.always })).toHaveAccessibleDescription(ko.alwaysDescription);
    expect(screen.getByRole('radio', { name: ko.never })).toHaveAccessibleDescription(ko.neverDescription);
    expect(screen.getByRole('radio', { name: ko.weekly })).toHaveAccessibleDescription(ko.weeklyDescription);
    expect(screen.getByRole('radio', { name: '소리' })).toHaveAccessibleDescription(ko.alertDescription);
    expect(screen.getByRole('radio', { name: '진동만' })).toHaveAccessibleDescription(ko.alertDescription);
    expect(screen.getByRole('radio', { name: '무음' })).toHaveAccessibleDescription(ko.alertDescription);
    expect(screen.getByRole('button', { name: ko.save })).toBeDisabled();
    await user.click(screen.getByRole('radio', { name: ko.never }));
    await user.click(screen.getByRole('button', { name: ko.save }));
    expect(save).toHaveBeenCalledExactlyOnceWith({ schedule: { mode: 'never' }, alert: 'sound' });
    expect(screen.queryByText(ko.saved)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.saving })).toBeDisabled();
    const confirmed: NotificationPolicy = { schedule: { mode: 'never' }, alert: 'sound' };
    await act(async () => { pending.resolve(confirmed); await pending.promise; });
    view.rerender(<PolicyEditor policy={confirmed} disabled={false} saving={false} onSave={save} />);
    expect(screen.getByRole('status')).toHaveTextContent(ko.saved);
    expect(screen.getByRole('button', { name: ko.save })).toBeDisabled();
  });

  it('maps weekday bits and numeric overnight/end-exclusive inputs without client policy decisions', async () => {
    const user = userEvent.setup();
    const save = vi.fn((policy: NotificationPolicy) => Promise.resolve(policy));
    render(<PolicyEditor policy={defaultPolicy} disabled={false} saving={false} onSave={save} />);
    await user.click(screen.getByRole('radio', { name: ko.weekly }));
    await user.click(screen.getByRole('checkbox', { name: '월요일' }));
    await user.click(screen.getByRole('checkbox', { name: '일요일' }));
    fireEvent.change(screen.getByLabelText(ko.startTime), { target: { value: '22:30' } });
    fireEvent.change(screen.getByLabelText(ko.endTime), { target: { value: '06:15' } });
    expect(screen.getByText(ko.nextDay)).toBeInTheDocument();
    await user.click(screen.getByRole('radio', { name: '진동만' }));
    await user.click(screen.getByRole('button', { name: ko.save }));
    expect(save).toHaveBeenCalledExactlyOnceWith({ schedule: { mode: 'weekly', windows: [{ days: 65, start_minute: 1350, end_minute: 375 }] }, alert: 'vibrate_only' });
  });

  it('validates basic input after submit and does not send an unfinished IME composition', async () => {
    const user = userEvent.setup();
    const save = vi.fn(() => Promise.resolve(null));
    const { container } = render(<PolicyEditor policy={defaultPolicy} disabled={false} saving={false} onSave={save} />);
    await user.click(screen.getByRole('radio', { name: ko.weekly }));
    expect(screen.queryByText(ko.daysRequired)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.save }));
    expect(screen.getByText(ko.daysRequired)).toBeInTheDocument();
    expect(save).not.toHaveBeenCalled();
    expect(screen.getByRole('checkbox', { name: '월요일' })).toHaveFocus();
    await user.click(screen.getByRole('checkbox', { name: '화요일' }));
    const form = container.querySelector('form');
    if (!form) throw new Error('Expected policy form');
    fireEvent.compositionStart(screen.getByLabelText(ko.startTime));
    fireEvent.submit(form);
    expect(save).not.toHaveBeenCalled();
    fireEvent.compositionEnd(screen.getByLabelText(ko.startTime));
    fireEvent.submit(form);
    await act(async () => { await Promise.resolve(); });
    expect(save).toHaveBeenCalledOnce();
  });

  it('preserves a dirty draft across background updates and restores latest native values on cancel', async () => {
    const user = userEvent.setup();
    const save = vi.fn(() => Promise.resolve(null));
    const view = render(<PolicyEditor policy={defaultPolicy} disabled={false} saving={false} onSave={save} />);
    await user.click(screen.getByRole('radio', { name: ko.never }));
    const refreshed: NotificationPolicy = { schedule: { mode: 'always' }, alert: 'silent' };
    view.rerender(<PolicyEditor policy={refreshed} disabled={false} saving={false} onSave={save} />);
    expect(screen.getByRole('radio', { name: ko.never })).toBeChecked();
    expect(screen.getByRole('radio', { name: '소리' })).toBeChecked();
    await user.click(screen.getByRole('button', { name: ko.cancel }));
    expect(screen.getByRole('radio', { name: ko.always })).toBeChecked();
    expect(screen.getByRole('radio', { name: '무음' })).toBeChecked();
  });

  it('preserves drafts after failure, rejects duplicate saves, and does not claim a mismatched result was saved', async () => {
    const user = userEvent.setup();
    const pending = deferred<NotificationPolicy | null>();
    const save = vi.fn(() => pending.promise);
    render(<PolicyEditor policy={defaultPolicy} disabled={false} saving={false} onSave={save} />);
    await user.click(screen.getByRole('radio', { name: '무음' }));
    const button = screen.getByRole('button', { name: ko.save });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(save).toHaveBeenCalledOnce();
    await act(async () => { pending.resolve(defaultPolicy); await pending.promise; });
    expect(screen.getByRole('radio', { name: '무음' })).toBeChecked();
    expect(screen.getByRole('status')).toHaveTextContent(ko.saveFailure);
    expect(screen.queryByText(ko.saved)).not.toBeInTheDocument();
  });

  it('keeps draft after real bridge failure and navigation, then permits retry after refresh', async () => {
    const user = userEvent.setup();
    const snapshot = exampleSnapshot('android');
    const qa = createQaBridge(snapshot);
    const savePolicy = vi.fn<ControllerBridge['savePolicy']>().mockRejectedValueOnce(new Error('private backend detail')).mockImplementation((policy) => Promise.resolve({ ...snapshot, policy }));
    const bridge = { ...qa, savePolicy };
    render(<App bridge={bridge} initialPage="schedule" />);
    await screen.findByRole('heading', { name: ko.schedule });
    await user.click(screen.getByRole('radio', { name: '무음' }));
    await user.click(screen.getByRole('button', { name: ko.save }));
    expect(await screen.findByText(ko.saveFailure)).toBeInTheDocument();
    expect(screen.queryByText('private backend detail')).not.toBeInTheDocument();
    expect(screen.getByRole('radio', { name: '무음' })).toBeChecked();
    expect(screen.getByRole('button', { name: ko.save })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: ko.requests }));
    await user.click(screen.getByRole('button', { name: ko.schedule }));
    expect(screen.getByRole('radio', { name: '무음' })).toBeChecked();
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    await screen.findByText(ko.updated);
    await user.click(screen.getByRole('button', { name: ko.save }));
    expect(await screen.findByText(ko.saved)).toBeInTheDocument();
    expect(savePolicy).toHaveBeenCalledTimes(2);
  });

  it('does not overwrite a draft when the App receives a new snapshot', async () => {
    const user = userEvent.setup();
    const snapshot = exampleSnapshot('android');
    const changed: AppSnapshot = { ...snapshot, policy: { schedule: { mode: 'never' }, alert: 'vibrate_only' } };
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot).mockResolvedValue(changed);
    render(<App bridge={{ ...createQaBridge(snapshot), snapshot: read }} initialPage="schedule" />);
    await screen.findByRole('heading', { name: ko.schedule });
    await user.click(screen.getByRole('radio', { name: '무음' }));
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    await screen.findByText(ko.updated);
    expect(screen.getByRole('radio', { name: ko.always })).toBeChecked();
    expect(screen.getByRole('radio', { name: '무음' })).toBeChecked();
  });
});

describe('policy draft formatting, not runtime authorization', () => {
  it('rejects incomplete time text and retains exact minute boundaries', () => {
    expect(timeToMinute('23:59')).toBe(1439);
    expect(timeToMinute('00:00')).toBe(0);
    expect(timeToMinute('24:00')).toBeNull();
    expect(timeToMinute('09:')).toBeNull();
    const policy: NotificationPolicy = { schedule: { mode: 'weekly', windows: [{ days: 127, start_minute: 123, end_minute: 123 }] }, alert: 'silent' };
    expect(parseDraft(draftFromPolicy(policy)).policy).toEqual(policy);
    expect(samePolicy({ alert: 'sound', schedule: { mode: 'always' } }, defaultPolicy)).toBe(true);
  });

  it('preserves Rust end_minute=1440 without an invalid HTML time value', async () => {
    const user = userEvent.setup();
    const policy: NotificationPolicy = { schedule: { mode: 'weekly', windows: [{ days: 1, start_minute: 0, end_minute: 1440 }] }, alert: 'sound' };
    const save = vi.fn((next: NotificationPolicy) => Promise.resolve(next));
    expect(parseDraft(draftFromPolicy(policy)).policy).toEqual(policy);
    render(<PolicyEditor policy={policy} disabled={false} saving={false} onSave={save} />);
    expect(screen.getByRole('checkbox', { name: ko.endOfDay })).toBeChecked();
    expect(screen.getByLabelText(ko.endTime)).toHaveValue('00:00');
    expect(screen.getByLabelText(ko.endTime)).toBeDisabled();
    expect(screen.getByRole('button', { name: ko.save })).toBeDisabled();
    await user.click(screen.getByRole('radio', { name: '무음' }));
    await user.click(screen.getByRole('button', { name: ko.save }));
    expect(save).toHaveBeenCalledExactlyOnceWith({ ...policy, alert: 'silent' });
  });
});
