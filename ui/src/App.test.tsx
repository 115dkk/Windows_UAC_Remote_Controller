// SPDX-License-Identifier: GPL-2.0-or-later
// Client tests use explicitly synthetic data. They do not exercise Windows/Android owners.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge } from './contracts';
import { ko } from './messages.ko';
import { createQaBridge, exampleSnapshot, qaCase } from './qa-fixtures';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((accept, fail) => { resolve = accept; reject = fail; });
  return { promise, resolve, reject };
}

function bridgeFor(snapshot: AppSnapshot, overrides: Partial<ControllerBridge> = {}): ControllerBridge {
  return { ...createQaBridge(snapshot), ...overrides };
}

describe('native snapshot truth in the client', () => {
  it('starts with neutral loading, not a missing-lock warning', async () => {
    const pending = deferred<AppSnapshot>();
    const bridge = bridgeFor(exampleSnapshot('android'), { snapshot: () => pending.promise });
    render(<App bridge={bridge} />);
    expect(screen.getByRole('heading', { name: ko.loadingTitle })).toBeInTheDocument();
    expect(screen.queryByText(ko.lockMissing)).not.toBeInTheDocument();
    await act(async () => { pending.resolve(exampleSnapshot('android')); await pending.promise; });
    expect(await screen.findByRole('heading', { name: ko.requestEmpty })).toBeInTheDocument();
    expect(screen.queryByText(ko.lockMissing)).not.toBeInTheDocument();
    expect(screen.queryByText(ko.lockUnknown)).not.toBeInTheDocument();
  });

  it('does not make unavailable data into empty data or enabled placeholder navigation', async () => {
    const snapshot = qaCase('desktop-unavailable').snapshot;
    render(<App bridge={bridgeFor(snapshot)} />);
    expect(await screen.findByRole('heading', { name: ko.serviceMissing })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.phones })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.activity })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.pairPhone })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '서비스 설치' })).not.toBeInTheDocument();
    expect(screen.queryByText(ko.noPhones)).not.toBeInTheDocument();
    expect(screen.getByText(ko.devicesUnavailableBody)).toBeInTheDocument();
  });

  it('does not equate a running service with remote readiness', async () => {
    render(<App bridge={bridgeFor(qaCase('desktop-running').snapshot)} />);
    expect(await screen.findByRole('heading', { name: '서비스 실행 중' })).toBeInTheDocument();
    expect(screen.getByText(ko.remoteNotReady)).toBeInTheDocument();
    expect(screen.queryByText(ko.remoteReady)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: '서비스 시작' })).not.toBeInTheDocument();
  });

  it('offers lock setup only for an explicitly missing lock with native capability', async () => {
    const openLockSettings = vi.fn<ControllerBridge['openLockSettings']>(() => Promise.resolve());
    const bridge = bridgeFor(qaCase('phone-lock-missing').snapshot, { openLockSettings });
    const user = userEvent.setup();
    render(<App bridge={bridge} />);
    await user.click(await screen.findByRole('button', { name: ko.openLockSettings }));
    expect(openLockSettings).toHaveBeenCalledOnce();
    expect(await screen.findByText(ko.returnFromSettings)).toBeInTheDocument();
  });

  it('explains unknown readiness without asking a configured user to create a lock', async () => {
    render(<App bridge={bridgeFor(qaCase('phone-lock-unknown').snapshot)} />);
    expect(await screen.findByRole('heading', { name: ko.lockUnknown })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.openLockSettings })).not.toBeInTheDocument();
    expect(screen.queryByText(ko.lockMissingBody)).not.toBeInTheDocument();
  });

  it('shows native cancellation copy without raw codes or fabricated success', async () => {
    const user = userEvent.setup();
    const snapshot = qaCase('phone-pending').snapshot;
    const bridge = bridgeFor(snapshot, { decide: vi.fn(() => Promise.resolve({ ...snapshot, issue: { code: 'RAW_NATIVE_CANCEL_0123', message: '본인 확인을 취소했어요.', nextAction: '승인하려면 다시 선택해 주세요.' } })) });
    render(<App bridge={bridge} />);
    await user.click(await screen.findByRole('button', { name: ko.approve }));
    expect(await screen.findByText('본인 확인을 취소했어요.')).toBeInTheDocument();
    expect(screen.queryByText('RAW_NATIVE_CANCEL_0123')).not.toBeInTheDocument();
    expect(screen.queryByText('요청 승인됨')).not.toBeInTheDocument();
  });

  it('uses fixed Korean recovery for unexpected bridge exceptions', async () => {
    render(<App bridge={bridgeFor(exampleSnapshot(), { snapshot: () => Promise.reject(new Error('INTERNAL_CODE C:\\private-path stack trace')) })} />);
    expect(await screen.findByRole('heading', { name: ko.unexpectedTitle })).toBeInTheDocument();
    expect(screen.getByText(ko.loadFailure)).toBeInTheDocument();
    expect(screen.queryByText(/INTERNAL_CODE/)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.refresh })).toBeEnabled();
  });
});

describe('request interaction boundaries', () => {
  it('reveals untrusted details as inert text and respects per-decision availability', async () => {
    const user = userEvent.setup();
    const fixture = qaCase('phone-pending').snapshot;
    const unsafeText = '<img src=x onerror="alert(1)"><script>exampleOnly()</script>';
    const snapshot = { ...fixture, requests: fixture.requests.map((request) => ({ ...request, details: unsafeText, canApprove: false })) };
    const decide = vi.fn<ControllerBridge['decide']>(() => Promise.resolve(snapshot));
    const bridge = bridgeFor(snapshot, { decide });
    const { container } = render(<App bridge={bridge} />);
    expect(await screen.findByRole('button', { name: ko.approve })).toBeDisabled();
    expect(screen.getByRole('button', { name: ko.deny })).toBeEnabled();
    expect(screen.queryByText(unsafeText)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.details }));
    expect(screen.getByRole('button', { name: ko.fewerDetails })).toHaveAttribute('aria-expanded', 'true');
    expect(screen.getByRole('region', { name: ko.commandDetails })).toHaveTextContent(unsafeText);
    expect(container.querySelector('img')).toBeNull();
    expect(container.querySelector('script')).toBeNull();
    await user.click(screen.getByRole('button', { name: ko.deny }));
    expect(decide).toHaveBeenCalledWith('synthetic-request-1', 'deny');
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });

  it('suppresses duplicate decisions and ignores an older refresh result', async () => {
    const user = userEvent.setup();
    const initial = qaCase('phone-pending').snapshot;
    const oldRead = deferred<AppSnapshot>();
    const decision = deferred<AppSnapshot>();
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(initial).mockImplementation(() => oldRead.promise);
    const decide = vi.fn<ControllerBridge['decide']>(() => decision.promise);
    render(<App bridge={bridgeFor(initial, { snapshot: read, decide })} />);
    const approve = await screen.findByRole('button', { name: ko.approve });
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    fireEvent.click(approve);
    fireEvent.click(approve);
    expect(decide).toHaveBeenCalledOnce();
    expect(approve).toBeDisabled();
    const confirmed = { ...initial, requests: [] };
    await act(async () => { decision.resolve(confirmed); await decision.promise; });
    expect(await screen.findByRole('heading', { name: ko.requestEmpty })).toBeInTheDocument();
    await act(async () => { oldRead.resolve(initial); await oldRead.promise; });
    expect(screen.queryByRole('button', { name: ko.approve })).not.toBeInTheDocument();
  });

  it('preserves a labelled stale snapshot and disables mutations after refresh failure', async () => {
    const user = userEvent.setup();
    const initial = qaCase('phone-pending').snapshot;
    const snapshot = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(initial).mockRejectedValue(new Error('network internals'));
    render(<App bridge={bridgeFor(initial, { snapshot })} />);
    await screen.findByRole('button', { name: ko.approve });
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(await screen.findByText(ko.stale)).toBeInTheDocument();
    expect(screen.getByText('설정 도우미.exe')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.approve })).toBeDisabled();
    expect(screen.getByRole('button', { name: ko.deny })).toBeDisabled();
  });

  it('ignores a previous bridge response after a new bridge takes ownership', async () => {
    const firstRead = deferred<AppSnapshot>();
    const firstBridge = bridgeFor(exampleSnapshot(), { snapshot: () => firstRead.promise });
    const secondSnapshot = { ...exampleSnapshot(), computerName: '새 화면 예시 PC' };
    const secondBridge = bridgeFor(secondSnapshot);
    const view = render(<App bridge={firstBridge} />);
    await act(async () => { await Promise.resolve(); });
    view.rerender(<App bridge={secondBridge} />);
    expect(await screen.findByText('새 화면 예시 PC')).toBeInTheDocument();
    await act(async () => { firstRead.resolve({ ...exampleSnapshot(), computerName: '이전 화면 예시 PC' }); await firstRead.promise; });
    expect(screen.queryByText('이전 화면 예시 PC')).not.toBeInTheDocument();
  });
});

describe('destructive action confirmation', () => {
  it('supports cancel, Escape, focus return and a single confirmed service command', async () => {
    const user = userEvent.setup();
    const snapshot = qaCase('desktop-running').snapshot;
    const pending = deferred<AppSnapshot>();
    const controlService = vi.fn<ControllerBridge['controlService']>(() => pending.promise);
    render(<App bridge={bridgeFor(snapshot, { controlService })} />);
    const stop = await screen.findByRole('button', { name: '서비스 중지' });
    await user.click(stop);
    let dialog = screen.getByRole('dialog');
    expect(within(dialog).getByRole('button', { name: ko.cancel })).toHaveFocus();
    await user.click(within(dialog).getByRole('button', { name: ko.cancel }));
    expect(stop).toHaveFocus();
    expect(controlService).not.toHaveBeenCalled();
    await user.click(stop);
    dialog = screen.getByRole('dialog');
    fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(stop).toHaveFocus();
    await user.click(stop);
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '서비스 중지' }));
    expect(controlService).toHaveBeenCalledExactlyOnceWith('stop');
    expect(stop).toBeDisabled();
    await act(async () => { pending.resolve({ ...snapshot, service: { installed: true, state: 'stopped', allowedActions: ['start'], controlHint: 'available', remoteRequestsReady: false } }); await pending.promise; });
    await waitFor(() => { expect(screen.getByRole('button', { name: '서비스 시작' })).toBeEnabled(); });
  });
});
