// SPDX-License-Identifier: GPL-2.0-or-later
// Client tests use explicitly synthetic data. They do not exercise Windows/Android owners.
import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, ServiceAction } from './contracts';
import { ko, serviceActionText, serviceStateText } from './messages.ko';
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
const serviceActions: readonly ServiceAction[] = ['install', 'start', 'restart', 'stop', 'uninstall'];

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
    expect(screen.queryByRole('button', { name: serviceActionText.install })).not.toBeInTheDocument();
    expect(screen.queryByText(ko.noPhones)).not.toBeInTheDocument();
    expect(screen.getByText(ko.devicesUnavailableBody)).toBeInTheDocument();
  });

  it('does not equate a running service with remote readiness', async () => {
    render(<App bridge={bridgeFor(qaCase('desktop-running').snapshot)} />);
    expect(await screen.findByRole('heading', { name: '휴대폰 승인 켜짐' })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: 'PC 승인을 휴대폰에서' })).toBeInTheDocument();
    expect(screen.getByText(ko.homePurpose)).toBeInTheDocument();
    expect(screen.getByText('이 PC에서 실행')).toBeInTheDocument();
    expect(screen.getByText(ko.remoteNotReady)).toBeInTheDocument();
    expect(screen.getByText('지금은 PC의 관리자 권한 창에서 직접 선택해 주세요.')).toBeInTheDocument();
    expect(screen.queryByText(ko.remoteReady)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: serviceActionText.start })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /서비스/u })).not.toBeInTheDocument();
    expect(screen.queryByText(/서비스/u)).not.toBeInTheDocument();
  });

  it('uses the separate native readiness flag, not the renamed on state', async () => {
    const fixture = qaCase('desktop-running').snapshot;
    const ready: AppSnapshot = { ...fixture, service: { ...fixture.service!, remoteRequestsReady: true } };
    render(<App bridge={bridgeFor(ready)} />);
    expect(await screen.findByText(ko.remoteReady)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: serviceStateText.running })).toBeInTheDocument();
    expect(screen.getByText(ko.remoteReadyBody)).toBeInTheDocument();
    expect(screen.queryByText(ko.remoteNotReady)).not.toBeInTheDocument();
    expect(screen.queryByText(ko.serviceRunningBody)).not.toBeInTheDocument();
  });

  it.each(serviceActions)('renames %s without adding an action beyond the native list', async (action) => {
    const snapshot: AppSnapshot = { ...exampleSnapshot(), service: {
      installed: action !== 'install', state: action === 'install' ? null : action === 'start' ? 'stopped' : 'running',
      allowedActions: [action], controlHint: 'available', remoteRequestsReady: false,
    } };
    render(<App bridge={bridgeFor(snapshot)} />);
    expect(await screen.findByRole('button', { name: serviceActionText[action] })).toBeEnabled();
    for (const other of (['install', 'start', 'restart', 'stop', 'uninstall'] as const).filter((item) => item !== action)) {
      expect(screen.queryByRole('button', { name: serviceActionText[other] })).not.toBeInTheDocument();
    }
    expect(screen.getByRole('heading', { level: 1, name: ko.homeTitle })).toBeInTheDocument();
    expect(screen.getByText(ko.remoteNotReady)).toBeInTheDocument();
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
    expect(screen.queryByRole('button', { name: ko.openNotificationSettings })).not.toBeInTheDocument();
  });

  it('opens notification settings once without claiming the permission was granted', async () => {
    const pending = deferred<void>();
    const openNotificationSettings = vi.fn<ControllerBridge['openNotificationSettings']>(() => pending.promise);
    const fixture = qaCase('phone-notifications-denied');
    const user = userEvent.setup();
    render(<App bridge={bridgeFor(fixture.snapshot, { openNotificationSettings })} initialPage={fixture.page} />);
    const button = await screen.findByRole('button', { name: ko.openNotificationSettings });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(openNotificationSettings).toHaveBeenCalledOnce();
    expect(button).toBeDisabled();
    await act(async () => { pending.resolve(); await pending.promise; });
    expect(await screen.findByText(ko.returnFromSettings)).toBeInTheDocument();
    expect(screen.getByRole('heading', { name: ko.notificationsDenied })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(screen.getByRole('heading', { name: ko.notificationsDenied })).toBeInTheDocument();
  });

  it('keeps manual notification directions when the native settings destination is unavailable', async () => {
    const fixture = qaCase('phone-notifications-denied');
    const snapshot = { ...fixture.snapshot, mobile: { ...fixture.snapshot.mobile!, canOpenNotificationSettings: false } };
    render(<App bridge={bridgeFor(snapshot)} initialPage={fixture.page} />);
    expect(await screen.findByText(ko.notificationsDeniedBody)).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.openNotificationSettings })).not.toBeInTheDocument();
  });

  it('reports a failed settings handoff without exposing a native exception', async () => {
    const fixture = qaCase('phone-notifications-denied');
    const openNotificationSettings = () => Promise.reject(new Error('RAW_SETTINGS_COMPONENT synthetic-private-detail'));
    const user = userEvent.setup();
    render(<App bridge={bridgeFor(fixture.snapshot, { openNotificationSettings })} initialPage={fixture.page} />);
    await user.click(await screen.findByRole('button', { name: ko.openNotificationSettings }));
    expect(await screen.findByText(ko.actionFailure)).toBeInTheDocument();
    expect(screen.queryByText(/RAW_SETTINGS_COMPONENT/)).not.toBeInTheDocument();
    expect(screen.queryByText(ko.returnFromSettings)).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.openNotificationSettings })).toBeDisabled();
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
  it('preserves the service word when it belongs to original request or terminal text', async () => {
    const user = userEvent.setup();
    const fixture = qaCase('phone-pending').snapshot;
    const original = '서비스 확인.exe';
    const path = 'C:\\서비스 원문\\서비스 확인.exe';
    const details = 'Write-Output "서비스 원문 그대로"';
    const snapshot = { ...fixture, requests: fixture.requests.map((request) => ({ ...request, programName: original, executablePath: path, details })) };
    render(<App bridge={bridgeFor(snapshot)} />);
    expect(await screen.findByRole('heading', { name: original })).toBeInTheDocument();
    expect(screen.getByText(path)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.details }));
    expect(screen.getByRole('region', { name: ko.commandDetails })).toHaveTextContent(details);
  });

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

  it('keeps recovery but withdraws request bodies and decisions after refresh failure', async () => {
    const user = userEvent.setup();
    const initial = qaCase('phone-pending').snapshot;
    const snapshot = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(initial).mockRejectedValue(new Error('network internals'));
    render(<App bridge={bridgeFor(initial, { snapshot })} />);
    await screen.findByRole('button', { name: ko.approve });
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(await screen.findByText(ko.stale)).toBeInTheDocument();
    expect(screen.queryByText('설정 도우미.exe')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.approve })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.deny })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: ko.requestUnavailable })).toBeInTheDocument();
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
  it('shows coarse PC completion without claiming approval and clears only after the owner confirms', async () => {
    const user = userEvent.setup();
    const fixture = qaCase('phone-history');
    const cleared = deferred<AppSnapshot>();
    const clearActivity = vi.fn<ControllerBridge['clearActivity']>(() => cleared.promise);
    render(<App bridge={bridgeFor(fixture.snapshot, { clearActivity })} initialPage={fixture.page} />);
    expect(await screen.findByRole('heading', { name: 'PC에서 요청 종료됨' })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: '요청 승인됨' })).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.clearActivity }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: ko.cancel }));
    expect(clearActivity).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: ko.clearActivity }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: ko.clearActivity }));
    expect(clearActivity).toHaveBeenCalledOnce();
    expect(screen.getByRole('heading', { name: 'PC에서 요청 종료됨' })).toBeInTheDocument();
    await act(async () => { cleared.resolve({ ...fixture.snapshot, activity: [], canClearActivity: false }); await cleared.promise; });
    expect(await screen.findByRole('heading', { name: ko.noActivity })).toBeInTheDocument();
  });

  it('supports cancel, Escape, focus return and a single confirmed service command', async () => {
    const user = userEvent.setup();
    const snapshot = qaCase('desktop-running').snapshot;
    const pending = deferred<AppSnapshot>();
    const controlService = vi.fn<ControllerBridge['controlService']>(() => pending.promise);
    render(<App bridge={bridgeFor(snapshot, { controlService })} />);
    const stop = await screen.findByRole('button', { name: serviceActionText.stop });
    await user.click(stop);
    let dialog = screen.getByRole('dialog');
    expect(dialog).toHaveTextContent('자동 실행 설정은 바뀌지 않아요.');
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
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: serviceActionText.stop }));
    expect(controlService).toHaveBeenCalledExactlyOnceWith('stop');
    expect(stop).toBeDisabled();
    await act(async () => { pending.resolve({ ...snapshot, service: { installed: true, state: 'stopped', allowedActions: ['start'], controlHint: 'available', remoteRequestsReady: false } }); await pending.promise; });
    await waitFor(() => { expect(screen.getByRole('button', { name: serviceActionText.start })).toBeEnabled(); });
  });

  it('explains that removing the PC connection feature leaves the settings app, and waits for the owner', async () => {
    const user = userEvent.setup();
    const snapshot = qaCase('desktop-running').snapshot;
    const pending = deferred<AppSnapshot>();
    const controlService = vi.fn<ControllerBridge['controlService']>(() => pending.promise);
    render(<App bridge={bridgeFor(snapshot, { controlService })} />);
    await user.click(await screen.findByRole('button', { name: 'PC 연결 기능 제거' }));
    const dialog = screen.getByRole('dialog', { name: 'PC 연결 기능을 제거할까요?' });
    expect(dialog).toHaveTextContent('PC에서 실행되는 휴대폰 승인 기능만 제거하고, 이 설정 앱은 남겨 둡니다.');
    expect(dialog).not.toHaveTextContent(/키|데이터|기록/u);
    expect(controlService).not.toHaveBeenCalled();
    await user.click(within(dialog).getByRole('button', { name: 'PC 연결 기능 제거' }));
    expect(controlService).toHaveBeenCalledExactlyOnceWith('uninstall');
    expect(screen.getByRole('heading', { name: serviceStateText.running })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'PC 연결 기능 제거' })).toBeDisabled();
    await act(async () => {
      pending.resolve({ ...snapshot, service: { installed: false, state: null, allowedActions: ['install'], controlHint: 'available', remoteRequestsReady: false } });
      await pending.promise;
    });
    expect(await screen.findByRole('heading', { name: ko.serviceMissing })).toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1, name: ko.homeTitle })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'PC 연결 기능 설치' })).toBeEnabled();
  });
});
