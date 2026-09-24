// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic bridge rejections only. They model the shape of a Tauri command
// rejection carrying a serialized AppIssue, not a native owner's decision.
import { act, fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge } from './contracts';
import { setPreviewLanguage, tr } from './i18n';
import { ko } from './messages';
import { createQaBridge, exampleSnapshot, qaCase } from './qa-fixtures';
import { authoredIssue, useController } from './useController';

/** The exact JSON a Tauri command rejects with for `Err(AppIssue)`. */
const refusal = Object.freeze({
  code: 'invalid_external_address',
  message: '이 주소로는 외부에서 연결할 수 없습니다.',
  nextAction: '공유기 관리 페이지에 표시된 공인 IP와 포트를 입력하십시오.',
});

afterEach(() => {
  vi.useRealTimers();
  setPreviewLanguage('ko');
});

describe('authored refusal parsing', () => {
  it('accepts exactly a serialized AppIssue with catalogued copy', () => {
    expect(authoredIssue({ ...refusal })).toEqual({ message: refusal.message, nextAction: refusal.nextAction });
    expect(authoredIssue({ code: 'app_busy', message: '앱이 다른 작업을 처리하는 중입니다.', nextAction: null }))
      .toEqual({ message: '앱이 다른 작업을 처리하는 중입니다.', nextAction: null });
    expect(authoredIssue(JSON.parse(JSON.stringify(refusal)))).not.toBeNull();
  });

  it.each([
    ['a transport error', new Error('IPC connection lost')],
    ['a timeout', new Error('snapshot_timeout')],
    ['an Error carrying issue fields', Object.assign(new Error(refusal.message), { code: refusal.code, nextAction: refusal.nextAction })],
    ['a bare string', refusal.message],
    ['null', null],
    ['an array', [refusal.code, refusal.message, refusal.nextAction]],
    ['a missing nextAction', { code: refusal.code, message: refusal.message }],
    ['an extra field', { ...refusal, nativeStage: 3 }],
    ['an uncatalogued message', { ...refusal, message: 'RAW_NATIVE C:\\private\\path' }],
    ['an uncatalogued next action', { ...refusal, nextAction: 'call support at 555-0100' }],
    ['a prototype property as message', { ...refusal, message: 'constructor' }],
    ['a non-string message', { ...refusal, message: 42 }],
    ['a non-string next action', { ...refusal, nextAction: 7 }],
    ['an empty message', { ...refusal, message: '' }],
    ['a malformed code', { ...refusal, code: 'Invalid Code!' }],
    ['a class instance', Object.assign(Object.create({ inherited: true }) as object, refusal)],
  ])('falls back for %s', (_label, rejection) => {
    expect(authoredIssue(rejection)).toBeNull();
  });
});

describe('command rejections on screen', () => {
  async function saveFixedAddress(bridge: ControllerBridge) {
    const user = userEvent.setup();
    render(<App bridge={bridge} initialPage="network" />);
    await user.click(await screen.findByRole('radio', { name: '외부 주소 직접 입력' }));
    fireEvent.change(screen.getByRole('textbox', { name: '외부 주소' }), { target: { value: '1.2.3.4:7443' } });
    await user.click(screen.getAllByRole('button', { name: ko.save })[0]!);
  }

  it('shows the PC\'s own refusal and its next step instead of the generic line', async () => {
    const source = qaCase('desktop-network-auto-no-mapping').snapshot;
    const setExternalAccess = vi.fn<ControllerBridge['setExternalAccess']>().mockRejectedValue({ ...refusal });
    await saveFixedAddress({ ...createQaBridge(source), setExternalAccess });
    expect(setExternalAccess).toHaveBeenCalledExactlyOnceWith({ mode: 'fixed', fixedAddress: '1.2.3.4:7443' });
    const alert = await screen.findByText(refusal.message);
    expect(alert.closest('[role="alert"]')).toHaveTextContent(refusal.nextAction);
    expect(screen.queryByText(ko.saveFailure)).not.toBeInTheDocument();
  });

  it('translates the refusal through the catalogue', async () => {
    setPreviewLanguage('en');
    const source = qaCase('desktop-network-auto-no-mapping').snapshot;
    const user = userEvent.setup();
    const setExternalAccess = vi.fn<ControllerBridge['setExternalAccess']>().mockRejectedValue({ ...refusal });
    render(<App bridge={{ ...createQaBridge(source), setExternalAccess }} initialPage="network" />);
    await user.click(await screen.findByRole('radio', { name: tr('외부 주소 직접 입력') }));
    fireEvent.change(screen.getByRole('textbox', { name: tr('외부 주소') }), { target: { value: '1.2.3.4:7443' } });
    await user.click(screen.getAllByRole('button', { name: tr('저장') })[0]!);
    expect(await screen.findByText(tr(refusal.message))).toBeVisible();
    expect(screen.getByText(tr(refusal.nextAction))).toBeVisible();
    expect(tr(refusal.message)).not.toBe(refusal.message);
  });

  it('keeps the generic line for a transport failure', async () => {
    const source = qaCase('desktop-network-auto-no-mapping').snapshot;
    const setExternalAccess = vi.fn<ControllerBridge['setExternalAccess']>(() => Promise.reject(new Error('IPC connection lost')));
    await saveFixedAddress({ ...createQaBridge(source), setExternalAccess });
    expect(await screen.findByText(ko.saveFailure)).toBeVisible();
    expect(screen.queryByText(refusal.message)).not.toBeInTheDocument();
    expect(screen.queryByText(/IPC connection lost/u)).not.toBeInTheDocument();
  });

  it('keeps the generic line for a malformed refusal and never shows its raw text', async () => {
    const source = qaCase('desktop-running').snapshot;
    const controlService = vi.fn<ControllerBridge['controlService']>().mockRejectedValue({ code: 'service_action_unavailable', message: 'RAW_NATIVE detail', nextAction: null });
    const user = userEvent.setup();
    render(<App bridge={{ ...createQaBridge(source), controlService }} />);
    await user.click(await screen.findByRole('button', { name: '휴대폰 승인 다시 켜기' }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '휴대폰 승인 다시 켜기' }));
    expect(await screen.findByText(ko.actionFailure)).toBeVisible();
    expect(screen.queryByText(/RAW_NATIVE/u)).not.toBeInTheDocument();
  });

  it('shows a refused snapshot read on the launch screen with its next step', async () => {
    const storage = { code: 'app_storage_unavailable', message: '앱 설정을 열지 못했습니다.', nextAction: '앱을 닫았다가 다시 여십시오.' };
    const bridge = { ...createQaBridge(exampleSnapshot()), snapshot: vi.fn<ControllerBridge['snapshot']>().mockRejectedValue({ ...storage }) };
    render(<App bridge={bridge} />);
    expect(await screen.findByRole('heading', { name: ko.unexpectedTitle })).toBeVisible();
    expect(screen.getByText(storage.message)).toBeVisible();
    expect(screen.getByText(storage.nextAction)).toBeVisible();
    expect(screen.queryByText(ko.loadFailure)).not.toBeInTheDocument();
  });

  it('keeps the generic load line when a snapshot read times out', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout'] });
    const value = exampleSnapshot();
    const snapshot = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(value)
      .mockImplementation(() => new Promise<AppSnapshot>(() => undefined));
    const bridge = { ...createQaBridge(value), snapshot };
    const { result } = renderHook(() => useController(bridge));
    await act(async () => { await vi.advanceTimersByTimeAsync(0); });
    expect(result.current.snapshot).toBe(value);
    expect(result.current.error).toBeNull();
    let refresh!: Promise<void>;
    act(() => { refresh = result.current.refresh(true); });
    await act(async () => { await vi.advanceTimersByTimeAsync(15000); await refresh; });
    expect(result.current.error).toEqual({ message: ko.loadFailure, nextAction: null });
    expect(result.current.stale).toBe(true);
  });

  it('does not repeat a refusal that the snapshot already shows as its issue', async () => {
    const issue = { code: 'service_control_pending', message: '휴대폰 승인 설정 변경이 끝나지 않았습니다.', nextAction: '잠시 기다린 뒤 앱을 닫았다가 다시 여십시오.' };
    const source: AppSnapshot = { ...qaCase('desktop-running').snapshot, issue };
    const controlService = vi.fn<ControllerBridge['controlService']>().mockRejectedValue({ ...issue });
    const user = userEvent.setup();
    render(<App bridge={{ ...createQaBridge(source), controlService }} />);
    await user.click(await screen.findByRole('button', { name: '휴대폰 승인 다시 켜기' }));
    await user.click(within(screen.getByRole('dialog')).getByRole('button', { name: '휴대폰 승인 다시 켜기' }));
    await waitFor(() => expect(controlService).toHaveBeenCalledOnce());
    await waitFor(() => expect(screen.getByText(ko.stale)).toBeVisible());
    expect(screen.getAllByText(issue.message)).toHaveLength(1);
  });
});
