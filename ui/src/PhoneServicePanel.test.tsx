// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic client state only; no real service/boot/persistence is exercised.
import { act, fireEvent, render, renderHook, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, NotificationPolicy, PhoneServiceView, ServiceAction } from './contracts';
import { ko, phoneServiceStateText, serviceActionText } from './messages.ko';
import { createQaBridge, exampleSnapshot, qaCase } from './qa-fixtures';
import { useController } from './useController';

const policy: NotificationPolicy = { schedule: { mode: 'always' }, alert: 'sound' };
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((accept) => { resolve = accept; });
  return { promise, resolve };
}
function bridgeFor(snapshot: AppSnapshot, overrides: Partial<ControllerBridge> = {}): ControllerBridge {
  return { ...createQaBridge(snapshot), ...overrides };
}

describe('Android service controls from actual snapshot capabilities', () => {
  it('keeps schedule/start reachable with null policy and no invented history/defaults', async () => {
    const user = userEvent.setup();
    render(<App bridge={bridgeFor(qaCase('phone-service-stopped').snapshot)} />);
    await user.click(await screen.findByRole('button', { name: ko.schedule }));
    expect(screen.getByRole('region', { name: ko.phoneServiceLabel })).toBeInTheDocument();
    expect(screen.getByText(phoneServiceStateText.stopped)).toBeInTheDocument();
    expect(screen.getByText(ko.phoneBootOff)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.phoneStartAction })).toBeEnabled();
    expect(screen.queryByRole('button', { name: ko.phoneStopAction })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { name: ko.policyStoppedTitle })).toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.save })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.phoneActivity })).not.toBeInTheDocument();
    expect(screen.queryByText(ko.noActivity)).not.toBeInTheDocument();
    for (const name of [serviceActionText.install, serviceActionText.uninstall, serviceActionText.restart]) {
      expect(screen.queryByRole('button', { name })).not.toBeInTheDocument();
    }
  });

  it('sends one start and shows returned preparing rather than running/saved success', async () => {
    const pending = deferred<AppSnapshot>();
    const controlService = vi.fn<ControllerBridge['controlService']>(() => pending.promise);
    const initial = qaCase('phone-service-stopped').snapshot;
    render(<App bridge={bridgeFor(initial, { controlService })} initialPage="schedule" />);
    const start = await screen.findByRole('button', { name: ko.phoneStartAction });
    expect(start).toHaveAccessibleDescription(ko.phoneStartConsequence);
    fireEvent.click(start);
    fireEvent.click(start);
    expect(controlService).toHaveBeenCalledExactlyOnceWith('start');
    expect(start).toBeDisabled();
    await act(async () => { pending.resolve(qaCase('phone-service-preparing').snapshot); await pending.promise; });
    expect(await screen.findByText(phoneServiceStateText.preparing)).toBeInTheDocument();
    expect(screen.getByText(ko.phoneBootOn)).toBeInTheDocument();
    expect(screen.queryByText(phoneServiceStateText.local_settings_ready)).not.toBeInTheDocument();
    expect(screen.queryByText(ko.saved)).not.toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.phoneStopAction })).toBeEnabled();
  });

  it('uses phone stop consequences, supports Escape/focus return and waits for native cleanup state', async () => {
    const user = userEvent.setup();
    const pending = deferred<AppSnapshot>();
    const controlService = vi.fn<ControllerBridge['controlService']>(() => pending.promise);
    render(<App bridge={bridgeFor(qaCase('phone-service-ready').snapshot, { controlService })} initialPage="schedule" />);
    const stop = await screen.findByRole('button', { name: ko.phoneStopAction });
    await user.click(stop);
    let dialog = screen.getByRole('dialog', { name: ko.phoneStopTitle });
    expect(dialog).toHaveAccessibleDescription(ko.phoneStopBody);
    expect(dialog).not.toHaveTextContent('이 PC');
    fireEvent(dialog, new Event('cancel', { bubbles: true, cancelable: true }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
    expect(stop).toHaveFocus();
    expect(controlService).not.toHaveBeenCalled();
    await user.click(stop);
    dialog = screen.getByRole('dialog', { name: ko.phoneStopTitle });
    await user.click(within(dialog).getByRole('button', { name: ko.phoneStopAction }));
    expect(controlService).toHaveBeenCalledExactlyOnceWith('stop');
    expect(screen.getByText(phoneServiceStateText.local_settings_ready)).toBeInTheDocument();
    await act(async () => { pending.resolve(qaCase('phone-service-cleanup').snapshot); await pending.promise; });
    expect(await screen.findByText(phoneServiceStateText.cleanup_pending)).toBeInTheDocument();
    expect(screen.getByText(ko.phoneBootOff)).toBeInTheDocument();
    expect(screen.queryByText(phoneServiceStateText.stopped)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.phoneStartAction })).not.toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
  });

  it('does not convert unknown boot/service state into disabled boot or actionable placeholders', async () => {
    render(<App bridge={bridgeFor(qaCase('phone-service-unavailable').snapshot)} initialPage="schedule" />);
    expect(await screen.findByText(ko.phoneBootUnknown)).toBeInTheDocument();
    expect(screen.queryByText(ko.phoneBootOff)).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.phoneStartAction })).not.toBeInTheDocument();
    expect(screen.queryByRole('button', { name: ko.phoneStopAction })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.refresh })).toBeEnabled();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
  });

  it('keeps native error copy and a native-enabled recovery action while policy is null', async () => {
    render(<App bridge={bridgeFor(qaCase('phone-service-error').snapshot)} initialPage="schedule" />);
    expect(await screen.findByText('휴대폰 승인을 켜지 못했어요.')).toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.phoneStartAction })).toBeEnabled();
    expect(screen.queryByText('synthetic_service_start_rejected')).not.toBeInTheDocument();
    expect(screen.queryByRole('radio')).not.toBeInTheDocument();
  });

  it('labels local activation without claiming that phone requests or a PC connection are ready', async () => {
    render(<App bridge={bridgeFor(qaCase('phone-service-ready').snapshot)} initialPage="schedule" />);
    const panel = await screen.findByRole('region', { name: '휴대폰 승인' });
    expect(within(panel).getByText('휴대폰 승인 켜짐')).toBeInTheDocument();
    expect(within(panel).getByText(ko.phoneServiceReadyBody)).toBeInTheDocument();
    expect(within(panel).getByText('휴대폰을 켤 때 자동 실행')).toBeInTheDocument();
    expect(panel).not.toHaveTextContent(/서비스|PC 요청을 휴대폰으로 보낼 준비가 됐어요/u);
    expect(within(panel).getByRole('button', { name: '휴대폰 승인 끄기' })).toBeEnabled();
  });

  it('keeps a failed service reply stale and disabled without exposing exception text', async () => {
    const user = userEvent.setup();
    const controlService = vi.fn<ControllerBridge['controlService']>(() => Promise.reject(new Error('SYNTHETIC_PRIVATE_NATIVE_ERROR')));
    render(<App bridge={bridgeFor(qaCase('phone-service-stopped').snapshot, { controlService })} initialPage="schedule" />);
    await user.click(await screen.findByRole('button', { name: ko.phoneStartAction }));
    expect(await screen.findByText(ko.actionFailure)).toBeInTheDocument();
    expect(screen.getByText(ko.stale)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.phoneStartAction })).toBeDisabled();
    expect(screen.queryByText('SYNTHETIC_PRIVATE_NATIVE_ERROR')).not.toBeInTheDocument();
  });
});

describe('defensive presentation gates, not native authorization', () => {
  it('ignores Windows action lists on Android and only dispatches an enabled phone action', async () => {
    const initial: AppSnapshot = { ...qaCase('phone-service-stopped').snapshot,
      service: { installed: true, state: 'running', allowedActions: ['install', 'start', 'stop', 'restart', 'uninstall'], controlHint: 'available', remoteRequestsReady: false } };
    const controlService = vi.fn<ControllerBridge['controlService']>(() => Promise.resolve(initial));
    const savePolicy = vi.fn<ControllerBridge['savePolicy']>(() => Promise.resolve(initial));
    const bridge = bridgeFor(initial, { controlService, savePolicy });
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => { expect(result.current.snapshot).toBe(initial); });
    const forbidden: readonly ServiceAction[] = ['install', 'uninstall', 'restart', 'stop'];
    await act(async () => {
      for (const action of forbidden) await result.current.run({ kind: 'service', action });
      await result.current.run({ kind: 'policy', policy });
    });
    expect(controlService).not.toHaveBeenCalled();
    expect(savePolicy).not.toHaveBeenCalled();
    await act(async () => { await result.current.run({ kind: 'service', action: 'start' }); });
    expect(controlService).toHaveBeenCalledExactlyOnceWith('start');
  });

  it.each([
    { name: 'missing policy', value: null, ownerReady: true, allowed: false },
    { name: 'owner not ready', value: policy, ownerReady: false, allowed: false },
    { name: 'real policy and ready owner', value: policy, ownerReady: true, allowed: true },
  ])('requires both actual policy and owner readiness: $name', async ({ value, ownerReady, allowed }) => {
    const phoneService: PhoneServiceView = { state: 'local_settings_ready', bootEnabled: true, canStart: false, canStop: true, policyOwnerReady: ownerReady };
    const initial = { ...exampleSnapshot('android'), policy: value, phoneService };
    const savePolicy = vi.fn<ControllerBridge['savePolicy']>(() => Promise.resolve({ ...initial, policy }));
    const bridge = bridgeFor(initial, { savePolicy });
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => { expect(result.current.snapshot).toBe(initial); });
    await act(async () => { await result.current.run({ kind: 'policy', policy }); });
    expect(savePolicy).toHaveBeenCalledTimes(allowed ? 1 : 0);
  });
});
