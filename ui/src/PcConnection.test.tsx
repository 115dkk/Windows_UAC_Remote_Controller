// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic catalogue observations and a controlled clock. No socket, dial or firewall.
import { act, render, renderHook, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, PcConnectionView } from './contracts';
import { ko } from './messages';
import { DIALING_GRACE_MS, RECONNECT_GRACE_MS, pcConnectionPresentation, usePcConnectionClock } from './pcConnection';
import type { PcConnectionClock } from './pcConnection';
import { createQaBridge, qaCase } from './qa-fixtures';
import { RequestPanel } from './RequestPanel';

const failed = 'PC에 연결하지 못했습니다';
const refused = 'PC에 닿았지만 휴대폰 승인이 연결을 받지 않습니다. PC에서 휴대폰 승인이 켜져 있는지 확인하십시오.';
const noAnswer = 'PC의 휴대폰 승인이 응답하지 않습니다. PC 앱에서 상태를 확인하거나 PC를 다시 시작하십시오.';
const awake = 'PC가 켜져 있고 절전 상태가 아닌지 확인하십시오.';
const firewall = '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.';
const setUp = '집 밖에서 쓰려면 PC 앱의 [외부 연결]을 설정한 뒤 이 휴대폰을 집 Wi-Fi에 한 번 연결하십시오.';
const forward = '집 밖이라면 공유기의 포트포워딩과 PC의 [외부 연결] 설정을 확인하십시오.';
const oldCopy = ['컴퓨터와 연결을 기다리고 있어요', 'PC 연결 대기 중', 'PC에서 휴대폰 승인과 인터넷 연결 상태를 확인해 주세요.'];

function disconnected(connection?: PcConnectionView | null): AppSnapshot {
  const phone = qaCase('phone-empty').snapshot;
  return { ...phone, requestCatalog: { status: 'ready', revision: '2', peerCount: 1, connectedPeerCount: 0, ...(connection !== undefined ? { connection } : {}) } };
}
function panel(snapshot: AppSnapshot, clock: PcConnectionClock) {
  return render(<RequestPanel snapshot={snapshot} disabled={false} onDecision={vi.fn()} readDetails={vi.fn()}
    onOpenScanner={vi.fn()} scannerButtonRef={null} connectionClock={clock} />);
}
const at = (elapsed: number, everConnected = true): PcConnectionClock => ({ everConnected, disconnectedSince: 1000, now: 1000 + elapsed });

afterEach(() => { vi.useRealTimers(); });

describe('phone connection presentation', () => {
  it('waits 60 s, or 120 s while a dial is in flight, before naming a failure', () => {
    const quiet: PcConnectionView = { dialing: false, lastFailure: 'refused', externalRoute: true };
    expect(pcConnectionPresentation(RECONNECT_GRACE_MS - 1, true, quiet)).toEqual({ kind: 'reconnecting' });
    expect(pcConnectionPresentation(RECONNECT_GRACE_MS - 1, false, quiet)).toEqual({ kind: 'connecting' });
    expect(pcConnectionPresentation(RECONNECT_GRACE_MS, true, quiet)).toEqual({ kind: 'failed', failure: 'refused', externalRoute: true });
    const dialing = { ...quiet, dialing: true };
    expect(pcConnectionPresentation(DIALING_GRACE_MS - 1, true, dialing)).toEqual({ kind: 'reconnecting' });
    expect(pcConnectionPresentation(DIALING_GRACE_MS, true, dialing)).toEqual({ kind: 'failed', failure: 'refused', externalRoute: true });
  });

  it('treats an absent diagnosis as unknown: no dial, an unreachable guide, the forwarding line', () => {
    for (const connection of [undefined, null]) {
      expect(pcConnectionPresentation(RECONNECT_GRACE_MS - 1, true, connection)).toEqual({ kind: 'reconnecting' });
      expect(pcConnectionPresentation(RECONNECT_GRACE_MS, false, connection)).toEqual({ kind: 'failed', failure: 'unreachable', externalRoute: true });
    }
  });

  it('shows a spinner row, no notice and no firewall text, under the threshold', () => {
    const { container } = panel(disconnected({ dialing: false, lastFailure: 'unreachable', externalRoute: false }), at(RECONNECT_GRACE_MS - 1));
    const row = screen.getByText('PC에 다시 연결하는 중');
    expect(row).toHaveClass('state-line');
    expect(row.querySelector('.spinner')).not.toBeNull();
    expect(row.closest('[role="status"]')).not.toBeNull();
    expect(container.querySelector('.notice-box')).toBeNull();
    expect(container.textContent).not.toMatch(/V3|방화벽/u);
    for (const copy of oldCopy) expect(screen.queryByText(copy)).not.toBeInTheDocument();
  });

  it.each([
    ['refused', true, [refused]],
    ['no_answer', true, [noAnswer]],
    ['unreachable', false, [awake, firewall, setUp]],
    ['unreachable', true, [awake, firewall, forward]],
  ] as const)('past 60 s names %s guidance (external route %s)', (lastFailure, externalRoute, lines) => {
    panel(disconnected({ dialing: false, lastFailure, externalRoute }), at(RECONNECT_GRACE_MS));
    const notice = screen.getByRole('region', { name: failed });
    const shown = [...notice.querySelectorAll('p, li')].map((node) => node.textContent);
    expect(shown).toEqual(lines);
    expect(screen.queryByText('PC에 다시 연결하는 중')).not.toBeInTheDocument();
  });

  it('keeps the row for a dial in flight until 120 s', () => {
    const connection: PcConnectionView = { dialing: true, lastFailure: 'unreachable', externalRoute: false };
    const view = panel(disconnected(connection), at(RECONNECT_GRACE_MS + 1000));
    expect(screen.getByText('PC에 다시 연결하는 중')).toBeVisible();
    expect(screen.queryByRole('region', { name: failed })).not.toBeInTheDocument();
    view.unmount();
    panel(disconnected(connection), at(DIALING_GRACE_MS));
    expect(within(screen.getByRole('region', { name: failed })).getByText(setUp)).toBeVisible();
  });

  it('works without any native diagnosis', () => {
    const view = panel(disconnected(), at(1000, false));
    expect(screen.getByText('PC에 연결하는 중')).toBeVisible();
    view.unmount();
    panel(disconnected(null), at(RECONNECT_GRACE_MS));
    const notice = screen.getByRole('region', { name: failed });
    expect([...notice.querySelectorAll('li')].map((node) => node.textContent)).toEqual([awake, firewall, forward]);
  });

  it('says nothing about the link when the phone approval owner is not running or no PC is paired', () => {
    const stopped = { ...disconnected(), phoneService: { ...disconnected().phoneService!, state: 'stopped' as const } };
    const view = panel(stopped, at(RECONNECT_GRACE_MS));
    expect(screen.queryByText('PC에 다시 연결하는 중')).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: failed })).not.toBeInTheDocument();
    view.unmount();
    panel(qaCase('phone-unpaired').snapshot, at(RECONNECT_GRACE_MS));
    expect(screen.queryByRole('region', { name: failed })).not.toBeInTheDocument();
    expect(screen.queryByText('PC에 연결하는 중')).not.toBeInTheDocument();
  });
});

describe('phone connection clock', () => {
  it('measures from the last connected observation and wakes at the boundary', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'performance'] });
    const connected = qaCase('phone-empty').snapshot;
    const lost = disconnected({ dialing: false, lastFailure: 'refused', externalRoute: true });
    const hook = renderHook(({ snapshot, observedAt }) => usePcConnectionClock(snapshot, observedAt, snapshot.requestCatalog?.connection),
      { initialProps: { snapshot: connected, observedAt: 1000 } });
    expect(hook.result.current).toMatchObject({ everConnected: true, disconnectedSince: null });
    await act(async () => { await vi.advanceTimersByTimeAsync(4000); });
    hook.rerender({ snapshot: lost, observedAt: performance.now() });
    expect(hook.result.current.disconnectedSince).toBe(1000);
    const elapsed = () => hook.result.current.now - hook.result.current.disconnectedSince!;
    expect(pcConnectionPresentation(elapsed(), true, lost.requestCatalog!.connection).kind).toBe('reconnecting');
    await act(async () => { await vi.advanceTimersByTimeAsync(RECONNECT_GRACE_MS - performance.now() + 1000 + 2); });
    expect(elapsed()).toBeGreaterThanOrEqual(RECONNECT_GRACE_MS);
    expect(pcConnectionPresentation(elapsed(), true, lost.requestCatalog!.connection).kind).toBe('failed');
    hook.rerender({ snapshot: connected, observedAt: performance.now() });
    expect(hook.result.current.disconnectedSince).toBeNull();
  });

  it('starts a never-connected session at its first disconnected observation', () => {
    const lost = disconnected();
    const hook = renderHook(({ observedAt }) => usePcConnectionClock(lost, observedAt, undefined), { initialProps: { observedAt: 500 } });
    expect(hook.result.current).toMatchObject({ everConnected: false, disconnectedSince: 500 });
    hook.rerender({ observedAt: 5500 });
    expect(hook.result.current).toMatchObject({ disconnectedSince: 500, now: 5500 });
  });
});

describe('phone connection in the app', () => {
  it('says reconnecting after a lost link, then names the failure once the observation passes 60 s', async () => {
    let now = 10_000;
    vi.spyOn(performance, 'now').mockImplementation(() => now);
    const user = userEvent.setup();
    const connected = qaCase('phone-empty').snapshot;
    const lost = disconnected({ dialing: false, lastFailure: 'no_answer', externalRoute: true });
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(connected).mockResolvedValue(lost);
    render(<App bridge={{ ...createQaBridge(connected), snapshot: read }} />);
    expect(await screen.findByRole('heading', { name: ko.requestEmpty })).toBeVisible();
    expect(screen.queryByText('PC에 다시 연결하는 중')).not.toBeInTheDocument();
    now = 15_000;
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(await screen.findByText('PC에 다시 연결하는 중')).toBeVisible();
    expect(screen.getByRole('heading', { name: ko.requestEmpty })).toBeVisible();
    now = 10_000 + RECONNECT_GRACE_MS;
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    const notice = await screen.findByRole('region', { name: failed });
    expect(notice).toHaveTextContent(noAnswer);
    expect(screen.queryByText('PC에 다시 연결하는 중')).not.toBeInTheDocument();
  });
});
