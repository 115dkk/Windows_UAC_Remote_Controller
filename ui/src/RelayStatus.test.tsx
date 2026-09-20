// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic DTO/client regression cases, not native listener or UAC proof.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { DevicesPanel } from './CollectionPanels';
import type { AppSnapshot } from './contracts';
import { ko } from './messages';
import { createQaBridge, qaCase } from './qa-fixtures';
import { RelayStatusLine } from './RelayStatusLine';
import { locales, setPreviewLanguage, tr } from './i18n';

describe('Windows relay observation and service recovery', () => {
  it('keeps unknown relay state when the stopped SCM value is only cached', () => {
    const cached = qaCase('desktop-relay-stopped').snapshot;
    render(<RelayStatusLine snapshot={{ ...cached, relayStatus: { mode: 'embedded', state: 'unknown' } }} />);
    expect(screen.getByRole('status')).toHaveTextContent('중계 실행 상태를 확인하지 못했습니다. 다시 확인하십시오.');
    expect(screen.queryByText('내장 중계 중지됨 · 수신 대기하지 않습니다.')).not.toBeInTheDocument();
  });
  it.each(locales)('translates stopped relay, selected mode and the next step in %s', (locale) => {
    setPreviewLanguage(locale);
    const snapshot = qaCase('desktop-relay-stopped').snapshot;
    const view = render(<DevicesPanel snapshot={snapshot} disabled={false} onPair={vi.fn()} onRemove={vi.fn()} onOpenStatus={vi.fn()} onSetRelay={vi.fn()} />);
    const relay = view.container.querySelector('.auxiliary-card')!;
    expect(relay.textContent.length).toBeGreaterThan(0);
    if (locale !== 'ko') expect(relay.textContent).not.toMatch(/[가-힣]/u);
    expect(within(relay as HTMLElement).getByRole('status')).not.toHaveClass('is-success');
  });

  it.each([
    ['desktop-relay-stopped', '내장 중계 중지됨 · 수신 대기하지 않습니다.'],
    ['desktop-relay-listening', '내장 중계 수신 대기 중'],
    ['desktop-relay-waiting', '내장 중계: 네트워크 연결 대기 중'],
    ['desktop-relay-unknown', '중계 실행 상태를 확인하지 못했습니다. 다시 확인하십시오.'],
    ['desktop-relay-external', '외부 중계 설정됨 · 연결 가능 여부는 아직 확인되지 않았습니다.'],
  ])('renders %s from observed runtime state', (fixture, message) => {
    render(<RelayStatusLine snapshot={qaCase(fixture).snapshot} />);
    expect(screen.getByRole('status')).toHaveTextContent(message);
    expect(screen.getByRole('status').classList.contains('is-success')).toBe(fixture === 'desktop-relay-listening');
    expect(screen.getByRole('status').querySelector('.state-dot')).toHaveAttribute('aria-hidden', 'true');
  });

  it('never promotes readiness or a stale listening DTO while SCM is stopped', () => {
    const source = qaCase('desktop-relay-stopped').snapshot;
    const view = render(<RelayStatusLine snapshot={{ ...source, relayConfigured: true, relayStatus: null }} />);
    expect(screen.getByRole('status')).toHaveTextContent('수신 대기하지 않습니다.');
    view.rerender(<RelayStatusLine snapshot={{ ...source, relayConfigured: true, relayStatus: { mode: 'embedded', state: 'listening' } }} />);
    expect(screen.getByRole('status')).not.toHaveClass('is-success');
    expect(screen.getByRole('status')).toHaveTextContent('수신 대기하지 않습니다.');
  });

  it('keeps legacy readiness and unknown management distinct from listening', () => {
    const source = qaCase('desktop-running').snapshot;
    const view = render(<RelayStatusLine snapshot={{ ...source, relayConfigured: true }} />);
    expect(screen.getByRole('status')).toHaveTextContent('중계 실행 상태를 확인하지 못했습니다.');
    view.rerender(<RelayStatusLine snapshot={{ ...source, service: null, relayStatus: { mode: 'embedded', state: 'listening' } }} />);
    expect(screen.getByRole('status')).not.toHaveClass('is-success');
    expect(screen.getByRole('status')).toHaveTextContent('중계 실행 상태를 확인하지 못했습니다.');
  });

  it('shows preparation failure and keeps unknown external runtime distinct from reachability', () => {
    const source = qaCase('desktop-relay-listening').snapshot;
    const view = render(<RelayStatusLine snapshot={{ ...source, relayStatus: { mode: 'embedded', state: 'unavailable' } }} />);
    expect(screen.getByRole('status')).toHaveTextContent('내장 중계를 준비하지 못했습니다. PC의 네트워크와 중계 설정을 확인하십시오.');
    view.rerender(<RelayStatusLine snapshot={{ ...source, relayStatus: { mode: 'external', state: 'unknown' } }} />);
    expect(screen.getByRole('status')).toHaveTextContent('중계 실행 상태를 확인하지 못했습니다.');
    expect(screen.getByRole('status')).not.toHaveClass('is-success');
  });

  it('does not create a retry capability when native service actions are unavailable', async () => {
    const source = qaCase('desktop-start-failed').snapshot;
    render(<App bridge={createQaBridge({ ...source, service: { ...source.service!, state: null, allowedActions: [] } })} />);
    expect(await screen.findByText(tr(source.service!.actionIssue!.message))).toBeVisible();
    expect(screen.queryByRole('button', { name: '휴대폰 승인 켜기' })).not.toBeInTheDocument();
  });

  it('selects embedded configuration while stopped without claiming a listener or repeating the command', async () => {
    const stopped = qaCase('desktop-relay-stopped').snapshot;
    const initial: AppSnapshot = { ...stopped, relayStatus: { mode: 'external', state: 'stopped' } };
    const setRelay = vi.fn(() => Promise.resolve(stopped));
    render(<App bridge={{ ...createQaBridge(initial), setRelay }} initialPage="devices" />);
    fireEvent.click(await screen.findByRole('button', { name: '이 PC의 내장 중계 사용' }));
    const selected = await screen.findByRole('button', { name: '내장 중계 선택됨' });
    expect(selected).toBeDisabled();
    fireEvent.click(selected);
    expect(setRelay).toHaveBeenCalledExactlyOnceWith('embedded');
    expect(screen.getByText('내장 중계 중지됨 · 수신 대기하지 않습니다.')).toBeVisible();
    expect(screen.getByText('내장 중계가 선택되어 있습니다. 상태 화면에서 휴대폰 승인을 켜면 중계를 준비합니다.')).toBeVisible();
    expect(screen.queryByText('중계 서버 주소가 설정되어 있습니다.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: ko.pairingPcOpenStatus }));
    expect(screen.getByRole('heading', { level: 1, name: ko.homeTitle })).toBeVisible();
    expect(screen.getByRole('button', { name: '휴대폰 승인 켜기' })).toBeEnabled();
  });

  it.each(['busy', 'unknown-owner', 'pending', 'unsupported'] as const)('keeps native and stale/busy relay gates: %s', (condition) => {
    const source = qaCase('desktop-relay-external').snapshot;
    const snapshot: AppSnapshot = condition === 'unknown-owner' ? { ...source, service: null }
      : condition === 'pending' ? { ...source, service: { ...source.service!, state: 'start_pending' } }
      : condition === 'unsupported' ? { ...source, service: { ...source.service!, controlHint: 'unsupported' } } : source;
    const onSetRelay = vi.fn();
    render(<DevicesPanel snapshot={snapshot} disabled={condition === 'busy'} onPair={vi.fn()} onRemove={vi.fn()} onSetRelay={onSetRelay} />);
    const select = screen.getByRole('button', { name: '이 PC의 내장 중계 사용' });
    expect(select).toBeDisabled();
    const address = screen.getByRole('textbox', { name: ko.relayAddress });
    expect(address).toBeEnabled();
    fireEvent.change(address, { target: { value: '203.0.113.10:443' } });
    expect(address).toHaveValue('203.0.113.10:443');
    expect(screen.getByRole('button', { name: ko.save })).toBeDisabled();
    fireEvent.submit(screen.getByRole('form', { name: ko.relayAddress }));
    fireEvent.click(select);
    expect(onSetRelay).not.toHaveBeenCalled();
  });

  it('keeps a writable relay draft through management failure and recovery without submitting it', () => {
    const unavailable = qaCase('desktop-relay-unknown').snapshot;
    const onSetRelay = vi.fn();
    const view = render(<DevicesPanel snapshot={unavailable} disabled={false} onPair={vi.fn()} onRemove={vi.fn()} onSetRelay={onSetRelay} />);
    const address = screen.getByRole('textbox', { name: ko.relayAddress });
    expect(address).toBeEnabled();
    fireEvent.change(address, { target: { value: '203.0.113.10:443' } });
    expect(screen.getByRole('button', { name: ko.save })).toBeDisabled();
    fireEvent.submit(screen.getByRole('form', { name: ko.relayAddress }));
    expect(onSetRelay).not.toHaveBeenCalled();
    const ready = qaCase('desktop-relay-listening').snapshot;
    view.rerender(<DevicesPanel snapshot={ready} disabled={false} onPair={vi.fn()} onRemove={vi.fn()} onSetRelay={onSetRelay} />);
    expect(address).toHaveValue('203.0.113.10:443');
    expect(screen.getByRole('button', { name: ko.save })).toBeEnabled();
    expect(onSetRelay).not.toHaveBeenCalled();
  });

  it('keeps the native action error after a fresh poll and enables an allowed start retry', async () => {
    const initial = qaCase('desktop-relay-stopped').snapshot;
    const failed = qaCase('desktop-start-failed').snapshot;
    let current = initial;
    const snapshot = vi.fn(() => Promise.resolve(current));
    const controlService = vi.fn(() => { current = failed; return Promise.resolve({ ...failed, issue: failed.service!.actionIssue! }); });
    render(<App bridge={{ ...createQaBridge(initial), snapshot, controlService }} />);
    fireEvent.click(await screen.findByRole('button', { name: '휴대폰 승인 켜기' }));
    const message = tr(failed.service!.actionIssue!.message);
    expect(await screen.findAllByText(message)).toHaveLength(1);
    fireEvent.focus(window);
    await waitFor(() => expect(snapshot).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(within(screen.getByRole('region', { name: '서비스 중지됨' })).getByText(message)).toBeVisible());
    expect(screen.getAllByText(message)).toHaveLength(1);
    const retry = screen.getByRole('button', { name: '휴대폰 승인 켜기' });
    expect(retry).toBeEnabled();
    fireEvent.click(retry);
    await waitFor(() => expect(controlService).toHaveBeenCalledTimes(2));
  });
});
