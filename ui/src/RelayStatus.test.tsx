// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic DTO/client regression cases, not native listener or UAC proof.
import { fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { ExternalAccessPanel } from './ExternalAccessPanel';
import { RelaySettings } from './RelaySettings';
import type { AppSnapshot } from './contracts';
import { ko } from './messages';
import { createQaBridge, qaCase } from './qa-fixtures';
import { RelayStatusLine } from './RelayStatusLine';
import { ServicePanel } from './StatusPanels';
import { DevicesPanel } from './CollectionPanels';
import { locales, setPreviewLanguage, tr } from './i18n';

describe('Windows relay observation and service recovery', () => {
  it('withdraws stale or unavailable-owner listener success', () => {
    const snapshot = qaCase('desktop-relay-listening').snapshot;
    const view = render(<RelayStatusLine snapshot={snapshot} stale />);
    expect(screen.getByRole('status')).not.toHaveClass('is-success');
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 연결 대기 상태 확인 불가');
    view.rerender(<RelayStatusLine snapshot={{ ...snapshot, dataAvailability: { ...snapshot.dataAvailability, devices: 'unavailable' } }} />);
    expect(screen.getByRole('status')).not.toHaveClass('is-success');
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 연결 대기 상태 확인 불가');
  });
  it('keeps unknown relay state when the stopped SCM value is only cached', () => {
    const cached = qaCase('desktop-relay-stopped').snapshot;
    render(<RelayStatusLine snapshot={{ ...cached, relayStatus: { mode: 'embedded', state: 'unknown' } }} />);
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 연결 대기 상태 확인 불가 · [다시 확인]을 누르십시오.');
    expect(screen.queryByText('휴대폰 연결 받지 않음 · 휴대폰 승인을 켜면 다시 받습니다.')).not.toBeInTheDocument();
  });
  it.each(locales)('translates stopped relay, selected mode and the next step in %s', (locale) => {
    setPreviewLanguage(locale);
    const snapshot = qaCase('desktop-relay-stopped').snapshot;
    const view = render(<ExternalAccessPanel snapshot={snapshot} disabled={false} onOpenStatus={vi.fn()} onSave={vi.fn()} onSetRelay={vi.fn()} />);
    const relay = view.container.querySelector('.auxiliary-card')!;
    expect(relay.textContent.length).toBeGreaterThan(0);
    expect(within(relay as HTMLElement).getByRole('button', { name: tr('PC 상태 열기') })).toBeEnabled();
    if (locale !== 'ko') expect(view.container.textContent).not.toMatch(/[가-힣]/u);
    for (const status of within(view.container).getAllByRole('status')) expect(status).not.toHaveClass('is-success');
  });

  it.each([
    ['desktop-relay-stopped', '휴대폰 연결 받지 않음 · 휴대폰 승인을 켜면 다시 받습니다.'],
    ['desktop-relay-listening', '휴대폰 연결 대기 중'],
    ['desktop-relay-waiting', '네트워크 연결 대기 중 · PC의 네트워크 연결을 확인하십시오.'],
    ['desktop-relay-unknown', '휴대폰 연결 대기 상태 확인 불가 · [다시 확인]을 누르십시오.'],
    ['desktop-relay-external', '외부 중계 서버 사용'],
  ])('renders %s from observed runtime state', (fixture, message) => {
    render(<RelayStatusLine snapshot={qaCase(fixture).snapshot} />);
    expect(screen.getByRole('status')).toHaveTextContent(message);
    expect(screen.getByRole('status').classList.contains('is-success')).toBe(fixture === 'desktop-relay-listening');
    expect(screen.getByRole('status').querySelector('.state-dot')).toHaveAttribute('aria-hidden', 'true');
  });

  it('never promotes readiness or a stale listening DTO while SCM is stopped', () => {
    const source = qaCase('desktop-relay-stopped').snapshot;
    const view = render(<RelayStatusLine snapshot={{ ...source, relayConfigured: true, relayStatus: null }} />);
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 승인을 켜면 다시 받습니다.');
    view.rerender(<RelayStatusLine snapshot={{ ...source, relayConfigured: true, relayStatus: { mode: 'embedded', state: 'listening' } }} />);
    expect(screen.getByRole('status')).not.toHaveClass('is-success');
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 승인을 켜면 다시 받습니다.');
  });

  it('keeps legacy readiness and unknown management distinct from listening', () => {
    const source = qaCase('desktop-running').snapshot;
    const view = render(<RelayStatusLine snapshot={{ ...source, relayConfigured: true }} />);
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 연결 대기 상태 확인 불가');
    view.rerender(<RelayStatusLine snapshot={{ ...source, service: null, relayStatus: { mode: 'embedded', state: 'listening' } }} />);
    expect(screen.getByRole('status')).not.toHaveClass('is-success');
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 연결 대기 상태 확인 불가');
  });

  it('shows preparation failure and keeps unknown external runtime distinct from reachability', () => {
    const source = qaCase('desktop-relay-listening').snapshot;
    const view = render(<RelayStatusLine snapshot={{ ...source, relayStatus: { mode: 'embedded', state: 'unavailable' } }} />);
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 연결을 받지 못하고 있습니다. PC의 네트워크 연결을 확인하십시오. 연결되면 자동으로 다시 시도합니다.');
    view.rerender(<RelayStatusLine snapshot={{ ...source, relayStatus: { mode: 'external', state: 'unknown' } }} />);
    expect(screen.getByRole('status')).toHaveTextContent('휴대폰 연결 대기 상태 확인 불가');
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
    render(<App bridge={{ ...createQaBridge(initial), setRelay }} initialPage="network" />);
    fireEvent.click(await screen.findByRole('button', { name: '이 PC 사용' }));
    const selected = await screen.findByRole('button', { name: '이 PC 사용 중' });
    expect(selected).toBeDisabled();
    fireEvent.click(selected);
    expect(setRelay).toHaveBeenCalledExactlyOnceWith('embedded');
    expect(screen.getByText('휴대폰 연결 받지 않음 · 휴대폰 승인을 켜면 다시 받습니다.')).toBeVisible();
    expect(screen.getByText('[PC 상태]에서 휴대폰 승인을 켜면 휴대폰이 이 PC에 접속할 수 있습니다.')).toBeVisible();
    expect(screen.queryByText('중계 서버 주소가 설정되어 있습니다.')).not.toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: ko.pairingPcOpenStatus }));
    expect(screen.getByRole('heading', { level: 1, name: ko.appName })).toBeVisible();
    expect(screen.getByRole('button', { name: '휴대폰 승인 켜기' })).toBeEnabled();
  });

  it.each(['busy', 'unknown-owner', 'pending', 'unsupported'] as const)('keeps native and stale/busy relay gates: %s', (condition) => {
    const source = qaCase('desktop-relay-external').snapshot;
    const snapshot: AppSnapshot = condition === 'unknown-owner' ? { ...source, service: null }
      : condition === 'pending' ? { ...source, service: { ...source.service!, state: 'start_pending' } }
      : condition === 'unsupported' ? { ...source, service: { ...source.service!, controlHint: 'unsupported' } } : source;
    const onSetRelay = vi.fn();
    render(<RelaySettings snapshot={snapshot} disabled={condition === 'busy'} onSetRelay={onSetRelay} />);
    const select = screen.getByRole('button', { name: '이 PC 사용' });
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
    const view = render(<RelaySettings snapshot={unavailable} disabled={false} onSetRelay={onSetRelay} />);
    const address = screen.getByRole('textbox', { name: ko.relayAddress });
    expect(address).toBeEnabled();
    fireEvent.change(address, { target: { value: '203.0.113.10:443' } });
    expect(screen.getByRole('button', { name: ko.save })).toBeDisabled();
    fireEvent.submit(screen.getByRole('form', { name: ko.relayAddress }));
    expect(onSetRelay).not.toHaveBeenCalled();
    const ready = qaCase('desktop-relay-listening').snapshot;
    view.rerender(<RelaySettings snapshot={ready} disabled={false} onSetRelay={onSetRelay} />);
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
    await waitFor(() => expect(within(screen.getByRole('region', { name: '휴대폰 승인 꺼짐' })).getByText(message)).toBeVisible());
    expect(screen.getAllByText(message)).toHaveLength(1);
    const retry = screen.getByRole('button', { name: '휴대폰 승인 켜기' });
    expect(retry).toBeEnabled();
    fireEvent.click(retry);
    await waitFor(() => expect(controlService).toHaveBeenCalledTimes(2));
  });
});

describe('PC status card says each fact once', () => {
  const relayLine = (container: HTMLElement) => container.querySelector('.relay-state');
  const directLine = (container: HTMLElement) => container.querySelector('.direct-connection');

  it('hides the relay and direct lines while phone approval is off, but keeps them on the external access tab', () => {
    const stopped = qaCase('desktop-relay-stopped').snapshot;
    const card = render(<ServicePanel snapshot={stopped} disabled={false} onAction={vi.fn()} />);
    expect(screen.getByRole('heading', { name: '휴대폰 승인 꺼짐' })).toBeVisible();
    expect(relayLine(card.container)).toBeNull();
    expect(directLine(card.container)).toBeNull();
    expect(screen.queryByText('휴대폰 연결 받지 않음 · 휴대폰 승인을 켜면 다시 받습니다.')).not.toBeInTheDocument();
    expect(screen.queryByText('외부 연결 꺼짐 · 휴대폰 승인을 켜면 다시 준비합니다.')).not.toBeInTheDocument();
    card.unmount();
    const tab = render(<ExternalAccessPanel snapshot={stopped} disabled={false} onSave={vi.fn()} onSetRelay={vi.fn()} />);
    expect(relayLine(tab.container)).toHaveTextContent('휴대폰 연결 받지 않음 · 휴대폰 승인을 켜면 다시 받습니다.');
    expect(screen.getByText('외부 연결 꺼짐 · 휴대폰 승인을 켜면 다시 준비합니다.')).toBeVisible();
  });

  it('keeps both lines while stale, since a cached stopped state is not known', () => {
    const stopped = qaCase('desktop-relay-stopped').snapshot;
    const card = render(<ServicePanel snapshot={stopped} disabled={false} onAction={vi.fn()} stale />);
    expect(relayLine(card.container)).toHaveTextContent('휴대폰 연결 대기 상태 확인 불가 · [다시 확인]을 누르십시오.');
    expect(directLine(card.container)).toHaveTextContent('외부 연결 상태 확인 불가 · [다시 확인]을 누르십시오.');
  });

  it('shows the relay line while no phone is connected and hides it once one is', async () => {
    const offline = qaCase('desktop-status-phone-offline').snapshot;
    const view = render(<ServicePanel snapshot={offline} disabled={false} onAction={vi.fn()} />);
    expect(screen.getByText('휴대폰 연결 안 됨')).toBeVisible();
    expect(relayLine(view.container)).toHaveTextContent('휴대폰 연결 대기 중');
    view.unmount();
    const connected = qaCase('desktop-connected').snapshot;
    const card = render(<ServicePanel snapshot={connected} disabled={false} onAction={vi.fn()} />);
    expect(await screen.findByText('휴대폰 연결됨')).toBeVisible();
    expect(relayLine(card.container)).toBeNull();
    expect(directLine(card.container)).not.toBeNull();
  });

  it('hides the computer-name row while no name is supplied', () => {
    const running = qaCase('desktop-running').snapshot;
    const unnamed = render(<ServicePanel snapshot={{ ...running, computerName: '' }} disabled={false} onAction={vi.fn()} />);
    expect(screen.queryByText(ko.thisComputer, { selector: 'dt' })).not.toBeInTheDocument();
    expect(unnamed.container.textContent).not.toContain('—');
    unnamed.unmount();
    render(<ServicePanel snapshot={{ ...running, computerName: 'OFFICE-PC' }} disabled={false} onAction={vi.fn()} />);
    expect(screen.getByText(ko.thisComputer, { selector: 'dt' }).nextElementSibling).toHaveTextContent('OFFICE-PC');
  });

  it.each(['ko', 'en'] as const)('labels a generated phone name as 휴대폰 {id} in %s, never as a serial number', (locale) => {
    setPreviewLanguage(locale);
    const id = '3fa9c01b'.padEnd(32, '0');
    const snapshot: AppSnapshot = { ...qaCase('desktop-running').snapshot, canUnpair: true,
      devices: [{ id, name: '휴대폰 3fa9c01b', revision: 1, connected: false, routePresent: true, lastSeenLabel: null }] };
    render(<DevicesPanel snapshot={snapshot} disabled={false} onPair={vi.fn()} onRemove={vi.fn()} />);
    expect(screen.getByRole('heading', { name: tr('휴대폰 {id}').replace('{id}', '3fa9c01b') })).toBeVisible();
    expect(screen.queryByText(/3fa9c01b번/u)).not.toBeInTheDocument();
    setPreviewLanguage('ko');
  });
});
