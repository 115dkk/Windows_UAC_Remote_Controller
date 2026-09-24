// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic presentation regression only; not WAN, firewall or native UAC proof.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, RelayStatus } from './contracts';
import { DirectConnectionStatus } from './DirectConnectionStatus';
import { directConnectionState } from './directConnection';
import { locales, setPreviewLanguage, tr } from './i18n';
import { createQaBridge, qaCase } from './qa-fixtures';
import { ServicePanel } from './StatusPanels';

const candidateCopy = '외부에서 접속할 주소가 있음';
const firewallCopy = '휴대폰이 연결되지 않으면 V3나 방화벽이 UAC 원격 승인기 서비스(uac-service.exe)의 연결 허용을 묻고 있는지 확인하십시오.';
const phoneCopy = '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.';
const candidate = (): AppSnapshot => qaCase('desktop-relay-wan-candidate').snapshot;

describe('direct WAN observation boundaries', () => {
  it.each(['discovering', 'lan_only', 'candidate', 'unavailable', 'stopped', 'unknown'] as const)('shows the fresh native %s observation without success styling', (internetState) => {
    const snapshot = candidate();
    render(<DirectConnectionStatus snapshot={{ ...snapshot, relayStatus: { ...snapshot.relayStatus!, internetState } }} />);
    expect(directConnectionState({ ...snapshot, relayStatus: { ...snapshot.relayStatus!, internetState } })).toBe(internetState);
    const region = screen.getByRole('region', { name: '외부 네트워크 연결' });
    expect(within(region).getByRole('status')).not.toHaveClass('is-success');
    expect(within(region).getByText(firewallCopy)).toBeVisible();
    expect(region.querySelector('button, a, input')).toBeNull();
  });

  it.each([undefined, null, 'unknown'] as const)('keeps missing or unknown direct observations unknown: %s', (internetState) => {
    const snapshot = candidate();
    const relayStatus: RelayStatus = internetState === undefined
      ? { mode: 'embedded', state: 'listening' }
      : { mode: 'embedded', state: 'listening', internetState };
    expect(directConnectionState({ ...snapshot, relayStatus })).toBe('unknown');
  });

  it.each(['no-relay', 'no-service', 'not-installed', 'stale-devices', 'pending', 'unavailable-owner', 'unknown-relay', 'waiting-network'] as const)('rejects a candidate with %s', (condition) => {
    const source = candidate();
    const snapshot: AppSnapshot = condition === 'no-relay' ? { ...source, relayStatus: null }
      : condition === 'no-service' ? { ...source, service: null }
      : condition === 'not-installed' ? { ...source, service: { ...source.service!, installed: false } }
      : condition === 'stale-devices' ? { ...source, dataAvailability: { ...source.dataAvailability, devices: 'unavailable' } }
      : condition === 'pending' ? { ...source, service: { ...source.service!, state: 'start_pending' } }
      : condition === 'unavailable-owner' ? { ...source, service: { ...source.service!, controlHint: 'unsupported' } }
      : { ...source, relayStatus: { ...source.relayStatus!, state: condition === 'unknown-relay' ? 'unknown' : 'waiting_network' } };
    render(<DirectConnectionStatus snapshot={snapshot} />);
    expect(directConnectionState(snapshot)).toBe('unknown');
    expect(screen.queryByText(candidateCopy)).not.toBeInTheDocument();
    expect(screen.queryByText(firewallCopy)).not.toBeInTheDocument();
    expect(screen.getByRole('status')).toHaveTextContent('PC 상태를 다시 확인하십시오.');
  });

  it('keeps native unknown ahead of a cached stopped SCM observation', () => {
    const source = candidate();
    const stopped: AppSnapshot = { ...source, service: { ...source.service!, state: 'stopped' } };
    expect(directConnectionState(stopped)).toBe('stopped');
    expect(directConnectionState({ ...stopped, relayStatus: { ...source.relayStatus!, state: 'unknown' } })).toBe('unknown');
    expect(directConnectionState({ ...source, relayStatus: { ...source.relayStatus!, state: 'stopped' } })).toBe('stopped');
  });

  it.each(['status', 'network'] as const)('withdraws a cached candidate when the snapshot refresh fails on %s', async (initialPage) => {
    const source = candidate();
    const snapshot = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(source).mockRejectedValue(new Error('synthetic read failure'));
    render(<App bridge={{ ...createQaBridge(source), snapshot }} initialPage={initialPage} />);
    expect(await screen.findByText(candidateCopy)).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: '다시 확인' }));
    expect(await screen.findByText('외부 연결 상태 확인 불가 · PC 상태를 다시 확인하십시오.')).toBeVisible();
    expect(screen.queryByText(candidateCopy)).not.toBeInTheDocument();
    expect(screen.queryByText(firewallCopy)).not.toBeInTheDocument();
  });

  it('keeps connected LAN peers separate from the external candidate', () => {
    const source = candidate();
    render(<ServicePanel snapshot={{ ...source, devices: qaCase('desktop-connected').snapshot.devices }} disabled={false} onAction={vi.fn()} />);
    expect(screen.getByText('휴대폰 연결됨')).toBeVisible();
    const region = screen.getByRole('region', { name: '외부 네트워크 연결' });
    expect(within(region).getByRole('status')).toHaveTextContent(candidateCopy);
    expect(region.querySelector('.is-success')).toBeNull();
  });

  it.each(['android', 'external'] as const)('omits Windows direct status on %s', (condition) => {
    const source = candidate();
    render(<DirectConnectionStatus snapshot={condition === 'android' ? { ...source, platform: 'android' }
      : { ...source, relayStatus: { mode: 'external', state: 'external_configured', internetState: 'candidate' } }} />);
    expect(screen.queryByRole('region')).not.toBeInTheDocument();
  });

  it.each(locales)('localizes the direct state and program-specific guidance in %s', (locale) => {
    setPreviewLanguage(locale);
    render(<DirectConnectionStatus snapshot={candidate()} />);
    const region = screen.getByRole('region', { name: tr('외부 네트워크 연결') });
    expect(within(region).getByRole('status')).toHaveTextContent(tr(candidateCopy));
    expect(region).toHaveTextContent('uac-service.exe');
    if (locale !== 'ko') expect(region.textContent).not.toMatch(/[가-힣]/u);
  });
});

describe('PC firewall paragraph', () => {
  it('appears only while paired phones exist and none of them is connected', async () => {
    const view = render(<App bridge={createQaBridge(qaCase('desktop-status-phone-offline').snapshot)} />);
    expect(await screen.findByText(firewallCopy)).toBeVisible();
    view.unmount();
    for (const fixture of ['desktop-connected', 'desktop-relay-listening'] as const) {
      const rendered = render(<App bridge={createQaBridge(qaCase(fixture).snapshot)} initialPage="status" />);
      await screen.findByRole('button', { name: '다시 확인' });
      expect(screen.queryByText(firewallCopy)).not.toBeInTheDocument();
      rendered.unmount();
    }
  });

  it.each(['status', 'network'] as const)('follows the paired phones on the %s page', async (initialPage) => {
    const source = qaCase('desktop-status-phone-offline').snapshot;
    const connected = { ...source, devices: source.devices.map((device) => ({ ...device, connected: true })) };
    const unread = { ...source, dataAvailability: { ...source.dataAvailability, devices: 'unavailable' as const } };
    for (const [snapshot, shown] of [[source, true], [connected, false], [{ ...source, devices: [] }, false], [unread, false]] as const) {
      const rendered = render(<App bridge={createQaBridge(snapshot)} initialPage={initialPage} />);
      await screen.findByRole('button', { name: '다시 확인' });
      if (shown) expect(screen.getByText(firewallCopy)).toBeVisible();
      else expect(screen.queryByText(firewallCopy)).not.toBeInTheDocument();
      rendered.unmount();
    }
  });
});

describe('phone firewall recovery context', () => {
  it('keeps the V3 line out of a fresh disconnection', async () => {
    render(<App bridge={createQaBridge(qaCase('phone-disconnected').snapshot)} />);
    expect(await screen.findByText('PC에 연결하는 중')).toBeVisible();
    expect(screen.queryByText(phoneCopy)).not.toBeInTheDocument();
  });

  it.each(['phone-empty', 'phone-unpaired', 'phone-unavailable', 'phone-reconciling', 'phone-pending'])('does not diagnose a firewall from %s', async (fixture) => {
    render(<App bridge={createQaBridge(qaCase(fixture).snapshot)} />);
    await screen.findByRole('button', { name: '다시 확인' });
    expect(screen.queryByText(phoneCopy)).not.toBeInTheDocument();
  });
});
