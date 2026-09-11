// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic client behavior only; no native camera, enrollment or UAC acceptance.
import { fireEvent, render, screen, within } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { hasNoPairedPc } from './phoneConnection';
import { ko } from './messages.ko';
import { createQaBridge, qaCase } from './qa-fixtures';

describe('pre-approval connection guidance', () => {
  it('keeps PC setup reachable before inventory is available and explains the disabled QR action', async () => {
    const snapshot = qaCase('desktop-unavailable').snapshot;
    const beginPairing = vi.fn(() => Promise.resolve(snapshot));
    render(<App bridge={{ ...createQaBridge(snapshot), beginPairing }} />);
    fireEvent.click(await screen.findByRole('button', { name: ko.phones }));
    const entry = screen.getByRole('button', { name: ko.pairPhone });
    expect(entry).toBeDisabled();
    expect(screen.getByText(ko.pairingQrPurpose)).toBeVisible();
    expect(screen.getByText(ko.pairingPcInstallFirst)).toBeVisible();
    fireEvent.click(entry);
    expect(beginPairing).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole('button', { name: ko.pairingPcOpenStatus }));
    expect(screen.getByRole('heading', { level: 1, name: ko.homeTitle })).toBeVisible();
  });

  it('shows the PC QR action through navigation even with unread inventory, but requires relay and native capability', async () => {
    const source = qaCase('desktop-running').snapshot;
    for (const relayConfigured of [false, true]) {
      const snapshot = { ...source, canPair: true, relayConfigured,
        dataAvailability: { ...source.dataAvailability, devices: 'unavailable' as const } };
      const beginPairing = vi.fn(() => Promise.resolve(snapshot));
      const view = render(<App bridge={{ ...createQaBridge(snapshot), beginPairing }} />);
      fireEvent.click(await screen.findByRole('button', { name: ko.phones }));
      const entry = screen.getByRole('button', { name: ko.pairPhone });
      if (relayConfigured) { expect(entry).toBeEnabled(); fireEvent.click(entry); expect(beginPairing).toHaveBeenCalledExactlyOnceWith(); }
      else { expect(entry).toBeDisabled(); fireEvent.click(entry); expect(beginPairing).not.toHaveBeenCalled(); expect(screen.getByText(ko.pairingPcRelayFirst)).toBeVisible(); }
      view.unmount();
    }
  });

  it('uses the same PC management menu and connection action names in Android guidance', async () => {
    expect(ko.pairingGuide).toContain(`‘${ko.phones}’ → ‘${ko.pairPhone}’`);
    render(<App bridge={createQaBridge(qaCase('desktop-devices').snapshot)} initialPage="devices" />);
    expect(await screen.findByRole('heading', { level: 1, name: '휴대폰 관리' })).toBeVisible();
    expect(screen.getByRole('navigation')).toHaveTextContent('휴대폰 관리');
  });

  it('shows no waiting requests and a separate unpaired state on the main request screen', async () => {
    render(<App bridge={createQaBridge(qaCase('phone-scanner-launch').snapshot)} />);
    expect(await screen.findByRole('heading', { name: ko.requestEmpty })).toBeVisible();
    expect(screen.getByRole('heading', { name: ko.noComputers })).toBeVisible();
    expect(screen.getByRole('button', { name: ko.openPairingScanner })).toBeEnabled();
    expect(screen.queryByText(/요청을 확인할 수 없어요/)).not.toBeInTheDocument();
  });

  it('does not turn an empty connected request list into a connection error', async () => {
    render(<App bridge={createQaBridge(qaCase('phone-empty').snapshot)} />);
    expect(await screen.findByRole('heading', { name: ko.requestEmpty })).toBeVisible();
    expect(screen.queryByRole('heading', { name: ko.noComputers })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: ko.requestUnavailable })).not.toBeInTheDocument();
  });

  it('keeps an unavailable catalogue distinct from a known empty list without implying internet loss', async () => {
    render(<App bridge={createQaBridge(qaCase('phone-scanner-unavailable-catalog').snapshot)} />);
    expect(await screen.findByRole('heading', { name: ko.requestUnavailable })).toBeVisible();
    expect(screen.queryByRole('heading', { name: ko.requestEmpty })).not.toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: ko.noComputers })).not.toBeInTheDocument();
    expect(screen.queryByText(/확인할 수 없어요|인터넷.*끊/)).not.toBeInTheDocument();
  });

  it('distinguishes known unpaired, disconnected, unknown and reconciling', () => {
    expect(hasNoPairedPc(qaCase('phone-scanner-launch').snapshot)).toBe(true);
    for (const fixture of ['phone-disconnected', 'phone-reconciling', 'phone-scanner-unavailable-catalog']) {
      expect(hasNoPairedPc(qaCase(fixture).snapshot)).toBe(false);
    }
    const empty = qaCase('phone-scanner-launch').snapshot;
    expect(hasNoPairedPc({ ...empty, requestCatalog: { ...empty.requestCatalog!, status: 'unavailable' } })).toBe(false);
    expect(hasNoPairedPc({ ...empty, dataAvailability: { ...empty.dataAvailability, requests: 'unavailable' } })).toBe(false);
  });

  it('offers the native scan entry directly from an unpaired schedule without enabling unavailable tabs', async () => {
    const snapshot = qaCase('phone-scanner-launch').snapshot;
    const openPairingScanner = vi.fn(() => Promise.resolve());
    const bridge = { ...createQaBridge(snapshot), openPairingScanner };
    render(<App bridge={bridge} initialPage="schedule" />);
    const entry = await screen.findByRole('region', { name: ko.noComputers });
    expect(within(entry).getByText(ko.pairingGuide)).toBeVisible();
    const nav = screen.getByRole('navigation');
    const unavailable = within(nav).getByRole('button', { name: `${ko.computers} ${ko.unavailable}` });
    expect(unavailable).toBeDisabled();
    expect(unavailable).toHaveClass('passive');
    expect(unavailable).not.toHaveAttribute('aria-current');
    fireEvent.click(unavailable);
    expect(screen.getByRole('heading', { level: 1, name: ko.schedule })).toBeVisible();
    fireEvent.click(within(entry).getByRole('button', { name: ko.openPairingScanner }));
    expect(openPairingScanner).toHaveBeenCalledExactlyOnceWith();
  });

  it('keeps actual local settings failures separate from unknown pairing inventory', async () => {
    const base = qaCase('phone-service-unavailable').snapshot;
    render(<App bridge={createQaBridge({ ...base, requestCatalog: null })} initialPage="schedule" />);
    expect(await screen.findByRole('region', { name: ko.pairComputer })).toBeVisible();
    expect(screen.queryByRole('heading', { name: ko.noComputers })).not.toBeInTheDocument();
    expect(screen.getByText(ko.serviceUnknown)).toBeVisible();
    expect(screen.getByRole('heading', { name: ko.policyUnavailableTitle })).toBeVisible();
    expect(screen.getByRole('button', { name: ko.openPairingScanner })).toBeDisabled();
    expect(screen.getByRole('button', { name: ko.refresh })).toBeEnabled();
  });
});
