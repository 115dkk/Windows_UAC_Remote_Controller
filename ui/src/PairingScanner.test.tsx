// SPDX-License-Identifier: GPL-2.0-or-later
// Client-only synthetic launch/state tests. No camera, QR, native permission or pairing runs.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge } from './contracts';
import { ko } from './messages.ko';
import { createQaBridge, qaCase } from './qa-fixtures';

afterEach(() => { vi.restoreAllMocks(); });

function available(): AppSnapshot { return qaCase('phone-scanner-launch').snapshot; }
function view(snapshot: AppSnapshot, overrides: Partial<ControllerBridge> = {}) {
  const bridge = { ...createQaBridge(snapshot), ...overrides };
  return { bridge, ...render(<App bridge={bridge} />) };
}
function deferred() {
  let resolve!: () => void;
  const promise = new Promise<void>((complete) => { resolve = complete; });
  return { promise, resolve };
}

describe('native QR-input entry, separate from pairing', () => {
  it('requires literal native capability true, including on an unavailable device collection', async () => {
    for (const capability of [false, undefined, null, 'true']) {
      const source = available();
      const snapshot = { ...source, mobile: { ...source.mobile, canOpenPairingScanner: capability } } as unknown as AppSnapshot;
      const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>();
      const rendered = view(snapshot, { openPairingScanner });
      await screen.findByRole('heading', { name: ko.noComputers });
      const disabledEntry = screen.getByRole('button', { name: ko.openPairingScanner });
      expect(disabledEntry).toBeDisabled();
      fireEvent.click(disabledEntry);
      expect(openPairingScanner).not.toHaveBeenCalled();
      rendered.unmount();
    }
    const unrelated = available();
    const unrelatedView = view({ ...unrelated, canPair: true, mobile: { ...unrelated.mobile!, canOpenPairingScanner: false } });
    await screen.findByRole('heading', { name: ko.noComputers });
    expect(screen.getByRole('button', { name: ko.openPairingScanner })).toBeDisabled();
    unrelatedView.unmount();
    for (const fixture of ['phone-scanner-launch', 'phone-scanner-unavailable-catalog']) {
      const rendered = view(qaCase(fixture).snapshot);
      expect(await screen.findByRole('button', { name: ko.openPairingScanner })).toBeEnabled();
      expect(screen.queryByRole('button', { name: ko.computers })).not.toBeInTheDocument();
      expect(screen.queryByRole('button', { name: ko.pairComputer })).not.toBeInTheDocument();
      rendered.unmount();
    }
  });

  it('leaves lock recovery and Windows presentation unchanged', async () => {
    const lock = view(qaCase('phone-lock-missing').snapshot);
    expect(await screen.findByRole('button', { name: ko.openLockSettings })).toBeEnabled();
    expect(screen.getByRole('button', { name: ko.openPairingScanner })).toBeDisabled();
    lock.unmount();
    const windows = qaCase('desktop-running').snapshot;
    view({ ...windows, mobile: available().mobile }); // Even a crossed capability cannot create Windows camera UI.
    await screen.findByRole('heading', { name: 'PC 승인을 휴대폰에서' });
    expect(screen.queryByRole('button', { name: ko.openPairingScanner })).not.toBeInTheDocument();
  });

  it('uses one zero-argument keyboard launch and no pairing or success mutation', async () => {
    const snapshot = available(), opened = deferred();
    const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>(() => opened.promise);
    const beginPairing = vi.fn<ControllerBridge['beginPairing']>();
    const read = vi.fn(() => Promise.resolve(snapshot));
    const user = userEvent.setup();
    view(snapshot, { snapshot: read, openPairingScanner, beginPairing });
    const button = await screen.findByRole('button', { name: ko.openPairingScanner });
    button.focus(); expect(button).toHaveFocus();
    await user.keyboard('{Enter}');
    expect(openPairingScanner).toHaveBeenCalledExactlyOnceWith();
    expect(button).toBeDisabled();
    fireEvent.click(button);
    expect(openPairingScanner).toHaveBeenCalledTimes(1);
    await act(async () => { opened.resolve(); await opened.promise; });
    await waitFor(() => expect(button).toBeEnabled());
    expect(read).toHaveBeenCalledTimes(2);
    expect(beginPairing).not.toHaveBeenCalled();
    expect(snapshot.canPair).toBe(false); expect(snapshot.canUnpair).toBe(false);
    expect(snapshot.devices).toEqual([]); expect(snapshot.dataAvailability.devices).toBe('unavailable');
    expect(screen.getByRole('heading', { name: ko.noComputers })).toBeInTheDocument();
    expect(screen.queryByText(ko.updated)).not.toBeInTheDocument();
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument(); // Native modal is not simulated in the DOM.
  });

  it('shows fixed busy/failure outcomes, hides raw errors and refreshes without enabling full pairing', async () => {
    const failures: readonly [unknown, string][] = [
      [{ code: 'pairing_scanner_busy', message: 'RAW_SYNTHETIC_ERROR' }, ko.pairingScannerBusy],
      [{ code: 'app_busy', message: 'RAW_SYNTHETIC_ERROR' }, ko.pairingScannerBusy],
      [{ code: 'pairing_scanner_unavailable', message: 'RAW_SYNTHETIC_ERROR' }, ko.pairingScannerFailure],
      [new Error('RAW_SYNTHETIC_ERROR'), ko.pairingScannerFailure],
    ];
    for (const [failure, copy] of failures) {
      const snapshot = available(), read = vi.fn(() => Promise.resolve(snapshot));
      const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>().mockRejectedValue(failure);
      const rendered = view(snapshot, { snapshot: read, openPairingScanner });
      fireEvent.click(await screen.findByRole('button', { name: ko.openPairingScanner }));
      expect(await screen.findByText(copy)).toBeInTheDocument();
      expect(screen.queryByText('RAW_SYNTHETIC_ERROR')).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: ko.openPairingScanner })).toBeEnabled();
      expect(read).toHaveBeenCalledTimes(2);
      expect(snapshot.canPair).toBe(false); expect(snapshot.devices).toEqual([]);
      rendered.unmount();
    }
  });

  it('does not call an acknowledged opened dialog a failed launch if snapshot refresh fails', async () => {
    const snapshot = available();
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot).mockRejectedValue(new Error('RAW_REFRESH'));
    view(snapshot, { snapshot: read });
    fireEvent.click(await screen.findByRole('button', { name: ko.openPairingScanner }));
    expect(await screen.findByText(ko.loadFailure)).toBeInTheDocument();
    expect(screen.getByText(ko.stale)).toBeInTheDocument();
    expect(screen.queryByText(ko.pairingScannerFailure)).not.toBeInTheDocument();
    expect(screen.queryByText('RAW_REFRESH')).not.toBeInTheDocument();
  });

  it('waits for a later native capability observation after modal dismissal without a paired toast or automatic relaunch', async () => {
    const original = available();
    let snapshot = original;
    const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>(() => {
      snapshot = { ...original, mobile: { ...original.mobile!, canOpenPairingScanner: false } };
      return Promise.resolve();
    });
    const user = userEvent.setup();
    const foreground = vi.spyOn(document, 'hasFocus').mockReturnValue(true);
    view(original, { snapshot: () => Promise.resolve(snapshot), openPairingScanner });
    await user.click(await screen.findByRole('button', { name: ko.openPairingScanner }));
    await waitFor(() => expect(screen.getByRole('button', { name: ko.openPairingScanner })).toBeDisabled());
    // Synthetic native close/cancel observation. This is not a camera or modal-focus test.
    snapshot = original;
    fireEvent(window, new Event('focus'));
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    expect(entry).toBeEnabled();
    await waitFor(() => expect(entry).toHaveFocus());
    screen.getByRole('button', { name: ko.refresh }).focus();
    await user.tab(); expect(screen.getByRole('button', { name: '앱 설정' })).toHaveFocus();
    await user.tab(); expect(entry).toHaveFocus();
    expect(openPairingScanner).toHaveBeenCalledTimes(1);
    expect(snapshot.devices).toEqual([]); expect(snapshot.canPair).toBe(false);
    expect(screen.queryByText(ko.updated)).not.toBeInTheDocument();
    foreground.mockRestore();
  });

  it('does not request DOM focus on opened acknowledgement alone or steal it after navigation', async () => {
    const snapshot = available(), opened = deferred();
    const user = userEvent.setup();
    view(snapshot, { openPairingScanner: () => opened.promise });
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    const focus = vi.spyOn(entry, 'focus');
    fireEvent.click(entry);
    await act(async () => { opened.resolve(); await opened.promise; });
    await waitFor(() => expect(entry).toBeEnabled());
    expect(focus).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: ko.schedule }));
    fireEvent(window, new Event('focus'));
    await waitFor(() => expect(screen.getByRole('button', { name: ko.refresh })).toBeEnabled());
    expect(screen.getByRole('heading', { level: 1, name: ko.schedule })).toBeInTheDocument();
    expect(focus).not.toHaveBeenCalled();
  });

  it('disables stale entry and preserves the stopped-owner recovery route', async () => {
    const snapshot = available();
    const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>();
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot).mockRejectedValue(new Error('stale'));
    const stale = view(snapshot, { snapshot: read, openPairingScanner });
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    await screen.findByText(ko.stale);
    expect(entry).toBeDisabled(); fireEvent.click(entry);
    expect(openPairingScanner).not.toHaveBeenCalled();
    stale.unmount();
    const stopped = qaCase('phone-service-stopped').snapshot;
    const user = userEvent.setup();
    view(stopped);
    await user.click(await screen.findByRole('button', { name: ko.schedule }));
    expect(screen.getByRole('button', { name: '휴대폰 승인 켜기' })).toBeEnabled();
    expect(screen.queryByRole('button', { name: ko.openPairingScanner })).not.toBeInTheDocument();
  });

  it('does not publish a launch result into a replacement bridge owner', async () => {
    const snapshot = available(), pending = deferred();
    const oldRead = vi.fn(() => Promise.resolve(snapshot));
    const old = { ...createQaBridge(snapshot), snapshot: oldRead, openPairingScanner: () => pending.promise };
    const next = createQaBridge(qaCase('phone-lock-missing').snapshot);
    const rendered = render(<App bridge={old} />);
    fireEvent.click(await screen.findByRole('button', { name: ko.openPairingScanner }));
    rendered.rerender(<App bridge={next} />);
    await screen.findByRole('button', { name: ko.openLockSettings });
    await act(async () => { pending.resolve(); await pending.promise; });
    expect(oldRead).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: ko.openPairingScanner })).toBeDisabled();
  });
});
