// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic admission ordering; actual minified native startup is a separate CI gate.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge } from './contracts';
import { ko } from './messages.ko';
import { createQaBridge, qaCase } from './qa-fixtures';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((done, fail) => { resolve = done; reject = fail; });
  return { promise, resolve, reject };
}
function setup() {
  const snapshot = qaCase('phone-scanner-launch').snapshot;
  const pending = deferred<AppSnapshot>();
  let nativeReadHeld = false;
  const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot)
    .mockImplementationOnce(() => {
      nativeReadHeld = true;
      return pending.promise.finally(() => { nativeReadHeld = false; });
    }).mockResolvedValue(snapshot);
  const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>(() => nativeReadHeld
    ? Promise.reject({ code: 'app_busy' }) : Promise.resolve());
  const bridge = { ...createQaBridge(snapshot), snapshot: read, openPairingScanner };
  return { snapshot, pending, read, openPairingScanner, bridge };
}

describe('scanner intent waits for the actual background read', () => {
  it('does not collide with the native read lease or launch twice', async () => {
    const test = setup();
    render(<App bridge={test.bridge} />);
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    expect(test.read).toHaveBeenCalledTimes(2);
    fireEvent.click(entry);
    expect(test.openPairingScanner).not.toHaveBeenCalled();
    expect(entry).toBeDisabled();
    fireEvent.click(entry);
    await act(async () => { test.pending.resolve(test.snapshot); await test.pending.promise; });
    await waitFor(() => expect(test.openPairingScanner).toHaveBeenCalledExactlyOnceWith());
    await waitFor(() => expect(entry).toBeEnabled());
    expect(screen.queryByText(ko.pairingScannerBusy)).not.toBeInTheDocument();
    expect(screen.queryByText(ko.updated)).not.toBeInTheDocument();
  });

  it('rechecks the completed read and withdraws a revoked capability', async () => {
    const test = setup();
    render(<App bridge={test.bridge} />);
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    fireEvent.click(entry);
    await act(async () => {
      test.pending.resolve({ ...test.snapshot, mobile: { ...test.snapshot.mobile!, canOpenPairingScanner: false } });
      await test.pending.promise;
    });
    expect(await screen.findByText(ko.pairingScannerNotReady)).toBeVisible();
    expect(entry).toBeDisabled();
    expect(test.openPairingScanner).not.toHaveBeenCalled();
  });

  it('keeps a failed read stale without attempting a scanner launch', async () => {
    const test = setup();
    render(<App bridge={test.bridge} />);
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    fireEvent.click(entry);
    await act(async () => { test.pending.reject(new Error('synthetic-read-failure')); });
    expect(await screen.findByText(ko.loadFailure)).toBeVisible();
    expect(entry).toBeDisabled();
    expect(test.openPairingScanner).not.toHaveBeenCalled();
    expect(screen.queryByText(ko.pairingScannerFailure)).not.toBeInTheDocument();
  });

  it('navigation cancels the waiting scanner intent', async () => {
    const test = setup();
    render(<App bridge={test.bridge} />);
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    fireEvent.click(entry);
    fireEvent.click(screen.getByRole('button', { name: ko.schedule }));
    await act(async () => { test.pending.resolve(test.snapshot); await test.pending.promise; });
    await waitFor(() => expect(screen.queryByText(ko.pending)).not.toBeInTheDocument());
    expect(screen.getByRole('heading', { level: 1, name: ko.schedule })).toBeVisible();
    expect(test.openPairingScanner).not.toHaveBeenCalled();
  });

  it('an old read cannot open a scanner after bridge replacement', async () => {
    const test = setup();
    const view = render(<App bridge={test.bridge} />);
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    fireEvent.click(entry);
    view.rerender(<App bridge={createQaBridge(qaCase('phone-lock-missing').snapshot)} />);
    await screen.findByRole('button', { name: ko.openLockSettings });
    await act(async () => { test.pending.resolve(test.snapshot); await test.pending.promise; });
    expect(test.openPairingScanner).not.toHaveBeenCalled();
  });

  it('a hidden read completion neither opens the camera nor restores request bodies', async () => {
    const test = setup();
    render(<App bridge={test.bridge} />);
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    fireEvent.click(entry);
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      fireEvent(document, new Event('visibilitychange'));
      const incoming = { ...qaCase('phone-pending').snapshot, mobile: test.snapshot.mobile };
      await act(async () => { test.pending.resolve(incoming); await test.pending.promise; });
      await waitFor(() => expect(screen.queryByText(ko.pending)).not.toBeInTheDocument());
      expect(test.openPairingScanner).not.toHaveBeenCalled();
      expect(screen.queryByText(incoming.requests[0]!.programName)).not.toBeInTheDocument();
    } finally { visibility.mockRestore(); }
  });

  it('leaving and returning before the read completes still cancels the old intent', async () => {
    const test = setup();
    render(<App bridge={test.bridge} />);
    const entry = await screen.findByRole('button', { name: ko.openPairingScanner });
    fireEvent(window, new Event('focus'));
    fireEvent.click(entry);
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      fireEvent(document, new Event('visibilitychange'));
      visibility.mockReturnValue('visible');
      fireEvent(document, new Event('visibilitychange'));
      await act(async () => { test.pending.resolve(test.snapshot); await test.pending.promise; });
      await waitFor(() => expect(entry).toBeEnabled());
      expect(test.openPairingScanner).not.toHaveBeenCalled();
    } finally { visibility.mockRestore(); }
  });
});
