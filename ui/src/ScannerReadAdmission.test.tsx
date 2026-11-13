// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic admission ordering; actual minified native startup is a separate CI gate.
import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge } from './contracts';
import { ko } from './messages';
import { createQaBridge, qaCase } from './qa-fixtures';
import { useController } from './useController';

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
    ? Promise.reject(Object.assign(new Error('synthetic native read busy'), { code: 'app_busy' })) : Promise.resolve());
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
    await act(async () => {
      test.pending.reject(new Error('synthetic-read-failure'));
      await test.pending.promise.catch(() => undefined);
    });
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

describe('PC pairing start waits for the actual background read', () => {
  function pcSetup() {
    const snapshot = qaCase('desktop-pairing-ready').snapshot;
    const pending = deferred<AppSnapshot>();
    let nativeReadHeld = false;
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot)
      .mockImplementationOnce(() => {
        nativeReadHeld = true;
        return pending.promise.finally(() => { nativeReadHeld = false; });
      }).mockResolvedValue(snapshot);
    // The native single slot refuses rather than queues, as with_runtime does.
    const beginPairing = vi.fn<ControllerBridge['beginPairing']>(() => nativeReadHeld
      ? Promise.reject(Object.assign(new Error('synthetic native read busy'), { code: 'app_busy' })) : Promise.resolve(snapshot));
    const bridge = { ...createQaBridge(snapshot), snapshot: read, beginPairing };
    return { snapshot, pending, read, beginPairing, bridge };
  }

  it('starts pairing once after the read instead of colliding with it', async () => {
    const test = pcSetup();
    render(<App bridge={test.bridge} initialPage="devices" />);
    const entry = await screen.findByRole('button', { name: ko.pairPhone });
    fireEvent(window, new Event('focus'));
    expect(test.read).toHaveBeenCalledTimes(2);
    fireEvent.click(entry);
    expect(test.beginPairing).not.toHaveBeenCalled();
    await act(async () => { test.pending.resolve(test.snapshot); await test.pending.promise; });
    await waitFor(() => expect(test.beginPairing).toHaveBeenCalledExactlyOnceWith());
  });

  it('does not start when the completed read withdrew the capability', async () => {
    const test = pcSetup();
    render(<App bridge={test.bridge} initialPage="devices" />);
    const entry = await screen.findByRole('button', { name: ko.pairPhone });
    fireEvent(window, new Event('focus'));
    fireEvent.click(entry);
    await act(async () => { test.pending.resolve({ ...test.snapshot, canPair: false }); await test.pending.promise; });
    await waitFor(() => expect(entry).toBeDisabled());
    expect(test.beginPairing).not.toHaveBeenCalled();
  });
});

describe('owner commands wait for the actual background read', () => {
  // The native single slot refuses rather than queues, as with_runtime does.
  function held(snapshot: AppSnapshot) {
    const pending = deferred<AppSnapshot>();
    const state = { held: false };
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot)
      .mockImplementationOnce(() => {
        state.held = true;
        return pending.promise.finally(() => { state.held = false; });
      }).mockResolvedValue(snapshot);
    const admit = <T,>(value: T) => state.held
      ? Promise.reject(Object.assign(new Error('synthetic native read busy'), { code: 'app_busy' })) : Promise.resolve(value);
    return { pending, read, admit };
  }

  it('saves external access once after the read instead of losing the save', async () => {
    const snapshot = qaCase('desktop-running').snapshot;
    const test = held(snapshot);
    const setExternalAccess = vi.fn<ControllerBridge['setExternalAccess']>(() => test.admit(snapshot));
    const bridge = { ...createQaBridge(snapshot), snapshot: test.read, setExternalAccess };
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => expect(result.current.snapshot).toBe(snapshot));
    act(() => { void result.current.refresh(); });
    let saved!: Promise<AppSnapshot | null>;
    act(() => { saved = result.current.run({ kind: 'external-access', access: { mode: 'router_forward', externalPort: 41327 } }); });
    expect(setExternalAccess).not.toHaveBeenCalled();
    await act(async () => { test.pending.resolve(snapshot); await saved; });
    expect(setExternalAccess).toHaveBeenCalledExactlyOnceWith({ mode: 'router_forward', externalPort: 41327 });
    expect(result.current.error).toBeNull();
    expect(result.current.stale).toBe(false);
  });

  it('does not remove a device the completed read no longer lists', async () => {
    const snapshot = qaCase('desktop-devices').snapshot;
    const device = snapshot.devices[0]!;
    const test = held(snapshot);
    const removeDevice = vi.fn<ControllerBridge['removeDevice']>(() => test.admit(snapshot));
    const bridge = { ...createQaBridge(snapshot), snapshot: test.read, removeDevice };
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => expect(result.current.snapshot).toBe(snapshot));
    act(() => { void result.current.refresh(); });
    let removed!: Promise<AppSnapshot | null>;
    act(() => { removed = result.current.run({ kind: 'remove', deviceId: device.id }); });
    const fresh = { ...snapshot, devices: snapshot.devices.filter((item) => item.id !== device.id) };
    await act(async () => { test.pending.resolve(fresh); await removed; });
    expect(removeDevice).not.toHaveBeenCalled();
    expect(result.current.snapshot).toBe(fresh);
    expect(result.current.busy).toBeNull();
  });

  // This used to assert the opposite: the approval went out at once, into the
  // admission the read was holding, and was refused as busy. The refusal took
  // the request off the screen until the next read brought it back.
  it('sends an approval once the running read lets go, instead of losing it as busy', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const request = snapshot.requests.find((item) => item.state === 'pending' && item.canApprove)!;
    const test = held(snapshot);
    const decide = vi.fn<ControllerBridge['decide']>(() => test.admit(snapshot));
    const bridge = { ...createQaBridge(snapshot), snapshot: test.read, decide };
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => expect(result.current.snapshot?.requests).toHaveLength(snapshot.requests.length));
    act(() => { void result.current.refresh(); });
    let approved!: Promise<AppSnapshot | null>;
    act(() => { approved = result.current.run({ kind: 'decision', requestId: request.id, decision: 'approve' }); });
    expect(decide).not.toHaveBeenCalled();
    expect(result.current.busy).toBe('decision');
    expect(result.current.snapshot?.requests).toHaveLength(snapshot.requests.length);
    await act(async () => { test.pending.resolve(snapshot); await approved; });
    expect(decide).toHaveBeenCalledExactlyOnceWith(request.id, 'approve');
    expect(result.current.stale).toBe(false);
    expect(result.current.error).toBeNull();
    expect(result.current.busy).toBeNull();
    expect(result.current.snapshot?.requests).toHaveLength(snapshot.requests.length);
  });

  it('drops a kept approval when the completed read no longer shows that request', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const request = snapshot.requests.find((item) => item.state === 'pending' && item.canApprove)!;
    const test = held(snapshot);
    const decide = vi.fn<ControllerBridge['decide']>(() => test.admit(snapshot));
    const bridge = { ...createQaBridge(snapshot), snapshot: test.read, decide };
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => expect(result.current.snapshot?.requests).toHaveLength(snapshot.requests.length));
    act(() => { void result.current.refresh(); });
    let approved!: Promise<AppSnapshot | null>;
    act(() => { approved = result.current.run({ kind: 'decision', requestId: request.id, decision: 'approve' }); });
    const resolved = { ...snapshot, requests: [] };
    await act(async () => { test.pending.resolve(resolved); await approved; });
    expect(decide).not.toHaveBeenCalled();
    expect(result.current.snapshot).toBe(resolved);
    expect(result.current.busy).toBeNull();
    expect(result.current.stale).toBe(false);
  });
});

describe('a decision is not lost to a busy native side', () => {
  const busyIssue = { code: 'app_busy', message: '앱이 다른 작업을 처리하는 중입니다.', nextAction: '잠시 후 다시 시도하십시오.' };
  function shown() {
    const snapshot = qaCase('phone-pending').snapshot;
    const request = snapshot.requests.find((item) => item.state === 'pending' && item.canApprove)!;
    return { snapshot, request };
  }
  async function ready(bridge: ControllerBridge, count: number) {
    const hook = renderHook(() => useController(bridge));
    await waitFor(() => expect(hook.result.current.snapshot?.requests).toHaveLength(count));
    return hook.result;
  }

  it('offers the same tap again after a busy refusal and keeps the request on screen meanwhile', async () => {
    const { snapshot, request } = shown();
    const decide = vi.fn<ControllerBridge['decide']>()
      .mockRejectedValueOnce(busyIssue).mockRejectedValueOnce(busyIssue).mockResolvedValue(snapshot);
    const result = await ready({ ...createQaBridge(snapshot), decide }, snapshot.requests.length);
    let approved!: Promise<AppSnapshot | null>;
    act(() => { approved = result.current.run({ kind: 'decision', requestId: request.id, decision: 'approve' }); });
    await waitFor(() => { expect(decide).toHaveBeenCalledTimes(2); });
    // Between tries the card is still there and still says the tap was taken.
    expect(result.current.busy).toBe('decision');
    expect(result.current.stale).toBe(false);
    expect(result.current.error).toBeNull();
    expect(result.current.snapshot?.requests).toHaveLength(snapshot.requests.length);
    await act(async () => { await approved; });
    expect(decide).toHaveBeenCalledTimes(3);
    for (const call of decide.mock.calls) expect(call).toEqual([request.id, 'approve']);
    expect(result.current.busy).toBeNull();
    expect(result.current.error).toBeNull();
    expect(result.current.stale).toBe(false);
  });

  it('tries again when busy comes back as the snapshot issue, without showing that issue', async () => {
    const { snapshot, request } = shown();
    const decide = vi.fn<ControllerBridge['decide']>()
      .mockResolvedValueOnce({ ...snapshot, issue: busyIssue }).mockResolvedValue(snapshot);
    const result = await ready({ ...createQaBridge(snapshot), decide }, snapshot.requests.length);
    const issues: (string | undefined)[] = [];
    let approved!: Promise<AppSnapshot | null>;
    act(() => { approved = result.current.run({ kind: 'decision', requestId: request.id, decision: 'deny' }); });
    await waitFor(() => { issues.push(result.current.snapshot?.issue?.code); expect(decide).toHaveBeenCalledTimes(2); });
    await act(async () => { await approved; });
    expect(issues.every((code) => code === undefined)).toBe(true);
    expect(result.current.snapshot?.issue).toBeNull();
    expect(decide).toHaveBeenCalledTimes(2);
    expect(result.current.snapshot?.requests).toHaveLength(snapshot.requests.length);
  });

  it('says the app is busy only after the waits run out, and leaves the request where it was', async () => {
    const { snapshot, request } = shown();
    const decide = vi.fn<ControllerBridge['decide']>().mockRejectedValue(busyIssue);
    const result = await ready({ ...createQaBridge(snapshot), decide }, snapshot.requests.length);
    await act(async () => { await result.current.run({ kind: 'decision', requestId: request.id, decision: 'approve' }); });
    expect(decide).toHaveBeenCalledTimes(6);
    expect(result.current.error).toEqual({ message: busyIssue.message, nextAction: busyIssue.nextAction });
    // Refused before anything began: the screen is not stale and nothing left it.
    expect(result.current.stale).toBe(false);
    expect(result.current.busy).toBeNull();
    expect(result.current.snapshot?.requests).toHaveLength(snapshot.requests.length);
  });

  it('still withdraws the request and marks the screen stale for a refusal that is not busy', async () => {
    const { snapshot, request } = shown();
    const decide = vi.fn<ControllerBridge['decide']>().mockRejectedValue(new Error('synthetic transport failure'));
    const result = await ready({ ...createQaBridge(snapshot), decide }, snapshot.requests.length);
    await act(async () => { await result.current.run({ kind: 'decision', requestId: request.id, decision: 'approve' }); });
    expect(decide).toHaveBeenCalledOnce();
    expect(result.current.stale).toBe(true);
    expect(result.current.snapshot?.requests).toHaveLength(0);
  });
});
