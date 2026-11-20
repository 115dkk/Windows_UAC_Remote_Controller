// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic bridge ordering and presentation checks, not native device evidence.
import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AppSnapshot, ControllerBridge, RequestDetailsView } from './contracts';
import { createQaBridge, qaCase } from './qa-fixtures';
import { useController } from './useController';

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}

async function ready(bridge: ControllerBridge) {
  const hook = renderHook(() => useController(bridge));
  await waitFor(() => expect(hook.result.current.snapshot).not.toBeNull());
  return hook;
}

function visibilityChange() {
  act(() => { document.dispatchEvent(new Event('visibilitychange')); });
}

describe('controller admission and publication', () => {
  function details(id: string): RequestDetailsView {
    return { version: 1, id, programName: '', executablePath: '', details: 'SYNTHETIC_BODY', remainingSeconds: 30, refreshAfterMillis: 30000 };
  }

  it('serializes overlapping detail queries instead of failing the second with app_busy', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const first = deferred<RequestDetailsView>();
    let held = false;
    const requestDetails = vi.fn<ControllerBridge['requestDetails']>((id) => {
      if (held) return Promise.reject(Object.assign(new Error('synthetic busy'), { code: 'app_busy' }));
      if (id === 'first') {
        held = true;
        return first.promise.finally(() => { held = false; });
      }
      return Promise.resolve(details(id));
    });
    const { result } = await ready({ ...createQaBridge(snapshot), requestDetails });
    let one!: Promise<RequestDetailsView>;
    let two!: Promise<RequestDetailsView>;
    act(() => {
      one = result.current.readDetails('first');
      two = result.current.readDetails('second');
    });
    // Attach a handler before resolving the first call, including on the broken implementation.
    const second = two.catch((error: unknown) => error);
    await act(async () => { first.resolve(details('first')); await one; await second; });
    expect(await second).toEqual(details('second'));
    expect(requestDetails.mock.calls).toEqual([['first'], ['second']]);
  });

  it('lets a kept decision precede queued details and coalesces refresh wakes', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const first = deferred<RequestDetailsView>();
    const order: string[] = [];
    const requestDetails = vi.fn<ControllerBridge['requestDetails']>((id) => {
      order.push(id);
      return id === 'first' ? first.promise : Promise.resolve(details(id));
    });
    const read = vi.fn<ControllerBridge['snapshot']>(() => { order.push('read'); return Promise.resolve(snapshot); });
    const decide = vi.fn<ControllerBridge['decide']>(() => { order.push('decision'); return Promise.resolve(snapshot); });
    const { result } = await ready({ ...createQaBridge(snapshot), snapshot: read, requestDetails, decide });
    order.length = 0;
    let one!: Promise<RequestDetailsView>;
    let two!: Promise<unknown>;
    let denied!: Promise<AppSnapshot | null>;
    act(() => {
      one = result.current.readDetails('first');
      two = result.current.readDetails('second').catch(() => null);
      void result.current.refresh();
      void result.current.refresh();
      denied = result.current.run({ kind: 'decision', requestId: snapshot.requests[0]!.id, decision: 'deny' });
    });
    expect(order).toEqual(['first']);
    await act(async () => { first.resolve(details('first')); await one.catch(() => null); await denied; await two; });
    expect(order).toEqual(['first', 'decision', 'read']);
    expect(decide).toHaveBeenCalledExactlyOnceWith(snapshot.requests[0]!.id, 'deny');
  });

  it('does not send a kept decision after its display lease ends behind a details read', async () => {
    let now = 0;
    const clock = vi.spyOn(performance, 'now').mockImplementation(() => now);
    try {
      const snapshot = qaCase('phone-pending').snapshot;
      const response = deferred<RequestDetailsView>();
      const requestDetails = vi.fn<ControllerBridge['requestDetails']>().mockReturnValue(response.promise);
      const decide = vi.fn<ControllerBridge['decide']>().mockResolvedValue(snapshot);
      const { result } = await ready({ ...createQaBridge(snapshot), requestDetails, decide });
      let body!: Promise<unknown>;
      let denied!: Promise<AppSnapshot | null>;
      act(() => {
        body = result.current.readDetails(snapshot.requests[0]!.id).catch(() => null);
        denied = result.current.run({ kind: 'decision', requestId: snapshot.requests[0]!.id, decision: 'deny' });
      });
      expect(decide).not.toHaveBeenCalled();
      now = 30001;
      await act(async () => { response.resolve(details(snapshot.requests[0]!.id)); await body; await denied; });
      expect(decide).not.toHaveBeenCalled();
      expect(result.current.busy).toBeNull();
    } finally { clock.mockRestore(); }
  });

  it('waits for a snapshot before reading original details', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const response = deferred<AppSnapshot>();
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot).mockReturnValueOnce(response.promise);
    const requestDetails = vi.fn<ControllerBridge['requestDetails']>((id) => Promise.resolve(details(id)));
    const { result } = await ready({ ...createQaBridge(snapshot), snapshot: read, requestDetails });
    let body!: Promise<RequestDetailsView>;
    act(() => { void result.current.refresh(); body = result.current.readDetails('first'); });
    expect(requestDetails).not.toHaveBeenCalled();
    await act(async () => { response.resolve(snapshot); await body; });
    expect(requestDetails).toHaveBeenCalledExactlyOnceWith('first');
  });

  it.each(['hidden', 'replaced'] as const)('rejects detail publication and queued calls when the page is %s', async (change) => {
    const snapshot = qaCase('phone-pending').snapshot;
    const response = deferred<RequestDetailsView>();
    const requestDetails = vi.fn<ControllerBridge['requestDetails']>().mockReturnValue(response.promise);
    const bridge: ControllerBridge = { ...createQaBridge(snapshot), requestDetails };
    const hook = renderHook(({ owner }: { owner: ControllerBridge }) => useController(owner), { initialProps: { owner: bridge } });
    await waitFor(() => expect(hook.result.current.snapshot).not.toBeNull());
    let one!: Promise<unknown>;
    let two!: Promise<unknown>;
    act(() => {
      one = hook.result.current.readDetails('first').catch(() => null);
      two = hook.result.current.readDetails('second').catch(() => null);
    });
    const visibility = vi.spyOn(document, 'visibilityState', 'get');
    try {
      if (change === 'hidden') { visibility.mockReturnValue('hidden'); visibilityChange(); }
      else hook.rerender({ owner: createQaBridge({ ...snapshot, requests: [] }) });
      await act(async () => { response.resolve(details('first')); await one; await two; });
      expect(await one).toBeNull();
      expect(await two).toBeNull();
      expect(requestDetails).toHaveBeenCalledExactlyOnceWith('first');
    } finally { visibility.mockRestore(); }
  });

  it('does not release native admission when the JavaScript snapshot timeout expires', async () => {
    vi.useFakeTimers({ toFake: ['setTimeout', 'clearTimeout', 'setInterval', 'clearInterval', 'performance'] });
    try {
      const snapshot = qaCase('phone-pending').snapshot;
      const response = deferred<AppSnapshot>();
      const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot).mockReturnValueOnce(response.promise).mockResolvedValue(snapshot);
      const openLockSettings = vi.fn<ControllerBridge['openLockSettings']>().mockResolvedValue();
      const source = { ...snapshot, mobile: qaCase('phone-lock-missing').snapshot.mobile };
      read.mockReset().mockResolvedValueOnce(source).mockReturnValueOnce(response.promise).mockResolvedValue(source);
      const bridge = { ...createQaBridge(source), snapshot: read, openLockSettings };
      const { result } = renderHook(() => useController(bridge));
      await act(async () => { await vi.advanceTimersByTimeAsync(0); });
      let opened!: Promise<AppSnapshot | null>;
      act(() => {
        void result.current.refresh();
        opened = result.current.run({ kind: 'lock-settings' });
      });
      await act(async () => { await vi.advanceTimersByTimeAsync(15000); });
      expect(openLockSettings).not.toHaveBeenCalled();
      expect(read).toHaveBeenCalledTimes(2);
      await act(async () => { response.resolve(source); await opened; });
      expect(openLockSettings).toHaveBeenCalledOnce();
    } finally { vi.useRealTimers(); }
  });

  it('does not publish an old owner response or open its waiting scanner after bridge replacement', async () => {
    const snapshot = { ...qaCase('phone-pending').snapshot, mobile: qaCase('phone-scanner-launch').snapshot.mobile };
    const response = deferred<AppSnapshot>();
    const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>().mockResolvedValue();
    const old: ControllerBridge = { ...createQaBridge(snapshot), openPairingScanner, snapshot: vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot).mockReturnValue(response.promise) };
    const fresh = { ...snapshot, requests: [] };
    const hook = renderHook(({ owner }: { owner: ControllerBridge }) => useController(owner), { initialProps: { owner: old } });
    await waitFor(() => expect(hook.result.current.snapshot).not.toBeNull());
    let scanning!: Promise<AppSnapshot | null>;
    act(() => {
      void hook.result.current.refresh();
      scanning = hook.result.current.run({ kind: 'scan_pairing' });
    });
    hook.rerender({ owner: createQaBridge(fresh) });
    await waitFor(() => expect(hook.result.current.snapshot?.requests).toHaveLength(0));
    await act(async () => { response.resolve(snapshot); await scanning; });
    await waitFor(() => expect(hook.result.current.snapshot?.requests).toHaveLength(0));
    expect(openPairingScanner).not.toHaveBeenCalled();
  });

  it('confirms scanner return with a fresh capability after a wake', async () => {
    const snapshot = qaCase('phone-scanner-launch').snapshot;
    const opened = deferred<void>();
    const openPairingScanner = vi.fn<ControllerBridge['openPairingScanner']>().mockReturnValue(opened.promise);
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValue(snapshot);
    const { result } = await ready({ ...createQaBridge(snapshot), snapshot: read, openPairingScanner });
    let scanning!: Promise<AppSnapshot | null>;
    act(() => { scanning = result.current.run({ kind: 'scan_pairing' }); });
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      await act(async () => { opened.resolve(); await scanning; });
      visibilityChange();
      expect(result.current.scannerFocusRevision).toBe(0);
      visibility.mockReturnValue('visible');
      visibilityChange();
      await waitFor(() => expect(result.current.scannerFocusRevision).toBe(1));
      expect(openPairingScanner).toHaveBeenCalledOnce();
    } finally { visibility.mockRestore(); }
  });
});

describe('decision intent lifetime', () => {
  it.each(['read', 'refused decision'] as const)('gives up a denial across leaving and returning during a %s', async (held) => {
    const snapshot = qaCase('phone-pending').snapshot;
    const request = snapshot.requests[0]!;
    const response = deferred<AppSnapshot>();
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValue(snapshot);
    const decide = vi.fn<ControllerBridge['decide']>().mockResolvedValue(snapshot);
    const { result } = await ready({ ...createQaBridge(snapshot), snapshot: read, decide });
    if (held === 'read') {
      read.mockReturnValueOnce(response.promise);
      act(() => { void result.current.refresh(); });
    } else decide.mockReturnValueOnce(response.promise);
    let denied!: Promise<AppSnapshot | null>;
    act(() => { denied = result.current.run({ kind: 'decision', requestId: request.id, decision: 'deny' }); });
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      visibilityChange();
      visibility.mockReturnValue('visible');
      visibilityChange();
      await act(async () => {
        response.resolve(held === 'read' ? snapshot : { ...snapshot,
          issue: { code: 'request_action_busy', message: '앱이 다른 작업을 처리하는 중입니다.', nextAction: null } });
        await denied;
      });
      expect(decide).toHaveBeenCalledTimes(held === 'read' ? 0 : 1);
      expect(result.current.busy).toBeNull();
      await waitFor(() => expect(result.current.refreshing).toBe(false));
      expect(result.current.snapshot?.requests).toHaveLength(1);
    } finally { visibility.mockRestore(); }
  });
});

describe('controller response publication', () => {
  it('does not restore request bodies when a refresh finishes on a hidden page', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const response = deferred<AppSnapshot>();
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot).mockReturnValue(response.promise);
    const { result } = await ready({ ...createQaBridge(snapshot), snapshot: read });
    let refreshed!: Promise<void>;
    act(() => { refreshed = result.current.refresh(); });
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      visibilityChange();
      expect(result.current.snapshot?.requests).toHaveLength(0);
      await act(async () => { response.resolve(snapshot); await refreshed; });
      expect(result.current.snapshot?.requests).toHaveLength(0);
      expect(result.current.refreshing).toBe(false);
    } finally { visibility.mockRestore(); }
  });

  it('does not restore request bodies when a policy save finishes on a hidden page', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const response = deferred<AppSnapshot>();
    const savePolicy = vi.fn<ControllerBridge['savePolicy']>().mockReturnValue(response.promise);
    const { result } = await ready({ ...createQaBridge(snapshot), savePolicy });
    let saved!: Promise<AppSnapshot | null>;
    act(() => { saved = result.current.run({ kind: 'policy', policy: snapshot.policy! }); });
    expect(savePolicy).toHaveBeenCalledOnce();
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      visibilityChange();
      await act(async () => { response.resolve(snapshot); await saved; });
      expect(result.current.snapshot?.requests).toHaveLength(0);
      expect(result.current.busy).toBeNull();
    } finally { visibility.mockRestore(); }
  });

  it('keeps the current body withdrawal when a settings handoff finishes after returning', async () => {
    const pending = qaCase('phone-pending').snapshot;
    const snapshot = { ...pending, mobile: qaCase('phone-lock-missing').snapshot.mobile };
    const response = deferred<void>();
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot)
      .mockReturnValue(new Promise<AppSnapshot>(() => undefined));
    const openLockSettings = vi.fn<ControllerBridge['openLockSettings']>().mockReturnValue(response.promise);
    const { result } = await ready({ ...createQaBridge(snapshot), snapshot: read, openLockSettings });
    let opened!: Promise<AppSnapshot | null>;
    act(() => { opened = result.current.run({ kind: 'lock-settings' }); });
    expect(openLockSettings).toHaveBeenCalledOnce();
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      visibilityChange();
      visibility.mockReturnValue('visible');
      visibilityChange();
      await act(async () => { response.resolve(); await opened; });
      expect(result.current.snapshot?.requests).toHaveLength(0);
    } finally { visibility.mockRestore(); }
  });
});
