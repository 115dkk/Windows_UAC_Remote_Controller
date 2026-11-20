// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic bridge ordering and presentation checks, not native device evidence.
import { act, renderHook, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AppSnapshot, ControllerBridge } from './contracts';
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
