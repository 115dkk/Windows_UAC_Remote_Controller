// SPDX-License-Identifier: GPL-2.0-or-later
import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { PHONE_RECONNECT_GRACE_MS, useConnectionDisplay } from './useConnectionDisplay';
import type { ConnectionDisplay } from './useConnectionDisplay';

describe('display-only connection continuity', () => {
  afterEach(() => vi.useRealTimers());
  it('shows a dropped phone as reconnecting until one bounded deadline, not reset by later samples', async () => {
    vi.useFakeTimers();
    const hook = renderHook(({ value }) => useConnectionDisplay(value, 'peer:1'), { initialProps: { value: true } });
    expect(hook.result.current).toBe('connected');
    hook.rerender({ value: false });
    expect(hook.result.current).toBe('reconnecting');
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    hook.rerender({ value: false });
    await act(async () => { await vi.advanceTimersByTimeAsync(PHONE_RECONNECT_GRACE_MS - 5001); });
    expect(hook.result.current).toBe('reconnecting');
    await act(async () => { await vi.advanceTimersByTimeAsync(1); });
    expect(hook.result.current).toBe('disconnected');
  });
  it('returns to connected on recovery and cancels the old loss timer', async () => {
    vi.useFakeTimers();
    const hook = renderHook(({ value }) => useConnectionDisplay(value, 'peer:1'), { initialProps: { value: true } });
    hook.rerender({ value: false });
    await act(async () => { await vi.advanceTimersByTimeAsync(5000); });
    hook.rerender({ value: true });
    expect(hook.result.current).toBe('connected');
    await act(async () => { await vi.advanceTimersByTimeAsync(PHONE_RECONNECT_GRACE_MS); });
    expect(hook.result.current).toBe('connected');
  });
  it('never invents a reconnect and immediately invalidates unknown, new identity or stopped owner', () => {
    vi.useFakeTimers();
    type Input = { value: boolean | null; identity: string; active: boolean };
    const hook = renderHook<ConnectionDisplay | null, Input>(({ value, identity, active }) => useConnectionDisplay(value, identity, active),
      { initialProps: { value: false, identity: 'peer:1', active: true } });
    expect(hook.result.current).toBe('disconnected');
    hook.rerender({ value: true, identity: 'peer:1', active: true });
    hook.rerender({ value: false, identity: 'peer:2', active: true });
    expect(hook.result.current).toBe('disconnected');
    hook.rerender({ value: true, identity: 'peer:2', active: true });
    hook.rerender({ value: null, identity: 'peer:2', active: true });
    expect(hook.result.current).toBeNull();
    hook.rerender({ value: false, identity: 'peer:2', active: true });
    expect(hook.result.current).toBe('disconnected');
    hook.rerender({ value: true, identity: 'peer:2', active: true });
    hook.rerender({ value: false, identity: 'peer:2', active: false });
    expect(hook.result.current).toBe('disconnected');
  });
});
