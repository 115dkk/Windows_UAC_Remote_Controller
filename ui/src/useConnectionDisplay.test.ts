// SPDX-License-Identifier: GPL-2.0-or-later
import { act, renderHook } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { CONNECTION_DISPLAY_GRACE_MS, useConnectionDisplay } from './useConnectionDisplay';

describe('display-only connection continuity', () => {
  afterEach(() => vi.useRealTimers());
  it('coalesces one short loss without resetting the bounded loss deadline', async () => {
    vi.useFakeTimers();
    const hook = renderHook(({ value }) => useConnectionDisplay(value, 'peer:1'), { initialProps: { value: true } });
    hook.rerender({ value: false });
    expect(hook.result.current).toBe(true);
    await act(async () => { vi.advanceTimersByTime(5000); });
    hook.rerender({ value: false });
    await act(async () => { vi.advanceTimersByTime(CONNECTION_DISPLAY_GRACE_MS - 5001); });
    expect(hook.result.current).toBe(true);
    await act(async () => { vi.advanceTimersByTime(1); });
    expect(hook.result.current).toBe(false);
  });
  it('keeps a recovered link steady and cancels the old loss timer', async () => {
    vi.useFakeTimers();
    const hook = renderHook(({ value }) => useConnectionDisplay(value, 'peer:1'), { initialProps: { value: true } });
    hook.rerender({ value: false });
    await act(async () => { vi.advanceTimersByTime(5000); });
    hook.rerender({ value: true });
    await act(async () => { vi.advanceTimersByTime(CONNECTION_DISPLAY_GRACE_MS); });
    expect(hook.result.current).toBe(true);
  });
  it('never invents initial connectivity and immediately invalidates unknown, new identity or stopped owner', () => {
    vi.useFakeTimers();
    type Input = { value: boolean | null; identity: string; active: boolean };
    const hook = renderHook<boolean | null, Input>(({ value, identity, active }) => useConnectionDisplay(value, identity, active),
      { initialProps: { value: false, identity: 'peer:1', active: true } });
    expect(hook.result.current).toBe(false);
    hook.rerender({ value: true, identity: 'peer:1', active: true });
    hook.rerender({ value: false, identity: 'peer:2', active: true });
    expect(hook.result.current).toBe(false);
    hook.rerender({ value: true, identity: 'peer:2', active: true });
    hook.rerender({ value: null, identity: 'peer:2', active: true });
    expect(hook.result.current).toBeNull();
    hook.rerender({ value: false, identity: 'peer:2', active: true });
    expect(hook.result.current).toBe(false);
    hook.rerender({ value: true, identity: 'peer:2', active: true });
    hook.rerender({ value: false, identity: 'peer:2', active: false });
    expect(hook.result.current).toBe(false);
  });
});
