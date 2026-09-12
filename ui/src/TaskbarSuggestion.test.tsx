// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic presentation tests; actual Windows shell consent remains native QA.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { TaskbarSuggestion } from './TaskbarSuggestion';
import type { TaskbarBridge, TaskbarStatus } from './TaskbarSuggestion';

function client(status: TaskbarStatus = 'available', version: string | null = '0.1.0-alpha.14'): TaskbarBridge {
  return { offer: vi.fn().mockResolvedValue({ status, version }), request: vi.fn().mockResolvedValue('pinned') };
}

describe('installer taskbar suggestion', () => {
  beforeEach(() => localStorage.clear());

  it('only requests the OS prompt after a click, then hides verified success', async () => {
    const native = client();
    render(<TaskbarSuggestion client={native} />);
    const button = await screen.findByRole('button', { name: '작업 표시줄에 고정' });
    expect(native.request).not.toHaveBeenCalled();
    fireEvent.click(button);
    await waitFor(() => expect(screen.queryByRole('region')).not.toBeInTheDocument());
    expect(native.request).toHaveBeenCalledExactlyOnceWith();
  });

  it.each(['hidden', 'pinned'] as const)('does not ask for %s state', async (status) => {
    const native = client(status);
    render(<TaskbarSuggestion client={native} />);
    await act(async () => { await native.offer(); });
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    expect(native.request).not.toHaveBeenCalled();
  });

  it('persists dismissal for this version and offers a newly selected version', async () => {
    const first = render(<TaskbarSuggestion client={client()} />);
    fireEvent.click(await screen.findByRole('button', { name: '나중에' }));
    first.unmount();
    const next = render(<TaskbarSuggestion client={client()} />);
    await act(async () => {});
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
    next.unmount();
    render(<TaskbarSuggestion client={client('available', '0.1.0-alpha.15')} />);
    expect(await screen.findByRole('button', { name: '작업 표시줄에 고정' })).toBeEnabled();
  });

  it('shows manual instructions instead of a nonworking action on unsupported Windows', async () => {
    const native = client('unavailable');
    render(<TaskbarSuggestion client={native} />);
    expect(await screen.findByRole('status')).toHaveTextContent('마우스 오른쪽 버튼');
    expect(screen.queryByRole('button', { name: '작업 표시줄에 고정' })).not.toBeInTheDocument();
    expect(native.request).not.toHaveBeenCalled();
  });

  it('disables duplicate clicks and reports cancellation without success', async () => {
    let resolve!: (status: TaskbarStatus) => void;
    const native = client();
    native.request = vi.fn(() => new Promise((accept) => { resolve = accept; }));
    render(<TaskbarSuggestion client={native} />);
    const button = await screen.findByRole('button', { name: '작업 표시줄에 고정' });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(button).toBeDisabled();
    expect(native.request).toHaveBeenCalledTimes(1);
    await act(async () => resolve('declined'));
    expect(await screen.findByRole('status')).toHaveTextContent('추가되지 않았어요');
    expect(screen.queryByRole('button', { name: '작업 표시줄에 고정' })).not.toBeInTheDocument();
  });
});
