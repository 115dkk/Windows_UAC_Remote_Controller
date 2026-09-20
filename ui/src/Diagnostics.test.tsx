// SPDX-License-Identifier: GPL-2.0-or-later
// Client proof only: synthetic bridges are not native Explorer, storage or Sharesheet evidence.
import { act, fireEvent, render, renderHook, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { createQaBridge, exampleSnapshot, qaCase } from './qa-fixtures';
import { ko } from './messages';
import { useController } from './useController';

describe('fixed Windows diagnostic folder handoff', () => {
  it('waits for the same native snapshot read to release command admission', async () => {
    const value = exampleSnapshot('windows');
    let resolveRead!: (snapshot: typeof value) => void;
    const pending = new Promise<typeof value>(resolve => { resolveRead = resolve; });
    const snapshot = vi.fn().mockResolvedValue(value).mockResolvedValueOnce(value).mockImplementationOnce(() => pending);
    const openDiagnosticsFolder = vi.fn().mockResolvedValue(undefined);
    render(<App initialPage="activity" bridge={{ ...createQaBridge(value), snapshot, openDiagnosticsFolder }} />);
    const button = await screen.findByRole('button', { name: ko.openDiagnosticsFolder });
    fireEvent.click(screen.getByRole('button', { name: ko.refresh }));
    fireEvent.click(button);
    expect(openDiagnosticsFolder).not.toHaveBeenCalled();
    resolveRead(value);
    await waitFor(() => expect(openDiagnosticsFolder).toHaveBeenCalledExactlyOnceWith());
  });
  it('remains reachable when the service activity snapshot is unavailable', async () => {
    const snapshot = qaCase('desktop-unavailable').snapshot;
    const openDiagnosticsFolder = vi.fn().mockResolvedValue(undefined);
    render(<App bridge={{ ...createQaBridge(snapshot), openDiagnosticsFolder }} />);
    fireEvent.click(await screen.findByRole('button', { name: ko.activity }));
    const button = await screen.findByRole('button', { name: ko.openDiagnosticsFolder });
    expect(button).toBeEnabled();
    fireEvent.click(button);
    await waitFor(() => expect(openDiagnosticsFolder).toHaveBeenCalledExactlyOnceWith());
  });

  it('shows a truthful failure and keeps the folder action available for retry', async () => {
    const openDiagnosticsFolder = vi.fn().mockRejectedValue(new Error('synthetic unavailable'));
    render(<App initialPage="activity" bridge={{ ...createQaBridge(exampleSnapshot('windows')), openDiagnosticsFolder }} />);
    fireEvent.click(await screen.findByRole('button', { name: ko.openDiagnosticsFolder }));
    expect(await screen.findByText(ko.diagnosticsFolderFailure)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: ko.openDiagnosticsFolder })).toBeEnabled();
  });

  it('does not offer the Windows filesystem action on Android', async () => {
    render(<App initialPage="activity" bridge={createQaBridge(exampleSnapshot('android'))} />);
    await screen.findByRole('heading', { name: ko.phoneActivity });
    expect(screen.queryByRole('button', { name: ko.openDiagnosticsFolder })).not.toBeInTheDocument();
  });
});

describe('Android diagnostic log export handoff', () => {
  it('exports from activity with an exact no-argument call, retaining history', async () => {
    const value = qaCase('phone-history').snapshot;
    const snapshot = vi.fn().mockResolvedValue(value);
    const exportAndroidDiagnostics = vi.fn().mockResolvedValue(undefined);
    render(<App initialPage="activity" bridge={{ ...createQaBridge(value), snapshot, exportAndroidDiagnostics }} />);
    const before = await screen.findByRole('list');
    const history = before.textContent;
    fireEvent.click(screen.getByRole('button', { name: ko.exportDiagnostics }));
    expect(await screen.findByText(ko.diagnosticsExported)).toBeInTheDocument();
    expect(exportAndroidDiagnostics).toHaveBeenCalledExactlyOnceWith();
    expect(screen.getByRole('list').textContent).toBe(history);
    expect(snapshot).toHaveBeenCalledTimes(1);
    expect(screen.getByRole('button', { name: ko.clearActivity })).toBeEnabled();
    expect(screen.getByRole('button', { name: ko.exportDiagnostics })).toBeEnabled();
    expect(screen.queryByRole('button', { name: ko.openDiagnosticsFolder })).not.toBeInTheDocument();
  });

  it('keeps diagnostic recovery reachable when activity data is unavailable', async () => {
    const value = qaCase('phone-unavailable').snapshot;
    const exportAndroidDiagnostics = vi.fn().mockResolvedValue(undefined);
    render(<App bridge={{ ...createQaBridge(value), exportAndroidDiagnostics }} />);
    const navigation = await screen.findByRole('button', { name: ko.phoneActivity });
    expect(navigation).toBeEnabled();
    fireEvent.click(navigation);
    expect(screen.getByRole('heading', { name: ko.activityUnavailable })).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: ko.exportDiagnostics }));
    await waitFor(() => expect(exportAndroidDiagnostics).toHaveBeenCalledExactlyOnceWith());
  });

  it('suppresses repeated taps while exporting and clears busy after completion', async () => {
    let resolveExport!: () => void;
    const pending = new Promise<void>(resolve => { resolveExport = resolve; });
    const exportAndroidDiagnostics = vi.fn(() => pending);
    render(<App initialPage="activity" bridge={{ ...createQaBridge(exampleSnapshot('android')), exportAndroidDiagnostics }} />);
    const button = await screen.findByRole('button', { name: ko.exportDiagnostics });
    fireEvent.click(button);
    fireEvent.click(button);
    expect(button).toBeDisabled();
    expect(button).toHaveAttribute('aria-busy', 'true');
    await waitFor(() => expect(exportAndroidDiagnostics).toHaveBeenCalledExactlyOnceWith());
    await act(async () => { resolveExport(); await pending; });
    expect(button).toBeEnabled();
    expect(button).toHaveAttribute('aria-busy', 'false');
  });

  it('shows a closed failure, preserves history and permits a successful retry', async () => {
    const value = qaCase('phone-history').snapshot;
    const snapshot = vi.fn().mockResolvedValue(value);
    const exportAndroidDiagnostics = vi.fn().mockRejectedValueOnce(new Error('RAW_PRIVATE_PATH token=secret')).mockResolvedValue(undefined);
    render(<App initialPage="activity" bridge={{ ...createQaBridge(value), snapshot, exportAndroidDiagnostics }} />);
    const history = (await screen.findByRole('list')).textContent;
    const button = screen.getByRole('button', { name: ko.exportDiagnostics });
    fireEvent.click(button);
    expect(await screen.findByText(ko.diagnosticsExportFailure)).toBeInTheDocument();
    expect(screen.queryByText(/RAW_PRIVATE_PATH/u)).not.toBeInTheDocument();
    expect(screen.queryByText(ko.stale)).not.toBeInTheDocument();
    expect(screen.queryByText(ko.diagnosticsExported)).not.toBeInTheDocument();
    expect(screen.getByRole('list').textContent).toBe(history);
    expect(snapshot).toHaveBeenCalledTimes(1);
    expect(button).toBeEnabled();
    fireEvent.click(button);
    expect(await screen.findByText(ko.diagnosticsExported)).toBeInTheDocument();
    expect(screen.queryByText(ko.diagnosticsExportFailure)).not.toBeInTheDocument();
    expect(exportAndroidDiagnostics).toHaveBeenCalledTimes(2);
  });

  it('waits for the active native read to release admission before exporting', async () => {
    const value = exampleSnapshot('android');
    let resolveRead!: (snapshot: typeof value) => void;
    const pending = new Promise<typeof value>(resolve => { resolveRead = resolve; });
    const snapshot = vi.fn().mockResolvedValue(value).mockResolvedValueOnce(value).mockImplementationOnce(() => pending);
    const exportAndroidDiagnostics = vi.fn().mockResolvedValue(undefined);
    render(<App initialPage="activity" bridge={{ ...createQaBridge(value), snapshot, exportAndroidDiagnostics }} />);
    const button = await screen.findByRole('button', { name: ko.exportDiagnostics });
    fireEvent.click(screen.getByRole('button', { name: ko.refresh }));
    fireEvent.click(button);
    expect(exportAndroidDiagnostics).not.toHaveBeenCalled();
    resolveRead(value);
    await waitFor(() => expect(exportAndroidDiagnostics).toHaveBeenCalledExactlyOnceWith());
  });

  it.each(['windows', 'unsupported'] as const)('does not offer export on %s', async platform => {
    const value = { ...exampleSnapshot(), platform };
    render(<App initialPage="activity" bridge={createQaBridge(value)} />);
    await screen.findByRole('heading', { name: platform === 'windows' ? ko.activity : ko.unsupportedTitle });
    expect(screen.queryByRole('button', { name: ko.exportDiagnostics })).not.toBeInTheDocument();
    if (platform === 'windows') expect(screen.getByRole('button', { name: ko.openDiagnosticsFolder })).toBeInTheDocument();
  });

  it('does not expose export when the native bridge cannot load a snapshot', async () => {
    const snapshot = vi.fn().mockRejectedValue(new Error('native bridge unavailable'));
    render(<App bridge={{ ...createQaBridge(exampleSnapshot('android')), snapshot }} />);
    await screen.findByRole('heading', { name: ko.unexpectedTitle });
    expect(screen.queryByRole('button', { name: ko.exportDiagnostics })).not.toBeInTheDocument();
  });

  it.each([false, true])('preserves the snapshot on export completion (failure=%s)', async fails => {
    const value = qaCase('phone-history').snapshot;
    const exportAndroidDiagnostics = vi.fn(() => fails ? Promise.reject(new Error('synthetic export failure')) : Promise.resolve());
    const bridge = { ...createQaBridge(value), exportAndroidDiagnostics };
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => expect(result.current.snapshot).toBe(value));
    await act(async () => { await result.current.run({ kind: 'diagnostics-export' }); });
    expect(result.current.snapshot).toBe(value);
    expect(result.current.stale).toBe(false);
    expect(result.current.busy).toBeNull();
    expect(result.current.error).toBe(fails ? ko.diagnosticsExportFailure : null);
    expect(result.current.notice).toBe(fails ? null : ko.diagnosticsExported);
  });

  it('does not restore request bodies withdrawn while the share screen was opening', async () => {
    const value = qaCase('phone-pending').snapshot;
    let resolveExport!: () => void;
    const pending = new Promise<void>(resolve => { resolveExport = resolve; });
    const bridge = { ...createQaBridge(value), exportAndroidDiagnostics: () => pending };
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => expect(result.current.snapshot?.requests).toHaveLength(1));
    let run!: Promise<unknown>;
    act(() => { run = result.current.run({ kind: 'diagnostics-export' }); });
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      act(() => { document.dispatchEvent(new Event('visibilitychange')); });
      expect(result.current.snapshot?.requests).toHaveLength(0);
      await act(async () => { resolveExport(); await run; });
      expect(result.current.snapshot?.requests).toHaveLength(0);
      expect(result.current.snapshot?.dataAvailability.requests).toBe('unavailable');
      expect(result.current.snapshot?.requestReview).toBeNull();
    } finally { visibility.mockRestore(); }
  });

  it.each(['windows', 'unsupported'] as const)('rejects programmatic export admission on %s', async platform => {
    const value = { ...exampleSnapshot(), platform };
    const exportAndroidDiagnostics = vi.fn().mockResolvedValue(undefined);
    const bridge = { ...createQaBridge(value), exportAndroidDiagnostics };
    const { result } = renderHook(() => useController(bridge));
    await waitFor(() => expect(result.current.snapshot).toEqual(value));
    await act(async () => { await result.current.run({ kind: 'diagnostics-export' }); });
    expect(exportAndroidDiagnostics).not.toHaveBeenCalled();
  });
});
