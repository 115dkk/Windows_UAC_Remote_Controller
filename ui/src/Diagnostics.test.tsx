// SPDX-License-Identifier: GPL-2.0-or-later
// Client proof only: a synthetic bridge is not native Explorer or ACL evidence.
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import { createQaBridge, exampleSnapshot, qaCase } from './qa-fixtures';
import { ko } from './messages';

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
