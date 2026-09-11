// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic client contract checks, not OS notification/authentication evidence.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, RequestDetailsView, RequestView } from './contracts';
import { ko } from './messages.ko';
import { createQaBridge, qaCase } from './qa-fixtures';
import { ageRequestPresentation } from './requestPresentation';

function pending() { return qaCase('phone-pending').snapshot; }
function view(snapshot: AppSnapshot, overrides: Partial<ControllerBridge> = {}) {
  const bridge = { ...createQaBridge(snapshot), ...overrides };
  return { bridge, ...render(<App bridge={bridge} />) };
}

describe('native request presentation integration', () => {
  it('loads original details only on disclosure and does not confuse review with approval', async () => {
    const snapshot = pending();
    const original = createQaBridge(snapshot);
    const requestDetails = vi.fn((id: string) => original.requestDetails(id));
    const decide = vi.fn<ControllerBridge['decide']>(() => Promise.resolve(snapshot));
    const user = userEvent.setup();
    view(snapshot, { requestDetails, decide });
    await screen.findByRole('button', { name: ko.details });
    expect(requestDetails).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: ko.details }));
    expect(await screen.findByText(/화면 확인을 위한 예시 문자열/u)).toBeInTheDocument();
    expect(requestDetails).toHaveBeenCalledExactlyOnceWith('synthetic-request-1');
    expect(decide).not.toHaveBeenCalled();
  });

  it('does not relabel waiting or delivery as expiry or Windows success', async () => {
    const states: readonly [RequestView['state'], string][] = [
      ['waiting', ko.requestWaiting], ['sending', ko.sending], ['awaiting_outcome', ko.awaitingOutcome],
    ];
    for (const [state, copy] of states) {
      const initial = pending();
      const snapshot = { ...initial, requests: initial.requests.map((request) => ({ ...request, state, canApprove: false, canDeny: false })) };
      const rendered = view(snapshot);
      const phase = await screen.findByText(copy);
      expect(phase).toBeInTheDocument();
      expect(phase.compareDocumentPosition(rendered.container.querySelector('.path-output')!)).toBe(Node.DOCUMENT_POSITION_FOLLOWING);
      expect(screen.queryByText(ko.requestIntro)).not.toBeInTheDocument();
      expect(screen.queryByText(ko.expired)).not.toBeInTheDocument();
      expect(screen.queryByText('요청 승인됨')).not.toBeInTheDocument();
      rendered.unmount();
    }
  });

  it('can request denial during authentication when native exposes it', async () => {
    const initial = pending();
    const snapshot = { ...initial, requests: initial.requests.map((request) => ({ ...request, state: 'authenticating' as const, canApprove: false })) };
    const decide = vi.fn<ControllerBridge['decide']>(() => Promise.resolve(snapshot));
    const user = userEvent.setup();
    view(snapshot, { decide });
    expect(await screen.findByRole('button', { name: ko.approve })).toBeDisabled();
    await user.click(screen.getByRole('button', { name: ko.deny }));
    expect(decide).toHaveBeenCalledExactlyOnceWith('synthetic-request-1', 'deny');
  });

  it('rejects a late details response for another locator and hides raw exceptions', async () => {
    const snapshot = pending();
    const requestDetails = vi.fn<ControllerBridge['requestDetails']>().mockResolvedValue({
      version: 1, id: 'other-locator', programName: 'private', executablePath: 'private', details: 'PRIVATE_WRONG_REQUEST', remainingSeconds: 20, refreshAfterMillis: 1000,
    });
    const user = userEvent.setup();
    view(snapshot, { requestDetails });
    await user.click(await screen.findByRole('button', { name: ko.details }));
    expect(await screen.findByText(ko.detailsUnavailable)).toBeInTheDocument();
    expect(screen.queryByText('PRIVATE_WRONG_REQUEST')).not.toBeInTheDocument();
    requestDetails.mockRejectedValue(new Error('RAW_NATIVE_ERROR'));
    await user.click(screen.getByRole('button', { name: ko.detailsRefresh }));
    expect(await screen.findByText(ko.detailsUnavailable)).toBeInTheDocument();
    expect(screen.queryByText('RAW_NATIVE_ERROR')).not.toBeInTheDocument();
  });

  it('does not publish a details response after disclosure was closed', async () => {
    let resolve!: (value: RequestDetailsView) => void;
    const response = new Promise<RequestDetailsView>((done) => { resolve = done; });
    const user = userEvent.setup();
    view(pending(), { requestDetails: () => response });
    await user.click(await screen.findByRole('button', { name: ko.details }));
    expect(await screen.findByText(ko.detailsLoading)).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.fewerDetails }));
    await act(async () => { resolve({ version: 1, id: 'synthetic-request-1', programName: '', executablePath: '', details: 'LATE_BODY', remainingSeconds: 20, refreshAfterMillis: 1000 }); await response; });
    expect(screen.queryByText('LATE_BODY')).not.toBeInTheDocument();
    expect(screen.queryByRole('region', { name: ko.commandDetails })).not.toBeInTheDocument();
  });

  it('sticky notification review navigates once and never auto-approves', async () => {
    const initial = pending();
    const snapshot = { ...initial, requestReview: { locator: 'synthetic-request-1', revision: '18446744073709551615' } };
    const decide = vi.fn<ControllerBridge['decide']>(() => Promise.resolve(snapshot));
    const bridge = { ...createQaBridge(snapshot), decide };
    const user = userEvent.setup();
    render(<App bridge={bridge} initialPage="schedule" />);
    expect(await screen.findByRole('region', { name: ko.commandDetails })).toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.schedule }));
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(screen.getByRole('heading', { name: ko.schedule })).toBeInTheDocument();
    expect(decide).not.toHaveBeenCalled();
  });

  it('shows empty requests alongside connection state, but not during reconciliation', async () => {
    const states = [
      { status: 'ready' as const, peerCount: 0, connectedPeerCount: 0, title: ko.noComputers },
      { status: 'ready' as const, peerCount: 1, connectedPeerCount: 0, title: ko.requestDisconnected },
      { status: 'reconciling' as const, peerCount: 1, connectedPeerCount: 1, title: ko.requestReconciling },
    ];
    for (const { title, ...catalog } of states) {
      const rendered = view({ ...pending(), requests: [], requestCatalog: { ...catalog, revision: '1' } });
      expect(await screen.findByRole('heading', { name: title })).toBeInTheDocument();
      if (catalog.status === 'ready') expect(screen.getByText(ko.requestEmpty)).toBeInTheDocument();
      else expect(screen.queryByText(ko.requestEmpty)).not.toBeInTheDocument();
      rendered.unmount();
    }
  });

  it('brings the selected notification request first and keeps recovery on that page after withdrawal', async () => {
    const initial = pending();
    const first = initial.requests[0]!;
    const selected = { ...first, id: 'synthetic-second-request', programName: '두 번째 요청' };
    const snapshot = { ...initial, requests: [first, selected], requestReview: { locator: selected.id, revision: '2' } };
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(snapshot)
      .mockResolvedValue({ ...initial, requests: [], requestReview: null });
    const bridge = { ...createQaBridge(snapshot), snapshot: read };
    const user = userEvent.setup();
    const rendered = render(<App bridge={bridge} initialPage="schedule" />);
    const heading = await screen.findByRole('heading', { name: '두 번째 요청' });
    // Presence can precede RequestCard's passive focus effect. Await the exact
    // selected heading's focus, not an arbitrary delay or only DOM visibility.
    await waitFor(() => {
      expect(heading).toBeInTheDocument();
      expect(heading).toHaveFocus();
    });
    expect(rendered.container.querySelector('article h2')).toHaveTextContent('두 번째 요청');
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(await screen.findByRole('heading', { name: ko.requestEmpty })).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: ko.schedule })).not.toBeInTheDocument();
  });

  it('rechecks elapsed display time at click even if a timer has not run yet', async () => {
    let now = 0;
    const clock = vi.spyOn(performance, 'now').mockImplementation(() => now);
    try {
      const initial = pending();
      const decide = vi.fn<ControllerBridge['decide']>(() => Promise.resolve(initial));
      view(initial, { decide });
      const button = await screen.findByRole('button', { name: ko.approve });
      now = 30000;
      fireEvent.click(button);
      expect(decide).not.toHaveBeenCalled();
    } finally { clock.mockRestore(); }
  });

  it('subtracts bridge latency without extending display validity or declaring expiry', () => {
    const initial = pending();
    const aged = ageRequestPresentation(initial, 50);
    expect(aged.requests[0]?.refreshAfterMillis).toBe(29950);
    for (const elapsed of [30000, 31000, NaN, -1]) {
      const stale = ageRequestPresentation(initial, elapsed);
      expect(stale.requests).toHaveLength(0);
      expect(stale.dataAvailability.requests).toBe('unavailable');
      expect(stale.requestReview).toBeNull();
      expect(stale.activity).toEqual(initial.activity);
    }
  });
});
