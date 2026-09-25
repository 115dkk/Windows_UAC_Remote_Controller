// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic client contract checks, not OS notification/authentication evidence.
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, RequestDetailsView, RequestView } from './contracts';
import { ko } from './messages';
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

  it('reads the details again when their minute ends instead of reporting a failure', async () => {
    const body = (details: string, refreshAfterMillis: number): RequestDetailsView => ({
      version: 1, id: 'synthetic-request-1', programName: '', executablePath: '', details, remainingSeconds: 40, refreshAfterMillis });
    const requestDetails = vi.fn<ControllerBridge['requestDetails']>()
      // Long enough to be observed under a loaded test run, short of findBy's one-second wait.
      .mockResolvedValueOnce(body('FIRST_MINUTE', 400))
      .mockResolvedValue(body('NEXT_MINUTE', 30000));
    const user = userEvent.setup();
    view(pending(), { requestDetails });
    await user.click(await screen.findByRole('button', { name: ko.details }));
    expect(await screen.findByText('FIRST_MINUTE')).toBeInTheDocument();
    expect(await screen.findByText('NEXT_MINUTE')).toBeInTheDocument();
    expect(screen.queryByText('FIRST_MINUTE')).not.toBeInTheDocument();
    expect(screen.queryByText(ko.detailsUnavailable)).not.toBeInTheDocument();
    expect(requestDetails).toHaveBeenCalledTimes(2);
  });

  it('withdraws the details in the background and reads them again when opened on return', async () => {
    const original = createQaBridge(pending());
    const requestDetails = vi.fn((id: string) => original.requestDetails(id));
    const user = userEvent.setup();
    view(pending(), { requestDetails });
    await user.click(await screen.findByRole('button', { name: ko.details }));
    expect(await screen.findByText(/화면 확인을 위한 예시 문자열/u)).toBeInTheDocument();
    const visibility = vi.spyOn(document, 'visibilityState', 'get').mockReturnValue('hidden');
    try {
      act(() => { document.dispatchEvent(new Event('visibilitychange')); });
      expect(screen.queryByText(/화면 확인을 위한 예시 문자열/u)).not.toBeInTheDocument();
      visibility.mockReturnValue('visible');
      act(() => { document.dispatchEvent(new Event('visibilitychange')); });
      // The request comes back with its details closed, not as a failure.
      await user.click(await screen.findByRole('button', { name: ko.details }));
      expect(await screen.findByText(/화면 확인을 위한 예시 문자열/u)).toBeInTheDocument();
    } finally {
      visibility.mockRestore();
    }
    expect(screen.queryByText(ko.detailsUnavailable)).not.toBeInTheDocument();
    expect(requestDetails).toHaveBeenCalledTimes(2);
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
      { status: 'reconciling' as const, peerCount: 1, connectedPeerCount: 1, title: ko.requestReconciling },
    ];
    for (const { title, ...catalog } of states) {
      const rendered = view({ ...pending(), requests: [], requestCatalog: { ...catalog, revision: '1' } });
      expect(await screen.findByRole('heading', { name: title })).toBeInTheDocument();
      if (catalog.status === 'ready') expect(screen.getByText(ko.requestEmpty)).toBeInTheDocument();
      else expect(screen.queryByText(ko.requestEmpty)).not.toBeInTheDocument();
      rendered.unmount();
    }
    // A fresh disconnection is a progress row beside the empty list, not a notice.
    const rendered = view({ ...pending(), requests: [], requestCatalog: { status: 'ready', revision: '1', peerCount: 1, connectedPeerCount: 0 } });
    expect(await screen.findByText('PC에 연결하는 중')).toBeInTheDocument();
    expect(screen.getByText(ko.requestEmpty)).toBeInTheDocument();
    expect(screen.queryByRole('heading', { name: 'PC에 연결하지 못했습니다' })).not.toBeInTheDocument();
    rendered.unmount();
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

  it('renews the display lease before it ends, and still withdraws on time when no answer comes', async () => {
    const initial = pending();
    const short = { ...initial, requests: initial.requests.map((request) => ({ ...request, refreshAfterMillis: 1400 })) };
    let answer: (value: AppSnapshot) => void = () => {};
    const reads = vi.fn<ControllerBridge['snapshot']>()
      .mockResolvedValueOnce(short)
      .mockImplementationOnce(() => new Promise<AppSnapshot>((resolve) => { answer = resolve; }))
      .mockResolvedValue(short);
    view(short, { snapshot: reads });
    await screen.findByText('설정 도우미.exe');
    // The lead starts the next read while the current lease still holds, so the
    // request is on screen at the moment it is asked for again. Withdrawing
    // first and asking afterwards is what made it vanish and come back.
    await waitFor(() => { expect(reads).toHaveBeenCalledTimes(2); }, { timeout: 1200 });
    expect(screen.getByText('설정 도우미.exe')).toBeInTheDocument();
    // A read that never answers extends nothing. The lease is still the lease.
    expect(await screen.findByText(ko.requestUnavailable, {}, { timeout: 2000 })).toBeInTheDocument();
    await act(() => { answer(short); return Promise.resolve(); });
  });

  // Native catalogue changes arrive as an empty wake. On 1.5.0 the wake never
  // reached the page, and the card waited for the five-second periodic read.
  function wakeable() {
    const wake = { notify: () => undefined as void };
    const watchRequests: ControllerBridge['watchRequests'] = (notify) => {
      wake.notify = notify;
      return Promise.resolve(() => Promise.resolve());
    };
    return { wake, watchRequests };
  }
  const settled = () => screen.findByRole('button', { name: ko.refresh });
  const busyOwner = { code: 'app_busy', message: '앱이 다른 작업을 처리하는 중입니다.', nextAction: '잠시 후 다시 시도하십시오.' };

  it('shows a request the native owner announces without waiting for the periodic read', async () => {
    const empty = { ...pending(), requests: [] };
    const { wake, watchRequests } = wakeable();
    const reads = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(empty).mockResolvedValue(pending());
    view(empty, { snapshot: reads, watchRequests });
    expect(await screen.findByRole('heading', { name: ko.requestEmpty })).toBeInTheDocument();
    await settled();
    act(() => { wake.notify(); });
    expect(await screen.findByText('설정 도우미.exe', {}, { timeout: 500 })).toBeInTheDocument();
    expect(reads).toHaveBeenCalledTimes(2);
  });

  it('reads again for a wake that arrives while another read is still running', async () => {
    const empty = { ...pending(), requests: [] };
    const { wake, watchRequests } = wakeable();
    let answer: (value: AppSnapshot) => void = () => {};
    const reads = vi.fn<ControllerBridge['snapshot']>()
      .mockResolvedValueOnce(empty)
      .mockImplementationOnce(() => new Promise<AppSnapshot>((resolve) => { answer = resolve; }))
      .mockResolvedValue(pending());
    view(empty, { snapshot: reads, watchRequests });
    await settled();
    act(() => { wake.notify(); });
    await waitFor(() => { expect(reads).toHaveBeenCalledTimes(2); });
    // This read may already have passed the catalogue when the request landed.
    act(() => { wake.notify(); });
    expect(reads).toHaveBeenCalledTimes(2);
    await act(async () => { answer(empty); await Promise.resolve(); });
    expect(await screen.findByText('설정 도우미.exe', {}, { timeout: 500 })).toBeInTheDocument();
    expect(reads).toHaveBeenCalledTimes(3);
  });

  it('keeps the request on screen when a wake finds the owner busy, and still reports it on an explicit refresh', async () => {
    const shown = pending();
    const busy: AppSnapshot = { ...shown, requests: [], requestCatalog: null, issue: busyOwner,
      dataAvailability: { ...shown.dataAvailability, requests: 'unavailable' } };
    const { wake, watchRequests } = wakeable();
    const reads = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(shown).mockResolvedValue(busy);
    const user = userEvent.setup();
    view(shown, { snapshot: reads, watchRequests });
    await screen.findByText('설정 도우미.exe');
    await settled();
    act(() => { wake.notify(); });
    await waitFor(() => { expect(reads).toHaveBeenCalledTimes(2); });
    await settled();
    expect(screen.getByText('설정 도우미.exe')).toBeInTheDocument();
    expect(screen.queryByText(/앱이 다른 작업을 처리하는 중/u)).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(await screen.findByText(/앱이 다른 작업을 처리하는 중/u)).toBeInTheDocument();
  });

  it('reads details after the snapshot read that holds the native admission instead of failing', async () => {
    const shown = pending();
    const original = createQaBridge(shown);
    const { wake, watchRequests } = wakeable();
    let holding = false;
    let answer: (value: AppSnapshot) => void = () => {};
    const reads = vi.fn<ControllerBridge['snapshot']>()
      .mockResolvedValueOnce(shown)
      .mockImplementationOnce(() => {
        holding = true;
        return new Promise<AppSnapshot>((resolve) => { answer = (value) => { holding = false; resolve(value); }; });
      })
      .mockResolvedValue(shown);
    // The native command admission refuses a second command while a read holds it.
    const requestDetails = vi.fn((id: string) => holding
      ? Promise.reject(Object.assign(new Error('busy'), { code: 'app_busy' })) : original.requestDetails(id));
    const user = userEvent.setup();
    view(shown, { snapshot: reads, requestDetails, watchRequests });
    await screen.findByRole('button', { name: ko.details });
    await settled();
    act(() => { wake.notify(); });
    await waitFor(() => { expect(reads).toHaveBeenCalledTimes(2); });
    await user.click(screen.getByRole('button', { name: ko.details }));
    expect(await screen.findByText(ko.detailsLoading)).toBeInTheDocument();
    expect(requestDetails).not.toHaveBeenCalled();
    await act(async () => { answer(shown); await Promise.resolve(); });
    expect(await screen.findByText(/화면 확인을 위한 예시 문자열/u)).toBeInTheDocument();
    expect(requestDetails).toHaveBeenCalledExactlyOnceWith('synthetic-request-1');
    expect(screen.queryByText(ko.detailsUnavailable)).not.toBeInTheDocument();
  });

  it('opens a notification review with its details once, while the next read still holds the admission', async () => {
    const shown = pending();
    const reviewed = { ...shown, requestReview: { locator: 'synthetic-request-1', revision: '7' } };
    const original = createQaBridge(reviewed);
    const { wake, watchRequests } = wakeable();
    let holding = false;
    let answerReview: (value: AppSnapshot) => void = () => {};
    let answerNext: (value: AppSnapshot) => void = () => {};
    const held = (store: (answer: (value: AppSnapshot) => void) => void) => () => {
      holding = true;
      return new Promise<AppSnapshot>((resolve) => { store((value) => { holding = false; resolve(value); }); });
    };
    const reads = vi.fn<ControllerBridge['snapshot']>()
      .mockResolvedValueOnce(shown)
      .mockImplementationOnce(held((answer) => { answerReview = answer; }))
      .mockImplementationOnce(held((answer) => { answerNext = answer; }))
      .mockResolvedValue(reviewed);
    const requestDetails = vi.fn((id: string) => holding
      ? Promise.reject(Object.assign(new Error('busy'), { code: 'app_busy' })) : original.requestDetails(id));
    view(shown, { snapshot: reads, requestDetails, watchRequests });
    await settled();
    // The native review and its action reply each send a wake.
    act(() => { wake.notify(); });
    await waitFor(() => { expect(reads).toHaveBeenCalledTimes(2); });
    act(() => { wake.notify(); });
    await act(async () => { answerReview(reviewed); await Promise.resolve(); });
    expect(await screen.findByRole('region', { name: ko.commandDetails })).toBeInTheDocument();
    await waitFor(() => { expect(reads).toHaveBeenCalledTimes(3); });
    expect(requestDetails).not.toHaveBeenCalled();
    await act(async () => { answerNext(reviewed); await Promise.resolve(); });
    expect(await screen.findByText(/화면 확인을 위한 예시 문자열/u)).toBeInTheDocument();
    expect(requestDetails).toHaveBeenCalledExactlyOnceWith('synthetic-request-1');
    expect(screen.queryByText(ko.detailsUnavailable)).not.toBeInTheDocument();
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
