// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic decision views only: no native authentication, delivery or UAC result.
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, DecisionFeedbackView } from './contracts';
import { decisionCopy, emptyReceiptMemory, nextReceiptMemory, receiptsFor } from './decisionFeedback';
import type { DecisionPhase } from './decisionFeedback';
import { Icon } from './icons';
import type { IconName } from './icons';
import { ko } from './messages';
import { createQaBridge, qaCase } from './qa-fixtures';

const program = '설정 도우미.exe';
const path = 'C:\\Program Files\\화면 예시\\설정 도우미.exe';

function view(id: string, action: DecisionFeedbackView['action'], phase: DecisionPhase): DecisionFeedbackView {
  return { id, action, phase, elapsedMillis: 900, authenticationMillis: null, afterAuthenticationMillis: null, timingAvailable: false };
}
function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((done) => { resolve = done; });
  return { promise, resolve };
}
function iconMarkup(name: IconName): string {
  const { container, unmount } = render(<Icon name={name} />);
  const markup = container.querySelector('svg')!.innerHTML;
  unmount();
  return markup;
}

// Pinned copy and icon per phase (Korean catalogue values are what the user sees).
const expected: readonly { fixture: string; phase: DecisionPhase; title: string; body: string; icon: IconName; listed: boolean }[] = [
  { fixture: 'phone-decision-authenticating', phase: 'authenticating', title: '승인을 선택했습니다', body: '본인 확인을 진행하십시오.', icon: 'clock', listed: true },
  { fixture: 'phone-decision-preparing', phase: 'preparing', title: '거부를 선택했습니다', body: 'PC로 보내는 중입니다.', icon: 'clock', listed: true },
  { fixture: 'phone-decision-sending', phase: 'sending', title: '거부를 선택했습니다', body: 'PC로 보내는 중입니다.', icon: 'clock', listed: true },
  { fixture: 'phone-decision-awaiting-pc', phase: 'awaiting_pc', title: '승인을 보냈습니다', body: 'PC의 처리 결과를 기다리는 중입니다.', icon: 'clock', listed: true },
  { fixture: 'phone-decision-authentication-cancelled', phase: 'authentication_cancelled', title: '본인 확인을 취소했습니다', body: '요청이 남아 있으면 다시 선택할 수 있습니다.', icon: 'lock', listed: true },
  { fixture: 'phone-decision-approved', phase: 'approved', title: 'PC에서 승인했습니다', body: 'PC가 승인을 적용했습니다.', icon: 'check', listed: false },
  { fixture: 'phone-decision-denied', phase: 'denied', title: 'PC에서 거부했습니다', body: 'PC가 요청을 취소했습니다.', icon: 'close', listed: false },
  { fixture: 'phone-decision-failed', phase: 'failed', title: 'PC에서 처리하지 못했습니다', body: 'PC 화면에서 요청 창을 확인하십시오.', icon: 'alert', listed: false },
  { fixture: 'phone-decision-cancelled', phase: 'cancelled', title: 'PC에서 요청이 닫혔습니다', body: 'PC에서 직접 처리했거나 요청한 프로그램이 창을 닫았습니다.', icon: 'pc', listed: false },
  { fixture: 'phone-decision-expired', phase: 'expired', title: '요청 시간이 지났습니다', body: '필요하면 PC에서 다시 요청하십시오.', icon: 'alert', listed: false },
  { fixture: 'phone-decision-pc-completed', phase: 'pc_completed', title: 'PC에서 처리를 마쳤습니다', body: 'PC가 요청을 끝냈지만 승인 여부는 알려 주지 않았습니다.', icon: 'pc', listed: false },
  { fixture: 'phone-decision-local-unconfirmed', phase: 'local_unconfirmed', title: 'PC의 결과를 아직 확인하지 못했습니다', body: '선택이 PC에 전달되었는지 확인하지 못했습니다. 요청이 남아 있으면 다시 선택할 수 있습니다.', icon: 'alert', listed: false },
];

describe('decision phases', () => {
  it.each(expected)('$phase shows its title, body and icon where the request is', async ({ fixture, phase, title, body, icon, listed }) => {
    const markup = iconMarkup(icon);
    const { container } = render(<App bridge={createQaBridge(qaCase(fixture).snapshot)} />);
    const heading = await screen.findByText(title);
    const shown = container.querySelector<HTMLElement>(`[data-phase="${phase}"]`)!;
    expect(shown).toContainElement(heading);
    expect(within(shown).getByText(body)).toBeVisible();
    expect(shown.querySelector('svg')!.innerHTML).toBe(markup);
    // The phase is text inside a live region, with the icon only beside it.
    expect(shown.closest('[role="status"]')).not.toBeNull();
    if (listed) {
      const card = screen.getByRole('article');
      expect(card).toContainElement(shown);
      expect(within(card).getByRole('heading', { name: program })).toBeVisible();
      expect(container.querySelector('.decision-receipt')).toBeNull();
    } else {
      expect(screen.queryByRole('article')).not.toBeInTheDocument();
      expect(shown).toHaveClass('decision-receipt');
      expect(within(shown).getByRole('button', { name: '확인' })).toBeEnabled();
      // A receipt keeps no program name, path or computer name.
      expect(container.textContent).not.toContain(program);
      expect(container.textContent).not.toContain(path);
      expect(container.textContent).not.toContain('화면 예시 PC');
    }
  });

  it('keeps success styling for the PC-authenticated approval alone', () => {
    const phases: readonly DecisionPhase[] = ['authenticating', 'preparing', 'sending', 'awaiting_pc', 'authentication_cancelled',
      'local_unconfirmed', 'approved', 'denied', 'failed', 'cancelled', 'expired', 'pc_completed'];
    for (const phase of phases) for (const action of ['approve', 'deny'] as const) {
      expect(decisionCopy(action, phase).tone === 'success', `${action}/${phase}`).toBe(phase === 'approved');
    }
  });

  it.each(expected)('$phase draws no success colour unless it is the approval', async ({ fixture, phase }) => {
    const { container } = render(<App bridge={createQaBridge(qaCase(fixture).snapshot)} />);
    await screen.findByRole('button', { name: ko.refresh });
    const shown = container.querySelector(`[data-phase="${phase}"]`)!;
    expect(shown.classList.contains('tone-success')).toBe(phase === 'approved');
    expect(container.querySelectorAll('.tone-success')).toHaveLength(phase === 'approved' ? 1 : 0);
  });

  it('keeps the existing approve and deny rules on a still-listed card', async () => {
    const cancelled = render(<App bridge={createQaBridge(qaCase('phone-decision-authentication-cancelled').snapshot)} />);
    expect(await screen.findByRole('button', { name: ko.approve })).toBeEnabled();
    expect(screen.getByRole('button', { name: ko.deny })).toBeEnabled();
    cancelled.unmount();
    render(<App bridge={createQaBridge(qaCase('phone-decision-awaiting-pc').snapshot)} />);
    expect(await screen.findByRole('button', { name: ko.approve })).toBeDisabled();
    expect(screen.getByRole('button', { name: ko.deny })).toBeDisabled();
  });

  it('confirms the tap on the next frame, before the bridge replies', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const reply = deferred<AppSnapshot>();
    const decide = vi.fn<ControllerBridge['decide']>(() => reply.promise);
    render(<App bridge={{ ...createQaBridge(snapshot), decide }} />);
    fireEvent.click(await screen.findByRole('button', { name: ko.deny }));
    expect(decide).toHaveBeenCalledExactlyOnceWith('synthetic-request-1', 'deny');
    const card = screen.getByRole('article');
    expect(within(card).getByText('거부를 선택했습니다')).toBeVisible();
    expect(within(card).getByText('PC로 보내는 중입니다.')).toBeVisible();
    // The card says it; the generic line does not repeat it.
    expect(screen.queryByText(ko.pending)).not.toBeInTheDocument();
    expect(card.querySelector('.tone-success')).toBeNull();
    await act(async () => { reply.resolve({ ...snapshot, requestCatalog: { ...snapshot.requestCatalog!,
      decisions: [view('synthetic-request-1', 'deny', 'awaiting_pc')] },
    requests: snapshot.requests.map((request) => ({ ...request, state: 'awaiting_outcome' as const, canApprove: false, canDeny: false })) });
    await reply.promise; });
    expect(within(screen.getByRole('article')).getByText('거부를 보냈습니다')).toBeVisible();
  });

  it('shows the approval tap as the identity check it starts', async () => {
    const snapshot = qaCase('phone-pending').snapshot;
    const reply = deferred<AppSnapshot>();
    render(<App bridge={{ ...createQaBridge(snapshot), decide: () => reply.promise }} />);
    fireEvent.click(await screen.findByRole('button', { name: ko.approve }));
    const card = screen.getByRole('article');
    expect(within(card).getByText('승인을 선택했습니다')).toBeVisible();
    expect(within(card).getByText('본인 확인을 진행하십시오.')).toBeVisible();
    await act(async () => { reply.resolve(snapshot); await reply.promise; });
  });

  it('keeps a finished request as a receipt until 확인, and never brings it back', async () => {
    const user = userEvent.setup();
    const initial = qaCase('phone-decision-awaiting-pc').snapshot;
    const finished: AppSnapshot = { ...initial, requests: [],
      requestCatalog: { ...initial.requestCatalog!, decisions: [view('synthetic-request-1', 'approve', 'approved')] } };
    // The native owner may stop reporting a finished view; the receipt stays.
    const forgotten: AppSnapshot = { ...finished, requestCatalog: { ...finished.requestCatalog!, decisions: [] } };
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce(initial).mockResolvedValueOnce(finished)
      .mockResolvedValueOnce(forgotten).mockResolvedValue(finished);
    const { container } = render(<App bridge={{ ...createQaBridge(initial), snapshot: read }} />);
    expect(await screen.findByText('승인을 보냈습니다')).toBeVisible();
    const live = container.querySelector('.decision-receipts')!;
    expect(live).toHaveAttribute('role', 'status');
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    const receipt = await screen.findByRole('region', { name: 'PC에서 승인했습니다' });
    expect(live).toContainElement(receipt);
    expect(receipt).toHaveTextContent('PC가 승인을 적용했습니다.');
    expect(container.textContent).not.toContain(program);
    expect(container.textContent).not.toContain(path);
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(await screen.findByRole('region', { name: 'PC에서 승인했습니다' })).toBeVisible();
    await user.click(within(receipt).getByRole('button', { name: '확인' }));
    expect(screen.queryByRole('region', { name: 'PC에서 승인했습니다' })).not.toBeInTheDocument();
    expect(screen.getByRole('heading', { level: 1 })).toHaveFocus();
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    await screen.findByRole('heading', { name: ko.requestEmpty });
    expect(screen.queryByRole('region', { name: 'PC에서 승인했습니다' })).not.toBeInTheDocument();
  });

  it('moves on from finished receipts when another request is chosen or opened for review', async () => {
    const pending = qaCase('phone-pending').snapshot;
    const withReceipt: AppSnapshot = { ...pending, requestCatalog: { ...pending.requestCatalog!,
      decisions: [view('synthetic-request-0', 'deny', 'denied')] } };
    const first = render(<App bridge={{ ...createQaBridge(withReceipt), decide: () => new Promise<AppSnapshot>(() => undefined) }} />);
    expect(await screen.findByRole('region', { name: 'PC에서 거부했습니다' })).toBeVisible();
    fireEvent.click(screen.getByRole('button', { name: ko.approve }));
    expect(screen.queryByRole('region', { name: 'PC에서 거부했습니다' })).not.toBeInTheDocument();
    first.unmount();

    const reviewed: AppSnapshot = { ...withReceipt, requestReview: { locator: 'synthetic-request-1', revision: '4' } };
    const read = vi.fn<ControllerBridge['snapshot']>().mockResolvedValueOnce({ ...withReceipt, requests: [] }).mockResolvedValue(reviewed);
    const user = userEvent.setup();
    render(<App bridge={{ ...createQaBridge(withReceipt), snapshot: read }} />);
    expect(await screen.findByRole('region', { name: 'PC에서 거부했습니다' })).toBeVisible();
    await user.click(screen.getByRole('button', { name: ko.refresh }));
    expect(await screen.findByRole('heading', { name: program })).toBeVisible();
    expect(screen.queryByRole('region', { name: 'PC에서 거부했습니다' })).not.toBeInTheDocument();
  });
});

describe('receipt memory', () => {
  it('keeps what can no longer change and drops a stage the owner stopped reporting', () => {
    const base = qaCase('phone-empty').snapshot;
    const reported = (decisions: readonly DecisionFeedbackView[]): AppSnapshot => ({ ...base, requestCatalog: { ...base.requestCatalog!, decisions } });
    let memory = nextReceiptMemory(emptyReceiptMemory, reported([view('a', 'approve', 'approved'), view('b', 'deny', 'awaiting_pc')]));
    expect(receiptsFor(memory, base).receipts.map((item) => item.id)).toEqual(['b', 'a']);
    memory = nextReceiptMemory(memory, reported([]));
    expect(receiptsFor(memory, base).receipts.map((item) => item.id)).toEqual(['a']);
    // No report at all (an older owner or an unread catalogue) changes nothing.
    memory = nextReceiptMemory(memory, { ...base, requestCatalog: null });
    expect(receiptsFor(memory, base).receipts.map((item) => item.id)).toEqual(['a']);
    memory = nextReceiptMemory(memory, reported([view('a', 'approve', 'failed')]));
    expect(receiptsFor(memory, base).byId.get('a')?.phase).toBe('failed');
  });
});
