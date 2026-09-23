// SPDX-License-Identifier: GPL-2.0-or-later
// Body-free decision feedback. A receipt carries the chosen action and the PC's
// result only: no program name, path or computer name is kept for it.
import { useEffect, useId, useRef } from 'react';
import type { DecisionFeedbackView } from './contracts';
import { decisionCopy } from './decisionFeedback';
import type { DecisionAction, DecisionPhase } from './decisionFeedback';
import { Icon } from './icons';
import { tr } from './i18n';

/** Inside a request card that is still listed; the card owns the live region. */
export function DecisionPhaseLine({ action, phase }: { action: DecisionAction; phase: DecisionPhase }) {
  const copy = decisionCopy(action, phase);
  return <div className={`decision-phase tone-${copy.tone}`} data-phase={phase}>
    <Icon name={copy.icon} />
    <div><p className="decision-title">{tr(copy.title)}</p><p className="decision-body">{tr(copy.body)}</p></div>
  </div>;
}

function Receipt({ view, onDismiss }: { view: DecisionFeedbackView; onDismiss: (id: string) => void }) {
  const titleId = useId();
  const copy = decisionCopy(view.action, view.phase);
  return <section className={`notice-box decision-receipt tone-${copy.tone}`} aria-labelledby={titleId} data-phase={view.phase}>
    <Icon name={copy.icon} />
    <div>
      <h2 id={titleId}>{tr(copy.title)}</h2>
      <p>{tr(copy.body)}</p>
      <button type="button" className="button secondary" data-receipt={view.id} onClick={() => onDismiss(view.id)}>{tr('확인')}</button>
    </div>
  </section>;
}

/**
 * Receipts of requests that have left the list. The live region stays mounted
 * on the requests page, so a result that arrives as its card disappears is
 * announced once, and so is each later phase change.
 */
export function DecisionReceipts({ receipts, onDismiss }: { receipts: readonly DecisionFeedbackView[]; onDismiss: (id: string) => void }) {
  const list = useRef<HTMLDivElement>(null);
  const focusAfter = useRef<string | null | undefined>(undefined);
  useEffect(() => {
    const target = focusAfter.current;
    if (target === undefined) return;
    focusAfter.current = undefined;
    const next = [...(list.current?.querySelectorAll<HTMLButtonElement>('button[data-receipt]') ?? [])]
      .find((button) => button.dataset['receipt'] === target);
    (next ?? document.querySelector<HTMLElement>('#main-content h1'))?.focus();
  }, [receipts]);
  function dismiss(id: string) {
    // Keep keyboard users in place: the next receipt, else the page heading.
    const index = receipts.findIndex((view) => view.id === id);
    focusAfter.current = (receipts[index + 1] ?? receipts[index - 1])?.id ?? null;
    onDismiss(id);
  }
  return <div ref={list} className="decision-receipts" role="status" aria-atomic="false">
    {receipts.map((view) => <Receipt key={view.id} view={view} onDismiss={dismiss} />)}
  </div>;
}
