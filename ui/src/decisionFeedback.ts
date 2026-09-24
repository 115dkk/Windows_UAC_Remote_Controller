// SPDX-License-Identifier: GPL-2.0-or-later
// Presentation of the native, body-free decision views. Nothing here admits,
// signs, resends or expires a request; the native owners decide all of that.
import { useCallback, useState } from 'react';
import type { AppSnapshot, DecisionFeedbackView, RequestView } from './contracts';
import type { IconName } from './icons';

export type DecisionAction = DecisionFeedbackView['action'];
export type DecisionPhase = DecisionFeedbackView['phase'];
/** `success` is reserved for the PC's authenticated approval. */
export type DecisionTone = 'progress' | 'success' | 'neutral' | 'warning' | 'danger';
export interface DecisionCopy {
  /** Korean catalogue keys; render through tr(). */
  readonly title: string;
  readonly body: string;
  readonly icon: IconName;
  readonly tone: DecisionTone;
}

const inProgress: ReadonlySet<DecisionPhase> = new Set(['authenticating', 'preparing', 'sending', 'awaiting_pc']);
export const isDecisionInProgress = (phase: DecisionPhase): boolean => inProgress.has(phase);

/** The pinned copy, one catalogue key per action-dependent line. */
export function decisionCopy(action: DecisionAction, phase: DecisionPhase): DecisionCopy {
  const approve = action === 'approve';
  switch (phase) {
    case 'authenticating': return { title: '승인을 선택했습니다', body: '본인 확인을 진행하십시오.', icon: 'clock', tone: 'progress' };
    case 'preparing': case 'sending': return { title: approve ? '승인을 선택했습니다' : '거부를 선택했습니다',
      body: 'PC로 보내는 중입니다.', icon: 'clock', tone: 'progress' };
    case 'awaiting_pc': return { title: approve ? '승인을 보냈습니다' : '거부를 보냈습니다',
      body: 'PC의 처리 결과를 기다리는 중입니다.', icon: 'clock', tone: 'progress' };
    case 'approved': return { title: '승인 완료', body: 'PC에 승인을 적용했습니다.', icon: 'check', tone: 'success' };
    case 'denied': return { title: '거부 완료', body: 'PC에서 요청을 취소했습니다.', icon: 'close', tone: 'neutral' };
    case 'failed': return { title: 'PC에서 처리하지 못했습니다', body: 'PC 화면에서 요청 창을 확인하십시오.', icon: 'alert', tone: 'danger' };
    case 'cancelled': return { title: 'PC에서 요청이 닫혔습니다', body: 'PC에서 직접 처리했거나 요청한 프로그램이 창을 닫았습니다.', icon: 'pc', tone: 'neutral' };
    case 'expired': return { title: '요청 시간이 지났습니다', body: '필요하면 PC에서 다시 요청하십시오.', icon: 'alert', tone: 'warning' };
    case 'pc_completed': return { title: 'PC에서 요청이 끝났습니다', body: '처리 결과는 PC에서 확인하십시오.', icon: 'pc', tone: 'neutral' };
    case 'authentication_cancelled': return { title: '본인 확인을 취소했습니다', body: '요청이 남아 있으면 다시 선택할 수 있습니다.', icon: 'lock', tone: 'neutral' };
    case 'local_unconfirmed': return { title: 'PC의 결과를 아직 확인하지 못했습니다', body: '선택이 PC에 전달되었는지 확인하지 못했습니다. 요청이 남아 있으면 다시 선택할 수 있습니다.', icon: 'alert', tone: 'warning' };
  }
}

/**
 * A failed choice whose request the PC sent again: soon after the failure a
 * different request from the same PC for the same program and path is listed.
 * The PC does this when its approval window changed before the choice arrived.
 */
export function reissuedCopy(): DecisionCopy {
  return { title: 'PC가 같은 요청을 다시 보냈습니다',
    body: 'PC의 승인 창이 바뀌어 앞서 한 선택을 적용하지 못했습니다. 새 요청에서 다시 선택하십시오.', icon: 'alert', tone: 'warning' };
}

/** What the tap itself establishes before any bridge reply: the native owner's first phase. */
export function tapPhase(action: DecisionAction): DecisionPhase {
  return action === 'approve' ? 'authenticating' : 'preparing';
}

const RETAINED = 32;
/** How soon after a failure the same program counts as the same request sent again. */
export const REISSUE_WINDOW_MILLIS = 15_000;

export interface ReceiptMemory {
  readonly source: AppSnapshot | null;
  /** Latest body-free view per request id, oldest first. */
  readonly views: readonly DecisionFeedbackView[];
  readonly dismissed: ReadonlySet<string>;
  readonly reviewKey: string | null;
  /** One-way 32-bit marks of PC, program and path per request id; never the text. */
  readonly marks: ReadonlyMap<string, number>;
  /** When this app session first saw each failure. */
  readonly failedAt: ReadonlyMap<string, number>;
  /** Failed request id to the request the PC listed in its place. */
  readonly reissued: ReadonlyMap<string, string>;
}
export const emptyReceiptMemory: ReceiptMemory = {
  source: null, views: [], dismissed: new Set(), reviewKey: null, marks: new Map(), failedAt: new Map(), reissued: new Map(),
};

/** FNV-1a over the fields that name a request; equal marks mean the same program asked again. */
function markOf(request: RequestView): number {
  const text = [request.computerName, request.programName, request.executablePath].join('\u0000');
  let hash = 0x811c9dc5;
  for (let index = 0; index < text.length; index += 1) hash = Math.imul(hash ^ text.charCodeAt(index), 0x01000193) >>> 0;
  return hash;
}

function reviewKeyOf(snapshot: AppSnapshot): string | null {
  return snapshot.requestReview ? `${snapshot.requestReview.revision}:${snapshot.requestReview.locator}` : null;
}

function withoutListedReceipts(views: readonly DecisionFeedbackView[], dismissed: ReadonlySet<string>, snapshot: AppSnapshot,
  spared: ReadonlySet<string> = new Set()): ReadonlySet<string> {
  const listed = new Set(snapshot.requests.map((request) => request.id));
  const next = new Set(dismissed);
  for (const view of views) if (!listed.has(view.id) && !spared.has(view.id)) next.add(view.id);
  return next;
}

/**
 * Fold one snapshot into the app-session memory. A reported list replaces what
 * it reports. A native result or local stop the owner no longer reports stays
 * until dismissed, because it cannot change any more; a stage the owner stopped
 * reporting is dropped, because showing it would claim progress nobody sees.
 */
export function nextReceiptMemory(memory: ReceiptMemory, snapshot: AppSnapshot, now: number = Date.now()): ReceiptMemory {
  if (memory.source === snapshot) return memory;
  const reported = snapshot.requestCatalog?.decisions;
  let views = memory.views;
  if (reported) {
    const latest = new Map(reported.map((view) => [view.id, view]));
    const kept = memory.views.filter((view) => !latest.has(view.id) && !isDecisionInProgress(view.phase));
    views = [...kept, ...reported].slice(-RETAINED);
  }
  const retained = new Set(views.map((view) => view.id));
  const marks = new Map([...memory.marks].filter(([id]) => retained.has(id)));
  for (const request of snapshot.requests) marks.set(request.id, markOf(request));
  const failedAt = new Map<string, number>();
  const reissued = new Map<string, string>();
  for (const view of views) {
    if (view.phase !== 'failed') continue;
    const at = memory.failedAt.get(view.id) ?? now;
    failedAt.set(view.id, at);
    const mark = marks.get(view.id);
    const successor = memory.reissued.get(view.id)
      ?? (mark === undefined || now - at > REISSUE_WINDOW_MILLIS ? undefined
        : snapshot.requests.find((request) => request.id !== view.id && marks.get(request.id) === mark)?.id);
    if (successor !== undefined) reissued.set(view.id, successor);
  }
  const reviewKey = reviewKeyOf(snapshot);
  // A request opened for review supersedes the receipts of requests that have
  // left, except the one explaining why the reviewed request was sent again.
  const reviewed = snapshot.requestReview?.locator;
  const spared = new Set([...reissued].filter(([, successor]) => successor === reviewed).map(([id]) => id));
  const dismissed = reviewKey !== null && reviewKey !== memory.reviewKey
    ? withoutListedReceipts(views, memory.dismissed, snapshot, spared) : memory.dismissed;
  return { source: snapshot, views, dismissed, reviewKey, marks, failedAt, reissued };
}

/** A receipt as shown: the native view, marked when the PC sent its request again. */
export type ReceiptView = DecisionFeedbackView & { readonly reissued?: true };

export interface DecisionReceipts {
  /** The latest view for a request id, dismissed or not. */
  readonly byId: ReadonlyMap<string, DecisionFeedbackView>;
  /** Receipts for requests that are no longer listed, newest first. */
  readonly receipts: readonly ReceiptView[];
  readonly dismiss: (id: string) => void;
  /** Called when the user moves on to another request. */
  readonly dismissUnlisted: () => void;
}

export function receiptsFor(memory: ReceiptMemory, snapshot: AppSnapshot | null): Pick<DecisionReceipts, 'byId' | 'receipts'> {
  const listed = new Set(snapshot?.requests.map((request) => request.id) ?? []);
  return {
    byId: new Map(memory.views.map((view) => [view.id, view])),
    receipts: memory.views.filter((view) => !listed.has(view.id) && !memory.dismissed.has(view.id)).reverse()
      .map((view): ReceiptView => memory.reissued.has(view.id) ? { ...view, reissued: true } : view),
  };
}

export function useDecisionReceipts(snapshot: AppSnapshot | null): DecisionReceipts {
  const [memory, setMemory] = useState<ReceiptMemory>(emptyReceiptMemory);
  const current = snapshot ? nextReceiptMemory(memory, snapshot) : memory;
  if (current !== memory) setMemory(current);
  const dismiss = useCallback((id: string) => {
    setMemory((value) => ({ ...value, dismissed: new Set([...value.dismissed, id]) }));
  }, []);
  const dismissUnlisted = useCallback(() => {
    setMemory((value) => value.source ? { ...value, dismissed: withoutListedReceipts(value.views, value.dismissed, value.source) } : value);
  }, []);
  return { ...receiptsFor(current, snapshot), dismiss, dismissUnlisted };
}
