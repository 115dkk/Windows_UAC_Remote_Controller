// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useId, useRef } from 'react';
import type { Ref } from 'react';
import type { AppSnapshot, ControllerBridge, DecisionFeedbackView, RequestView } from './contracts';
import { Icon } from './icons';
import { ko, remainingLabel } from './messages';
import { EmptyState } from './StatusPanels';
import { RequestDetailsDisclosure } from './RequestDetailsDisclosure';
import { PairingEntry } from './PairingEntry';
import { hasPairedPc } from './phoneConnection';
import { displayText, hasDirectionControls } from './displayText';
import { tr } from './i18n';
import { emptyReceiptMemory, nextReceiptMemory, receiptsFor, tapPhase } from './decisionFeedback';
import type { DecisionAction, DecisionPhase } from './decisionFeedback';
import { DecisionPhaseLine, DecisionReceipts } from './DecisionReceipt';
import { initialConnectionClock, knownDisconnected, pcConnectionPresentation } from './pcConnection';
import type { PcConnectionClock } from './pcConnection';
import { PcConnectionStatus } from './PcConnectionStatus';

type Decide = (requestId: string, decision: DecisionAction) => void;
/** The tap that is waiting for its bridge reply, shown on the next frame. */
export interface PendingDecision { readonly requestId: string; readonly decision: DecisionAction }

function RequestCard({ request, disabled, onDecision, readDetails, initiallyOpen, phase }: {
  request: RequestView; disabled: boolean; onDecision: Decide;
  readDetails: ControllerBridge['requestDetails']; initiallyOpen: boolean;
  phase: { readonly action: DecisionAction; readonly phase: DecisionPhase } | null;
}) {
  const requestStateText: Record<Exclude<RequestView['state'], 'pending'>, string> = {
    authenticating: ko.authenticating, waiting: ko.requestWaiting, sending: ko.sending,
    awaiting_outcome: ko.awaitingOutcome, unavailable: ko.requestUnavailable, expired: ko.expired,
  };
  const headingId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (initiallyOpen) heading.current?.focus(); }, [initiallyOpen]);
  const pending = request.state === 'pending';
  if (request.state === 'unavailable') return <EmptyState icon="request" title={ko.requestUnavailable} description={ko.requestUnavailableBody} />;
  return <article className="surface request-card" aria-labelledby={headingId}>
    <div className="request-context"><Icon name="pc" /><bdi dir="ltr">{displayText(request.computerName)}</bdi></div>
    <p className="eyebrow request-eyebrow">{ko.needsDecision}</p>
    <h2 id={headingId} ref={heading} tabIndex={-1} className="program-name"><bdi dir="ltr">{displayText(request.programName)}</bdi></h2>
    {[request.programName,request.executablePath,request.computerName].some(hasDirectionControls) && <p className="supporting-text" role="note">{tr('숨은 방향 제어 문자를 눈에 보이게 표시했어요.')}</p>}
    {/* Always mounted, so each change of phase is announced once. The decision
        phase replaces the generic busy text; without one the old text stays. */}
    <div className={phase || !pending ? 'request-result request-status' : 'request-status'} role="status">
      {phase ? <DecisionPhaseLine action={phase.action} phase={phase.phase} />
        : !pending && <p className="pending-copy">{requestStateText[request.state]}</p>}
    </div>
    {/* A consent prompt does not always show a file path, and the protocol calls
        that legal. Drawing the row with nothing after it reads as a value that
        failed to load rather than one that was never there. */}
    {request.executablePath !== '' && <dl className="request-facts"><div><dt>{ko.executable}</dt><dd className="path-output original-text" dir="ltr">{displayText(request.executablePath)}</dd></div></dl>}
    {request.hasDetails && <RequestDetailsDisclosure request={request} disabled={disabled} read={readDetails} initiallyOpen={initiallyOpen} />}
    {pending && <div className="request-result" aria-live="polite"><p className="time-remaining"><Icon name="clock" />{remainingLabel(request.remainingSeconds)}</p></div>}
    <div className="request-actions"><button type="button" className="button secondary" disabled={disabled || !request.canDeny} onClick={() => onDecision(request.id, 'deny')}>{ko.deny}</button><button type="button" className="button primary" disabled={disabled || !pending || !request.canApprove} onClick={() => onDecision(request.id, 'approve')}><Icon name="check" />{ko.approve}</button></div>
  </article>;
}

interface RequestPanelProps {
  snapshot: AppSnapshot; disabled: boolean; onDecision: Decide;
  readDetails: ControllerBridge['requestDetails'];
  /** App-session receipt memory; without it only the current snapshot is shown. */
  decisions?: { readonly byId: ReadonlyMap<string, DecisionFeedbackView>; readonly receipts: readonly DecisionFeedbackView[]; readonly dismiss: (id: string) => void } | undefined;
  pendingDecision?: PendingDecision | null | undefined;
  connectionClock?: PcConnectionClock | undefined;
}

function RequestContents({ snapshot, disabled, onDecision, readDetails, byId, pendingDecision }: RequestPanelProps & {
  byId: ReadonlyMap<string, DecisionFeedbackView>;
}) {
  if (snapshot.requestCatalog?.status === 'reconciling') return <EmptyState icon="request" title={ko.requestReconciling} description={ko.requestReconcilingBody} />;
  if (snapshot.dataAvailability.requests !== 'available') return <EmptyState icon="request" title={ko.requestUnavailable} description={ko.requestUnavailableBody} />;
  if (!snapshot.requests.length) return <EmptyState icon="request" title={ko.requestEmpty} description={ko.requestEmptyBody} />;
  const selected = snapshot.requests.find((request) => request.id === snapshot.requestReview?.locator);
  const requests = selected ? [selected, ...snapshot.requests.filter((request) => request !== selected)] : snapshot.requests;
  return <div className="request-list">{requests.map((request) => {
    const review = snapshot.requestReview?.locator === request.id ? snapshot.requestReview : null;
    const decision = byId.get(request.id);
    const phase = pendingDecision?.requestId === request.id
      ? { action: pendingDecision.decision, phase: tapPhase(pendingDecision.decision) }
      : decision ? { action: decision.action, phase: decision.phase } : null;
    return <RequestCard key={`${request.id}:${review?.revision ?? ''}`} request={request} disabled={disabled} onDecision={onDecision} readDetails={readDetails} initiallyOpen={review !== null} phase={phase} />;
  })}</div>;
}

export function RequestPanel({ snapshot, disabled, readDetails, onDecision, onOpenScanner, onOpenUsb, scannerButtonRef, decisions, pendingDecision = null, connectionClock = initialConnectionClock }:
  RequestPanelProps & { onOpenScanner: () => void; onOpenUsb?: () => void; scannerButtonRef: Ref<HTMLButtonElement> }) {
  const fallback = decisions ? null : receiptsFor(nextReceiptMemory(emptyReceiptMemory, snapshot), snapshot);
  const byId = decisions?.byId ?? fallback?.byId ?? new Map<string, DecisionFeedbackView>();
  const receipts = decisions?.receipts ?? fallback?.receipts ?? [];
  // Connection state needs a paired PC this phone knows about and its own
  // approval owner running; an unread catalogue says nothing about the link.
  const connection = snapshot.phoneService?.state === 'local_settings_ready' && knownDisconnected(snapshot)
    ? pcConnectionPresentation(connectionClock.disconnectedSince === null ? 0 : connectionClock.now - connectionClock.disconnectedSince,
      connectionClock.everConnected, snapshot.requestCatalog?.connection) : null;
  return <>
    <DecisionReceipts receipts={receipts} onDismiss={decisions?.dismiss ?? (() => undefined)} />
    <RequestContents snapshot={snapshot} disabled={disabled} readDetails={readDetails} onDecision={onDecision} byId={byId} pendingDecision={pendingDecision} />
    <div className="connection-status" role="status">{connection && <PcConnectionStatus presentation={connection} />}</div>
    {snapshot.platform === 'android' && !hasPairedPc(snapshot) && <PairingEntry snapshot={snapshot} disabled={disabled} onOpenScanner={onOpenScanner} {...(onOpenUsb ? { onOpenUsb } : {})} scannerButtonRef={scannerButtonRef} />}
  </>;
}
