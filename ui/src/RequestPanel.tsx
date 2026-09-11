// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useId, useRef } from 'react';
import type { Ref } from 'react';
import type { AppSnapshot, ControllerBridge, RequestView } from './contracts';
import { Icon } from './icons';
import { ko, remainingLabel } from './messages.ko';
import { EmptyState } from './StatusPanels';
import { RequestDetailsDisclosure } from './RequestDetailsDisclosure';

const requestStateText: Record<Exclude<RequestView['state'], 'pending'>, string> = {
  authenticating: ko.authenticating, waiting: ko.requestWaiting, sending: ko.sending,
  awaiting_outcome: ko.awaitingOutcome, unavailable: ko.requestUnavailable, expired: ko.expired,
};

function RequestCard({ request, disabled, onDecision, readDetails, initiallyOpen }: {
  request: RequestView; disabled: boolean; onDecision: (requestId: string, decision: 'approve' | 'deny') => void;
  readDetails: ControllerBridge['requestDetails']; initiallyOpen: boolean;
}) {
  const headingId = useId();
  const heading = useRef<HTMLHeadingElement>(null);
  useEffect(() => { if (initiallyOpen) heading.current?.focus(); }, [initiallyOpen]);
  const pending = request.state === 'pending';
  if (request.state === 'unavailable') return <EmptyState icon="request" title={ko.requestUnavailable} description={ko.requestUnavailableBody} />;
  return <article className="surface request-card" aria-labelledby={headingId}>
    <div className="request-context"><Icon name="pc" /><bdi>{request.computerName}</bdi></div>
    <p className="eyebrow request-eyebrow">{ko.needsDecision}</p>
    <h2 id={headingId} ref={heading} tabIndex={-1} className="program-name"><bdi>{request.programName}</bdi></h2>
    {!pending && <div className="request-result" aria-live="polite"><p className="pending-copy">{requestStateText[request.state]}</p></div>}
    <dl className="request-facts"><div><dt>{ko.executable}</dt><dd className="path-output" dir="auto">{request.executablePath}</dd></div></dl>
    {request.hasDetails && <RequestDetailsDisclosure request={request} disabled={disabled} read={readDetails} initiallyOpen={initiallyOpen} />}
    {pending && <div className="request-result" aria-live="polite"><p className="time-remaining"><Icon name="clock" />{remainingLabel(request.remainingSeconds)}</p></div>}
    <div className="request-actions"><button type="button" className="button secondary" disabled={disabled || !request.canDeny} onClick={() => onDecision(request.id, 'deny')}>{ko.deny}</button><button type="button" className="button primary" disabled={disabled || !pending || !request.canApprove} onClick={() => onDecision(request.id, 'approve')}><Icon name="check" />{ko.approve}</button></div>
  </article>;
}

interface RequestPanelProps {
  snapshot: AppSnapshot; disabled: boolean; onDecision: (requestId: string, decision: 'approve' | 'deny') => void;
  readDetails: ControllerBridge['requestDetails'];
}

function RequestContents({ snapshot, disabled, onDecision, readDetails }: RequestPanelProps) {
  if (snapshot.requestCatalog?.status === 'reconciling') return <EmptyState icon="request" title={ko.requestReconciling} description={ko.requestReconcilingBody} />;
  if (snapshot.dataAvailability.requests !== 'available') return <EmptyState icon="request" title={ko.requestUnavailable} description={ko.requestUnavailableBody} />;
  if (!snapshot.requests.length && snapshot.requestCatalog?.peerCount === 0) return <EmptyState icon="pc" title={ko.noComputers} description={ko.pairingUnavailable} />;
  if (!snapshot.requests.length && snapshot.requestCatalog?.connectedPeerCount === 0) return <EmptyState icon="pc" title={ko.requestDisconnected} description={ko.requestDisconnectedBody} />;
  if (!snapshot.requests.length) return <EmptyState icon="request" title={ko.requestEmpty} description={ko.requestEmptyBody} />;
  const selected = snapshot.requests.find((request) => request.id === snapshot.requestReview?.locator);
  const requests = selected ? [selected, ...snapshot.requests.filter((request) => request !== selected)] : snapshot.requests;
  return <div className="request-list">{requests.map((request) => {
    const review = snapshot.requestReview?.locator === request.id ? snapshot.requestReview : null;
    return <RequestCard key={`${request.id}:${review?.revision ?? ''}`} request={request} disabled={disabled} onDecision={onDecision} readDetails={readDetails} initiallyOpen={review !== null} />;
  })}</div>;
}

export function RequestPanel({ snapshot, disabled, readDetails, onDecision, onOpenScanner, scannerButtonRef }:
  RequestPanelProps & { onOpenScanner: () => void; scannerButtonRef: Ref<HTMLButtonElement> }) {
  const scannerAvailable = snapshot.platform === 'android' && snapshot.mobile?.canOpenPairingScanner === true;
  return <>
    <RequestContents snapshot={snapshot} disabled={disabled} readDetails={readDetails} onDecision={onDecision} />
    {scannerAvailable && <div className="collection-actions"><button ref={scannerButtonRef} data-pairing-scanner="open" type="button" className="button secondary" disabled={disabled} onClick={onOpenScanner}>{ko.openPairingScanner}</button></div>}
  </>;
}
