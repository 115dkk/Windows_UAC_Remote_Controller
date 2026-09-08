// SPDX-License-Identifier: GPL-2.0-or-later
import { useId, useState } from 'react';
import type { AppSnapshot, RequestView } from './contracts';
import { Icon } from './icons';
import { ko, remainingLabel } from './messages.ko';
import { EmptyState } from './StatusPanels';

function RequestCard({ request, disabled, onDecision }: {
  request: RequestView; disabled: boolean; onDecision: (requestId: string, decision: 'approve' | 'deny') => void;
}) {
  const [expanded, setExpanded] = useState(false);
  const detailsId = useId();
  const headingId = useId();
  const pending = request.state === 'pending';
  return <article className="surface request-card" aria-labelledby={headingId}>
    <div className="request-context"><Icon name="pc" /><bdi>{request.computerName}</bdi></div>
    <p className="eyebrow request-eyebrow">{ko.needsDecision}</p>
    <h2 id={headingId} className="program-name"><bdi>{request.programName}</bdi></h2>
    <dl className="request-facts"><div><dt>{ko.executable}</dt><dd className="path-output" dir="auto">{request.executablePath}</dd></div></dl>
    {request.details && <div className="request-disclosure"><button type="button" className="disclosure-button" aria-expanded={expanded} aria-controls={detailsId} onClick={() => setExpanded(!expanded)}>{expanded ? ko.fewerDetails : ko.details}<Icon name="chevron" className={expanded ? 'chevron-expanded' : ''} /></button>{expanded && <section id={detailsId} className="command-region" role="region" aria-label={ko.commandDetails} tabIndex={0}><h3>{ko.commandDetails}</h3><pre dir="auto">{request.details}</pre></section>}</div>}
    <div className="request-result" aria-live="polite">{pending ? <p className="time-remaining"><Icon name="clock" />{remainingLabel(request.remainingSeconds)}</p> : <p className="pending-copy">{request.state === 'authenticating' ? ko.authenticating : request.state === 'sending' ? ko.sending : ko.expired}</p>}</div>
    <div className="request-actions"><button type="button" className="button secondary" disabled={disabled || !pending || !request.canDeny} onClick={() => onDecision(request.id, 'deny')}>{ko.deny}</button><button type="button" className="button primary" disabled={disabled || !pending || !request.canApprove} onClick={() => onDecision(request.id, 'approve')}><Icon name="check" />{ko.approve}</button></div>
  </article>;
}

export function RequestPanel({ snapshot, disabled, onDecision }: {
  snapshot: AppSnapshot; disabled: boolean; onDecision: (requestId: string, decision: 'approve' | 'deny') => void;
}) {
  if (snapshot.dataAvailability.requests !== 'available') return <EmptyState icon="request" title={ko.requestUnavailable} description={ko.requestUnavailableBody} />;
  if (!snapshot.requests.length) return <EmptyState icon="request" title={ko.requestEmpty} description={ko.requestEmptyBody} />;
  return <div className="request-list">{snapshot.requests.map((request) => <RequestCard key={request.id} request={request} disabled={disabled} onDecision={onDecision} />)}</div>;
}
