// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useId, useState } from 'react';
import type { ControllerBridge, RequestDetailsView, RequestView } from './contracts';
import { Icon } from './icons';
import { ko } from './messages';
import { displayText, hasDirectionControls } from './displayText';
import { tr } from './i18n';

function DetailsBody({ request, read, retry }: { request: RequestView; read: ControllerBridge['requestDetails']; retry: () => void }) {
  const [body, setBody] = useState<RequestDetailsView | null>(null);
  const [failed, setFailed] = useState(false);
  useEffect(() => {
    let live = true;
    let timer: number | undefined;
    const started = performance.now();
    const invalidate = () => { if (live) { setBody(null); setFailed(true); } };
    const onVisibility = () => { if (document.visibilityState !== 'visible') invalidate(); };
    document.addEventListener('visibilitychange', onVisibility);
    void read(request.id).then((value) => {
      if (!live) return;
      const remaining = value.refreshAfterMillis - (performance.now() - started);
      if (document.visibilityState !== 'visible' || value.version !== 1 || value.id !== request.id
        || !Number.isFinite(remaining) || remaining <= 0 || remaining > 60000) { invalidate(); return; }
      setBody(value);
      timer = window.setTimeout(invalidate, remaining);
    }).catch(invalidate);
    return () => { live = false; window.clearTimeout(timer); document.removeEventListener('visibilitychange', onVisibility); };
  }, [read, request.id]);
  if (failed) return <><p role="status">{ko.detailsUnavailable}</p><button type="button" className="button quiet" onClick={retry}>{ko.detailsRefresh}</button></>;
  if (!body) return <p role="status">{ko.detailsLoading}</p>;
  return <>
    {(request.programElided || request.pathElided) && <dl className="request-facts">
      {request.programElided && <div><dt>{ko.program}</dt><dd className="original-text" dir="ltr">{displayText(body.programName)}</dd></div>}
      {request.pathElided && <div><dt>{ko.executable}</dt><dd className="path-output original-text" dir="ltr">{displayText(body.executablePath)}</dd></div>}
    </dl>}
    {hasDirectionControls(body.details) && <p className="supporting-text" role="note">{tr('숨은 방향 제어 문자를 눈에 보이게 표시했어요.')}</p>}
    <pre className="original-text" dir="ltr">{displayText(body.details)}</pre>
  </>;
}

export function RequestDetailsDisclosure({ request, disabled, read, initiallyOpen }: {
  request: RequestView; disabled: boolean; read: ControllerBridge['requestDetails']; initiallyOpen: boolean;
}) {
  const [expanded, setExpanded] = useState(initiallyOpen);
  const [attempt, setAttempt] = useState(0);
  const detailsId = useId();
  return <div className="request-disclosure">
    <button type="button" className="disclosure-button" disabled={disabled} aria-expanded={expanded} aria-controls={detailsId}
      onClick={() => setExpanded(!expanded)}>{expanded ? ko.fewerDetails : ko.details}<Icon name="chevron" className={expanded ? 'chevron-expanded' : ''} /></button>
    {expanded && !disabled && <section id={detailsId} className="command-region" role="region" aria-label={ko.commandDetails} tabIndex={0}>
      <h3>{ko.commandDetails}</h3><DetailsBody key={attempt} request={request} read={read} retry={() => setAttempt(attempt + 1)} />
    </section>}
  </div>;
}
