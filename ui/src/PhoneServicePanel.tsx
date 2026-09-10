// SPDX-License-Identifier: GPL-2.0-or-later
import { useId } from 'react';
import type { PhoneServiceView } from './contracts';
import { Icon } from './icons';
import { ko, phoneServiceStateText } from './messages.ko';

/** Native state only. Request acceptance never becomes a local running result. */
export function PhoneServicePanel({ service, disabled, onAction }: {
  service: PhoneServiceView | null; disabled: boolean; onAction: (action: 'start' | 'stop') => void;
}) {
  const heading = useId();
  const consequence = useId();
  return <section className="surface service-card phone-service-card" aria-labelledby={heading}>
    <div className="service-heading-row"><Icon name="phone" /><h2 id={heading}>{ko.phoneServiceLabel}</h2></div>
    <p className="state-line" role="status" aria-live="polite" aria-atomic="true"><span className="state-dot" aria-hidden="true" />{service ? phoneServiceStateText[service.state] : ko.serviceUnknown}</p>
    <dl className="status-facts"><div><dt>{ko.phoneBootLabel}</dt><dd>{service?.bootEnabled === true ? ko.phoneBootOn : service?.bootEnabled === false ? ko.phoneBootOff : ko.phoneBootUnknown}</dd></div></dl>
    {service?.state === 'local_settings_ready' && service.policyOwnerReady && <p className="supporting-text">{ko.phoneServiceReadyBody}</p>}
    {!service && <p className="supporting-text">{ko.phoneServiceUnknownBody}</p>}
    {service && (service.canStart || service.canStop) && <>
      <p className="supporting-text" id={consequence}>{service.canStart ? ko.phoneStartConsequence : ko.phoneStopConsequence}</p>
      <div className="service-actions">
        {service.canStart && <button type="button" className="button primary" disabled={disabled} aria-describedby={consequence} onClick={() => onAction('start')}>{ko.phoneStartAction}</button>}
        {service.canStop && <button type="button" className="button secondary" disabled={disabled} onClick={() => onAction('stop')}>{ko.phoneStopAction}</button>}
      </div>
    </>}
  </section>;
}
