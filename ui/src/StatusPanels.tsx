// SPDX-License-Identifier: GPL-2.0-or-later
import type { ReactNode } from 'react';
import type { AppSnapshot, MobileReadiness, ServiceAction } from './contracts';
import { Icon } from './icons';
import type { IconName } from './icons';
import { ko, serviceActionText, serviceStateText } from './messages';
import { tr } from './i18n';
import { displayText } from './displayText';

export function EmptyState({ icon, title, description, children }: {
  icon: IconName; title: string; description: string; children?: ReactNode;
}) {
  return <section className="empty-state"><span className="empty-icon"><Icon name={icon} /></span><h2>{title}</h2><p>{description}</p>{children}</section>;
}

export function ServicePanel({ snapshot, disabled, onAction }: {
  snapshot: AppSnapshot; disabled: boolean; onAction: (action: ServiceAction) => void;
}) {
  const service = snapshot.service;
  const serviceTitle = !service ? ko.serviceUnknown : !service.installed ? ko.serviceMissing
    : service.state ? serviceStateText[service.state] : ko.serviceUnknown;
  const description = !service ? ko.serviceUnknownBody : !service.installed ? ko.serviceMissingBody
    : service.state === 'running' ? (service.remoteRequestsReady ? ko.remoteReadyBody : ko.serviceRunningBody)
      : service.state === 'stopped' ? (service.allowedActions.includes('start') ? ko.serviceStoppedBody : ko.serviceUnknownBody)
      : service.state === 'paused' ? ko.servicePausedBody : service.state ? ko.servicePendingBody : ko.serviceUnknownBody;
  const actions: readonly ServiceAction[] = ['install', 'start', 'restart', 'stop', 'uninstall'];
  const primary = actions.find((action) => service?.allowedActions.includes(action) && (action === 'install' || action === 'start'));
  return <>
    <section className="surface service-card" aria-labelledby="service-heading">
      <div className="service-heading-row"><span className="feature-icon"><Icon name="pc" /></span><div><p className="eyebrow">{ko.serviceLabel}</p><h2 id="service-heading">{serviceTitle}</h2></div></div>
      {service && <p className={`state-line ${service.remoteRequestsReady ? 'is-success' : ''}`}><span className="state-dot" aria-hidden="true" />{service.remoteRequestsReady ? ko.remoteReady : ko.remoteNotReady}</p>}
      <p className="service-description">{description}</p>
      <dl className="status-facts"><div><dt>{ko.thisComputer}</dt><dd><bdi dir="ltr">{displayText(snapshot.computerName === '이 PC' ? tr('이 PC') : snapshot.computerName || '—')}</bdi></dd></div></dl>
      {service?.controlHint === 'needs_installer' && <p className="supporting-text">{ko.serviceNeedsInstaller}</p>}
      {service?.controlHint === 'unsupported' && <p className="supporting-text">{ko.serviceUnsupported}</p>}
      {service && service.allowedActions.length > 0 && <div className="service-actions">{actions.filter((action) => service.allowedActions.includes(action)).map((action) =>
        <button key={action} type="button" className={`button ${action === primary ? 'primary' : action === 'uninstall' ? 'danger-quiet' : 'secondary'}`} disabled={disabled} onClick={() => onAction(action)}>{serviceActionText[action]}</button>)}</div>}
    </section>
    {snapshot.dataAvailability.devices === 'unavailable' && <section className="passive-note"><Icon name="phone" /><div><h2>{ko.phones}</h2><p>{ko.devicesUnavailableBody}</p></div></section>}
  </>;
}

export function MobileNotices({ mobile, disabled, onOpenLock, onOpenNotifications }: {
  mobile: MobileReadiness | null; disabled: boolean; onOpenLock: () => void; onOpenNotifications: () => void;
}) {
  const missing = mobile?.screenLock === 'missing';
  return <div className="mobile-notices">
    {(!mobile || mobile.screenLock !== 'configured') && <section className={`notice-box ${missing ? 'warning' : ''}`} aria-labelledby="lock-heading"><Icon name="lock" /><div><h2 id="lock-heading">{missing ? ko.lockMissing : ko.lockUnknown}</h2><p>{missing ? ko.lockMissingBody : ko.lockUnknownBody}</p>{missing && mobile?.canOpenLockSettings && <button type="button" className="button secondary" disabled={disabled} onClick={onOpenLock}>{ko.openLockSettings}</button>}</div></section>}
    {mobile?.notifications === 'denied' && <section className="notice-box warning"><Icon name="alert" /><div><h2>{ko.notificationsDenied}</h2><p>{ko.notificationsDeniedBody}</p>{mobile.canOpenNotificationSettings && <button type="button" className="button secondary" disabled={disabled} onClick={onOpenNotifications}>{ko.openNotificationSettings}</button>}</div></section>}
    {mobile?.notifications === 'unavailable' && <p className="supporting-text">{ko.notificationsUnknown}</p>}
  </div>;
}
