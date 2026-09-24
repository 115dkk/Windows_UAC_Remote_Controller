// SPDX-License-Identifier: GPL-2.0-or-later
import type { ReactNode } from 'react';
import type { AppSnapshot, MobileReadiness, ServiceAction } from './contracts';
import { Icon } from './icons';
import type { IconName } from './icons';
import { connectionUnknownText, devicesUnavailableText, ko, serviceActionText, serviceStateText } from './messages';
import { tr } from './i18n';
import { displayText } from './displayText';
import { RelayStatusLine } from './RelayStatusLine';
import { DirectConnectionStatus } from './DirectConnectionStatus';
import { directConnectionState } from './directConnection';
import { useConnectionDisplay } from './useConnectionDisplay';

export function EmptyState({ icon, title, description, children }: {
  icon: IconName; title: string; description: string; children?: ReactNode;
}) {
  return <section className="empty-state"><span className="empty-icon"><Icon name={icon} /></span><h2>{title}</h2><p>{description}</p>{children}</section>;
}

export function ServicePanel({ snapshot, disabled, onAction, onOpenNetwork, stale = false }: {
  snapshot: AppSnapshot; disabled: boolean; onAction: (action: ServiceAction) => void; stale?: boolean;
  /** Offered only when the PC has no address reachable from outside. */
  onOpenNetwork?: () => void;
}) {
  const service = snapshot.service;
  const actionIssue = service?.actionIssue;
  const issueAlreadyGlobal = actionIssue && snapshot.issue?.code === actionIssue.code
    && snapshot.issue.message === actionIssue.message && snapshot.issue.nextAction === actionIssue.nextAction;
  const serviceTitle = !service ? ko.serviceUnknown : !service.installed ? ko.serviceMissing
    : service.state ? serviceStateText[service.state] : ko.serviceUnknown;
  const connectionKnown = service?.state === 'running' && snapshot.dataAvailability.devices === 'available';
  const connected = useConnectionDisplay(connectionKnown ? snapshot.devices.some(device => device.connected) : null,
    snapshot.devices.map(device => `${device.id}:${device.revision}`).sort().join('|'));
  const connectionText = connected === true ? tr('휴대폰 연결됨') : connected === false ? tr('휴대폰 연결 안 됨') : connectionUnknownText(snapshot);
  const description = !service ? ko.serviceUnknownBody : !service.installed ? ko.serviceMissingBody
    : service.state === 'running' ? null
      : service.state === 'stopped' ? (service.allowedActions.includes('start') ? ko.serviceStoppedBody : ko.serviceUnknownBody)
      : service.state === 'paused' ? ko.servicePausedBody : service.state ? ko.servicePendingBody : ko.serviceUnknownBody;
  const actions: readonly ServiceAction[] = ['install', 'start', 'restart', 'stop', 'uninstall'];
  const primary = actions.find((action) => service?.allowedActions.includes(action) && (action === 'install' || action === 'start'));
  const direct = directConnectionState(snapshot, stale);
  const networkSetup = onOpenNetwork && snapshot.platform === 'windows' && (direct === 'lan_only' || direct === 'unavailable');
  // The heading and description already say phone approval is off; the relay
  // and direct lines would only repeat it. A connected phone says the relay works.
  const approvalOff = !stale && snapshot.relayStatus?.state !== 'unknown'
    && (service?.state === 'stopped' || snapshot.relayStatus?.state === 'stopped');
  return <>
    <section className="surface service-card" aria-labelledby="service-heading">
      <div className="service-heading-row"><span className="feature-icon"><Icon name="pc" /></span><div><h2 id="service-heading">{serviceTitle}</h2></div></div>
      {service && <p className={`state-line ${connected ? 'is-success' : ''}`}><span className="state-dot" aria-hidden="true" />{connectionText}</p>}
      {description && <p className="service-description">{description}</p>}
      {!approvalOff && connected !== true && <RelayStatusLine snapshot={snapshot} stale={stale} />}
      {/* Never beside a line that still says a phone is connected. */}
      {!approvalOff && <DirectConnectionStatus snapshot={snapshot} stale={stale} guidance={connected !== true} />}
      {networkSetup && <div className="network-setup-action"><button type="button" className="button secondary" disabled={disabled} onClick={onOpenNetwork}>{ko.networkSetup}</button></div>}
      {actionIssue && !issueAlreadyGlobal && <section className="notice-box warning" role="alert"><Icon name="alert" /><div><p>{tr(actionIssue.message)}</p>{actionIssue.nextAction && <p className="supporting-text">{tr(actionIssue.nextAction)}</p>}</div></section>}
      {/* No computer name is supplied yet; an empty row would read as a failed load. */}
      {snapshot.computerName && <dl className="status-facts"><div><dt>{ko.thisComputer}</dt><dd><bdi dir="ltr">{displayText(snapshot.computerName === '이 PC' ? tr('이 PC') : snapshot.computerName)}</bdi></dd></div></dl>}
      {service?.controlHint === 'needs_installer' && <p className="supporting-text">{ko.serviceNeedsInstaller}</p>}
      {service?.controlHint === 'unsupported' && <p className="supporting-text">{ko.serviceUnsupported}</p>}
      {service && service.allowedActions.length > 0 && <div className="service-actions">{actions.filter((action) => service.allowedActions.includes(action)).map((action) =>
        <button key={action} type="button" className={`button ${action === primary ? 'primary' : action === 'uninstall' ? 'danger-quiet' : 'secondary'}`} disabled={disabled} onClick={() => onAction(action)}>{serviceActionText[action]}</button>)}</div>}
    </section>
    {snapshot.dataAvailability.devices === 'unavailable' && <section className="passive-note"><Icon name="phone" /><div><h2>{ko.phones}</h2><p>{devicesUnavailableText(snapshot)}</p></div></section>}
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
