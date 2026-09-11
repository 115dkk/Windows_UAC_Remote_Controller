// SPDX-License-Identifier: GPL-2.0-or-later
import { useCallback, useEffect, useRef, useState } from 'react';
import type { AppSnapshot, ControllerBridge, PairedDeviceView, ServiceAction } from './contracts';
import { ActivityPanel, DevicesPanel } from './CollectionPanels';
import { ConfirmDialog } from './ConfirmDialog';
import type { Confirmation } from './ConfirmDialog';
import { Icon } from './icons';
import type { IconName } from './icons';
import { ko, policyUnavailableText, serviceActionText, serviceConfirmText } from './messages.ko';
import { PolicyEditor } from './PolicyEditor';
import { PhoneServicePanel } from './PhoneServicePanel';
import { PairingEntry } from './PairingEntry';
import { hasNoPairedPc } from './phoneConnection';
import { RequestPanel } from './RequestPanel';
import { EmptyState, MobileNotices, ServicePanel } from './StatusPanels';
import { useController } from './useController';

export type ClientPage = 'status' | 'devices' | 'activity' | 'requests' | 'schedule';
interface NavItem { readonly page: ClientPage; readonly label: string; readonly icon: IconName; readonly available: boolean }

function navigationFor(snapshot: AppSnapshot): readonly NavItem[] {
  const phone = snapshot.platform === 'android';
  const devices: NavItem = { page: 'devices', label: phone ? ko.computers : ko.phones, icon: phone ? 'pc' : 'phone', available: !phone || snapshot.dataAvailability.devices === 'available' };
  const activity: NavItem = { page: 'activity', label: phone ? ko.phoneActivity : ko.activity, icon: 'history', available: snapshot.dataAvailability.activity === 'available' };
  return phone ? [
    // Request recovery remains reachable even while native inventory is unknown.
    { page: 'requests', label: ko.requests, icon: 'request', available: true },
    devices, { page: 'schedule', label: ko.schedule, icon: 'clock', available: true }, activity,
  ] : [{ page: 'status', label: ko.status, icon: 'pc', available: true }, devices, activity];
}

export function App({ bridge, initialPage }: { bridge: ControllerBridge; initialPage?: ClientPage }) {
  const controller = useController(bridge);
  const readDetails = useCallback((id: string) => bridge.requestDetails(id), [bridge]);
  const [navigationState, setNavigationState] = useState<{ page: ClientPage | null; reviewKey: string | null }>({ page: initialPage ?? null, reviewKey: null });
  const [confirmation, setConfirmation] = useState<Confirmation | null>(null);
  const { snapshot, refreshing, busy, stale, error, notice } = controller;
  const phone = snapshot?.platform === 'android';
  const review = snapshot?.requestReview;
  const reviewKey = review ? `${review.revision}:${review.locator}` : null;
  const newReview = reviewKey !== null && reviewKey !== navigationState.reviewKey;
  if (newReview) setNavigationState({ page: 'requests', reviewKey });
  const page = newReview ? 'requests' : navigationState.page ?? (phone ? 'requests' : 'status');
  function navigate(next: ClientPage) {
    controller.dismissScannerReturnFocus();
    setNavigationState({ page: next, reviewKey });
  }
  const disabled = stale || busy !== null;
  const scannerButton = useRef<HTMLButtonElement>(null);
  const scannerFocusHandled = useRef({ owner: bridge, revision: 0 });
  useEffect(() => {
    if (scannerFocusHandled.current.owner !== bridge) scannerFocusHandled.current = { owner: bridge, revision: 0 };
    if (controller.scannerFocusRevision <= scannerFocusHandled.current.revision) return;
    scannerFocusHandled.current.revision = controller.scannerFocusRevision;
    if (!phone || (page !== 'requests' && page !== 'schedule')) return;
    const restore = () => {
      const focused = document.activeElement;
      if (focused !== document.body && focused !== document.documentElement && focused !== scannerButton.current) return;
      if (document.visibilityState === 'visible' && document.hasFocus() && !disabled
        && snapshot?.mobile?.canOpenPairingScanner === true) scannerButton.current?.focus();
    };
    restore();
    window.addEventListener('focus', restore, { once: true });
    return () => window.removeEventListener('focus', restore);
  }, [bridge, controller.scannerFocusRevision, disabled, page, phone, snapshot?.mobile?.canOpenPairingScanner]);
  function serviceAction(action: ServiceAction) {
    if (phone) {
      if (action === 'stop') setConfirmation({ title: ko.phoneStopTitle, body: ko.phoneStopBody, confirmLabel: ko.phoneStopAction, onConfirm: () => { void controller.run({ kind: 'service', action: 'stop' }); } });
      else if (action === 'start') void controller.run({ kind: 'service', action: 'start' });
      return;
    }
    const copy = serviceConfirmText[action];
    if (copy) setConfirmation({ ...copy, confirmLabel: serviceActionText[action], onConfirm: () => { void controller.run({ kind: 'service', action }); } });
    else void controller.run({ kind: 'service', action });
  }
  function removeDevice(device: PairedDeviceView) {
    setConfirmation({ title: ko.removeTitle, body: ko.removeBody, subject: device.name, confirmLabel: ko.removeDevice, onConfirm: () => { void controller.run({ kind: 'remove', deviceId: device.id }); } });
  }
  function clearActivity() {
    setConfirmation({ title: ko.clearTitle, body: ko.clearBody, confirmLabel: ko.clearActivity, onConfirm: () => { void controller.run({ kind: 'clear' }); } });
  }
  const refreshButton = <button className="button quiet refresh-button" type="button" disabled={refreshing || busy !== null} onClick={() => { void controller.refresh(true); }}><Icon name="refresh" />{refreshing ? ko.refreshing : ko.refresh}</button>;

  if (!snapshot) return <div className="launch-shell"><main id="main-content" className="launch-content" aria-busy={refreshing}><div className="launch-brand"><img className="app-logo" src="/app-logo.svg" alt="" /><span>{ko.appName}</span></div><div role={error ? 'alert' : 'status'}><EmptyState icon={error ? 'alert' : 'pc'} title={error ? ko.unexpectedTitle : ko.loadingTitle} description={error ?? ko.loadingBody} /></div>{error && <div className="launch-actions">{refreshButton}</div>}</main></div>;
  if (snapshot.platform === 'unsupported') return <div className="launch-shell"><main id="main-content" className="launch-content"><EmptyState icon="pc" title={ko.unsupportedTitle} description={ko.unsupportedBody} />{refreshButton}</main></div>;

  const items = navigationFor(snapshot);
  const title = !phone && page === 'status' ? ko.homeTitle
    : items.find((item) => item.page === page)?.label ?? (phone ? ko.requests : ko.status);
  const navigation = <aside className="navigation-shell">
    <div className="app-brand"><img className="app-logo" src="/app-logo.svg" alt="" /><span>{ko.appName}</span></div>
    <nav aria-label={ko.navigation}>{items.map((item) => item.available
      ? <button key={item.page} type="button" className={`navigation-item ${page === item.page ? 'current' : ''}`} aria-current={page === item.page ? 'page' : undefined} onClick={() => navigate(item.page)}><Icon name={item.icon} /><span>{item.label}</span></button>
      : <button key={item.page} type="button" disabled className="navigation-item passive"><Icon name={item.icon} /><span>{item.label}{' '}<small>{ko.unavailable}</small></span></button>)}</nav>
    <p className="rail-caption">{ko.appDescription}</p>
  </aside>;

  const main = <main id="main-content" className="main-scroll" tabIndex={-1}>
    <div className="page-content">
      <header className="page-header"><div><h1 tabIndex={-1}>{title}</h1>{!phone && page === 'status' && <p>{ko.homePurpose}</p>}{page === 'requests' && snapshot.requests.some((request) => request.state === 'pending') && snapshot.dataAvailability.requests === 'available' && <p>{ko.requestIntro}</p>}{page === 'schedule' && <p>{ko.scheduleIntro}</p>}</div>{refreshButton}</header>
      {stale && <p className="stale-label"><Icon name="alert" />{ko.stale}</p>}
      {error && <section className="notice-box error" role="alert"><Icon name="alert" /><p>{error}</p></section>}
      {snapshot.issue && <section className="notice-box warning" role="alert"><Icon name="alert" /><div><p>{snapshot.issue.message}</p>{snapshot.issue.nextAction && <p className="supporting-text">{snapshot.issue.nextAction}</p>}</div></section>}
      <div className={`global-feedback ${busy || notice ? 'has-feedback' : ''}`} role="status" aria-live="polite" aria-atomic="true">{busy ? (busy === 'policy' ? ko.saving : ko.pending) : notice}</div>
      {!phone && page === 'status' && <ServicePanel snapshot={snapshot} disabled={disabled} onAction={serviceAction} />}
      {phone && (page === 'requests' || page === 'schedule') && <MobileNotices mobile={snapshot.mobile} disabled={disabled} onOpenLock={() => { void controller.run({ kind: 'lock-settings' }); }} onOpenNotifications={() => { void controller.run({ kind: 'notification-settings' }); }} />}
      {phone && page === 'requests' && <RequestPanel snapshot={snapshot} disabled={disabled} readDetails={readDetails} onDecision={(requestId, decision) => { void controller.run({ kind: 'decision', requestId, decision }); }} onOpenScanner={() => { void controller.run({ kind: 'scan_pairing' }); }} scannerButtonRef={scannerButton} />}
      {phone && page === 'schedule' && (hasNoPairedPc(snapshot) || snapshot.requestCatalog?.status !== 'ready') && <PairingEntry snapshot={snapshot} disabled={disabled} onOpenScanner={() => { void controller.run({ kind: 'scan_pairing' }); }} scannerButtonRef={scannerButton} />}
      {page === 'devices' && <DevicesPanel snapshot={snapshot} disabled={disabled} onPair={() => { void controller.run({ kind: 'pair' }); }} onOpenStatus={() => navigate('status')} onRemove={removeDevice} onSetRelay={(address) => controller.run({ kind: 'relay', address })} />}
      {page === 'activity' && <ActivityPanel snapshot={snapshot} disabled={disabled} onClear={clearActivity} />}
      {phone && <div hidden={page !== 'schedule'}><PhoneServicePanel service={snapshot.phoneService} disabled={disabled} onAction={serviceAction} /><PolicyEditor policy={snapshot.policy} available={snapshot.phoneService?.policyOwnerReady === true} unavailableBody={policyUnavailableText(snapshot.phoneService)} disabled={disabled} saving={busy === 'policy'} onSave={async (policy) => {
        const result = await controller.run({ kind: 'policy', policy });
        return result?.policy ?? null;
      }} /></div>}
    </div>
  </main>;

  return <div className={`app-shell ${phone ? 'phone-shell' : 'desktop-shell'}`}><a className="skip-link" href="#main-content">{ko.skip}</a>{phone ? <>{main}{navigation}</> : <>{navigation}{main}</>}{confirmation && <ConfirmDialog confirmation={confirmation} onClose={() => setConfirmation(null)} />}</div>;
}
