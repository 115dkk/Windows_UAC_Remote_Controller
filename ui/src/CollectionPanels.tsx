// SPDX-License-Identifier: GPL-2.0-or-later
import { useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { AppSnapshot, PairedDeviceView } from './contracts';
import { Icon } from './icons';
import { activityText, ko } from './messages.ko';
import { EmptyState } from './StatusPanels';

export function DevicesPanel({ snapshot, disabled, onPair, onOpenStatus, onRemove, onSetRelay }: {
  snapshot: AppSnapshot; disabled: boolean; onPair: () => void; onRemove: (device: PairedDeviceView) => void;
  onSetRelay: (address: string) => Promise<AppSnapshot | null>;
  onOpenStatus?: () => void;
}) {
  const [address, setAddress] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submitLock = useRef(false);
  const id = useId();
  const phone = snapshot.platform === 'android';
  const relayOwnerAvailable = snapshot.service?.controlHint === 'available'
    && ((snapshot.service.installed === false && snapshot.service.state === null)
      || snapshot.service.state === 'stopped'
      || (snapshot.service.state === 'running' && snapshot.dataAvailability.devices === 'available'));
  const relayDisabled = disabled || snapshot.platform !== 'windows' || !relayOwnerAvailable;
  async function saveRelay() {
    if (relayDisabled || submitLock.current || !address.trim()) return;
    submitLock.current = true;
    setSubmitting(true);
    setError(null);
    try {
      const confirmed = await onSetRelay(address);
      if (confirmed && !confirmed.issue && confirmed.relayConfigured) setAddress('');
    } catch {
      setError(ko.saveFailure);
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void saveRelay();
  }
  const pairing = snapshot.pairing;
  const pairingActive = pairing?.phase === 'connecting' || pairing?.phase === 'waiting_for_admin' || pairing?.phase === 'helper_running';
  const unavailable = snapshot.dataAvailability.devices !== 'available';
  const unavailableState = <EmptyState icon="link" title={ko.devicesUnavailable} description={ko.devicesUnavailableBody} />;
  const relayForm = snapshot.platform === 'windows' && <form className="policy-form" onSubmit={submit} aria-label={ko.relayAddress}>
    <fieldset className="surface form-section" disabled={relayDisabled || submitting}>
      <legend><label htmlFor={`${id}-relay`}>{ko.relayAddress}</label></legend>
      <input id={`${id}-relay`} type="text" value={address} autoComplete="off" spellCheck={false}
        aria-describedby={`${id}-relay-hint ${id}-relay-status`} onChange={(event) => { setAddress(event.target.value); setError(null); }} />
      <p id={`${id}-relay-hint`} className="supporting-text">{ko.relayAddressHint}</p>
      <p id={`${id}-relay-status`} className="supporting-text" aria-live="polite">{snapshot.relayConfigured ? ko.relayConfigured : ko.relayUnconfigured}</p>
      {error && <p className="field-error" role="alert">{error}</p>}
      <div className="collection-actions"><button type="submit" className="button primary" disabled={relayDisabled || submitting || !address.trim()}>{submitting ? ko.saving : ko.save}</button></div>
    </fieldset>
  </form>;
  const pc = snapshot.platform === 'windows';
  const qrDisabled = disabled || !snapshot.canPair || pairingActive || !snapshot.relayConfigured;
  const recovery = snapshot.service?.installed === false ? ko.pairingPcInstallFirst
    : snapshot.service?.state === 'stopped' ? ko.pairingPcStartFirst
      : !snapshot.canPair ? ko.pairingPcCheck : !snapshot.relayConfigured ? ko.pairingPcRelayFirst : null;
  const qrEntry = pc && <section className="surface pairing-entry" aria-label={ko.pairPhone}>
    <p className="supporting-text" id={`${id}-qr-purpose`}>{ko.pairingQrPurpose}</p>
    <button type="button" className="button primary" disabled={qrDisabled} aria-describedby={`${id}-qr-purpose`} onClick={onPair}><Icon name="qr" />{ko.pairPhone}</button>
    {pairing && <p className="supporting-text" role="status">{pairing.message}</p>}
    {!pairingActive && recovery && <p className="supporting-text">{recovery}</p>}
    {!pairingActive && !snapshot.canPair && onOpenStatus && <button type="button" className="button secondary" onClick={onOpenStatus}>{ko.pairingPcOpenStatus}</button>}
  </section>;
  if (unavailable) return <>{qrEntry}{unavailableState}{relayForm}</>;
  return <>
    {qrEntry}
    {unavailable ? unavailableState : snapshot.devices.length ? <ul className="surface device-list">{snapshot.devices.map((device) => <li key={device.id}><span className="device-icon"><Icon name={phone ? 'pc' : 'phone'} /></span><div className="device-copy"><h2><bdi>{device.name}</bdi></h2><p className={`state-line ${device.connected ? 'is-success' : ''}`}><span className="state-dot" aria-hidden="true" />{device.connected ? ko.connected : ko.disconnected}</p>{device.lastSeenLabel && <p className="supporting-text"><bdi>{device.lastSeenLabel}</bdi></p>}</div>{snapshot.canUnpair && <button type="button" className="button danger-quiet" disabled={disabled} onClick={() => onRemove(device)} aria-label={`${device.name} ${ko.removeDevice}`}>{ko.removeDevice}</button>}</li>)}</ul>
      : <EmptyState icon={phone ? 'pc' : 'phone'} title={phone ? ko.noComputers : ko.noPhones} description={ko.noDevicesBody} />}
    {!pc && (snapshot.canPair || pairingActive ? <div className="collection-actions"><button type="button" className="button primary" disabled={disabled || pairingActive} onClick={onPair}><Icon name="plus" />{ko.pairComputer}</button></div> : !pairing && <p className="supporting-text">{ko.pairingUnavailable}</p>)}
    {!pc && pairing && <p className="supporting-text" role="status">{pairing.message}</p>}
    {relayForm}
  </>;
}

const dateFormatter = new Intl.DateTimeFormat('ko-KR', { month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });

function ActivityTime({ timestamp }: { timestamp: number }) {
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) return <span className="supporting-text">{ko.unknownActivityTime}</span>;
  return <time dateTime={date.toISOString()}>{dateFormatter.format(date)}</time>;
}

export function ActivityPanel({ snapshot, disabled, onClear }: {
  snapshot: AppSnapshot; disabled: boolean; onClear: () => void;
}) {
  if (snapshot.dataAvailability.activity !== 'available') return <EmptyState icon="history" title={ko.activityUnavailable} description={ko.activityUnavailableBody} />;
  return <>
    {snapshot.activity.length ? <ol className="surface activity-list">{snapshot.activity.map((event) => <li key={event.id}><span className={`activity-mark ${event.kind === 'failure' ? 'is-danger' : ''}`}><Icon name={event.kind === 'failure' ? 'alert' : 'history'} /></span><div><h2>{activityText[event.kind]}</h2><ActivityTime timestamp={event.timestampMillis} /></div></li>)}</ol>
      : <EmptyState icon="history" title={ko.noActivity} description={ko.noActivityBody} />}
    {snapshot.canClearActivity && snapshot.activity.length > 0 && <div className="collection-actions"><button type="button" className="button danger-quiet" disabled={disabled} onClick={onClear}>{ko.clearActivity}</button></div>}
  </>;
}
