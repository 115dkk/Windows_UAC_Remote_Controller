// SPDX-License-Identifier: GPL-2.0-or-later
import { useId } from 'react';
import type { AppSnapshot, PairedDeviceView } from './contracts';
import { Icon } from './icons';
import { activityText, activityUnavailableText, deviceLabel, devicesUnavailableText, ko } from './messages';
import { EmptyState } from './StatusPanels';
import { currentLocale, tr } from './i18n';
import { displayText } from './displayText';
import { useConnectionDisplay } from './useConnectionDisplay';

function DeviceConnectionLine({ device, active }: { device: PairedDeviceView; active: boolean }) {
  const connected = useConnectionDisplay(active && device.connected, `${device.id}:${device.revision}`, active);
  return <p className={`state-line ${connected ? 'is-success' : ''}`}><span className="state-dot" aria-hidden="true" />{connected ? ko.connected : ko.disconnected}</p>;
}

export function DevicesPanel({ snapshot, disabled, onPair, onPairUsb, onOpenStatus, onOpenNetwork, onRemove }: {
  snapshot: AppSnapshot; disabled: boolean; onPair: () => void; onRemove: (device: PairedDeviceView) => void;
  onOpenStatus?: () => void;
  /** Windows only: the external-access tab now owns the relay controls. */
  onOpenNetwork?: () => void;
  onPairUsb?: () => void;
}) {
  const id = useId();
  const phone = snapshot.platform === 'android';
  const pairing = snapshot.pairing;
  const pairingActive = pairing?.phase === 'connecting' || pairing?.phase === 'waiting_for_admin' || pairing?.phase === 'helper_running';
  const unavailable = snapshot.dataAvailability.devices !== 'available';
  const unavailableState = <EmptyState icon="link" title={ko.devicesUnavailable} description={devicesUnavailableText(snapshot)} />;
  const pc = snapshot.platform === 'windows';
  const qrDisabled = disabled || !snapshot.canPair || pairingActive || !snapshot.relayConfigured;
  const relayFirst = snapshot.service?.installed !== false && snapshot.service?.state !== 'stopped'
    && snapshot.canPair && !snapshot.relayConfigured;
  const recovery = snapshot.service?.installed === false ? ko.pairingPcInstallFirst
    : snapshot.service?.state === 'stopped' ? ko.pairingPcStartFirst
      : !snapshot.canPair ? ko.pairingPcCheck : relayFirst ? ko.pairingPcRelayFirst : null;
  const qrEntry = pc && <section className="surface pairing-entry" aria-label={ko.pairPhone}>
    <p className="supporting-text" id={`${id}-qr-purpose`}>{ko.pairingQrPurpose}</p>
    <button type="button" className="button secondary" disabled={qrDisabled} aria-describedby={`${id}-qr-purpose`} onClick={onPair}><Icon name="qr" />{ko.pairPhone}</button>
    {onPairUsb && <button type="button" className="button secondary" disabled={qrDisabled} onClick={onPairUsb}>{tr('USB로 연결')}</button>}
    {pairing && <p className="supporting-text" role="status">{tr(pairing.message)}</p>}
    {!pairingActive && recovery && <p className="supporting-text">{recovery}</p>}
    {!pairingActive && !snapshot.canPair && onOpenStatus && <button type="button" className="button secondary" disabled={disabled} onClick={onOpenStatus}>{ko.pairingPcOpenStatus}</button>}
    {!pairingActive && relayFirst && onOpenNetwork && <button type="button" className="button secondary" disabled={disabled} onClick={onOpenNetwork}>{ko.networkSetup}</button>}
  </section>;
  const phoneEntry = phone && snapshot.mobile?.canOpenPairingScanner === true && <div className="collection-actions">
    <button type="button" className="button secondary" disabled={disabled} onClick={onPair}>{ko.openPairingScanner}</button>
    {onPairUsb && <button type="button" className="button secondary" disabled={disabled} onClick={onPairUsb}>{tr('USB로 연결')}</button>}
  </div>;
  if (unavailable) return <>{qrEntry}{unavailableState}{phoneEntry}</>;
  return <>
    {qrEntry}
    {unavailable ? unavailableState : snapshot.devices.length ? <ul className="surface device-list">{snapshot.devices.map((device) => <li key={device.id}><span className="device-icon"><Icon name={phone ? 'pc' : 'phone'} /></span><div className="device-copy"><h2><bdi dir="ltr">{displayText(deviceLabel(device, pc))}</bdi></h2><DeviceConnectionLine device={device} active={phone ? snapshot.phoneService?.state === 'local_settings_ready' : snapshot.service?.state === 'running'} />{device.lastSeenLabel && <p className="supporting-text"><bdi dir="ltr">{displayText(device.lastSeenLabel)}</bdi></p>}</div>{snapshot.canUnpair && <button type="button" className="button danger-quiet" disabled={disabled} onClick={() => onRemove(device)} aria-label={`${displayText(deviceLabel(device, pc))} ${ko.removeDevice}`}>{ko.removeDevice}</button>}</li>)}</ul>
      : <EmptyState icon={phone ? 'pc' : 'phone'} title={phone ? ko.noComputers : ko.noPhones} description={ko.noDevicesBody} />}
    {phoneEntry}
    {!pc && pairing && <p className="supporting-text" role="status">{tr(pairing.message)}</p>}
  </>;
}

function ActivityTime({ timestamp }: { timestamp: number }) {
  const dateFormatter = new Intl.DateTimeFormat(currentLocale(), { month: 'long', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  const date = new Date(timestamp);
  if (!Number.isFinite(date.getTime())) return <span className="supporting-text">{ko.unknownActivityTime}</span>;
  return <time dateTime={date.toISOString()}>{dateFormatter.format(date)}</time>;
}

export function ActivityPanel({ snapshot, disabled, exporting, saving, onClear, onOpenDiagnostics, onExportDiagnostics, onSaveDiagnostics }: {
  snapshot: AppSnapshot; disabled: boolean; exporting: boolean; saving: boolean; onClear: () => void;
  onOpenDiagnostics: () => void; onExportDiagnostics: () => void; onSaveDiagnostics: () => void;
}) {
  const available = snapshot.dataAvailability.activity === 'available';
  const canClear = available && snapshot.canClearActivity && snapshot.activity.length > 0;
  return <>
    {!available ? <EmptyState icon="history" title={ko.activityUnavailable} description={activityUnavailableText(snapshot)} />
      : snapshot.activity.length ? <ol className="surface activity-list">{snapshot.activity.map((event) => <li key={event.id}><span className={`activity-mark ${event.kind === 'failure' ? 'is-danger' : ''}`}><Icon name={event.kind === 'failure' ? 'alert' : 'history'} /></span><div><h2>{activityText[event.kind]}</h2><ActivityTime timestamp={event.timestampMillis} /></div></li>)}</ol>
      : <EmptyState icon="history" title={ko.noActivity} description={ko.noActivityBody} />}
    {(snapshot.platform === 'windows' || snapshot.platform === 'android' || canClear) && <div className="collection-actions">
      {snapshot.platform === 'windows' && <button type="button" className="button secondary" disabled={disabled} onClick={onOpenDiagnostics}>{ko.openDiagnosticsFolder}</button>}
      {snapshot.platform === 'android' && <button type="button" className="button secondary" disabled={disabled} aria-busy={saving} onClick={onSaveDiagnostics}>{ko.saveDiagnostics}</button>}
      {snapshot.platform === 'android' && <button type="button" className="button secondary" disabled={disabled} aria-busy={exporting} onClick={onExportDiagnostics}>{ko.exportDiagnostics}</button>}
      {canClear && <button type="button" className="button danger-quiet" disabled={disabled} onClick={onClear}>{ko.clearActivity}</button>}
    </div>}
  </>;
}
