// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot, PairedDeviceView } from './contracts';
import { Icon } from './icons';
import { activityText, ko } from './messages.ko';
import { EmptyState } from './StatusPanels';

export function DevicesPanel({ snapshot, disabled, onPair, onRemove }: {
  snapshot: AppSnapshot; disabled: boolean; onPair: () => void; onRemove: (device: PairedDeviceView) => void;
}) {
  const phone = snapshot.platform === 'android';
  const pairing = snapshot.pairing;
  const pairingActive = pairing?.phase === 'connecting' || pairing?.phase === 'waiting_for_admin' || pairing?.phase === 'helper_running';
  const unavailable = snapshot.dataAvailability.devices !== 'available';
  const unavailableState = <EmptyState icon="link" title={ko.devicesUnavailable} description={ko.devicesUnavailableBody} />;
  if (unavailable && (snapshot.platform !== 'windows' || (!snapshot.canPair && !pairing))) return unavailableState;
  return <>
    {unavailable ? unavailableState : snapshot.devices.length ? <ul className="surface device-list">{snapshot.devices.map((device) => <li key={device.id}><span className="device-icon"><Icon name={phone ? 'pc' : 'phone'} /></span><div className="device-copy"><h2><bdi>{device.name}</bdi></h2><p className={`state-line ${device.connected ? 'is-success' : ''}`}><span className="state-dot" aria-hidden="true" />{device.connected ? ko.connected : ko.disconnected}</p>{device.lastSeenLabel && <p className="supporting-text"><bdi>{device.lastSeenLabel}</bdi></p>}</div>{snapshot.canUnpair && <button type="button" className="button danger-quiet" disabled={disabled} onClick={() => onRemove(device)} aria-label={`${device.name} ${ko.removeDevice}`}>{ko.removeDevice}</button>}</li>)}</ul>
      : <EmptyState icon={phone ? 'pc' : 'phone'} title={phone ? ko.noComputers : ko.noPhones} description={ko.noDevicesBody} />}
    {snapshot.canPair || pairingActive ? <div className="collection-actions"><button type="button" className="button primary" disabled={disabled || pairingActive} onClick={onPair}><Icon name="plus" />{phone ? ko.pairComputer : ko.pairPhone}</button></div> : !pairing && <p className="supporting-text">{ko.pairingUnavailable}</p>}
    {pairing && <p className="supporting-text" role="status">{pairing.message}</p>}
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
