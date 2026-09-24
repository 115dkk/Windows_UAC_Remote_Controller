// SPDX-License-Identifier: GPL-2.0-or-later
// Moved from the phone management page to the external-access tab with the same
// behaviour. Its runtime observation lines now live in that tab's current-status
// section, and its headings sit one level below the tab's relay heading.
import { useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { AppSnapshot } from './contracts';
import { ko } from './messages';
import { tr } from './i18n';

export function RelaySettings({ snapshot, disabled, onSetRelay, onOpenStatus }: {
  snapshot: AppSnapshot; disabled: boolean;
  onSetRelay: (address: string) => Promise<AppSnapshot | null>;
  onOpenStatus?: () => void;
}) {
  const [address, setAddress] = useState('');
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const submitLock = useRef(false);
  const id = useId();
  const relayOwnerAvailable = snapshot.service?.controlHint === 'available'
    && ((snapshot.service.installed === false && snapshot.service.state === null)
      || snapshot.service.state === 'stopped'
      || (snapshot.service.state === 'running' && snapshot.dataAvailability.devices === 'available'));
  const relayDisabled = disabled || snapshot.platform !== 'windows' || !relayOwnerAvailable;
  const relaySaveHint = relayOwnerAvailable ? null
    : snapshot.service?.controlHint === 'needs_installer' ? ko.pairingPcInstallFirst : ko.pairingPcCheck;
  const embeddedSelected = snapshot.relayStatus?.mode === 'embedded';
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
  async function enableEmbeddedRelay() {
    if (relayDisabled || embeddedSelected || submitLock.current) return;
    submitLock.current = true;
    setSubmitting(true);
    setError(null);
    try { await onSetRelay('embedded'); }
    catch { setError(ko.saveFailure); }
    finally { submitLock.current = false; setSubmitting(false); }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void saveRelay();
  }
  if (snapshot.platform !== 'windows') return null;
  return <>
    <section className="surface pairing-entry auxiliary-card" aria-label={tr('이 PC (기본)')}>
      <h3>{tr('이 PC (기본)')}</h3>
      <p className="supporting-text">{tr('휴대폰 승인이 켜져 있으면 앱 창을 닫아도 휴대폰이 이 PC에 직접 접속합니다.')}</p>
      <button type="button" className="button primary" disabled={relayDisabled || submitting || embeddedSelected} onClick={() => { void enableEmbeddedRelay(); }}>{tr(embeddedSelected ? '이 PC 사용 중' : '이 PC 사용')}</button>
      {embeddedSelected && snapshot.service?.state === 'stopped' && <>
        <p className="supporting-text">{tr('[PC 상태]에서 휴대폰 승인을 켜면 휴대폰이 이 PC에 접속할 수 있습니다.')}</p>
        {onOpenStatus && <button type="button" className="button secondary" disabled={disabled} onClick={onOpenStatus}>{ko.pairingPcOpenStatus}</button>}
      </>}
      {error && <p className="field-error" role="alert">{error}</p>}
    </section>
    <section className="relay-advanced" aria-label={tr('외부 중계 서버')}><h3>{tr('고급 설정: 외부 중계 서버')}</h3>
    <form className="policy-form" onSubmit={submit} aria-label={ko.relayAddress}>
    <fieldset className="surface form-section" disabled={submitting}>
      <legend><label htmlFor={`${id}-relay`}>{ko.relayAddress}</label></legend>
      <input id={`${id}-relay`} dir="ltr" type="text" value={address} autoComplete="off" spellCheck={false}
        aria-describedby={`${id}-relay-hint ${id}-relay-status${relaySaveHint ? ` ${id}-relay-availability` : ''}`} onChange={(event) => { setAddress(event.target.value); setError(null); }} />
      <p id={`${id}-relay-hint`} className="supporting-text">{ko.relayAddressHint}</p>
      <p id={`${id}-relay-status`} className="supporting-text" aria-live="polite">{snapshot.relayStatus
        ? tr('외부 중계 서버 주소를 저장하면 휴대폰이 이 PC 대신 그 서버에 접속합니다.')
        : snapshot.relayConfigured ? ko.relayConfigured : ko.relayUnconfigured}</p>
      <div className="collection-actions"><button type="submit" className="button primary" disabled={relayDisabled || submitting || !address.trim()}>{submitting ? ko.saving : ko.save}</button></div>
      {relaySaveHint && <p id={`${id}-relay-availability`} className="supporting-text">{relaySaveHint}</p>}
    </fieldset>
  </form></section></>;
}
