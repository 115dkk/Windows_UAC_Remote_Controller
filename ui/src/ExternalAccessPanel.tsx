// SPDX-License-Identifier: GPL-2.0-or-later
// Windows external-access tab. Addresses here are native observations of a
// published candidate; none of them proves the PC is reachable from outside.
import { Fragment, useId, useRef, useState } from 'react';
import type { FormEvent } from 'react';
import type { AppSnapshot, ExternalAccessInput, ExternalAccessMode, ExternalAccessView } from './contracts';
import { ko } from './messages';
import { formatText, tr } from './i18n';
import { displayText } from './displayText';
import { RelayStatusLine } from './RelayStatusLine';
import { DirectConnectionStatus, FirewallGuidance } from './DirectConnectionStatus';
import { RelaySettings } from './RelaySettings';
import {
  addressInvalidText, addressUnreachableText, DEFAULT_RELAY_PORT, draftChanged, draftFromView, failureText, FIXED_ADDRESS_EXAMPLE,
  inputFromDraft, lanEndpoint, modeText, parsePort, portInvalidText, sourceText,
} from './externalAccess';
import type { ExternalAccessDraft } from './externalAccess';

const modes: readonly ExternalAccessMode[] = ['automatic', 'router_forward', 'fixed'];

function confirms(view: ExternalAccessView | null | undefined, input: ExternalAccessInput): boolean {
  if (!view || view.mode !== input.mode) return false;
  if (input.mode === 'router_forward') return view.externalPort === input.externalPort;
  if (input.mode === 'fixed') return view.fixedAddress === input.fixedAddress;
  return true;
}

function ExternalAccessStatus({ snapshot, stale }: { snapshot: AppSnapshot; stale: boolean }) {
  const id = useId();
  // A stale or missing read cannot say that an address is absent.
  const view = stale ? null : snapshot.externalAccess ?? null;
  const reason = view && !view.externalAddress && view.failure ? failureText[view.failure] : null;
  const lan = view ? lanEndpoint(view) : null;
  const unknown = tr('확인 불가');
  return <section className="network-section" aria-labelledby={`${id}-heading`}>
    <h2 id={`${id}-heading`}>{tr('현재 상태')}</h2>
    <div className="surface network-card">
      <RelayStatusLine snapshot={snapshot} stale={stale} />
      <DirectConnectionStatus snapshot={snapshot} stale={stale} guidance={false} />
      {reason && <p className="supporting-text network-reason">{tr(reason)}</p>}
      <dl className="status-facts">
        <div><dt>{tr('외부 주소')}</dt><dd>{!view ? unknown : view.externalAddress
          ? <bdi dir="ltr">{displayText(view.externalAddress)}</bdi> : tr('없음')}</dd></div>
        <div><dt>{tr('주소를 얻은 방법')}</dt><dd>{!view ? unknown : view.source ? tr(sourceText[view.source]) : tr('없음')}</dd></div>
        <div><dt>{tr('이 PC의 내부 주소')}</dt><dd>{lan ? <bdi dir="ltr">{displayText(lan)}</bdi> : unknown}</dd></div>
      </dl>
    </div>
  </section>;
}

function ExternalAccessForm({ snapshot, stale, disabled, onSave }: {
  snapshot: AppSnapshot; stale: boolean; disabled: boolean;
  onSave: (input: ExternalAccessInput) => Promise<AppSnapshot | null>;
}) {
  // A null draft follows the refreshed native view; a real draft survives refreshes.
  const [draft, setDraft] = useState<ExternalAccessDraft | null>(null);
  const [fieldError, setFieldError] = useState<'port' | 'address' | 'address_unreachable' | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const submitLock = useRef(false);
  const composing = useRef(false);
  const form = useRef<HTMLFormElement>(null);
  const id = useId();
  const view = snapshot.externalAccess ?? null;
  const value = draft ?? draftFromView(view);
  const dirty = draftChanged(value, view);
  const ownerAvailable = snapshot.platform === 'windows' && snapshot.service?.controlHint === 'available'
    && ((snapshot.service.installed === false && snapshot.service.state === null)
      || snapshot.service.state === 'stopped'
      || (snapshot.service.state === 'running' && snapshot.dataAvailability.devices === 'available'));
  const saveHint = ownerAvailable ? null
    : snapshot.service?.controlHint === 'needs_installer' ? ko.pairingPcInstallFirst : ko.pairingPcCheck;
  const relayPort = view?.relayPort ?? DEFAULT_RELAY_PORT;
  const lan = stale ? null : view?.lanAddress ?? null;

  function edit(next: Partial<ExternalAccessDraft>) {
    setDraft({ ...value, ...next });
    setFieldError(null);
    setError(null);
  }
  async function save() {
    if (disabled || !ownerAvailable || submitLock.current || composing.current || value.mode === null || !dirty) return;
    const result = inputFromDraft({ ...value, mode: value.mode });
    if ('error' in result) {
      setFieldError(result.error);
      queueMicrotask(() => form.current?.querySelector<HTMLElement>('[aria-invalid="true"]')?.focus());
      return;
    }
    submitLock.current = true;
    setSubmitting(true);
    setError(null);
    try {
      const confirmed = await onSave(result.input);
      // Keep the draft unless the native owner reports exactly this setting.
      if (confirmed && !confirmed.issue && confirms(confirmed.externalAccess, result.input)) setDraft(null);
    } catch {
      setError(ko.saveFailure);
    } finally {
      submitLock.current = false;
      setSubmitting(false);
    }
  }
  function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void save();
  }
  const portError = fieldError === 'port';
  const addressError = fieldError === 'address' || fieldError === 'address_unreachable';
  const external = parsePort(value.port) ?? relayPort;
  return <section className="network-section" aria-labelledby={`${id}-heading`}>
    <form ref={form} className="network-form" onSubmit={submit} noValidate
      onCompositionStart={() => { composing.current = true; }} onCompositionEnd={() => { composing.current = false; }}
      onKeyDown={(event) => { if (event.key === 'Enter' && (event.nativeEvent.isComposing || composing.current)) event.preventDefault(); }}>
      <fieldset className="network-choice" disabled={submitting}>
        <legend><h2 id={`${id}-heading`}>{tr('외부에서 연결하는 방법')}</h2></legend>
        <div className="surface network-card">
          <div className="network-modes">{modes.map((mode) => <Fragment key={mode}>
            <label className={`radio-option ${value.mode === mode ? 'selected' : ''}`}>
              <input type="radio" name={`${id}-mode`} value={mode} checked={value.mode === mode}
                aria-labelledby={`${id}-${mode}-title`} aria-describedby={`${id}-${mode}-description`} onChange={() => edit({ mode })} />
              <span><span id={`${id}-${mode}-title`} className="option-title">{tr(modeText[mode].title)}</span>
                <span id={`${id}-${mode}-description`} className="option-description">{tr(modeText[mode].description)}</span></span>
            </label>
            {mode === 'router_forward' && value.mode === mode && <div className="network-option-detail">
              <div className="network-field">
                <label htmlFor={`${id}-port`}>{tr('공유기의 외부 포트')}</label>
                <input id={`${id}-port`} type="number" inputMode="numeric" min={1} max={65535} step={1} dir="ltr"
                  value={value.port} autoComplete="off" aria-invalid={portError}
                  aria-describedby={`${id}-port-hint${portError ? ` ${id}-port-error` : ''}`}
                  onChange={(event) => edit({ port: event.target.value })} />
                <p id={`${id}-port-hint`} className="supporting-text">{formatText('DMZ를 쓰면 {port}입니다.', { port: String(relayPort) })}</p>
                {portError && <p id={`${id}-port-error`} className="field-error">{tr(portInvalidText)}</p>}
              </div>
              <div className="notice-box network-instructions">
                <div>
                  <p>{formatText('공유기 관리 페이지의 포트포워딩에서 외부 포트 {external}을(를) {lan}의 {port} 포트(TCP)로 연결하십시오.',
                    { external: String(external), lan: lan ? displayText(lan) : tr('이 PC'), port: String(relayPort) })}</p>
                  <p className="supporting-text">{tr('PC의 내부 주소가 바뀌면 포트포워딩이 끊깁니다. 공유기의 DHCP 고정 할당으로 이 PC의 주소를 고정해 두십시오.')}</p>
                </div>
              </div>
            </div>}
            {mode === 'fixed' && value.mode === mode && <div className="network-option-detail">
              <div className="network-field">
                <label htmlFor={`${id}-address`}>{tr('외부 주소')}</label>
                <input id={`${id}-address`} type="text" dir="ltr" placeholder={FIXED_ADDRESS_EXAMPLE}
                  value={value.address} autoComplete="off" spellCheck={false} aria-invalid={addressError}
                  aria-describedby={addressError ? `${id}-address-error` : undefined}
                  onChange={(event) => edit({ address: event.target.value })} />
                {addressError && <p id={`${id}-address-error`} className="field-error">{tr(fieldError === 'address_unreachable' ? addressUnreachableText : addressInvalidText)}</p>}
              </div>
            </div>}
          </Fragment>)}</div>
          <div className="collection-actions"><button type="submit" className="button primary"
            disabled={disabled || !ownerAvailable || submitting || !dirty}>{submitting ? ko.saving : ko.save}</button></div>
          <p className="supporting-text network-note">{tr('설정을 바꾼 뒤에는 휴대폰을 집 Wi-Fi에 한 번 연결해야 새 외부 주소를 받습니다.')}</p>
          {saveHint && <p className="supporting-text network-note">{saveHint}</p>}
          {error && <p className="field-error" role="alert">{error}</p>}
        </div>
      </fieldset>
    </form>
  </section>;
}

export function ExternalAccessPanel({ snapshot, disabled, stale = false, onSave, onSetRelay, onOpenStatus }: {
  snapshot: AppSnapshot; disabled: boolean; stale?: boolean;
  onSave: (input: ExternalAccessInput) => Promise<AppSnapshot | null>;
  onSetRelay: (address: string) => Promise<AppSnapshot | null>;
  onOpenStatus?: () => void;
}) {
  const id = useId();
  if (snapshot.platform !== 'windows') return null;
  return <>
    <ExternalAccessStatus snapshot={snapshot} stale={stale} />
    <ExternalAccessForm snapshot={snapshot} stale={stale} disabled={disabled} onSave={onSave} />
    <section className="network-section" aria-labelledby={`${id}-relay`}>
      <h2 id={`${id}-relay`}>{tr('휴대폰이 접속할 곳')}</h2>
      <RelaySettings snapshot={snapshot} disabled={disabled} onSetRelay={onSetRelay} {...(onOpenStatus ? { onOpenStatus } : {})} />
    </section>
    <FirewallGuidance snapshot={snapshot} stale={stale} className="supporting-text network-guidance" />
  </>;
}
