// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useId, useRef, useState } from 'react';
import { languageNames, locales, setLanguage, tr, useLanguage } from './i18n';
import type { LanguagePreference } from './i18n';

export function LanguageSettings({ onClose }: {onClose: () => void}) {
  const current = useLanguage();
  const [choice,setChoice] = useState<LanguagePreference>(current.preference);
  const [saving,setSaving] = useState(false);
  const [error,setError] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const heading = useId();
  const hint = useId();
  useEffect(() => {
    const previous = document.activeElement;
    const element = dialog.current;
    element?.showModal();
    return () => { element?.close(); if (previous instanceof HTMLElement && previous.isConnected) previous.focus(); };
  }, []);
  async function save() {
    if (saving) return;
    setSaving(true); setError(false);
    try { await setLanguage(choice); onClose(); }
    catch { setError(true); setSaving(false); }
  }
  return <dialog ref={dialog} className="confirm-dialog language-settings" aria-labelledby={heading} aria-describedby={hint}
    onCancel={event => { event.preventDefault(); if (!saving) onClose(); }}>
    <h2 id={heading}>{tr('앱 설정')}</h2>
    <fieldset disabled={saving} className="language-choices"><legend>{tr('표시 언어')}</legend>
      <label><input type="radio" name={heading} checked={choice === 'system'} onChange={() => setChoice('system')} />{tr('시스템 언어 사용')}</label>
      {locales.map(locale => <label key={locale}><input type="radio" name={heading} checked={choice === locale} onChange={() => setChoice(locale)} /><bdi lang={locale} dir={locale === 'ar' ? 'rtl' : 'ltr'}>{languageNames[locale]}</bdi></label>)}
    </fieldset>
    <p id={hint} className="supporting-text">{tr('시스템 언어에 맞춰 표시합니다. 지원하지 않는 언어는 영어로 표시합니다.')}</p>
    <p className="supporting-text">{tr('언어를 바꿔도 PC 요청, 파일 경로와 연결 확인 숫자는 원문 그대로 표시합니다.')}</p>
    {error && <p role="alert">{tr('언어 설정을 저장하지 못했어요. 다시 시도해 주세요.')}</p>}
    <div className="dialog-actions"><button type="button" className="button secondary" disabled={saving} onClick={onClose}>{tr('취소')}</button><button type="button" className="button primary" disabled={saving} onClick={() => { void save(); }}>{tr('적용')}</button></div>
  </dialog>;
}
