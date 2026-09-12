// SPDX-License-Identifier: GPL-2.0-or-later
import { useSyncExternalStore } from 'react';
import { invoke, isTauri } from '@tauri-apps/api/core';
import ko from '../../locales/ko.json';
import en from '../../locales/en.json';
import fr from '../../locales/fr.json';
import de from '../../locales/de.json';
import ja from '../../locales/ja.json';
import hans from '../../locales/zh-Hans.json';
import hant from '../../locales/zh-Hant.json';
import es from '../../locales/es.json';
import br from '../../locales/pt-BR.json';
import pt from '../../locales/pt-PT.json';
import ar from '../../locales/ar.json';

export const locales = ['ko','en','fr','de','ja','zh-Hans','zh-Hant','es','pt-BR','pt-PT','ar'] as const;
export type Locale = typeof locales[number];
export type LanguagePreference = Locale | 'system';
export const languageNames: Record<Locale, string> = { ko:'한국어', en:'English', fr:'Français', de:'Deutsch', ja:'日本語', 'zh-Hans':'简体中文', 'zh-Hant':'繁體中文', es:'Español', 'pt-BR':'Português (Brasil)', 'pt-PT':'Português (Portugal)', ar:'العربية' };
const catalogs: Record<Locale, Readonly<Record<string,string>>> = {ko,en,fr,de,ja,'zh-Hans':hans,'zh-Hant':hant,es,'pt-BR':br,'pt-PT':pt,ar};
export function resolveLocale(languages: readonly string[]): Locale {
  for (const input of languages) {
    const tag = input.toLowerCase().replaceAll('_','-');
    const language = tag.split('-')[0];
    if (language === 'zh') {
      const parts = tag.split('-').slice(1);
      const extension = parts.findIndex(part => part.length === 1);
      const core = extension < 0 ? parts : parts.slice(0, extension);
      if (core.includes('hans')) return 'zh-Hans';
      return core.includes('hant') || core.some(part => ['tw','hk','mo'].includes(part)) ? 'zh-Hant' : 'zh-Hans';
    }
    if (language === 'pt') {
      const parts = tag.split('-').slice(1);
      const extension = parts.findIndex(part => part.length === 1);
      return (extension < 0 ? parts : parts.slice(0, extension)).includes('pt') ? 'pt-PT' : 'pt-BR';
    }
    if (language && locales.includes(language as Locale)) return language as Locale;
  }
  return 'en';
}
export function isPreference(value: unknown): value is LanguagePreference {
  return typeof value === 'string' && (value === 'system' || locales.includes(value as Locale));
}
interface LanguageState { readonly preference: LanguagePreference; readonly locale: Locale }
const browserLanguages = (): readonly string[] => typeof navigator === 'undefined' ? ['en'] : navigator.languages;
let state: LanguageState = { preference:'system', locale:resolveLocale(browserLanguages()) };
const listeners = new Set<() => void>();
function accept(preference: LanguagePreference, systemLocales: readonly string[]) {
  const locale = preference === 'system' ? resolveLocale(systemLocales) : preference;
  if (state.preference === preference && state.locale === locale) return;
  state = { preference, locale };
  for (const listener of listeners) listener();
}
export const currentLocale = (): Locale => state.locale;
export function useLanguage(): LanguageState {
  return useSyncExternalStore(listener => { listeners.add(listener); return () => { listeners.delete(listener); }; }, () => state);
}
interface NativeLanguage { preference: LanguagePreference; systemLocales: string[] }
function checkedReply(value: NativeLanguage): NativeLanguage {
  if (!isPreference(value.preference) || !Array.isArray(value.systemLocales) || value.systemLocales.length > 32
    || value.systemLocales.some(tag => typeof tag !== 'string' || tag.length > 85)) throw new Error('language_reply_invalid');
  return value;
}
export async function refreshLanguage(): Promise<void> {
  if (isTauri()) {
    try { const value = checkedReply(await invoke<NativeLanguage>('get_language')); accept(value.preference, value.systemLocales); return; }
    catch { /* Language-only fallback; no authority or request state is inferred. */ }
  }
  accept(state.preference, browserLanguages());
}
export async function setLanguage(preference: LanguagePreference): Promise<void> {
  if (!isPreference(preference)) throw new Error('invalid_language');
  if (isTauri()) {
    const value = checkedReply(await invoke<NativeLanguage>('set_language', {language:preference}));
    accept(value.preference, value.systemLocales);
  } else {
    // Browser preview preference only; installed apps use their native owner.
    localStorage.setItem('uac-language', preference);
    accept(preference, browserLanguages());
  }
}
export async function initializeLanguage(): Promise<void> {
  if (!isTauri()) {
    try { const saved = localStorage.getItem('uac-language'); if (isPreference(saved)) accept(saved, browserLanguages()); } catch { /* System default remains usable. */ }
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  await Promise.race([refreshLanguage(), new Promise<void>(resolve => { timer = setTimeout(resolve, 3000); })]);
  clearTimeout(timer);
  document.documentElement.lang = state.locale;
  document.documentElement.dir = state.locale === 'ar' ? 'rtl' : 'ltr';
  const family = state.locale === 'ko' ? 'IBM Plex Sans KR' : state.locale === 'ja' ? 'Noto Sans JP'
    : state.locale === 'zh-Hans' ? 'Noto Sans SC' : state.locale === 'zh-Hant' ? 'Noto Sans TC'
      : state.locale === 'ar' ? 'Noto Sans Arabic' : 'Noto Sans';
  try {
    await Promise.race([document.fonts.load(`400 16px "${family}"`), new Promise<void>(resolve => { timer = setTimeout(resolve, 3000); })]);
  } catch { /* Bundled-font failure leaves explicit system fallback. CI verifies shipped glyphs. */ }
  finally { clearTimeout(timer); }
  window.addEventListener('languagechange', () => { void refreshLanguage(); });
  window.addEventListener('focus', () => { void refreshLanguage(); });
}
/** Trusted authored copy only: never pass program/path/request/device data here. */
export function tr(source: string): string {
  return catalogs[state.locale][source] ?? catalogs.en[source] ?? source;
}
export function formatText(source: string, values: Readonly<Record<string,string>>): string {
  return tr(source).replace(/\{([a-z]+)\}/gu, (original: string, key: string) => values[key] ?? original);
}
export function numberText(value: number): string { return new Intl.NumberFormat(state.locale, { useGrouping:false }).format(value); }
/** Explicit synthetic test/gallery control, never an authorization or native setting. */
export function setPreviewLanguage(preference: LanguagePreference, systemLocales: readonly string[] = ['ko-KR']): void { accept(preference, systemLocales); }
