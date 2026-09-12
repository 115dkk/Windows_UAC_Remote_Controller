// SPDX-License-Identifier: GPL-2.0-or-later
import { afterEach, expect, it, vi } from 'vitest';
import { currentLocale, isPreference, refreshLanguage, resolveLocale, setLanguage, setPreviewLanguage, tr } from './i18n';

afterEach(() => { vi.restoreAllMocks(); localStorage.removeItem('uac-language'); });

it('quietly resolves ordered OS languages, scripts and regions without extension confusion', () => {
  for (const [tags, expected] of [
    [['xx', 'fr-CA'], 'fr'], [['zh-Hans-TW'], 'zh-Hans'], [['zh-Hant-CN'], 'zh-Hant'],
    [['zh-HK'], 'zh-Hant'], [['zh-u-rg-twzzzz'], 'zh-Hans'], [['pt'], 'pt-BR'],
    [['pt-PT'], 'pt-PT'], [['pt-BR-x-pt'], 'pt-BR'], [['ar-EG'], 'ar'],
    [['zz-ZZ'], 'en'], [[], 'en'], [['ja-JP', 'ko-KR'], 'ja'],
  ] as const) expect(resolveLocale(tags)).toBe(expected);
});

it('accepts only known manual preferences', () => {
  for (const value of ['system', 'ko', 'ar', 'pt-PT']) expect(isPreference(value)).toBe(true);
  for (const value of ['ar-EG', '\u202Ear', 'unknown', null, 42]) expect(isPreference(value)).toBe(false);
});

it('persists preview choice and resumes OS tracking only when system is selected', async () => {
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(['fr-CA']);
  await setLanguage('ar');
  expect(localStorage.getItem('uac-language')).toBe('ar');
  await refreshLanguage();
  expect(currentLocale()).toBe('ar');
  await setLanguage('system');
  expect(currentLocale()).toBe('fr');
  expect(localStorage.getItem('uac-language')).toBe('system');
});

it('changes authored copy while unknown text is not translated', () => {
  setPreviewLanguage('en');
  expect(tr('UAC 원격 승인')).toBe('UAC Remote Approval');
  expect(tr('unrecognized authored diagnostic')).toBe('unrecognized authored diagnostic');
  setPreviewLanguage('ko');
  expect(tr('UAC 원격 승인')).toBe('UAC 원격 승인');
});
