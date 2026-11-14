// SPDX-License-Identifier: GPL-2.0-or-later
import { afterEach, expect, it } from 'vitest';
import { formatText, isAuthoredCopy, locales, setPreviewLanguage, tr } from './i18n';
import { activityText } from './messages';

const one = 'PC의 UAC 창이 작업 표시줄에서 기다리고 있습니다';
const several = 'PC의 UAC 창 {count}개가 작업 표시줄에서 기다리고 있습니다';
const guidance = '이 창은 아직 휴대폰으로 승인할 수 없습니다. PC 앞에서 작업 표시줄의 깜박이는 방패 버튼을 누르면 이 휴대폰에 승인 요청이 옵니다.';
const waiting = 'UAC 창이 작업 표시줄에서 대기함';
const cleared = '작업 표시줄의 UAC 대기가 끝남';

afterEach(() => { setPreviewLanguage('ko'); });

it.each(locales)('translates parked prompt notice and activity labels in %s', (locale) => {
  setPreviewLanguage(locale);
  for (const key of [one, several, guidance, waiting, cleared]) {
    expect(isAuthoredCopy(key)).toBe(true);
    expect(tr(key)).not.toBe('');
    if (locale !== 'ko') expect(tr(key)).not.toMatch(/[가-힣]/u);
  }
  expect(tr(several).match(/\{[^{}]*\}/gu)).toEqual(['{count}']);
  expect(formatText(several, { count: '16' })).toContain('16');
  expect(formatText(several, { count: '16' })).not.toContain('{count}');
  expect(activityText.parked_on_taskbar).toBe(tr(waiting));
  expect(activityText.parked_cleared).toBe(tr(cleared));
});
