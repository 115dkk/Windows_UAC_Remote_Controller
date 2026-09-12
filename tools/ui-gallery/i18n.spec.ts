// SPDX-License-Identifier: GPL-2.0-or-later
// CLIENT / SYNTHETIC. Original browser PNGs and font observations need ROOT
// review; they do not certify Android/Windows native rendering or approval.
import type { Locator, Page, TestInfo } from '@playwright/test';
import { writeFile } from 'node:fs/promises';
import { galleryLocales, galleryText, test, expect } from './session';
import type { GalleryLocale } from './session';
import { i18nBidiCase, i18nDesktopCases, i18nHistoryCases, i18nPhoneCases, i18nSettingsCases } from './i18n-cases';

async function documentLocale(page: Page, locale: GalleryLocale): Promise<void> {
  await expect(page.locator('html')).toHaveAttribute('lang', locale);
  await expect(page.locator('html')).toHaveAttribute('dir', locale === 'ar' ? 'rtl' : 'ltr');
}

async function readable(element: Locator): Promise<void> {
  await element.scrollIntoViewIfNeeded();
  await expect(element).toBeVisible();
  await expect(element).toBeInViewport({ ratio: 1 });
  const metrics = await element.evaluate(node => ({
    width: node.clientWidth, scrollWidth: node.scrollWidth,
    height: node.clientHeight, scrollHeight: node.scrollHeight,
    ellipsis: getComputedStyle(node).textOverflow,
  }));
  expect(metrics.scrollWidth, 'localized text must not clip horizontally').toBeLessThanOrEqual(metrics.width + 1);
  expect(metrics.scrollHeight, 'localized text must not clip vertically').toBeLessThanOrEqual(metrics.height + 1);
  expect(metrics.ellipsis, 'decision/navigation labels must not be ellipsized').not.toBe('ellipsis');
}

const fontFamilies: Partial<Record<GalleryLocale, string>> = {
  ko: 'IBM Plex Sans KR', ar: 'Noto Sans Arabic', ja: 'Noto Sans JP',
  'zh-Hans': 'Noto Sans SC', 'zh-Hant': 'Noto Sans TC',
};
const fontFamily = (locale: GalleryLocale): string => fontFamilies[locale] ?? 'Noto Sans';

async function recordLocalizedFont(page: Page, info: TestInfo, locale: GalleryLocale): Promise<void> {
  const selector = '.page-header h1';
  const heading = page.locator(selector);
  await readable(heading);
  const family = fontFamily(locale);
  const css = await heading.evaluate(async (element, expectedFamily) => {
    await document.fonts.ready;
    const style = getComputedStyle(element);
    const text = element.textContent ?? '';
    return { text, family: style.fontFamily, weight: style.fontWeight,
      expectedLoaded: document.fonts.check(`${style.fontWeight} ${style.fontSize} "${expectedFamily}"`, text) };
  }, family);
  expect(css.text.length).toBeGreaterThan(0);
  expect(css.expectedLoaded, `bundled ${family} must be ready`).toBe(true);
  expect(css.family).toContain(family);
  const client = await page.context().newCDPSession(page);
  let observed: unknown = null;
  try {
    await client.send('DOM.enable');
    await client.send('CSS.enable');
    const { root } = await client.send('DOM.getDocument', { depth: 0 });
    const { nodeId } = await client.send('DOM.querySelector', { nodeId: root.nodeId, selector });
    expect(nodeId).toBeGreaterThan(0);
    const { fonts } = await client.send('CSS.getPlatformFontsForNode', { nodeId });
    observed = fonts;
    expect(fonts.length, 'readiness alone is not evidence of actual glyph use').toBeGreaterThan(0);
    for (const font of fonts) {
      expect(font.glyphCount).toBeGreaterThan(0);
      expect(font.isCustomFont, 'localized heading must use a bundled webfont').toBe(true);
      expect(font.familyName).toContain(family);
    }
  } finally {
    const path = info.outputPath('i18n-platform-fonts.json');
    await writeFile(path, `${JSON.stringify({
      scope: 'CLIENT / SYNTHETIC', locale, selector, expectedFamily: family, css, fonts: observed,
      method: 'CSS.getPlatformFontsForNode', visualReview: 'ROOT_REQUIRED', nativeVerified: false,
    }, null, 2)}\n`);
    await info.attach('i18n-platform-fonts', { contentType: 'application/json', path });
    await client.detach();
  }
}

for (const selected of i18nDesktopCases) {
  const { locale } = selected;
  test(selected.id, async ({ page, gallery }, info) => {
    await gallery.open(selected, locale);
    await documentLocale(page, locale);
    await recordLocalizedFont(page, info, locale);
    const pairing = page.getByRole('button', { name: galleryText(locale, 'UAC 원격 승인'), exact: true });
    await expect(pairing).toBeEnabled();
    await readable(pairing);
    await gallery.capture('localized-desktop', `CLIENT/SYNTHETIC · ${locale} desktop pairing entry and typography`);
  });
}

for (const selected of i18nPhoneCases) {
  const { locale } = selected;
  test(selected.id, async ({ page, gallery }, info) => {
    await gallery.open(selected, locale);
    await documentLocale(page, locale);
    await recordLocalizedFont(page, info, locale);
    await expect(page.locator('.program-name')).toHaveText('설정 도우미.exe');
    await expect(page.locator('.path-output')).toContainText('C:\\Program Files\\');
    await gallery.capture('localized-phone', `CLIENT/SYNTHETIC · ${locale} phone; original program/path are not translated`);
    // Refresh the synthetic read after font observations, without extending any
    // production request deadline or simulating a successful approval.
    await page.getByRole('button', { name: galleryText(locale, '다시 확인'), exact: true }).click();
    for (const source of ['거부', '승인']) {
      const action = page.getByRole('button', { name: galleryText(locale, source), exact: true });
      await expect(action).toBeEnabled();
      await readable(action);
    }
    await gallery.capture('localized-actions', `CLIENT/SYNTHETIC · ${locale} request action labels; no decision executed`);
  });
}

for (const selected of i18nSettingsCases) {
  const { locale } = selected;
  test(selected.id, async ({ page, gallery }) => {
    await gallery.open(selected, locale);
    const name = galleryText(locale, '앱 설정');
    const trigger = page.getByRole('button', { name, exact: true });
    await expect(page.getByRole('navigation').getByRole('button', { name, exact: true })).toHaveCount(0);
    await expect(trigger).toHaveAttribute('aria-haspopup', 'dialog');
    await readable(trigger);
    await trigger.click();
    const dialog = page.getByRole('dialog', { name, exact: true });
    await expect(dialog).toBeVisible();
    await expect(dialog.getByRole('radio')).toHaveCount(galleryLocales.length + 1);
    await expect(dialog.getByRole('radio', { name: galleryText(locale, '시스템 언어 사용'), exact: true })).toBeEnabled();
    await expect(dialog.locator('bdi[lang="ar"]')).toHaveAttribute('dir', 'rtl');
    await expect(dialog.locator('bdi[lang="en"]')).toHaveAttribute('dir', 'ltr');
    await gallery.capture('language-choices', `CLIENT/SYNTHETIC · ${locale} 320px settings; language is secondary, not a main tab`);
    await readable(dialog.getByRole('button', { name: galleryText(locale, '적용'), exact: true }));
    await readable(dialog.getByRole('button', { name: galleryText(locale, '취소'), exact: true }));
    await gallery.capture('language-settings-actions', `CLIENT/SYNTHETIC · ${locale} settings actions and long-copy wrapping`);
    await page.keyboard.press('Escape');
    await expect(dialog).toHaveCount(0);
    await expect(trigger).toBeFocused();
    await documentLocale(page, locale);
  });
}

for (const selected of i18nHistoryCases) {
  const { locale } = selected;
  test(selected.id, async ({ page, gallery }) => {
    await gallery.open(selected, locale);
    await documentLocale(page, locale);
    const dates = page.locator('time');
    await expect(dates).toHaveCount(2);
    for (const date of await dates.all()) {
      await expect(date).toHaveAttribute('datetime', /^2026-09-08T/u);
      await expect(date).toContainText(/\p{Number}/u);
      await expect(date).not.toContainText(/Invalid Date|undefined|NaN/u);
      await readable(date);
    }
    await gallery.capture('localized-dates', `CLIENT/SYNTHETIC · ${locale} date/time readability and translated history`);
  });
}

test(i18nBidiCase.id, async ({ page, gallery }) => {
  await gallery.open(i18nBidiCase, i18nBidiCase.locale);
  await documentLocale(page, 'ar');
  const program = page.locator('.program-name > bdi');
  const path = page.locator('.request-card > .request-facts .path-output');
  for (const original of [program, path]) {
    await expect(original).toHaveAttribute('dir', 'ltr');
    await expect(original).toHaveCSS('direction', 'ltr');
    await expect(original).toHaveCSS('unicode-bidi', 'isolate');
    await expect(original).toContainText('[U+202E]');
    await expect(original).toContainText('gpj.exe');
  }
  await expect(path).toContainText(/\p{Script=Arabic}/u);
  await gallery.capture('bidi-summary', 'CLIENT/SYNTHETIC · Arabic UI, isolated original Arabic/Latin fields, visible spoofing markers');
  await page.getByRole('button', { name: galleryText('ar', '더 보기'), exact: true }).click();
  const region = page.getByRole('region', { name: galleryText('ar', '프로그램 요청 세부 내용'), exact: true });
  const command = region.locator('pre');
  await expect(command).toContainText('[U+202E]');
  await expect(command).toContainText('gpj.exe');
  await expect(command).toContainText('\u200d\u200c');
  await expect(command).toHaveAttribute('dir', 'ltr');
  await expect(command).toHaveCSS('unicode-bidi', 'isolate');
  const text = await page.locator('.request-card').textContent();
  expect(text).not.toMatch(/[\u061c\u200e\u200f\u202a-\u202e\u2066-\u206f]/u);
  await command.scrollIntoViewIfNeeded();
  await gallery.capture('bidi-details', 'CLIENT/SYNTHETIC · full original command display with controls escaped; shaping characters retained');
});
