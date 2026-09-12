// SPDX-License-Identifier: GPL-2.0-or-later
// Actual client geometry with synthetic state. No native authorization claim.
import type { Page } from '@playwright/test';
import { headerCases } from './header-cases';
import { test, expect, galleryText } from './session';

async function anchor(page: Page, rtl: boolean) {
  const header = page.locator('.page-header');
  const settings = header.locator('.app-settings-button');
  await expect(settings).toBeInViewport({ ratio: 1 });
  const geometry = await header.evaluate(node => {
    const box = (selector: string) => {
      const rect = node.querySelector(selector)?.getBoundingClientRect();
      return rect ? { x: rect.x, y: rect.y, right: rect.right, bottom: rect.bottom, width: rect.width, height: rect.height } : null;
    };
    const rect = node.getBoundingClientRect();
    return { x: rect.x, y: rect.y, right: rect.right, width: node.clientWidth, scrollWidth: node.scrollWidth,
      title: box('h1'), actions: box('.header-actions'), settings: box('.app-settings-button'), description: box('.page-description') };
  });
  expect(geometry.scrollWidth).toBeLessThanOrEqual(geometry.width + 1);
  expect(geometry.settings!.width).toBeGreaterThanOrEqual(44);
  expect(geometry.settings!.height).toBeGreaterThanOrEqual(44);
  expect(Math.abs(geometry.settings!.y - geometry.y)).toBeLessThanOrEqual(1);
  expect(Math.abs(rtl ? geometry.settings!.x - geometry.x : geometry.right - geometry.settings!.right)).toBeLessThanOrEqual(1);
  if (rtl) expect(geometry.actions!.right).toBeLessThanOrEqual(geometry.title!.x);
  else expect(geometry.title!.right).toBeLessThanOrEqual(geometry.actions!.x);
  if (geometry.description) {
    expect(geometry.description.y).toBeGreaterThanOrEqual(Math.max(geometry.title!.bottom, geometry.actions!.bottom));
    expect(Math.abs(geometry.description.x - geometry.x)).toBeLessThanOrEqual(1);
    expect(Math.abs(geometry.description.right - geometry.right)).toBeLessThanOrEqual(1);
  }
  return geometry.settings!;
}

for (const selected of headerCases) {
  test(selected.id, async ({ page, gallery }) => {
    const { locale } = selected;
    await gallery.open(selected, locale);
    const first = await anchor(page, locale === 'ar');
    await gallery.capture('initial-anchor', 'CLIENT/SYNTHETIC · title-row controls, independent full-width description');
    const pages = selected.fixture.startsWith('phone-')
      ? ['알림 시간', '연결된 PC', '기록', '요청'] : ['PC 상태', '활동 기록', '휴대폰 관리'];
    for (const source of pages) {
      await page.getByRole('navigation').getByRole('button', { name: galleryText(locale, source), exact: true }).click();
      const next = await anchor(page, locale === 'ar');
      expect(Math.abs(next.x - first.x), `settings x after ${source}`).toBeLessThanOrEqual(1);
      expect(Math.abs(next.y - first.y), `settings y after ${source}`).toBeLessThanOrEqual(1);
      if (source === '알림 시간') await gallery.capture('schedule-anchor', 'CLIENT/SYNTHETIC · schedule description does not push controls down');
    }
    const refresh = page.locator('.page-header .refresh-button');
    await expect(refresh).toHaveAccessibleName(galleryText(locale, '다시 확인'));
    if (selected.rootTextSizePercent === 200 || selected.viewport.width === 320) {
      await expect(refresh.locator('.refresh-label')).toBeHidden();
      expect((await refresh.boundingBox())!.width).toBeGreaterThanOrEqual(48);
    }
    await refresh.click();
    await expect(refresh).toBeEnabled();
    await page.locator('.page-header .app-settings-button').click();
    await expect(page.getByRole('dialog')).toBeVisible();
    await page.keyboard.press('Escape');
    await expect(page.locator('.page-header .app-settings-button')).toBeFocused();
    await anchor(page, locale === 'ar');
    await gallery.capture('returned-anchor', 'CLIENT/SYNTHETIC · refresh and settings retain focus and the same anchor');
  });
}
