// SPDX-License-Identifier: GPL-2.0-or-later
import { test as base, expect } from '@playwright/test';
import { readFileSync } from 'node:fs';
import type { Browser, Page, TestInfo } from '@playwright/test';
import type { GalleryCase } from './cases';

const bannerText = '화면 예시 · 실제 연결 아님';
const maxMessages = 50;
export const galleryLocales = ['ko', 'en', 'fr', 'de', 'ja', 'zh-Hans', 'zh-Hant', 'es', 'pt-BR', 'pt-PT', 'ar'] as const;
export type GalleryLocale = typeof galleryLocales[number];
const catalogs = new Map<GalleryLocale, Record<string, string>>(galleryLocales.map(locale => [
  locale, JSON.parse(readFileSync(new URL(`../../locales/${locale}.json`, import.meta.url), 'utf8')) as Record<string, string>,
]));
export function galleryText(locale: GalleryLocale, source: string): string {
  const value = catalogs.get(locale)?.[source];
  if (!value) throw new Error(`Missing gallery translation: ${locale} / ${source}`);
  return value;
}

export class GallerySession {
  private readonly consoleMessages: { type: string; text: string }[] = [];
  private readonly pageErrors: string[] = [];
  private readonly failedRequests: string[] = [];
  private readonly captures: { stage: string; caption: string }[] = [];
  private hasConsoleProblem = false;
  private consoleTruncated = false;
  private selected: GalleryCase | null = null;
  private measurements: unknown[] = [];
  private locale: GalleryLocale = 'ko';

  constructor(private readonly page: Page, private readonly browser: Browser, private readonly info: TestInfo) {
    page.on('console', (message) => {
      if (message.type() === 'error' || message.type() === 'warning') this.hasConsoleProblem = true;
      if (this.consoleMessages.length < maxMessages) this.consoleMessages.push({ type: message.type(), text: message.text().slice(0, 2000) });
      else this.consoleTruncated = true;
    });
    page.on('pageerror', (error) => { if (this.pageErrors.length < maxMessages) this.pageErrors.push(error.message.slice(0, 2000)); });
    page.on('requestfailed', (request) => {
      if (this.failedRequests.length < maxMessages) this.failedRequests.push(`${request.method()} ${request.url()} ${request.failure()?.errorText ?? ''}`.slice(0, 2000));
    });
    page.on('response', (response) => {
      if (response.status() >= 400 && this.failedRequests.length < maxMessages) this.failedRequests.push(`${String(response.status())} ${response.url()}`.slice(0, 2000));
    });
  }

  async open(selected: GalleryCase, locale: GalleryLocale = 'ko'): Promise<void> {
    this.selected = selected;
    this.locale = locale;
    await this.page.setViewportSize(selected.viewport);
    await this.page.emulateMedia({ colorScheme: selected.colorScheme, forcedColors: selected.forcedColors, reducedMotion: 'reduce' });
    await this.page.routeWebSocket('**/*', async (socket) => {
      if (this.failedRequests.length < maxMessages) this.failedRequests.push('Unexpected WebSocket in the synthetic gallery.');
      await socket.close();
    });
    // Fixtures have no network owner. Unexpected nonlocal requests are a failure,
    // never a request to a real relay or an injected successful backend response.
    await this.page.route('**/*', async (route) => {
      if (new URL(route.request().url()).origin === 'http://127.0.0.1:4173') await route.continue();
      else {
        if (this.failedRequests.length < maxMessages) this.failedRequests.push(`Blocked external request: ${route.request().url()}`.slice(0, 2000));
        await route.abort('blockedbyclient');
      }
    });
    const response = await this.page.goto(`/qa.html?case=${encodeURIComponent(selected.fixture)}&locale=${encodeURIComponent(locale)}`, { waitUntil: 'load' });
    expect(response?.status()).toBe(200);
    if (selected.rootTextSizePercent === 200) {
      // Explicit QA-only text-size stress. No production switch, browser zoom,
      // native scaling claim, content masking or screenshot modification.
      await this.page.evaluate(() => { document.documentElement.style.fontSize = '200%'; });
    }
    const heading = ['desktop-devices', 'desktop-pairing-ready', 'desktop-setup-missing'].includes(selected.fixture) ? '휴대폰 관리'
      : selected.fixture === 'desktop-history' ? '활동 기록'
        : selected.fixture === 'phone-history' || selected.fixture === 'phone-history-empty' ? '기록'
        : selected.fixture.startsWith('desktop-') ? 'PC 승인을 휴대폰에서'
          : selected.fixture === 'phone-settings' || selected.fixture === 'phone-notifications-denied' || selected.fixture.startsWith('phone-service-') ? '알림 시간' : '요청';
    await expect(this.page.getByRole('heading', { name: galleryText(locale, heading), exact: true, level: 1 })).toBeVisible();
    await expect(this.page.getByRole('button', { name: galleryText(locale, '다시 확인'), exact: true })).toBeEnabled();
    await this.page.evaluate(async () => { await document.fonts.ready; });
    await expect(this.page.getByText(galleryText(locale, bannerText), { exact: true })).toBeInViewport({ ratio: 1 });
    await expect(this.page.locator('input[type="password"]')).toHaveCount(0);
  }

  async capture(stage: string, caption: string): Promise<void> {
    if (!this.selected) throw new Error('Gallery capture has no declared fixture.');
    if (!/^[a-z0-9-]+$/u.test(stage)) throw new Error('Invalid gallery stage name.');
    await this.page.evaluate(async () => { await document.fonts.ready; });
    await expect(this.page.getByText(galleryText(this.locale, bannerText), { exact: true })).toBeVisible();
    await expect(this.page.getByText(galleryText(this.locale, bannerText), { exact: true })).toBeInViewport({ ratio: 1 });
    const layout = await this.page.evaluate(() => {
      const selectors = ['html', 'body', '#root', '.app-shell', '.main-scroll', 'dialog[open]'];
      const owners = selectors.flatMap((selector) => Array.from(document.querySelectorAll<HTMLElement>(selector)).map((element) => ({
        selector, clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
      })));
      const main = document.querySelector<HTMLElement>('.main-scroll');
      const nav = document.querySelector<HTMLElement>('.phone-shell .navigation-shell');
      return {
        owners, mainScrollTop: main?.scrollTop ?? null,
        phoneMainBottom: main && nav ? main.getBoundingClientRect().bottom : null,
        phoneNavTop: nav?.getBoundingClientRect().top ?? null,
      };
    });
    this.measurements.push({ stage, ...layout });
    for (const owner of layout.owners) expect(owner.scrollWidth, `${owner.selector} horizontal overflow`).toBeLessThanOrEqual(owner.clientWidth + 1);
    if (layout.phoneMainBottom !== null && layout.phoneNavTop !== null) expect(layout.phoneMainBottom, 'phone navigation must not cover the main scroll owner').toBeLessThanOrEqual(layout.phoneNavTop + 1);
    const path = this.info.outputPath(`${this.selected.id}--${stage}.png`);
    await this.page.screenshot({ path, fullPage: false, animations: 'disabled', caret: 'hide', scale: 'css', timeout: 7_000 });
    await this.info.attach(`gallery-${stage}`, { path, contentType: 'image/png' });
    this.captures.push({ stage, caption });
  }

  async finish(): Promise<void> {
    const context = this.page.isClosed() ? null : await this.page.evaluate(() => ({
      userAgent: navigator.userAgent, language: navigator.language,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      fontsStatus: document.fonts.status, declaredFontFamily: getComputedStyle(document.body).fontFamily,
      rootFontSize: getComputedStyle(document.documentElement).fontSize,
      documentLanguage: document.documentElement.lang, documentDirection: document.documentElement.dir,
      devicePixelRatio: window.devicePixelRatio,
    })).catch(() => null);
    const data = {
      scope: 'CLIENT / SYNTHETIC', visualReview: 'not-performed-by-harness',
      fixture: this.selected, locale: this.locale, browserName: 'chromium', browserVersion: this.browser.version(),
      textSizeStress: this.selected?.rootTextSizePercent === 200
        ? { rootPercent: 200, scope: 'CLIENT QA ONLY; not browser zoom or native OS scaling' } : null,
      context, captures: this.captures, layoutMeasurements: this.measurements,
      console: this.consoleMessages, consoleTruncated: this.consoleTruncated,
      hasConsoleProblem: this.hasConsoleProblem, pageErrors: this.pageErrors, failedRequests: this.failedRequests,
    };
    await this.info.attach('gallery-observation', { body: Buffer.from(JSON.stringify(data, null, 2)), contentType: 'application/json' });
    expect.soft(this.hasConsoleProblem, 'rendered client console errors/warnings, including beyond the retained sample').toBe(false);
    expect.soft(this.pageErrors, 'rendered client page errors').toEqual([]);
    expect.soft(this.failedRequests, 'failed or unintended client requests').toEqual([]);
  }
}

export const test = base.extend<{ gallery: GallerySession }>({
  gallery: async ({ page, browser }, use, info) => {
    const gallery = new GallerySession(page, browser, info);
    try { await use(gallery); } finally { await gallery.finish(); }
  },
});

export { expect };
