// SPDX-License-Identifier: GPL-2.0-or-later
import { writeFile } from 'node:fs/promises';
import { expect } from '@playwright/test';
import type { Page, TestInfo } from '@playwright/test';

interface PlatformFont {
  familyName: string;
  postScriptName: string;
  isCustomFont: boolean;
  glyphCount: number;
}

interface FontObservation {
  purpose: string;
  selector: string;
  text: string;
  css: { family: string; weight: string; size: string; lineHeight: string };
  fonts: PlatformFont[];
}

/** Read-only Chromium evidence from existing visible text; no injected specimen,
 * style override, production-copy change, font substitution or screenshot edit.
 * CDP reports fonts used by child TextNodes, not just the CSS declaration.
 */
export async function recordClientFontProof(page: Page, info: TestInfo, target: 'desktop' | 'phone'): Promise<void> {
  const observations: FontObservation[] = [];
  let completed = false;
  const client = await page.context().newCDPSession(page);
  try {
    await page.evaluate(async () => { await document.fonts.ready; });
    await client.send('DOM.enable');
    await client.send('CSS.enable');
    const { root } = await client.send('DOM.getDocument', { depth: 0 });
    const samples = [
      { purpose: 'visible-hangul-navigation', selector: '.navigation-shell nav .navigation-item:first-child > span', contains: /[가-힣]/u },
      { purpose: 'visible-hangul-button', selector: '.page-header .refresh-button', contains: /[가-힣]/u },
      { purpose: 'visible-latin-heading', selector: target === 'desktop' ? '.page-header h1' : '.program-name > bdi', contains: /[A-Za-z]/u },
    ];
    for (const sample of samples) {
      const element = page.locator(sample.selector);
      await expect(element).toHaveCount(1);
      await expect(element).toBeVisible();
      await expect(element).toBeInViewport({ ratio: 1 });
      const details = await element.evaluate((node) => {
        const style = getComputedStyle(node);
        return { text: node.textContent ?? '', css: { family: style.fontFamily, weight: style.fontWeight, size: style.fontSize, lineHeight: style.lineHeight } };
      });
      expect(details.text.length).toBeLessThanOrEqual(128);
      expect(details.text).toMatch(sample.contains);
      const { nodeId } = await client.send('DOM.querySelector', { nodeId: root.nodeId, selector: sample.selector });
      expect(nodeId, 'actual rendered element must exist in the CDP document').toBeGreaterThan(0);
      const { fonts } = await client.send('CSS.getPlatformFontsForNode', { nodeId });
      observations.push({ purpose: sample.purpose, selector: sample.selector, ...details, fonts });
      expect(fonts.length, 'font readiness alone cannot prove any glyph used the bundled font').toBeGreaterThan(0);
      expect(fonts.length).toBeLessThanOrEqual(8);
      for (const font of fonts) {
        expect(font.glyphCount, sample.purpose).toBeGreaterThan(0);
        expect(font.isCustomFont, 'must use the packaged webfont, not an installed fallback').toBe(true);
        // Real static name tables may append Medm/SmBld to the family. Do not
        // require a fictitious exact family spelling or a variable-font name.
        expect(font.familyName).toMatch(/^IBM Plex Sans KR(?:\b|$)/u);
        expect(font.postScriptName).toMatch(/^IBMPlexSansKR(?:-|$)/u);
      }
    }
    completed = true;
  } finally {
    try {
      const path = info.outputPath('actual-fonts.json');
      await writeFile(path, `${JSON.stringify({
        schemaVersion: 1, scope: 'CLIENT / SYNTHETIC / READ_ONLY_FONT_DIAGNOSTIC',
        target, fixtureCase: info.title, viewport: page.viewportSize(),
        method: 'CSS.getPlatformFontsForNode', completed, observations,
        nativeShellVerified: false, glyphCoverageDecodedHere: false, visualReview: 'ROOT_REQUIRED',
      }, null, 2)}\n`);
      await info.attach('actual-platform-fonts', { path, contentType: 'application/json' });
    } finally { await client.detach(); }
  }
}
