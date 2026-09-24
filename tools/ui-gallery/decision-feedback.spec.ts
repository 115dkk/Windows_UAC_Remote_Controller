// SPDX-License-Identifier: GPL-2.0-or-later
// Client geometry with synthetic decision and connection views only. No native
// decision, PC result, dial or firewall prompt is exercised; ROOT reviews captures.
import type { Locator, Page } from '@playwright/test';
import { feedbackCases } from './decision-feedback-cases';
import type { FeedbackCase } from './decision-feedback-cases';
import { test, expect, galleryText } from './session';
import type { GalleryLocale } from './session';

const decisions: Record<string, { readonly title: string; readonly body: string; readonly listed: boolean }> = {
  'phone-decision-authenticating': { title: '승인을 선택했습니다', body: '본인 확인을 진행하십시오.', listed: true },
  'phone-decision-preparing': { title: '거부를 선택했습니다', body: 'PC로 보내는 중입니다.', listed: true },
  'phone-decision-sending': { title: '거부를 선택했습니다', body: 'PC로 보내는 중입니다.', listed: true },
  'phone-decision-awaiting-pc': { title: '승인을 보냈습니다', body: 'PC의 처리 결과를 기다리는 중입니다.', listed: true },
  'phone-decision-authentication-cancelled': { title: '본인 확인을 취소했습니다', body: '요청이 남아 있으면 다시 선택할 수 있습니다.', listed: true },
  'phone-decision-approved': { title: '승인 완료', body: 'PC에 승인을 적용했습니다.', listed: false },
  'phone-decision-denied': { title: '거부 완료', body: 'PC에서 요청을 취소했습니다.', listed: false },
  'phone-decision-failed': { title: 'PC에서 처리하지 못했습니다', body: 'PC 화면에서 요청 창을 확인하십시오.', listed: false },
  'phone-decision-cancelled': { title: 'PC에서 요청이 닫혔습니다', body: 'PC에서 직접 처리했거나 요청한 프로그램이 창을 닫았습니다.', listed: false },
  'phone-decision-expired': { title: '요청 시간이 지났습니다', body: '필요하면 PC에서 다시 요청하십시오.', listed: false },
  'phone-decision-pc-completed': { title: 'PC에서 요청이 끝났습니다', body: '처리 결과는 PC에서 확인하십시오.', listed: false },
  'phone-decision-local-unconfirmed': { title: 'PC의 결과를 아직 확인하지 못했습니다', body: '선택이 PC에 전달되었는지 확인하지 못했습니다. 요청이 남아 있으면 다시 선택할 수 있습니다.', listed: false },
};
const failed = 'PC에 연결하지 못했습니다';
const guidance: Record<string, readonly string[]> = {
  'phone-connection-refused': ['PC는 응답했지만 휴대폰 승인이 연결을 받지 않습니다. PC 앱에서 휴대폰 승인이 켜져 있는지 확인하십시오.'],
  'phone-connection-no-answer': ['PC의 휴대폰 승인이 응답하지 않습니다. PC 앱에서 상태를 확인하거나 PC를 다시 시작하십시오.'],
  'phone-connection-unreachable': ['PC가 켜져 있고 절전 상태가 아닌지 확인하십시오.', '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.',
    '집 밖에서 쓰려면 PC 앱의 [외부 연결]을 설정한 뒤 이 휴대폰을 집 Wi-Fi에 한 번 연결하십시오.'],
  'phone-connection-unreachable-route': ['PC가 켜져 있고 절전 상태가 아닌지 확인하십시오.', '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.',
    '집 밖이라면 공유기의 포트포워딩과 PC의 [외부 연결] 설정을 확인하십시오.'],
  'phone-disconnected': ['PC가 켜져 있고 절전 상태가 아닌지 확인하십시오.', '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.',
    '집 밖이라면 공유기의 포트포워딩과 PC의 [외부 연결] 설정을 확인하십시오.'],
  'phone-connection-dialing': ['PC가 켜져 있고 절전 상태가 아닌지 확인하십시오.', '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.',
    '집 밖에서 쓰려면 PC 앱의 [외부 연결]을 설정한 뒤 이 휴대폰을 집 Wi-Fi에 한 번 연결하십시오.'],
};
const firewallCopy = '휴대폰이 연결되지 않으면 V3나 방화벽이 UAC 원격 승인기 서비스(uac-service.exe)의 연결 허용을 묻고 있는지 확인하십시오.';

async function reachable(target: Locator, minimum: number): Promise<void> {
  await target.scrollIntoViewIfNeeded();
  await expect(target).toBeInViewport({ ratio: 1 });
  const box = await target.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.height).toBeGreaterThanOrEqual(minimum);
}

async function decision(page: Page, selected: FeedbackCase, locale: GalleryLocale, capture: (stage: string, caption: string) => Promise<void>): Promise<void> {
  const want = decisions[selected.fixture]!;
  const title = page.getByText(galleryText(locale, want.title), { exact: true });
  await expect(title).toBeVisible();
  await expect(page.getByText(galleryText(locale, want.body), { exact: true })).toBeVisible();
  const shown = page.locator('[data-phase]');
  await expect(shown).toHaveCount(1);
  await expect(shown.locator('xpath=ancestor-or-self::*[@role="status"]')).not.toHaveCount(0);
  await expect(page.locator('.tone-success')).toHaveCount(selected.fixture === 'phone-decision-approved' ? 1 : 0);
  if (want.listed) {
    const card = page.getByRole('article');
    await expect(card.locator('[data-phase]')).toHaveCount(1);
    await expect(card.getByRole('heading', { name: '설정 도우미.exe', exact: true })).toBeVisible();
    await shown.scrollIntoViewIfNeeded();
    await expect(shown).toBeInViewport({ ratio: 1 });
    await capture('decision-in-card', 'CLIENT/SYNTHETIC · the chosen action and its stage inside the still-listed card; not a native stage');
    const actions = card.locator('.request-actions');
    await actions.scrollIntoViewIfNeeded();
    await capture('decision-in-card-actions', 'CLIENT/SYNTHETIC · existing approve/deny availability beside the stage');
    return;
  }
  const receipt = page.getByRole('region', { name: galleryText(locale, want.title), exact: true });
  await expect(page.getByRole('article')).toHaveCount(0);
  await expect(receipt).toContainText(galleryText(locale, want.body));
  // A receipt keeps no program name, path or computer name.
  await expect(page.getByText(/설정 도우미|Program Files|화면 예시 PC/u)).toHaveCount(0);
  const ok = receipt.getByRole('button', { name: galleryText(locale, '확인'), exact: true });
  await reachable(ok, 48);
  await ok.focus();
  await expect(ok).toBeFocused();
  await capture('decision-receipt', 'CLIENT/SYNTHETIC · body-free receipt of a request that left the list; not a native PC result');
  await page.keyboard.press('Enter');
  await expect(receipt).toHaveCount(0);
  await expect(page.getByRole('heading', { level: 1 })).toBeFocused();
  await capture('decision-receipt-dismissed', 'CLIENT/SYNTHETIC · receipt dismissed for this app session, focus on the page heading');
}

async function connection(page: Page, selected: FeedbackCase, locale: GalleryLocale, capture: (stage: string, caption: string) => Promise<void>): Promise<void> {
  const region = page.locator('.connection-status');
  await expect(region).toHaveAttribute('role', 'status');
  if (selected.fixture === 'phone-connection-reconnecting') {
    // Connected first; every later synthetic observation has lost the PC.
    await page.getByRole('button', { name: galleryText(locale, '다시 확인'), exact: true }).click();
    await expect(region.getByText(galleryText(locale, 'PC에 다시 연결하는 중'), { exact: true })).toBeVisible();
    await expect(region.getByText(galleryText(locale, 'PC에 연결하는 중'), { exact: true })).toHaveCount(0);
  } else {
    await expect(region.getByText(galleryText(locale, 'PC에 연결하는 중'), { exact: true })).toBeVisible();
  }
  await expect(page.locator('.notice-box')).toHaveCount(0);
  await expect(page.getByText(/V3|방화벽/u)).toHaveCount(0);
  if (selected.motion) {
    await page.emulateMedia({ reducedMotion: 'no-preference' });
    await expect(region.locator('.spinner')).toBeVisible();
    await expect(region.locator('.spinner-still')).toBeHidden();
  } else {
    await expect(region.locator('.spinner')).toBeHidden();
    await expect(region.locator('.spinner-still')).toBeVisible();
  }
  await region.scrollIntoViewIfNeeded();
  await capture('connection-progress', selected.motion ? 'CLIENT/SYNTHETIC · progress row with the rotating ring; no dial is running'
    : 'CLIENT/SYNTHETIC · progress row, reduced motion shows the clock; no dial is running');
  const jumps = selected.clockMillis ?? [];
  for (const [index, jump] of jumps.entries()) {
    await page.clock.fastForward(jump);
    const last = index === jumps.length - 1;
    if (!last) {
      // A dial in flight keeps the row until 120 s.
      await page.getByRole('button', { name: galleryText(locale, '다시 확인'), exact: true }).click();
      await expect(region.getByText(galleryText(locale, 'PC에 연결하는 중'), { exact: true })).toBeVisible();
      await expect(page.locator('.notice-box')).toHaveCount(0);
      await capture('connection-dialing-extended', 'CLIENT/SYNTHETIC · 61 s synthetic clock, dial reported in flight: still the progress row');
      continue;
    }
    const notice = page.getByRole('region', { name: galleryText(locale, failed), exact: true });
    await expect(notice).toBeVisible();
    await expect(notice.locator('p, li')).toHaveText(guidance[selected.fixture]!.map(line => galleryText(locale, line)));
    await expect(region.getByText(galleryText(locale, 'PC에 연결하는 중'), { exact: true })).toHaveCount(0);
    // At 200% text the notice is taller than the phone; its start and end must each be reachable.
    const parts = selected.rootTextSizePercent === 200 ? [notice.getByRole('heading'), notice.locator('p, li').last()] : [notice];
    for (const [part, target] of parts.entries()) {
      await target.scrollIntoViewIfNeeded();
      await expect(target).toBeInViewport({ ratio: 1 });
      await capture(part === 0 ? 'connection-failure' : 'connection-failure-end',
        'CLIENT/SYNTHETIC · guidance chosen by the synthetic failure kind after a synthetic clock jump');
    }
  }
}

async function firewall(page: Page, selected: FeedbackCase, locale: GalleryLocale, capture: (stage: string, caption: string) => Promise<void>): Promise<void> {
  const paragraph = page.getByText(galleryText(locale, firewallCopy), { exact: true });
  const shown = selected.fixture === 'desktop-status-phone-offline' || selected.fixture === 'desktop-network-auto-no-mapping';
  if (!shown) {
    await expect(paragraph).toHaveCount(0);
    await capture('firewall-hidden', 'CLIENT/SYNTHETIC · no paired phone, or a connected one: no firewall paragraph');
    return;
  }
  await paragraph.scrollIntoViewIfNeeded();
  await expect(paragraph).toBeInViewport({ ratio: 1 });
  if (selected.fixture === 'desktop-status-phone-offline') await expect(page.getByText(galleryText(locale, '휴대폰 연결 안 됨'), { exact: true })).toBeVisible();
  await capture('firewall-paired-offline', 'CLIENT/SYNTHETIC · paired phone not connected: uac-service.exe firewall paragraph');
}

for (const selected of feedbackCases) {
  test(selected.id, async ({ page, gallery }) => {
    const { locale } = selected;
    if (selected.clockMillis) await page.clock.install();
    await gallery.open(selected, locale);
    const capture = (stage: string, caption: string) => gallery.capture(stage, caption);
    if (selected.kind === 'decision') await decision(page, selected, locale, capture);
    else if (selected.kind === 'connection') await connection(page, selected, locale, capture);
    else await firewall(page, selected, locale, capture);
  });
}
