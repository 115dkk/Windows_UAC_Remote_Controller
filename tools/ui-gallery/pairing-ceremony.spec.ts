// SPDX-License-Identifier: GPL-2.0-or-later
// CLIENT/SYNTHETIC only. The real ceremony is painted by GDI on a private
// desktop by crates/windows-service-host/.../renderer_ui.rs, and these captures
// are never evidence that it painted, that a desktop switched, or that any
// pairing happened. They exist so the layout and copy can be reviewed.
import { ceremonyBoots, pairingCeremonyCases } from './pairing-ceremony-cases';
import { test, expect, galleryText } from './session';

for (const selected of pairingCeremonyCases) {
  test(selected.id, async ({ page, gallery }) => {
    const { locale } = selected;
    await gallery.openStandalone(selected, locale);
    const screen = page.locator('[data-pairing-ceremony]');
    // The product signature appears once. A mark in every corner would read as
    // a seal, which is the thing this screen is trying not to be.
    const name = screen.locator('[data-signature-name]');
    await expect(name).toHaveCount(1);
    // The card is drawn over this corner. Whatever name survives must be whole:
    // a translated wordmark sliced by the card edge looks like a rendering fault.
    const signature = await name.evaluate((node) => ({
        shown: getComputedStyle(node).visibility === 'visible',
        wide: node.scrollWidth, room: node.clientWidth,
      }));
    if (signature.shown) expect(signature.wide, 'signature name is not clipped').toBeLessThanOrEqual(signature.room);

    // Every ceremony button holds its own label. A fixed-size native button
    // silently clips a translation that needs one more line than it has room
    // for, and Korean is always the shortest, so this only shows up elsewhere.
    for (const button of await screen.getByRole('button').all()) {
      const fits = await button.evaluate((node) => ({
        scroll: node.scrollHeight, client: node.clientHeight,
        wide: node.scrollWidth, room: node.clientWidth, label: node.textContent,
      }));
      expect(fits.scroll, `button text height: ${fits.label ?? ''}`).toBeLessThanOrEqual(fits.client);
      expect(fits.wide, `button text width: ${fits.label ?? ''}`).toBeLessThanOrEqual(fits.room);
    }

    if (selected.fixture.startsWith('pairing-ceremony-comparison')) {
      await expect(page.getByRole('heading', { name: galleryText(locale, 'UAC 원격 승인 · PC 연결'), exact: true })).toBeVisible();
      await expect(page.getByText(galleryText(locale, '휴대폰에 표시된 숫자와 같은지 확인해 주세요.'), { exact: true })).toBeVisible();
      // The digits are a fixed sample; a real comparison code is minted per
      // attempt and never leaves the protected desktop.
      const digits = page.getByText('123 456', { exact: true });
      await expect(digits).toBeVisible();
      for (const source of ['숫자가 같아요', '다릅니다, 취소']) {
        await expect(page.getByRole('button', { name: galleryText(locale, source), exact: true })).toBeInViewport({ ratio: 1 });
      }
      const notice = screen.locator('[data-boot-notice]');
      const boot = ceremonyBoots.find(value => selected.fixture === `pairing-ceremony-comparison-${value}`);
      if (boot === undefined) {
        // A phone on its manufacturer's verified system: the screen is as it was.
        await expect(notice).toHaveCount(0);
        await gallery.capture('comparison', 'CLIENT/SYNTHETIC · 여섯 자리 비교와 번역이 들어가는 단추');
        return;
      }
      await expect(notice).toHaveText(galleryText(locale, boot === 'unlocked'
        ? '이 휴대폰은 부트로더가 풀려 있습니다. 직접 푼 것이 아니라면 ESC를 눌러 중지하십시오.'
        : '이 휴대폰은 제조사 것이 아닌 운영체제로 시작했습니다. 직접 설치한 것이 아니라면 ESC를 눌러 중지하십시오.'));
      await expect(notice).toBeInViewport({ ratio: 1 });
      // The sentence is whole inside its band, the band sits between the digits
      // and the decision row, and the row is still on the card.
      const whole = await notice.evaluate((node) => ({ scroll: node.scrollHeight, client: node.clientHeight }));
      expect(whole.scroll, 'boot notice is not cut').toBeLessThanOrEqual(whole.client);
      const [digitsBox, noticeBox, rowBox, cardBox] = [
        await digits.boundingBox(), await notice.boundingBox(),
        await screen.locator('[data-comparison-actions]').boundingBox(), await screen.locator('section').boundingBox(),
      ];
      expect(digitsBox!.y + digitsBox!.height, 'notice clears the digits').toBeLessThanOrEqual(noticeBox!.y);
      expect(noticeBox!.y + noticeBox!.height, 'notice clears the decision row').toBeLessThan(rowBox!.y);
      expect(rowBox!.y + rowBox!.height, 'decision row stays on the card').toBeLessThanOrEqual(cardBox!.y + cardBox!.height);
      await gallery.capture(`comparison-${boot}`, boot === 'unlocked'
        ? 'CLIENT/SYNTHETIC · 부트로더가 풀린 휴대폰일 때 숫자 아래에 더해지는 안내'
        : 'CLIENT/SYNTHETIC · 제조사 것이 아닌 운영체제로 시작한 휴대폰일 때 더해지는 안내');
      return;
    }

    if (selected.fixture === 'pairing-ceremony-introduction') {
      await expect(page.getByRole('heading', { name: galleryText(locale, 'QR 연결 절차를 시작합니다.'), exact: true })).toBeVisible();
      await expect(page.getByText(galleryText(locale, 'ESC를 누르거나 [취소]를 눌러 언제든 중지할 수 있습니다.'), { exact: true })).toBeVisible();
      const caution = page.getByText(galleryText(locale, '주의: 다른 사람의 요청으로 이 절차에 들어왔다면 지금 바로 중지하세요. QR 코드를 다른 사람에게 절대 공유하지 마세요.'), { exact: true });
      await expect(caution).toBeInViewport({ ratio: 1 });
      const start = page.getByRole('button', { name: galleryText(locale, 'QR 코드 보기'), exact: true });
      const cancel = page.getByRole('button', { name: galleryText(locale, '취소'), exact: true });
      await expect(start).toBeInViewport({ ratio: 1 });
      await expect(cancel).toBeInViewport({ ratio: 1 });
      // Nothing that would be a code is on the screen that explains the code.
      await expect(screen.locator('svg')).toHaveCount(0);
      // The caution band ends where its text ends: a box far taller than the
      // words inside it is what made this notice look detached.
      const band = (await caution.boundingBox())!;
      const gap = await caution.evaluate((node) => {
        const style = getComputedStyle(node);
        return { top: parseFloat(style.paddingTop), bottom: parseFloat(style.paddingBottom) };
      });
      expect(band.height, 'caution band hugs its own text').toBeLessThan(
        (await caution.evaluate((node) => node.scrollHeight)) + gap.top + gap.bottom + 2);
      await gallery.capture('introduction', 'CLIENT/SYNTHETIC · 절차 안내, 중지 방법, 공유 금지 주의');
      return;
    }

    await expect(page.getByRole('heading', { name: galleryText(locale, 'UAC 원격 승인 · PC 연결'), exact: true })).toBeVisible();
    await expect(page.getByText(galleryText(locale, '{:02}:{:02} 후 종료').replace('{:02}:{:02}', '01:47'), { exact: true })).toBeVisible();
    const back = page.getByRole('button', { name: galleryText(locale, '취소하고 돌아가기'), exact: true });
    const hint = page.getByText(galleryText(locale, 'ESC 키를 눌러도 바로 돌아가요.'), { exact: true });
    await expect(back).toBeInViewport({ ratio: 1 });
    await expect(hint).toBeInViewport({ ratio: 1 });
    const code = screen.locator('svg');
    await expect(code).toHaveCount(1);
    const [codeBox, backBox] = [await code.boundingBox(), await back.boundingBox()];
    // The way out never covers the code the camera has to read.
    expect(codeBox!.y + codeBox!.height, 'code clears the way out').toBeLessThanOrEqual(backBox!.y);
    // The module grid stays at or above the size the lab decoder already reads.
    expect(codeBox!.width / (85 + 8), 'module pixels').toBeGreaterThanOrEqual(3);
    await gallery.capture('invitation', 'CLIENT/SYNTHETIC · QR과 항상 보이는 탈출구, 마감이 아닌 자동 종료 안내');
  });
}
