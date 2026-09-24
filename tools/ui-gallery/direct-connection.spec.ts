// SPDX-License-Identifier: GPL-2.0-or-later
// Client geometry and synthetic state only; ROOT reviews actual CI captures.
import { directConnectionCases } from './direct-connection-cases';
import { test, expect, galleryText } from './session';

const candidateCopy = '외부에서 접속할 주소가 있음';
// The WAN fixtures have a paired phone that is not connected, so the PC paragraph applies.
const firewallCopy = '휴대폰이 연결되지 않으면 V3나 방화벽이 UAC 원격 승인기 서비스(uac-service.exe)의 연결 허용을 묻고 있는지 확인하십시오.';
const phoneCopy = '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.';

for (const selected of directConnectionCases) {
  test(selected.id, async ({ page, gallery }) => {
    const { locale } = selected;
    const phone = selected.fixture === 'phone-disconnected';
    if (phone) await page.clock.install();
    await gallery.open(selected, locale);
    if (phone) {
      // The phone names the V3 prompt only once a disconnection has lasted 60 s.
      await expect(page.getByText(galleryText(locale, phoneCopy), { exact: true })).toHaveCount(0);
      await page.clock.fastForward(61_000);
      const hint = page.getByText(galleryText(locale, phoneCopy), { exact: true });
      await hint.scrollIntoViewIfNeeded();
      await expect(hint).toBeInViewport({ ratio: 1 });
      await gallery.capture('phone-firewall-recovery', 'CLIENT/SYNTHETIC · known disconnected peer past 60 s on a synthetic clock, PC prompt guidance; not an observed firewall failure');
      return;
    }

    const region = page.getByRole('region', { name: galleryText(locale, '외부 네트워크 연결'), exact: true });
    const source = selected.fixture === 'desktop-relay-wan-lan' ? '외부에서 접속할 주소가 없음'
      : selected.fixture === 'desktop-relay-wan-unavailable' ? '외부 주소를 확인하지 못했습니다. PC의 인터넷 연결과 공유기 설정을 확인하십시오.'
      : selected.fixture === 'desktop-relay-wan-stale' ? '외부 연결 상태 확인 불가 · [다시 확인]을 누르십시오.' : candidateCopy;
    const status = region.getByRole('status');
    await expect(status).toHaveText(galleryText(locale, source));
    await expect(region.locator('.is-success, button, a, input')).toHaveCount(0);
    await status.scrollIntoViewIfNeeded();
    await expect(status).toBeInViewport({ ratio: 1 });
    await gallery.capture('direct-state', 'CLIENT/SYNTHETIC · external route observation, neutral candidate or recovery state');
    // The external-access tab shows the guidance after its relay section.
    const hint = page.getByText(galleryText(locale, firewallCopy), { exact: true });
    if (selected.fixture === 'desktop-relay-wan-stale') await expect(hint).toHaveCount(0);
    else {
      await hint.scrollIntoViewIfNeeded();
      await expect(hint).toBeInViewport({ ratio: 1 });
      await gallery.capture('program-specific-firewall-guidance', 'CLIENT/SYNTHETIC · uac-service.exe-specific permission guidance, no blanket firewall change');
    }

    // Added content must not strand the adjacent advanced external-relay form.
    const address = page.getByRole('textbox', { name: galleryText(locale, '중계 서버 주소'), exact: true });
    await address.scrollIntoViewIfNeeded();
    await address.focus();
    await expect(address).toBeFocused();
    await expect(address).toBeInViewport({ ratio: 1 });
    await address.fill('203.0.113.10:443');
    await expect(address).toHaveValue('203.0.113.10:443');
    await gallery.capture('advanced-relay-draft', 'CLIENT/SYNTHETIC · existing external relay draft remains keyboard-reachable; not submitted');
  });
}
