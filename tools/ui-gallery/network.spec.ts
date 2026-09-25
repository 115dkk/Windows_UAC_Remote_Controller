// SPDX-License-Identifier: GPL-2.0-or-later
// Client geometry and synthetic external-access state only. No router, STUN,
// firewall, reachable address or native setting is exercised; ROOT reviews captures.
import type { Locator, Page } from '@playwright/test';
import { networkCases } from './network-cases';
import type { NetworkCase } from './network-cases';
import { test, expect, galleryText } from './session';
import type { GalleryLocale } from './session';

const forwardTitle = '공유기에서 포트를 직접 열었음';
const fixedTitle = '외부 주소 직접 입력';
const instructionSource = '공유기 관리 페이지의 포트포워딩에서 외부 포트 {external}을(를) {lan}의 {port} 포트(TCP)로 연결하십시오.';
// Shown because these synthetic PCs have a paired phone that is not connected.
const firewallCopy = '휴대폰이 연결되지 않으면 V3나 방화벽이 UAC 원격 승인기 서비스(uac-service.exe)의 연결 허용을 묻고 있는지 확인하십시오.';

interface Expected {
  readonly mode: string;
  readonly direct: string;
  readonly address: string | null;
  readonly source: string | null;
  readonly reason: string | null;
  readonly port?: number;
  readonly fixed?: string;
}
const expected: Record<string, Expected> = {
  'desktop-network-auto-no-mapping': { mode: '자동', direct: '외부에서 접속할 주소가 없음', address: null, source: null,
    reason: '공유기가 자동 포트 열기(UPnP·PCP)를 지원하지 않거나 꺼져 있습니다. 공유기에서 포트를 직접 열고 아래에서 그 방법을 고르십시오.' },
  'desktop-network-auto-upnp': { mode: '자동', direct: '외부에서 접속할 주소가 있음', address: '203.0.113.7:7443', source: '공유기 자동 포트 열기(UPnP)', reason: null },
  'desktop-network-forward-stun': { mode: forwardTitle, direct: '외부에서 접속할 주소가 있음', address: '198.51.100.24:17443', source: '외부 서버에 물어 확인', reason: null, port: 17443 },
  'desktop-network-forward-unavailable': { mode: forwardTitle, direct: '외부에서 접속할 주소가 없음', address: null, source: null,
    reason: '이 집의 공인 IP를 확인하지 못했습니다. 인터넷 연결을 확인하거나 외부 주소를 직접 입력하십시오.', port: 41327 },
  'desktop-network-fixed': { mode: fixedTitle, direct: '외부에서 접속할 주소가 있음', address: '203.0.113.7:7443', source: '직접 입력', reason: null, fixed: '203.0.113.7:7443' },
};

function fact(page: Page, locale: GalleryLocale, label: string): Locator {
  return page.locator('.status-facts > div').filter({ has: page.locator('dt', { hasText: galleryText(locale, label) }) }).locator('dd');
}

async function reachable(target: Locator, minimum = 44): Promise<void> {
  await target.scrollIntoViewIfNeeded();
  await expect(target).toBeInViewport({ ratio: 1 });
  const box = await target.boundingBox();
  expect(box).not.toBeNull();
  expect(box!.height).toBeGreaterThanOrEqual(minimum);
}

async function phoneShortcut(page: Page, selected: NetworkCase, gallery: { capture(stage: string, caption: string): Promise<void> }): Promise<void> {
  const { locale } = selected;
  const entry = page.getByRole('region', { name: galleryText(locale, 'QR 코드 보기'), exact: true });
  await expect(entry.getByText(galleryText(locale, '휴대폰이 접속할 준비가 되지 않아 QR 코드를 표시할 수 없습니다. PC의 네트워크 연결과 [외부 연결] 설정을 확인하십시오.'), { exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: galleryText(locale, '이 PC 사용'), exact: true })).toHaveCount(0);
  await expect(page.locator('.relay-advanced')).toHaveCount(0);
  const shortcut = entry.getByRole('button', { name: galleryText(locale, '외부 연결 설정'), exact: true });
  await expect(shortcut).toHaveClass(/\bsecondary\b/u);
  await reachable(shortcut);
  await gallery.capture('phone-page-shortcut', 'CLIENT/SYNTHETIC · pairing waits for the relay; the relay controls now live on the external-access tab');
  await shortcut.click();
  await expect(page.getByRole('heading', { level: 1, name: galleryText(locale, '외부 연결'), exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: galleryText(locale, '이 PC 사용'), exact: true })).toBeEnabled();
}

for (const selected of networkCases) {
  test(selected.id, async ({ page, gallery }) => {
    const { locale } = selected;
    await gallery.open(selected, locale);
    if (selected.fixture === 'desktop-pairing-relay-first') { await phoneShortcut(page, selected, gallery); return; }
    const want = expected[selected.fixture]!;
    await expect(page.getByText(galleryText(locale, '휴대폰이 집 밖에서도 이 PC에 연결할 수 있게 설정합니다.'), { exact: true })).toBeVisible();
    await expect(page.getByRole('navigation').getByRole('button')).toHaveCount(4);

    // 1. Current status: observation lines, reason and facts. Candidates are neutral text.
    const status = page.getByRole('region', { name: galleryText(locale, '현재 상태'), exact: true });
    await expect(status.getByRole('region', { name: galleryText(locale, '외부 네트워크 연결'), exact: true }).getByRole('status'))
      .toHaveText(galleryText(locale, want.direct));
    await expect(status.locator('.status-facts .is-success, .direct-connection .is-success')).toHaveCount(0);
    await expect(fact(page, locale, '외부 주소')).toHaveText(want.address ?? galleryText(locale, '없음'));
    await expect(fact(page, locale, '주소를 얻은 방법')).toHaveText(galleryText(locale, want.source ?? '없음'));
    await expect(fact(page, locale, '이 PC의 내부 주소')).toHaveText('192.168.0.23:7443');
    if (want.address) await expect(fact(page, locale, '외부 주소').locator('bdi')).toHaveAttribute('dir', 'ltr');
    if (want.reason) {
      const reason = status.getByText(galleryText(locale, want.reason), { exact: true });
      await reason.scrollIntoViewIfNeeded();
      await expect(reason).toBeInViewport({ ratio: 1 });
    } else {
      await expect(status.locator('.network-reason')).toHaveCount(0);
    }
    await gallery.capture('current-status', 'CLIENT/SYNTHETIC · published candidate, source and LAN endpoint; not reachability proof');

    // 2. Method: the saved mode is selected and only its own field is shown.
    const method = page.getByRole('region', { name: galleryText(locale, '외부에서 연결하는 방법'), exact: true });
    const group = method.getByRole('group', { name: galleryText(locale, '외부에서 연결하는 방법'), exact: true });
    await expect(group.getByRole('radio')).toHaveCount(3);
    const checked = group.getByRole('radio', { name: galleryText(locale, want.mode), exact: true });
    await expect(checked).toBeChecked();
    const port = method.getByRole('spinbutton', { name: galleryText(locale, '공유기의 외부 포트'), exact: true });
    const address = method.getByRole('textbox', { name: galleryText(locale, '외부 주소'), exact: true });
    const save = method.getByRole('button', { name: galleryText(locale, '저장'), exact: true });
    await expect(save).toBeDisabled();
    if (want.port !== undefined) {
      await expect(port).toHaveValue(String(want.port));
      await expect(address).toHaveCount(0);
      const instruction = galleryText(locale, instructionSource).replace('{external}', String(want.port))
        .replace('{lan}', '192.168.0.23').replace('{port}', '7443');
      await expect(method.getByText(instruction, { exact: true })).toBeVisible();
      await checked.focus();
      await page.keyboard.press('Tab');
      await expect(port).toBeFocused();
      await reachable(port);
    } else if (want.fixed !== undefined) {
      await expect(address).toHaveValue(want.fixed);
      await expect(address).toHaveAttribute('dir', 'ltr');
      await expect(port).toHaveCount(0);
      await checked.focus();
      await page.keyboard.press('Tab');
      await expect(address).toBeFocused();
      await reachable(address);
    } else {
      await expect(port).toHaveCount(0);
      await expect(address).toHaveCount(0);
    }
    await reachable(save);
    const note = method.getByText(galleryText(locale, '설정을 바꾼 뒤에는 휴대폰을 집 Wi-Fi에 한 번 연결해야 새 외부 주소를 받습니다.'), { exact: true });
    await note.scrollIntoViewIfNeeded();
    await expect(note).toBeInViewport({ ratio: 1 });
    await gallery.capture('connection-method', 'CLIENT/SYNTHETIC · saved method, its field and router instructions; nothing is submitted');

    if (selected.id === 'network-auto-no-mapping-980') {
      // Client validation shows the pinned messages and never reaches the synthetic owner.
      await group.getByRole('radio', { name: forwardTitle, exact: true }).check();
      await port.fill('0');
      await save.click();
      await expect(method.getByText('포트는 1에서 65535 사이의 숫자로 입력하십시오.', { exact: true })).toBeVisible();
      await expect(port).toBeFocused();
      await expect(port).toHaveAttribute('aria-invalid', 'true');
      await gallery.capture('invalid-port', 'CLIENT/SYNTHETIC · pinned port validation; no save requested');
      await group.getByRole('radio', { name: fixedTitle, exact: true }).check();
      await address.fill('192.168.0.23:7443');
      await save.click();
      await expect(method.getByText('이 주소로는 외부에서 연결할 수 없습니다. 공유기 관리 페이지에 표시된 공인 IP를 입력하십시오.', { exact: true })).toBeVisible();
      await expect(address).toBeFocused();
      await gallery.capture('invalid-address', 'CLIENT/SYNTHETIC · a LAN address is not a public address; no save requested');
      await address.fill('1.2.3.4:7443');
      await save.click();
      await expect(save).toBeDisabled();
      await expect(group.getByRole('radio', { name: fixedTitle, exact: true })).toBeChecked();
      await expect(fact(page, locale, '외부 주소')).toHaveText('없음');
      await gallery.capture('synthetic-save', 'CLIENT/SYNTHETIC · the synthetic owner records the mode only and invents no address');

      // PC status offers the way back here while no outside address exists.
      await page.getByRole('navigation').getByRole('button', { name: 'PC 상태', exact: true }).click();
      const shortcut = page.getByRole('button', { name: '외부 연결 설정', exact: true });
      await reachable(shortcut);
      await gallery.capture('status-shortcut', 'CLIENT/SYNTHETIC · PC status names the missing outside address and links to the tab');
      await shortcut.click();
      await expect(page.getByRole('heading', { level: 1, name: '외부 연결', exact: true })).toBeVisible();
    }

    // 3. Relay controls, moved unchanged, and 4. the firewall guidance last.
    const relay = page.getByRole('region', { name: galleryText(locale, '휴대폰이 접속할 곳'), exact: true });
    const embedded = relay.getByRole('button', { name: galleryText(locale, '이 PC 사용 중'), exact: true });
    await expect(embedded).toBeDisabled();
    await reachable(embedded);
    const relayInput = relay.getByRole('textbox', { name: galleryText(locale, '중계 서버 주소'), exact: true });
    await relayInput.scrollIntoViewIfNeeded();
    const field = await relayInput.evaluate(node => {
      const box = node.getBoundingClientRect();
      const parent = node.closest('fieldset')!;
      const container = parent.getBoundingClientRect();
      const style = getComputedStyle(parent);
      return { left: box.left, right: box.right, allowedLeft: container.left + Number.parseFloat(style.paddingLeft),
        allowedRight: container.right - Number.parseFloat(style.paddingRight) };
    });
    expect(field.left).toBeGreaterThanOrEqual(field.allowedLeft - 0.5);
    expect(field.right).toBeLessThanOrEqual(field.allowedRight + 0.5);
    const guidance = page.getByText(galleryText(locale, firewallCopy), { exact: true });
    await guidance.scrollIntoViewIfNeeded();
    await expect(guidance).toBeInViewport({ ratio: 1 });
    await gallery.capture('relay-and-guidance', 'CLIENT/SYNTHETIC · relay controls and program-specific firewall guidance; no relay change');
  });
}
