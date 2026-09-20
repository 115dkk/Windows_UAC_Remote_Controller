// SPDX-License-Identifier: GPL-2.0-or-later
import { galleryCases } from './cases';
import { diagnosticsExportCases, scannerLaunchCases } from './declared-cases';
import { test, expect } from './session';
import { registerPhoneServiceGallery } from './phone-service';
import { recordClientFontProof } from './font-proof';

registerPhoneServiceGallery(test);

for (const selected of diagnosticsExportCases) {
  test(selected.id, async ({ page, gallery }, info) => {
    await gallery.open(selected);
    const unavailable = selected.fixture === 'phone-unavailable';
    const pending = selected.fixture === 'phone-history-diagnostics-pending';
    if (unavailable) {
      const activity = page.getByRole('navigation').getByRole('button', { name: '기록', exact: true });
      await expect(activity).toBeEnabled();
      await activity.click();
      await expect(page.getByRole('heading', { name: '활동 기록 확인 불가', exact: true })).toBeVisible();
      await expect(page.locator('.activity-list')).toHaveCount(0);
      await expect(page.getByRole('button', { name: '기록 지우기', exact: true })).toHaveCount(0);
    } else {
      await expect(page.locator('.activity-list li')).toHaveCount(2);
    }
    const action = page.getByRole('button', { name: '진단 로그 내보내기', exact: true });
    await expect(action).toHaveCount(1);
    await expect(action).toBeEnabled();
    await expect(action).toHaveAttribute('aria-busy', 'false');
    await expect(page.getByRole('button', { name: '로그 폴더 열기', exact: true })).toHaveCount(0);
    await action.scrollIntoViewIfNeeded();
    await action.focus();
    await expect(action).toBeFocused();
    await expect(action).toBeInViewport({ ratio: 1 });
    const geometry = await action.evaluate(element => {
      const box = element.getBoundingClientRect();
      return { x: box.x, width: box.width, height: box.height, clientWidth: element.clientWidth,
        scrollWidth: element.scrollWidth, clientHeight: element.clientHeight, scrollHeight: element.scrollHeight };
    });
    expect(geometry.width).toBeGreaterThanOrEqual(48);
    expect(geometry.height).toBeGreaterThanOrEqual(48);
    expect(geometry.x).toBeGreaterThanOrEqual(0);
    expect(geometry.x + geometry.width).toBeLessThanOrEqual(selected.viewport.width + 0.5);
    expect(geometry.scrollWidth).toBeLessThanOrEqual(geometry.clientWidth + 1);
    expect(geometry.scrollHeight).toBeLessThanOrEqual(geometry.clientHeight + 1);
    if (selected.rootTextSizePercent === 200) await expect(page.locator('html')).toHaveCSS('font-size', '32px');
    await info.attach('diagnostics-export-geometry', {
      body: Buffer.from(JSON.stringify({ scope: 'CLIENT/SYNTHETIC', geometry, rootTextSizePercent: selected.rootTextSizePercent ?? 100 })),
      contentType: 'application/json',
    });
    await gallery.capture('diagnostics-export-ready', 'CLIENT/SYNTHETIC · diagnostic export reachability, touch target and keyboard focus');
    const history = await page.locator('.activity-list').allTextContents();
    await page.keyboard.press('Enter');
    if (pending) {
      await expect(action).toBeDisabled();
      await expect(action).toHaveAttribute('aria-busy', 'true');
      await expect(page.getByRole('button', { name: '기록 지우기', exact: true })).toBeDisabled();
      await expect(page.getByText('진단 로그 파일을 저장하고 공유 화면을 열었습니다.', { exact: true })).toHaveCount(0);
      await expect(page.locator('.global-feedback')).not.toBeEmpty();
      await action.scrollIntoViewIfNeeded();
      await expect(action).toBeInViewport({ ratio: 1 });
      await gallery.capture('diagnostics-export-pending', 'CLIENT/SYNTHETIC · held export reply, disabled action and unchanged history; no file or Sharesheet');
      await page.locator('.global-feedback').scrollIntoViewIfNeeded();
      await expect(page.locator('.global-feedback')).toBeInViewport({ ratio: 1 });
      await gallery.capture('diagnostics-export-progress', 'CLIENT/SYNTHETIC · pending status; 200% root text is not Android font-scaling evidence');
    } else {
      await expect(action).toBeEnabled();
      await expect(action).toHaveAttribute('aria-busy', 'false');
      const notice = page.getByText('진단 로그 파일을 저장하고 공유 화면을 열었습니다.', { exact: true });
      await expect(notice).toBeVisible();
      await notice.scrollIntoViewIfNeeded();
      await gallery.capture('diagnostics-export-acknowledged', 'CLIENT/SYNTHETIC · synthetic acknowledgement copy only, no saved-file, attachment or delivery proof');
    }
    expect(await page.locator('.activity-list').allTextContents()).toEqual(history);
  });
}

for (const selected of [...galleryCases.filter((item) => !item.id.startsWith('phone-service-')), ...scannerLaunchCases]) {
  test(selected.id, async ({ page, gallery }, info) => {
    await gallery.open(selected);
    const fixture = selected.fixture;
    if (fixture === 'desktop-connected') {
      await expect(page.getByRole('heading', { name: '승인기 실행 중', exact: true })).toBeVisible();
      await expect(page.getByText('휴대폰 연결됨', { exact: true })).toBeVisible();
      await expect(page.getByText('PC 서비스', { exact: true })).toHaveCount(0);
      await expect(page.getByText('지금은 PC의 관리자 권한 창에서 직접 선택하십시오.', { exact: true })).toHaveCount(0);
      await expect(page.getByText(/휴대폰 연결 여부는 별도로/)).toHaveCount(0);
    }
    if (fixture === 'phone-history-results') {
      for (const name of ['요청 승인됨', '요청 거부됨', '요청 처리 실패', 'PC에서 요청 종료됨']) {
        await expect(page.getByRole('heading', { name, exact: true })).toBeVisible();
      }
    }
    if (fixture === 'phone-devices-offline') {
      const trigger = page.getByRole('button', { name: '화면 예시 PC 연결 해제', exact: true });
      await trigger.click();
      const dialog = page.getByRole('dialog', { name: '이 PC의 등록을 휴대폰에서 삭제하시겠습니까?', exact: true });
      await expect(dialog).toBeVisible();
      await expect(dialog.getByRole('button', { name: '취소', exact: true })).toBeFocused();
      await gallery.capture('offline-removal-confirmation', 'CLIENT/SYNTHETIC · offline local PC registration removal confirmation');
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(trigger).toBeFocused();
    }
    if (fixture === 'phone-devices-pairing' || fixture === 'desktop-pairing-ready' || fixture === 'desktop-setup-missing') {
      const phone = fixture === 'phone-devices-pairing';
      const qr = page.getByRole('button', { name: phone ? 'PC의 QR 코드 촬영' : 'QR 코드 보기', exact: true });
      const usb = page.getByRole('button', { name: 'USB로 연결', exact: true });
      await expect(qr).toHaveClass(/\bsecondary\b/);
      await expect(usb).toHaveClass(/\bsecondary\b/);
      expect(await qr.evaluate(node => getComputedStyle(node).backgroundColor))
        .toBe(await usb.evaluate(node => getComputedStyle(node).backgroundColor));
      const a = await qr.boundingBox(), b = await usb.boundingBox();
      expect(a).not.toBeNull(); expect(b).not.toBeNull();
      const rootSize = await page.evaluate(() => Number.parseFloat(getComputedStyle(document.documentElement).fontSize));
      const horizontalGap = Math.max(b!.x - a!.x - a!.width, a!.x - b!.x - b!.width);
      const verticalGap = Math.max(b!.y - a!.y - a!.height, a!.y - b!.y - b!.height);
      const requiredGap = rootSize * (phone ? 0.75 : 1); // --space-3 row / --space-4 PC stack.
      expect(Math.max(horizontalGap, verticalGap)).toBeGreaterThanOrEqual(requiredGap - 0.5);
      for (const box of [a!, b!]) {
        expect(box.x).toBeGreaterThanOrEqual(0);
        expect(box.x + box.width).toBeLessThanOrEqual(selected.viewport.width + 0.5);
        expect(box.height).toBeGreaterThanOrEqual(phone ? 48 : 44);
      }
      if (await qr.isEnabled()) {
        await qr.focus(); await expect(qr).toBeFocused();
        await page.keyboard.press('Tab'); await expect(usb).toBeFocused();
      }
      await info.attach('pairing-action-geometry', {
        body: Buffer.from(JSON.stringify({ scope: 'CLIENT/SYNTHETIC', fixture, a, b, horizontalGap, verticalGap, requiredGap })),
        contentType: 'application/json',
      });
      if (!phone) {
        const input = page.locator('.relay-advanced input[type="text"]');
        const field = await input.evaluate(node => {
          const box = node.getBoundingClientRect();
          const parent = node.closest('fieldset')!;
          const container = parent.getBoundingClientRect();
          const style = getComputedStyle(parent);
          return { left: box.left, right: box.right, allowedLeft: container.left + Number.parseFloat(style.paddingLeft),
            allowedRight: container.right - Number.parseFloat(style.paddingRight) };
        });
        await info.attach('relay-input-geometry', { body: Buffer.from(JSON.stringify(field)), contentType: 'application/json' });
        expect(field.left).toBeGreaterThanOrEqual(field.allowedLeft - 0.5);
        expect(field.right).toBeLessThanOrEqual(field.allowedRight + 0.5);
      }
      await gallery.capture('pairing-action-spacing', 'CLIENT/SYNTHETIC · QR/USB gaps, wrapping and keyboard order');
    }
    if (selected.action === 'connection-setup') {
      await page.getByRole('button', { name: '알림 시간', exact: true }).click();
      const card = page.locator('.pairing-entry');
      await expect(card).toContainText('PC의 UAC 원격 승인기에서');
      const scanner = card.getByRole('button', { name: 'PC의 QR 코드 촬영', exact: true });
      const passive = page.getByRole('navigation').locator('button:disabled');
      expect(await passive.count()).toBeGreaterThan(0);
      for (const button of await passive.all()) {
        await expect(button).toHaveCSS('opacity', selected.forcedColors === 'active' ? '1' : '0.45');
        await expect(button).not.toHaveAttribute('aria-current', 'page');
      }
      if (fixture === 'phone-setup-unavailable') {
        await expect(card.getByRole('heading', { name: 'PC 연결', exact: true })).toBeVisible();
        await expect(page.getByText('PC와 아직 연결하지 않았습니다', { exact: true })).toHaveCount(0);
        await expect(scanner).toBeDisabled();
        await expect(page.getByText('휴대폰 승인 상태를 확인할 수 없습니다', { exact: true })).toBeVisible();
      } else {
        await expect(card.getByRole('heading', { name: 'PC와 아직 연결하지 않았습니다', exact: true })).toBeVisible();
        await expect(scanner).toBeEnabled();
      }
      await gallery.capture('connection-guidance', 'CLIENT/SYNTHETIC · 연결 안내와 비활성 메뉴');
      await scanner.scrollIntoViewIfNeeded();
      await expect(scanner).toBeInViewport({ ratio: 1 });
      await gallery.capture('connection-action', 'CLIENT/SYNTHETIC · 좁은 화면/확대에서 촬영 버튼 접근');
    }
    if (fixture.startsWith('desktop-') && !fixture.startsWith('desktop-relay-') && !['desktop-devices', 'desktop-pairing-ready', 'desktop-setup-missing', 'desktop-history'].includes(fixture)) {
      const purpose = page.getByRole('heading', { level: 1, name: 'UAC 원격 승인기', exact: true });
      await expect(purpose).toBeVisible();
      if (!selected.rootTextSizePercent) await expect(purpose).toBeInViewport({ ratio: 1 });
      await expect(page.getByText('PC에 표시되는 관리자 권한 요청을 휴대폰에서 승인하거나 거부하기 위한 앱입니다.', { exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: /서비스/u })).toHaveCount(0);
    }
    if (fixture === 'desktop-empty' || fixture === 'desktop-unavailable') {
      await expect(page.getByRole('heading', { name: '휴대폰 승인 설정이 필요합니다', exact: true })).toBeVisible();
      await expect(page.getByRole('region', { name: '휴대폰 승인 설정이 필요합니다', exact: true }).getByRole('button')).toHaveCount(0);
    }
    if (fixture === 'desktop-unavailable') {
      await expect(page.getByRole('navigation').locator('button:enabled')).toHaveCount(3);
      await expect(page.getByRole('navigation').locator('button:disabled')).toHaveCount(0);
      // History may be unavailable while independent diagnostic files remain useful.
      await page.getByRole('navigation').getByRole('button', { name: '활동 기록', exact: true }).click();
      await expect(page.getByRole('heading', { name: '활동 기록 확인 불가', exact: true })).toBeVisible();
      const logs = page.getByRole('button', { name: '로그 폴더 열기', exact: true });
      await expect(logs).toBeEnabled();
      await logs.scrollIntoViewIfNeeded();
      await logs.focus(); await expect(logs).toBeFocused();
      await gallery.capture('diagnostics-unavailable-history', 'CLIENT/SYNTHETIC · diagnostic folder remains reachable without service history');
      await page.getByRole('navigation').getByRole('button', { name: 'PC 상태', exact: true }).click();
    }
    if (fixture === 'desktop-running') {
      await expect(page.getByRole('heading', { name: '승인기 실행 중', exact: true })).toBeVisible();
      await expect(page.getByText('휴대폰 연결 안 됨', { exact: true })).toBeVisible();
      await expect(page.getByText('요청 전송 준비 안 됨', { exact: true })).toHaveCount(0);
      await expect(page.getByText('지금은 PC의 관리자 권한 창에서 직접 선택하십시오.', { exact: true })).toHaveCount(0);
      await expect(page.getByText('요청 전송 준비됨', { exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: '휴대폰 승인 끄기', exact: true })).toBeEnabled();
    }
    if (fixture === 'desktop-devices') await expect(page.getByRole('heading', { name: '화면 예시 휴대폰', exact: true })).toBeVisible();
    if (fixture === 'desktop-pairing-ready' || fixture === 'desktop-setup-missing') {
      const entry = page.getByRole('button', { name: 'QR 코드 보기', exact: true });
      await expect(entry).toBeVisible();
      await expect(page.getByText('연결용 QR 코드를 표시해 휴대폰을 등록합니다.', { exact: true })).toBeVisible();
      await expect(page.getByRole('navigation').getByRole('button', { name: '휴대폰 관리', exact: true })).toBeEnabled();
      if (fixture === 'desktop-pairing-ready') await expect(entry).toBeEnabled();
      else {
        await expect(entry).toBeDisabled();
        await expect(entry).toHaveCSS('opacity', '0.45');
        await expect(page.getByRole('button', { name: 'PC 상태 열기', exact: true })).toBeEnabled();
      }
    }
    if (fixture === 'desktop-history') {
      await expect(page.getByRole('heading', { name: '승인기 실행 중', exact: true })).toBeVisible();
      await expect(page.locator('time')).toHaveCount(2);
      await expect(page.locator('time').first()).toHaveAttribute('datetime', '2026-09-08T12:30:00.000Z');
      const logs = page.getByRole('button', { name: '로그 폴더 열기', exact: true });
      await expect(logs).toBeEnabled();
      await expect(page.getByRole('button', { name: '진단 로그 내보내기', exact: true })).toHaveCount(0);
      await logs.scrollIntoViewIfNeeded();
      await logs.focus();
      await expect(logs).toBeFocused();
      await expect(logs).toBeInViewport({ ratio: 1 });
      await gallery.capture('diagnostics-windows-history', 'CLIENT/SYNTHETIC · existing Windows log-folder action retained; no Explorer proof');
    }
    if (fixture === 'phone-empty') await expect(page.getByRole('heading', { name: '승인 요청 없음', exact: true })).toBeVisible();
    const intakeCopy: Record<string, string> = {
      'phone-unpaired': 'PC와 아직 연결하지 않았습니다', 'phone-disconnected': 'PC 연결 대기 중',
      'phone-reconciling': '받은 요청을 확인 중입니다', 'phone-authenticating': '본인 확인을 진행하십시오.',
      'phone-waiting': '앞선 작업이 끝나기를 대기 중입니다.', 'phone-awaiting-outcome': 'Windows 처리 결과 대기 중입니다.',
    };
    if (intakeCopy[fixture]) {
      await expect(page.getByText(intakeCopy[fixture], { exact: true })).toBeVisible();
      await expect(page.getByText(intakeCopy[fixture], { exact: true })).toBeInViewport({ ratio: 1 });
      await expect(page.getByText('요청 승인됨', { exact: true })).toHaveCount(0);
      await expect(page.getByText('요청 시간이 지났습니다.', { exact: true })).toHaveCount(0);
      if (fixture === 'phone-authenticating') {
        await expect(page.getByRole('button', { name: '승인', exact: true })).toBeDisabled();
        await expect(page.getByRole('button', { name: '거부', exact: true })).toBeEnabled();
      }
    }
    if (fixture === 'phone-history') {
      await expect(page.getByRole('heading', { name: 'PC에서 요청 종료됨', exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: '요청 시간 만료', exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: '요청 승인됨', exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: '기록 지우기', exact: true })).toBeEnabled();
    }
    if (fixture === 'phone-history-empty') {
      await expect(page.getByRole('heading', { name: '표시할 활동 기록이 없습니다', exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '기록 지우기', exact: true })).toHaveCount(0);
    }
    if (fixture === 'phone-unavailable') {
      await expect(page.getByRole('heading', { name: '요청을 받을 준비가 필요합니다', exact: true })).toBeVisible();
      await expect(page.getByRole('navigation').locator('button:enabled')).toHaveCount(3);
      await expect(page.getByRole('navigation').locator('button:disabled')).toHaveCount(1);
    }
    if (fixture === 'phone-pending' || fixture === 'phone-long-request' || fixture === 'phone-terminal') {
      await expect(page.getByRole('button', { name: '승인', exact: true })).toBeEnabled();
      await expect(page.getByRole('button', { name: '거부', exact: true })).toBeEnabled();
      await expect(page.getByRole('heading', { name: '휴대폰 화면 잠금이 필요합니다', exact: true })).toHaveCount(0);
      await expect(page.locator('.path-output')).toContainText('C:\\');
    }
    if (fixture === 'phone-terminal') {
      await expect(page.getByRole('heading', { name: 'PowerShell', exact: true })).toBeVisible();
      await expect(page.locator('.path-output')).toContainText('pwsh.exe');
      await expect(page.getByText(/Write-Output/u)).toHaveCount(0);
    }
    if (fixture === 'phone-settings') {
      await expect(page.getByRole('radio', { name: '요일과 시간 지정', exact: true })).toBeChecked();
      await expect(page.getByRole('radio', { name: '진동만', exact: true })).toBeChecked();
      await expect(page.getByLabel('시작', { exact: true })).toHaveValue('09:00');
      await expect(page.getByLabel('종료', { exact: true })).toHaveValue('18:00');
      await expect(page.getByRole('button', { name: '저장', exact: true })).toBeDisabled();
    }
    if (fixture === 'phone-lock-missing') {
      await expect(page.getByRole('heading', { name: '휴대폰 화면 잠금이 필요합니다', exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '화면 잠금 설정', exact: true })).toBeEnabled();
    }
    if (fixture === 'phone-lock-unknown') {
      await expect(page.getByRole('heading', { name: '화면 잠금 상태를 확인하지 못했습니다', exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '화면 잠금 설정', exact: true })).toHaveCount(0);
      await expect(page.getByRole('heading', { name: '휴대폰 화면 잠금이 필요합니다', exact: true })).toHaveCount(0);
    }
    if (fixture === 'phone-notifications-denied') await expect(page.getByRole('heading', { name: '휴대폰 알림이 꺼져 있습니다', exact: true })).toBeVisible();
    if (fixture === 'errors') {
      await expect(page.getByRole('alert')).toContainText('요청 상태를 확인하지 못했어요.');
      await expect(page.getByText('연결을 확인한 뒤 다시 시도해 주세요.', { exact: true })).toBeVisible();
      await expect(page.getByText('synthetic_unavailable', { exact: true })).toHaveCount(0);
      await expect(page.getByRole('heading', { name: '요청을 받을 준비가 필요합니다', exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: '승인 요청 없음', exact: true })).toHaveCount(0);
    }
    if (fixture.startsWith('desktop-')) await expect(page.locator('button[data-pairing-scanner="open"]')).toHaveCount(0);
    await gallery.capture('overview', '합성 클라이언트 초기 화면');
    if (fixture.startsWith('desktop-relay-')) {
      const card = page.getByRole('region', { name: 'PC 내장 중계', exact: true });
      const status = card.getByRole('status');
      const expected: Record<string, string> = {
        'desktop-relay-stopped': '내장 중계 중지됨 · 수신 대기하지 않습니다.',
        'desktop-relay-listening': '내장 중계 수신 대기 중',
        'desktop-relay-waiting': '내장 중계: 네트워크 연결 대기 중',
        'desktop-relay-unknown': '중계 실행 상태를 확인하지 못했습니다. 다시 확인하십시오.',
        'desktop-relay-external': '외부 중계 설정됨 · 연결 가능 여부는 아직 확인되지 않았습니다.',
      };
      await expect(status).toHaveText(expected[fixture]!);
      await status.scrollIntoViewIfNeeded();
      await expect(status).toBeInViewport({ ratio: 1 });
      if (fixture === 'desktop-relay-listening') await expect(status).toHaveClass(/is-success/u);
      else await expect(status).not.toHaveClass(/is-success/u);
      const selectedMode = ['desktop-relay-stopped', 'desktop-relay-listening', 'desktop-relay-waiting'].includes(fixture);
      const choice = card.getByRole('button', { name: selectedMode ? '내장 중계 선택됨' : '이 PC의 내장 중계 사용', exact: true });
      if (selectedMode || fixture === 'desktop-relay-unknown') await expect(choice).toBeDisabled();
      else await expect(choice).toBeEnabled();
      await gallery.capture('relay-observation', 'CLIENT/SYNTHETIC · 중계 설정과 실제 수신 상태 구분');
      if (fixture === 'desktop-relay-unknown') {
        const address = page.getByRole('textbox', { name: '중계 서버 주소', exact: true });
        await expect(address).toBeEnabled();
        await address.fill('203.0.113.10:443');
        await expect(address).toHaveValue('203.0.113.10:443');
        await expect(page.getByRole('button', { name: '저장', exact: true })).toBeDisabled();
        await page.getByRole('form', { name: '중계 서버 주소', exact: true }).scrollIntoViewIfNeeded();
        await expect(page.getByRole('button', { name: '저장', exact: true })).toBeInViewport({ ratio: 1 });
        await gallery.capture('relay-draft', 'CLIENT/SYNTHETIC · 상태 미확인 중 주소 작성, 저장은 대기');
      }
      if (fixture === 'desktop-relay-stopped') {
        const next = card.getByRole('button', { name: 'PC 상태 열기', exact: true });
        await next.scrollIntoViewIfNeeded();
        await expect(next).toBeInViewport({ ratio: 1 });
        await gallery.capture('relay-next-step', 'CLIENT/SYNTHETIC · 중지 상태의 다음 단계');
        await next.click();
        await expect(page.getByRole('button', { name: '휴대폰 승인 켜기', exact: true })).toBeEnabled();
      }
    }
    if (fixture === 'desktop-start-failed') {
      const error = page.getByRole('alert');
      await expect(error).toHaveText('작업 결과를 확인하지 못했습니다. 다시 확인한 뒤 시도하십시오.');
      await page.getByRole('button', { name: '다시 확인', exact: true }).click();
      await expect(error).toBeVisible();
      const retry = page.getByRole('button', { name: '휴대폰 승인 켜기', exact: true });
      await retry.scrollIntoViewIfNeeded();
      await expect(retry).toBeEnabled();
      await expect(retry).toBeInViewport({ ratio: 1 });
      await gallery.capture('start-failure-retry', 'CLIENT/SYNTHETIC · 조회 후에도 남는 실패 안내와 다시 시작');
    }
    if (fixture === 'desktop-taskbar-available' || fixture === 'desktop-taskbar-unavailable') {
      await page.getByRole('heading', { name: '작업 표시줄에서 바로 열기' }).scrollIntoViewIfNeeded();
      await gallery.capture('taskbar-suggestion', 'CLIENT/SYNTHETIC · 설치 선택 안내, 실제 Windows 고정 아님');
    }
    if (fixture === 'desktop-devices' || fixture === 'desktop-pairing-ready' || fixture === 'desktop-setup-missing') {
      await page.getByRole('button', { name: '이 PC의 내장 중계 사용' }).scrollIntoViewIfNeeded();
      await gallery.capture('embedded-relay', 'CLIENT/SYNTHETIC · 내장 중계 진입과 외부 중계 안내');
    }
    if (selected.id === 'desktop-running-980' || selected.id === 'phone-terminal-390') {
      await recordClientFontProof(page, info, selected.id === 'desktop-running-980' ? 'desktop' : 'phone');
    }

    if (selected.id === 'desktop-running-minimum-760' || (selected.rootTextSizePercent === 200 && fixture.startsWith('desktop-'))) {
      if (selected.rootTextSizePercent === 200) {
        await expect(page.locator('html')).toHaveCSS('font-size', '32px');
        const rail = page.locator('.desktop-shell .navigation-shell');
        const railBox = await rail.boundingBox();
        expect(railBox).not.toBeNull();
        expect(railBox?.width ?? Infinity).toBeLessThanOrEqual(selected.viewport.width * 0.3 + 1);
        await expect(rail).toHaveCSS('overflow-y', 'auto');
        const beforeMain = await page.locator('.main-scroll').evaluate((element) => element.scrollTop);
        const menu = page.getByRole('navigation', { name: '주요 메뉴', exact: true }).getByRole('button');
        await expect(menu).toHaveCount(3);
        const lastBefore = await menu.last().boundingBox();
        expect(lastBefore).not.toBeNull();
        await menu.first().focus();
        for (let index = 0; index < 3; index += 1) {
          if (index > 0) await page.keyboard.press('Tab');
          const item = menu.nth(index);
          await expect(item).toBeFocused();
          await expect(item).toBeInViewport({ ratio: 1 });
          const bounds = await item.evaluate((element) => {
            const box = element.getBoundingClientRect();
            const owner = element.closest('.navigation-shell')?.getBoundingClientRect();
            return { top: box.top, bottom: box.bottom, width: box.width, height: box.height,
              ownerTop: owner?.top, ownerBottom: owner?.bottom };
          });
          expect(bounds.ownerTop).toBeDefined();
          expect(bounds.ownerBottom).toBeDefined();
          expect(bounds.top).toBeGreaterThanOrEqual((bounds.ownerTop ?? Infinity) - 1);
          expect(bounds.bottom).toBeLessThanOrEqual((bounds.ownerBottom ?? -Infinity) + 1);
          expect(bounds.width).toBeGreaterThanOrEqual(44);
          expect(bounds.height).toBeGreaterThanOrEqual(44);
        }
        const railScroll = await rail.evaluate((element) => ({ top: element.scrollTop, height: element.clientHeight,
          scrollHeight: element.scrollHeight, width: element.clientWidth, scrollWidth: element.scrollWidth }));
        expect(railScroll.scrollWidth).toBeLessThanOrEqual(railScroll.width + 1);
        if (lastBefore && railBox && lastBefore.y + lastBefore.height > railBox.y + railBox.height + 1) {
          expect(railScroll.top).toBeGreaterThan(0);
        }
        expect(await page.locator('.main-scroll').evaluate((element) => element.scrollTop)).toBe(beforeMain);
        await gallery.capture('text-size-navigation', 'CLIENT 200% 글자 크기 · 30% 이하 탐색 너비와 Tab 초점·독립 스크롤 접근');
      }
    }

    if (fixture === 'desktop-running' && (selected.id === 'desktop-running-minimum-760' || selected.rootTextSizePercent === 200)) {
      for (const name of ['휴대폰 승인 다시 켜기', '휴대폰 승인 끄기', 'PC 연결 기능 제거']) {
        const action = page.getByRole('button', { name, exact: true });
        await action.scrollIntoViewIfNeeded();
        await action.focus();
        await expect(action).toBeInViewport({ ratio: 1 });
        await expect(action).toBeFocused();
        const box = await action.boundingBox();
        expect(box?.width ?? 0).toBeGreaterThanOrEqual(44);
        expect(box?.height ?? 0).toBeGreaterThanOrEqual(44);
        const dimensions = await action.evaluate((element) => ({ clientWidth: element.clientWidth, scrollWidth: element.scrollWidth,
          clientHeight: element.clientHeight, scrollHeight: element.scrollHeight }));
        expect(dimensions.scrollWidth).toBeLessThanOrEqual(dimensions.clientWidth + 1);
        expect(dimensions.scrollHeight).toBeLessThanOrEqual(dimensions.clientHeight + 1);
      }
      await gallery.capture('activation-actions', selected.rootTextSizePercent === 200
        ? 'CLIENT 200% 루트 글자 크기 스트레스 · 실제 브라우저 확대/OS 배율 증거 아님'
        : '최소 데스크톱 크기에서 동작 접근 · 실제 Windows 실행 아님');
    }

    if (selected.action === 'remove-feature') {
      const trigger = page.getByRole('button', { name: 'PC 연결 기능 제거', exact: true });
      await trigger.scrollIntoViewIfNeeded();
      await trigger.focus();
      await page.keyboard.press('Enter');
      const dialog = page.getByRole('dialog', { name: 'PC 연결 기능 제거', exact: true });
      await expect(dialog).toBeVisible();
      await expect(dialog).toContainText('PC에서 실행되는 휴대폰 승인 기능만 제거하고, 이 설정 앱은 남겨 둡니다.');
      await expect(dialog).not.toContainText(/키|데이터|기록/u);
      const cancel = dialog.getByRole('button', { name: '취소', exact: true });
      await expect(cancel).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(dialog.getByRole('button', { name: 'PC 연결 기능 제거', exact: true })).toBeFocused();
      await page.keyboard.press('Shift+Tab');
      await expect(cancel).toBeFocused();
      await gallery.capture('remove-feature-confirmation', 'PC 연결 기능만 제거하는 범위 · 설정 앱 유지 · 실제 제거 아님');
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(trigger).toBeFocused();
      await expect(page.getByRole('heading', { name: '승인기 실행 중', exact: true })).toBeVisible();
      await gallery.capture('remove-feature-cancelled', 'Escape 취소와 초점 복귀 · 제거 명령 실행 없음');
    }

    if (selected.action === 'notification-settings') {
      const settings = page.getByRole('button', { name: '앱 알림 설정', exact: true });
      await settings.scrollIntoViewIfNeeded();
      await settings.focus();
      await expect(settings).toBeInViewport({ ratio: 1 });
      await expect(settings).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(page.getByText('설정을 마치면 앱으로 돌아와 다시 확인하십시오.', { exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: '휴대폰 알림이 꺼져 있습니다', exact: true })).toBeVisible();
      await gallery.capture('settings-handoff-simulated', '설정 이동 후에도 허용 상태를 가정하지 않음 · 실제 Android 설정 화면 아님');
    }

    if (selected.action === 'details' || selected.action === 'long-details') {
      await page.getByRole('button', { name: '더 보기', exact: true }).click();
      const region = page.getByRole('region', { name: '프로그램 요청 세부 내용', exact: true });
      await expect(region).toBeVisible();
      if (fixture === 'phone-terminal') await expect(region.locator('pre')).toContainText('Write-Output');
      await expect(page.getByRole('button', { name: '접기', exact: true })).toHaveAttribute('aria-expanded', 'true');
      if (selected.action === 'long-details') {
        await expect(region.locator('pre')).toContainText('<img src=x onerror="exampleOnly()">');
        await expect(region.locator('img, script, iframe, [onerror]')).toHaveCount(0);
        await expect(page.locator('.path-output')).toContainText('אבג');
      }
      await region.scrollIntoViewIfNeeded();
      await region.focus();
      await page.keyboard.press('ArrowDown');
      await expect(region).toBeFocused();
      await gallery.capture('details-keyboard', '원문은 실행되지 않는 텍스트 · 키보드 접근 가능한 세부 영역');
      if (selected.action === 'long-details') {
        await page.getByRole('button', { name: '승인', exact: true }).scrollIntoViewIfNeeded();
        await expect(page.getByRole('button', { name: '승인', exact: true })).toBeInViewport({ ratio: 1 });
        await expect(page.getByRole('button', { name: '거부', exact: true })).toBeInViewport({ ratio: 1 });
        await gallery.capture('long-request-actions', '긴 원문 아래의 동작도 내부 스크롤로 접근 · 실제 승인 실행 없음');
      }
    }
    if (selected.action === 'schedule') {
      await page.getByRole('button', { name: '저장', exact: true }).scrollIntoViewIfNeeded();
      await gallery.capture('schedule-footer', '시간대와 알림 방식 · 변경 전 저장 비활성');
    }
    if (selected.action === 'dialog') {
      const trigger = page.getByRole('button', { name: '화면 예시 휴대폰 연결 해제', exact: true });
      await trigger.focus();
      await page.keyboard.press('Enter');
      const dialog = page.getByRole('dialog', { name: '기기 연결 해제', exact: true });
      const cancel = dialog.getByRole('button', { name: '취소', exact: true });
      await expect(dialog).toBeVisible();
      await expect(cancel).toBeFocused();
      await page.keyboard.press('Tab');
      await expect(dialog.getByRole('button', { name: '연결 해제', exact: true })).toBeFocused();
      await page.keyboard.press('Shift+Tab');
      await expect(cancel).toBeFocused();
      await gallery.capture('dialog-cancel-focus', '강제 색상 · 합성 연결 해제 확인, 취소에 키보드 초점');
      await page.keyboard.press('Escape');
      await expect(dialog).toHaveCount(0);
      await expect(trigger).toBeFocused();
      await expect(page.getByRole('heading', { name: '화면 예시 휴대폰', exact: true })).toBeVisible();
      await gallery.capture('dialog-escape-return', 'Escape 취소 후 원래 제어로 초점 복귀 · 실제 연결 해제 없음');
    }
    if (selected.action === 'draft') {
      const silent = page.getByRole('radio', { name: '무음', exact: true });
      await silent.focus();
      await page.keyboard.press('Space');
      await expect(silent).toBeChecked();
      await expect(page.getByText('저장하지 않은 변경 사항이 있습니다.', { exact: true })).toBeVisible();
      const cancel = page.getByRole('button', { name: '취소', exact: true });
      await cancel.scrollIntoViewIfNeeded();
      await gallery.capture('keyboard-dirty-draft', '키보드로 바꾼 합성 초안 · 저장 호출 없음');
      await cancel.click();
      await expect(page.getByRole('radio', { name: '진동만', exact: true })).toBeChecked();
      await expect(page.getByRole('button', { name: '저장', exact: true })).toBeDisabled();
      await expect(page.getByText('변경을 취소했습니다.', { exact: true })).toBeVisible();
      await gallery.capture('draft-cancelled', '초안 취소 후 기존 합성 설정 복원');
    }
    if (selected.action === 'deny') {
      await page.getByRole('button', { name: '거부', exact: true }).focus();
      await page.keyboard.press('Enter');
      await expect(page.getByText('선택한 내용을 컴퓨터로 전송 중입니다.', { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '승인', exact: true })).toBeDisabled();
      await expect(page.getByRole('button', { name: '거부', exact: true })).toBeDisabled();
      await expect(page.getByText('본인 확인을 진행하십시오.', { exact: true })).toHaveCount(0);
      await gallery.capture('simulated-sending', '합성 전송 상태만 표시 · 거부 완료/Windows 동작 증거 아님');
    }
    if (selected.id === 'phone-pending-landscape-844') {
      await page.getByRole('button', { name: '승인', exact: true }).scrollIntoViewIfNeeded();
      await gallery.capture('landscape-actions', '가로 클라이언트 화면에서 요청 동작 접근 · 실제 기기 아님');
    }
    if (selected.id.startsWith('client-scanner-launch-')) {
      const entry = page.getByRole('button', { name: 'PC의 QR 코드 촬영', exact: true });
      await expect(entry).toHaveAttribute('data-pairing-scanner', 'open');
      await expect(page.getByRole('navigation', { name: '주요 메뉴' }).getByRole('button', { name: '연결된 PC', exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: 'PC 연결', exact: true })).toHaveCount(0);
      await entry.scrollIntoViewIfNeeded();
      await entry.focus();
      await expect(entry).toBeFocused();
      await expect(entry).toBeInViewport({ ratio: 1 });
      const box = await entry.boundingBox();
      expect(box?.width ?? 0).toBeGreaterThanOrEqual(48);
      expect(box?.height ?? 0).toBeGreaterThanOrEqual(48);
      const text = await entry.evaluate(element => ({ width: element.clientWidth, scrollWidth: element.scrollWidth,
        height: element.clientHeight, scrollHeight: element.scrollHeight }));
      expect(text.scrollWidth).toBeLessThanOrEqual(text.width + 1);
      expect(text.scrollHeight).toBeLessThanOrEqual(text.height + 1);
      if (selected.rootTextSizePercent === 200) await expect(page.locator('html')).toHaveCSS('font-size', '32px');
      await gallery.capture('client-scanner-entry', 'CLIENT/SYNTHETIC · QR 입력 화면 열기 제어, 실제 카메라 아님');
      await page.keyboard.press('Enter');
      await expect(page.getByRole('button', { name: '다시 확인', exact: true })).toBeEnabled();
      await expect(entry).toBeEnabled();
      await expect(page.getByRole('dialog')).toHaveCount(0);
      await expect(page.getByText('PC 연결 QR을 읽었어요.', { exact: true })).toHaveCount(0);
      await expect(page.getByText('상태를 새로 확인했어요.', { exact: true })).toHaveCount(0);
      if (fixture === 'phone-scanner-launch-error') {
        const error = page.getByRole('alert').filter({ hasText: 'QR 읽기 화면을 열지 못했습니다.' });
        await expect(error).toContainText('휴대폰 상태를 다시 확인한 뒤 시도하십시오.');
        await error.scrollIntoViewIfNeeded();
        await expect(error).toBeInViewport({ ratio: 1 });
      }
      await gallery.capture('client-scanner-launch-result', 'CLIENT/SYNTHETIC · 열기 응답/실패만 모의, QR 읽기·연결 완료 증거 아님');
    }
  });
}
