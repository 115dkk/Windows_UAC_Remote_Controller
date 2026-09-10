// SPDX-License-Identifier: GPL-2.0-or-later
import { galleryCases } from './cases';
import { test, expect } from './session';
import { registerPhoneServiceGallery } from './phone-service';
import { recordClientFontProof } from './font-proof';

registerPhoneServiceGallery(test);

for (const selected of galleryCases.filter((item) => !item.id.startsWith('phone-service-'))) {
  test(selected.id, async ({ page, gallery }, info) => {
    await gallery.open(selected);
    const fixture = selected.fixture;
    if (fixture.startsWith('desktop-') && fixture !== 'desktop-devices' && fixture !== 'desktop-history') {
      const purpose = page.getByRole('heading', { level: 1, name: 'PC 승인을 휴대폰에서', exact: true });
      await expect(purpose).toBeVisible();
      if (!selected.rootTextSizePercent) await expect(purpose).toBeInViewport({ ratio: 1 });
      await expect(page.getByText('PC에 표시되는 관리자 권한 요청을 휴대폰에서 승인하거나 거부하기 위한 앱이에요.', { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: /서비스/u })).toHaveCount(0);
    }
    if (fixture === 'desktop-empty' || fixture === 'desktop-unavailable') {
      await expect(page.getByRole('heading', { name: '휴대폰 승인 설정이 필요해요', exact: true })).toBeVisible();
      await expect(page.getByRole('region', { name: '휴대폰 승인 설정이 필요해요', exact: true }).getByRole('button')).toHaveCount(0);
    }
    if (fixture === 'desktop-unavailable') await expect(page.getByRole('navigation', { name: '주요 메뉴' }).getByRole('button')).toHaveCount(1);
    if (fixture === 'desktop-running') {
      await expect(page.getByRole('heading', { name: '휴대폰 승인 켜짐', exact: true })).toBeVisible();
      await expect(page.getByText('PC 요청을 휴대폰으로 보낼 준비가 아직 되지 않았어요.', { exact: true })).toBeVisible();
      await expect(page.getByText('지금은 PC의 관리자 권한 창에서 직접 선택해 주세요.', { exact: true })).toBeVisible();
      await expect(page.getByText('PC 요청을 휴대폰으로 보낼 준비가 됐어요.', { exact: true })).toHaveCount(0);
      await expect(page.getByRole('button', { name: '휴대폰 승인 끄기', exact: true })).toBeEnabled();
    }
    if (fixture === 'desktop-devices') await expect(page.getByRole('heading', { name: '화면 예시 휴대폰', exact: true })).toBeVisible();
    if (fixture === 'desktop-history') {
      await expect(page.getByRole('heading', { name: '휴대폰 승인 켜짐', exact: true })).toBeVisible();
      await expect(page.locator('time')).toHaveCount(2);
      await expect(page.locator('time').first()).toHaveAttribute('datetime', '2026-09-08T12:30:00.000Z');
    }
    if (fixture === 'phone-empty') await expect(page.getByRole('heading', { name: '기다리는 요청이 없어요', exact: true })).toBeVisible();
    const intakeCopy: Record<string, string> = {
      'phone-unpaired': '연결된 PC가 없어요', 'phone-disconnected': '컴퓨터와 연결을 기다리고 있어요',
      'phone-reconciling': '받은 요청을 확인하고 있어요', 'phone-authenticating': '휴대폰에서 본인 확인을 진행해 주세요.',
      'phone-waiting': '앞선 작업이 끝나기를 기다리고 있어요.', 'phone-awaiting-outcome': 'Windows의 처리 결과를 기다리고 있어요.',
    };
    if (intakeCopy[fixture]) {
      await expect(page.getByText(intakeCopy[fixture], { exact: true })).toBeVisible();
      await expect(page.getByText(intakeCopy[fixture], { exact: true })).toBeInViewport({ ratio: 1 });
      await expect(page.getByText('요청 승인됨', { exact: true })).toHaveCount(0);
      await expect(page.getByText('요청 시간이 지났어요.', { exact: true })).toHaveCount(0);
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
      await expect(page.getByRole('heading', { name: '표시할 활동 기록이 없어요', exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '기록 지우기', exact: true })).toHaveCount(0);
    }
    if (fixture === 'phone-unavailable') {
      await expect(page.getByRole('heading', { name: '현재 요청을 확인할 수 없어요', exact: true })).toBeVisible();
      await expect(page.getByRole('navigation', { name: '주요 메뉴' }).getByRole('button')).toHaveCount(2);
    }
    if (fixture === 'phone-pending' || fixture === 'phone-long-request' || fixture === 'phone-terminal') {
      await expect(page.getByRole('button', { name: '승인', exact: true })).toBeEnabled();
      await expect(page.getByRole('button', { name: '거부', exact: true })).toBeEnabled();
      await expect(page.getByRole('heading', { name: '휴대폰 화면 잠금이 필요해요', exact: true })).toHaveCount(0);
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
      await expect(page.getByRole('heading', { name: '휴대폰 화면 잠금이 필요해요', exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '화면 잠금 설정', exact: true })).toBeEnabled();
    }
    if (fixture === 'phone-lock-unknown') {
      await expect(page.getByRole('heading', { name: '화면 잠금 상태를 확인하지 못했어요', exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '화면 잠금 설정', exact: true })).toHaveCount(0);
      await expect(page.getByRole('heading', { name: '휴대폰 화면 잠금이 필요해요', exact: true })).toHaveCount(0);
    }
    if (fixture === 'phone-notifications-denied') await expect(page.getByRole('heading', { name: '휴대폰 알림이 꺼져 있어요', exact: true })).toBeVisible();
    if (fixture === 'errors') {
      await expect(page.getByRole('alert')).toContainText('요청 상태를 확인하지 못했어요.');
      await expect(page.getByText('연결을 확인한 뒤 다시 시도해 주세요.', { exact: true })).toBeVisible();
      await expect(page.getByText('synthetic_unavailable', { exact: true })).toHaveCount(0);
      await expect(page.getByRole('heading', { name: '현재 요청을 확인할 수 없어요', exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: '기다리는 요청이 없어요', exact: true })).toHaveCount(0);
    }
    await gallery.capture('overview', '합성 클라이언트 초기 화면');
    if (selected.id === 'desktop-running-980' || selected.id === 'phone-terminal-390') {
      await recordClientFontProof(page, info, selected.id === 'desktop-running-980' ? 'desktop' : 'phone');
    }

    if (selected.id === 'desktop-running-minimum-760' || selected.rootTextSizePercent === 200) {
      if (selected.rootTextSizePercent === 200) {
        await expect(page.locator('html')).toHaveCSS('font-size', '32px');
      }
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
      const dialog = page.getByRole('dialog', { name: 'PC 연결 기능을 제거할까요?', exact: true });
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
      await expect(page.getByRole('heading', { name: '휴대폰 승인 켜짐', exact: true })).toBeVisible();
      await gallery.capture('remove-feature-cancelled', 'Escape 취소와 초점 복귀 · 제거 명령 실행 없음');
    }

    if (selected.action === 'notification-settings') {
      const settings = page.getByRole('button', { name: '앱 알림 설정', exact: true });
      await settings.scrollIntoViewIfNeeded();
      await settings.focus();
      await expect(settings).toBeInViewport({ ratio: 1 });
      await expect(settings).toBeFocused();
      await page.keyboard.press('Enter');
      await expect(page.getByText('설정을 마치면 앱으로 돌아와 다시 확인해 주세요.', { exact: true })).toBeVisible();
      await expect(page.getByRole('heading', { name: '휴대폰 알림이 꺼져 있어요', exact: true })).toBeVisible();
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
      const dialog = page.getByRole('dialog', { name: '기기 연결을 해제할까요?', exact: true });
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
      await expect(page.getByText('저장하지 않은 변경 사항이 있어요.', { exact: true })).toBeVisible();
      const cancel = page.getByRole('button', { name: '취소', exact: true });
      await cancel.scrollIntoViewIfNeeded();
      await gallery.capture('keyboard-dirty-draft', '키보드로 바꾼 합성 초안 · 저장 호출 없음');
      await cancel.click();
      await expect(page.getByRole('radio', { name: '진동만', exact: true })).toBeChecked();
      await expect(page.getByRole('button', { name: '저장', exact: true })).toBeDisabled();
      await expect(page.getByText('변경을 취소했어요.', { exact: true })).toBeVisible();
      await gallery.capture('draft-cancelled', '초안 취소 후 기존 합성 설정 복원');
    }
    if (selected.action === 'deny') {
      await page.getByRole('button', { name: '거부', exact: true }).focus();
      await page.keyboard.press('Enter');
      await expect(page.getByText('선택한 내용을 컴퓨터로 보내고 있어요.', { exact: true })).toBeVisible();
      await expect(page.getByRole('button', { name: '승인', exact: true })).toBeDisabled();
      await expect(page.getByRole('button', { name: '거부', exact: true })).toBeDisabled();
      await expect(page.getByText('휴대폰에서 본인 확인을 진행해 주세요.', { exact: true })).toHaveCount(0);
      await gallery.capture('simulated-sending', '합성 전송 상태만 표시 · 거부 완료/Windows 동작 증거 아님');
    }
    if (selected.id === 'phone-pending-landscape-844') {
      await page.getByRole('button', { name: '승인', exact: true }).scrollIntoViewIfNeeded();
      await gallery.capture('landscape-actions', '가로 클라이언트 화면에서 요청 동작 접근 · 실제 기기 아님');
    }
  });
}
