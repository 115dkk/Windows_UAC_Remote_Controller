// SPDX-License-Identifier: GPL-2.0-or-later
import { expect } from '@playwright/test';
import type { test as GalleryTest } from './session';
import { phoneServiceGalleryCases } from './phone-service-cases';
import { policyUnavailableTitleText } from '../../ui/src/messages.ko';
import { qaCase } from '../../ui/src/qa-fixtures';

/** ROOT registers these once, and lists the same cases in the report inventory. */
export function registerPhoneServiceGallery(test: typeof GalleryTest): void {
  for (const selected of phoneServiceGalleryCases) {
    test(selected.id, async ({ page, gallery }) => {
      await gallery.open(selected);
      const panel = page.getByRole('region', { name: '휴대폰 승인', exact: true });
      await expect(panel).toBeVisible();
      await expect(page.getByRole('heading', { level: 1, name: '알림 시간', exact: true })).toBeVisible();
      for (const name of ['PC 연결 기능 설치', 'PC 연결 기능 제거', '휴대폰 승인 다시 켜기']) {
        await expect(page.getByRole('button', { name, exact: true })).toHaveCount(0);
      }
      const ready = selected.fixture === 'phone-service-ready';
      if (ready) {
        await expect(panel.getByText('휴대폰 승인 켜짐', { exact: true })).toBeVisible();
        await expect(panel.getByText('앱 설정을 사용할 수 있어요. 받은 요청은 요청 화면에서 확인해 주세요.', { exact: true })).toBeVisible();
        await expect(page.getByRole('radio', { name: '항상', exact: true })).toBeChecked();
        await expect(panel.getByText('켜짐', { exact: true })).toBeVisible();
      } else {
        await expect(page.getByRole('heading', { name: policyUnavailableTitleText(qaCase(selected.fixture).snapshot.phoneService), exact: true })).toBeVisible();
        await expect(page.getByRole('radio')).toHaveCount(0);
        await expect(page.getByRole('button', { name: '저장', exact: true })).toHaveCount(0);
      }
      if (selected.fixture === 'phone-service-stopped') {
        await expect(panel.getByText('휴대폰 승인 꺼짐', { exact: true })).toBeVisible();
        await expect(panel.getByText('꺼짐', { exact: true })).toBeVisible();
        await expect(panel.getByRole('button', { name: '휴대폰 승인 켜기', exact: true })).toBeEnabled();
        await expect(panel.getByRole('button', { name: '휴대폰 승인 끄기', exact: true })).toHaveCount(0);
      }
      if (selected.fixture === 'phone-service-preparing') await expect(panel.getByText('휴대폰 승인을 켜고 있어요', { exact: true })).toBeVisible();
      if (selected.fixture === 'phone-service-waiting-unlock') {
        await expect(panel.getByText('휴대폰 잠금 해제를 기다리고 있어요', { exact: true })).toBeVisible();
        await expect(page.getByRole('button', { name: '화면 잠금 설정', exact: true })).toHaveCount(0);
      }
      if (selected.fixture === 'phone-service-cleanup') {
        await expect(panel.getByText('이전 작업을 정리하고 있어요', { exact: true })).toBeVisible();
        await expect(panel.getByRole('button')).toHaveCount(0);
      }
      if (selected.fixture === 'phone-service-unavailable') {
        await expect(panel.getByText('확인할 수 없음', { exact: true })).toBeVisible();
        await expect(panel.getByRole('button')).toHaveCount(0);
      }
      if (selected.fixture === 'phone-service-error') {
        await expect(page.getByRole('alert')).toContainText('휴대폰 승인을 켜지 못했어요.');
        await expect(page.getByText('synthetic_service_start_rejected', { exact: true })).toHaveCount(0);
        await expect(panel.getByRole('button', { name: '휴대폰 승인 켜기', exact: true })).toBeEnabled();
      }
      for (const action of await panel.getByRole('button').all()) {
        const box = await action.boundingBox();
        expect(box).not.toBeNull();
        expect(box?.width ?? 0).toBeGreaterThanOrEqual(48);
        expect(box?.height ?? 0).toBeGreaterThanOrEqual(48);
      }
      await expect(panel).not.toContainText('서비스');
      await gallery.capture('overview', '휴대폰 승인 실행 상태 · 합성 클라이언트 화면, 실제 실행 증거 아님');

      if (selected.fixture === 'phone-service-stopped') {
        const start = panel.getByRole('button', { name: '휴대폰 승인 켜기', exact: true });
        await start.scrollIntoViewIfNeeded();
        await start.focus();
        await expect(start).toBeFocused();
        await page.keyboard.press('Enter');
        await expect(panel.getByText('휴대폰 승인을 켜고 있어요', { exact: true })).toBeVisible();
        await expect(panel.getByText('켜짐', { exact: true })).toBeVisible();
        await expect(panel.getByRole('button', { name: '휴대폰 승인 켜기', exact: true })).toHaveCount(0);
        await expect(page.getByRole('radio')).toHaveCount(0);
        await expect(panel.getByText('휴대폰 승인 켜짐', { exact: true })).toHaveCount(0);
        await gallery.capture('start-request-simulated', '합성 시작 응답은 준비 중일 뿐 실행 완료가 아님');
      }
      if (ready) {
        const stop = panel.getByRole('button', { name: '휴대폰 승인 끄기', exact: true });
        await stop.scrollIntoViewIfNeeded();
        await stop.focus();
        await page.keyboard.press('Enter');
        let dialog = page.getByRole('dialog', { name: '이 휴대폰에서 휴대폰 승인을 끌까요?', exact: true });
        await expect(dialog).toBeVisible();
        await expect(dialog).toContainText('휴대폰을 다시 켜거나 앱을 열어도 자동으로 시작하지 않아요.');
        await expect(dialog).not.toContainText('이 PC');
        await expect(dialog.getByRole('button', { name: '취소', exact: true })).toBeFocused();
        await gallery.capture('phone-stop-confirmation', '휴대폰 중지·부팅 자동 시작 해제 설명, 실제 중지 아님');
        await page.keyboard.press('Escape');
        await expect(dialog).toHaveCount(0);
        await expect(stop).toBeFocused();
        await page.keyboard.press('Enter');
        dialog = page.getByRole('dialog', { name: '이 휴대폰에서 휴대폰 승인을 끌까요?', exact: true });
        await dialog.getByRole('button', { name: '휴대폰 승인 끄기', exact: true }).click();
        await expect(panel.getByText('이전 작업을 정리하고 있어요', { exact: true })).toBeVisible();
        await expect(panel.getByText('꺼짐', { exact: true })).toBeVisible();
        await expect(panel.getByRole('button')).toHaveCount(0);
        await expect(page.getByRole('radio')).toHaveCount(0);
        await gallery.capture('stop-request-simulated', '합성 중지 응답은 정리 중 상태, 네이티브 종료 증거 아님');
      }
    });
  }
}
