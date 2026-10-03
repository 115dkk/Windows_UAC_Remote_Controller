// SPDX-License-Identifier: GPL-2.0-or-later
// The service cannot see UAC prompts, so no request reaches a phone. Without
// this notice the PC looked healthy while every prompt went unanswered.
import type { AppSnapshot } from './contracts';

export const watcherNoticeText = {
  damaged: 'UAC 창을 감시하는 보조 프로그램 파일이 손상되어 휴대폰으로 승인 요청을 보내지 못합니다. 이 PC에 같은 버전을 다시 설치하십시오.',
  failed: 'UAC 창을 감시하는 보조 프로그램이 시작되지 않아 휴대폰으로 승인 요청을 보내지 못합니다. 자동으로 다시 시도합니다. 계속되면 이 PC에 같은 버전을 다시 설치하십시오.',
} as const;

/** Text for a watcher the service reports as down, or null when there is nothing to say. */
export function watcherNoticeMessage(snapshot: AppSnapshot, stale: boolean): string | null {
  const watcher = snapshot.watcherStatus;
  // A stopped service is explained by the service panel; an old reading proves nothing.
  if (stale || !watcher || watcher.state !== 'unavailable' || snapshot.service?.state === 'stopped') return null;
  if (watcher.refusal === 'helper_damaged') return watcherNoticeText.damaged;
  if (watcher.refusal === 'helper_failed') return watcherNoticeText.failed;
  // No signed-in user: nothing to watch yet, and this app cannot be open then anyway.
  return null;
}
