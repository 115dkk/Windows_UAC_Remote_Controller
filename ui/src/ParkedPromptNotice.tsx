// SPDX-License-Identifier: GPL-2.0-or-later
import { useId } from 'react';
import { Icon } from './icons';
import { formatText, numberText, tr } from './i18n';

/**
 * A UAC prompt the PC parked on its taskbar because the program that asked was
 * not in front. It never reaches the secure desktop until someone clicks it at
 * the PC, so this phone cannot approve it. Guidance only, never a request.
 */
export function ParkedPromptNotice({ count }: { count: number }) {
  const titleId = useId();
  if (!Number.isInteger(count) || count < 1) return null;
  return <section className="notice-box warning parked-prompt" aria-labelledby={titleId}>
    <Icon name="pc" />
    <div>
      <h2 id={titleId}>{count === 1
        ? tr('PC의 UAC 창이 작업 표시줄에서 기다리고 있습니다')
        : formatText('PC의 UAC 창 {count}개가 작업 표시줄에서 기다리고 있습니다', { count: numberText(count) })}</h2>
      <p>{tr('이 창은 아직 휴대폰으로 승인할 수 없습니다. PC 앞에서 작업 표시줄의 깜박이는 방패 버튼을 누르면 이 휴대폰에 승인 요청이 옵니다.')}</p>
    </div>
  </section>;
}
