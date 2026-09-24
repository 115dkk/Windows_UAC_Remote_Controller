// SPDX-License-Identifier: GPL-2.0-or-later
import { useId } from 'react';
import type { PcConnectionPresentation } from './pcConnection';
import { Icon } from './icons';
import { tr } from './i18n';

const unreachableChecks = [
  'PC가 켜져 있고 절전 상태가 아닌지 확인하십시오.',
  '같은 Wi-Fi에 있다면 PC에 V3나 방화벽의 연결 허용 알림이 떠 있는지 확인하십시오.',
] as const;

/** A small rotating ring; reduced motion shows the clock icon in its place. */
export function Spinner() {
  return <span className="progress-indicator" aria-hidden="true"><span className="spinner" /><Icon name="clock" className="spinner-still" /></span>;
}

export function PcConnectionStatus({ presentation }: { presentation: PcConnectionPresentation }) {
  const titleId = useId();
  if (presentation.kind !== 'failed') return <p className="state-line connection-progress">
    <Spinner />{tr(presentation.kind === 'reconnecting' ? 'PC에 다시 연결하는 중' : 'PC에 연결하는 중')}</p>;
  return <section className="notice-box warning connection-failure" aria-labelledby={titleId}>
    <Icon name="pc" />
    <div>
      <h2 id={titleId}>{tr('PC에 연결하지 못했습니다')}</h2>
      {presentation.failure === 'refused' && <p>{tr('PC는 응답했지만 휴대폰 승인이 연결을 받지 않습니다. PC 앱에서 휴대폰 승인이 켜져 있는지 확인하십시오.')}</p>}
      {presentation.failure === 'no_answer' && <p>{tr('PC의 휴대폰 승인이 응답하지 않습니다. PC 앱에서 상태를 확인하거나 PC를 다시 시작하십시오.')}</p>}
      {presentation.failure === 'unreachable' && <ul className="connection-checks">
        {unreachableChecks.map((check) => <li key={check}>{tr(check)}</li>)}
        <li>{tr(presentation.externalRoute
          ? '집 밖이라면 공유기의 포트포워딩과 PC의 [외부 연결] 설정을 확인하십시오.'
          : '집 밖에서 쓰려면 PC 앱의 [외부 연결]을 설정한 뒤 이 휴대폰을 집 Wi-Fi에 한 번 연결하십시오.')}</li>
      </ul>}
    </div>
  </section>;
}
