// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';
import { tr } from './i18n';
import { directConnectionState, hasLiveEmbeddedListener } from './directConnection';
import type { InternetState } from './directConnection';

const stateCopy: Record<InternetState, string> = {
  discovering: '외부 연결 경로 확인 중',
  lan_only: '외부에서 접속할 주소가 없음',
  candidate: '외부 연결 주소 확보 · 모바일망에서 연결 확인 필요',
  unavailable: '외부 연결 경로를 준비하지 못했습니다. PC와 공유기의 네트워크 설정을 확인하십시오.',
  stopped: '외부 연결 준비 중지됨 · PC 상태에서 휴대폰 승인을 켜십시오.',
  unknown: '외부 연결 상태 확인 불가 · PC 상태를 다시 확인하십시오.',
};

const firewallCopy = 'V3 또는 방화벽이 연결 허용을 요청하면 UAC 원격 승인기 서비스(uac-service.exe)인지 확인한 뒤 해당 프로그램의 연결을 허용하십시오.';

/** Program-specific V3/firewall guidance, only beside a freshly observed embedded listener. */
export function FirewallGuidance({ snapshot, stale = false, className = 'supporting-text' }: { snapshot: AppSnapshot; stale?: boolean; className?: string }) {
  if (stale || !hasLiveEmbeddedListener(snapshot)) return null;
  return <p className={className}>{tr(firewallCopy)}</p>;
}

export function DirectConnectionStatus({ snapshot, stale = false, guidance = true }: { snapshot: AppSnapshot; stale?: boolean; guidance?: boolean }) {
  if (snapshot.platform !== 'windows' || snapshot.relayStatus?.mode === 'external') return null;
  return <section className="direct-connection" aria-label={tr('외부 네트워크 연결')}>
    <p className="supporting-text" role="status">{tr(stateCopy[directConnectionState(snapshot, stale)])}</p>
    {guidance && <FirewallGuidance snapshot={snapshot} stale={stale} />}
  </section>;
}
