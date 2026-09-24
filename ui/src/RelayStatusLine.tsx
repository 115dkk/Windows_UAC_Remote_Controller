// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';
import { tr } from './i18n';
import { hasLiveEmbeddedListener } from './directConnection';

/** Settings and legacy readiness do not establish a live listener. */
export function RelayStatusLine({ snapshot, stale = false }: { snapshot: AppSnapshot; stale?: boolean }) {
  const relay = snapshot.relayStatus;
  // Native unknown takes priority over a cached SCM stopped observation.
  const stopped = relay?.state !== 'unknown'
    && (snapshot.service?.state === 'stopped' || relay?.state === 'stopped');
  const listening = !stale && !stopped && hasLiveEmbeddedListener(snapshot);
  const unknown = '휴대폰 연결 대기 상태 확인 불가 · [다시 확인]을 누르십시오.';
  const message = stale ? unknown
    : stopped ? '휴대폰 연결 받지 않음 · 휴대폰 승인을 켜면 다시 받습니다.'
    : listening ? '휴대폰 연결 대기 중'
    // The product never checks an external relay; say which one is in use, nothing more.
    : relay?.mode === 'external' && relay.state === 'external_configured' ? '외부 중계 서버 사용'
    : relay?.mode === 'embedded' && relay.state === 'waiting_network' ? '네트워크 연결 대기 중 · PC의 네트워크 연결을 확인하십시오.'
    // The service retries the listener on its own every few seconds.
    : relay?.mode === 'embedded' && relay.state === 'unavailable' ? '휴대폰 연결을 받지 못하고 있습니다. PC의 네트워크 연결을 확인하십시오. 연결되면 자동으로 다시 시도합니다.'
    : unknown;
  return <p className={`state-line relay-state ${listening ? 'is-success' : ''}`} role="status">
    <span className="state-dot" aria-hidden="true" />{tr(message)}
  </p>;
}
