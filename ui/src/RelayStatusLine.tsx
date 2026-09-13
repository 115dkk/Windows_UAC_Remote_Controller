// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';
import { tr } from './i18n';

/** Settings and legacy readiness do not establish a live listener. */
export function RelayStatusLine({ snapshot }: { snapshot: AppSnapshot }) {
  const relay = snapshot.relayStatus;
  // Native unknown takes priority over a cached SCM stopped observation.
  const stopped = relay?.state !== 'unknown'
    && (snapshot.service?.state === 'stopped' || relay?.state === 'stopped');
  const listening = !stopped && snapshot.service?.state === 'running'
    && relay?.mode === 'embedded' && relay.state === 'listening';
  const message = stopped ? '내장 중계 중지됨 · 수신 대기하지 않아요.'
    : listening ? '내장 중계 수신 대기 중 · 휴대폰 연결 여부는 별도로 확인해 주세요.'
    : relay?.mode === 'external' && relay.state === 'external_configured' ? '외부 중계 설정됨 · 연결 가능 여부는 아직 확인되지 않았어요.'
    : relay?.mode === 'embedded' && relay.state === 'waiting_network' ? '내장 중계가 네트워크를 기다리고 있어요.'
    : relay?.mode === 'embedded' && relay.state === 'unavailable' ? '내장 중계를 준비하지 못했어요. PC의 네트워크와 중계 설정을 확인해 주세요.'
    : '중계 실행 상태를 확인하지 못했어요. 다시 확인해 주세요.';
  return <p className={`state-line relay-state ${listening ? 'is-success' : ''}`} role="status">
    <span className="state-dot" aria-hidden="true" />{tr(message)}
  </p>;
}
