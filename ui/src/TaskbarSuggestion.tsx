// SPDX-License-Identifier: GPL-2.0-or-later
import { invoke, isTauri } from '@tauri-apps/api/core';
import { useEffect, useId, useRef, useState } from 'react';
import { tr } from './i18n';

export type TaskbarStatus = 'hidden' | 'available' | 'pinned' | 'unavailable' | 'declined';
export interface TaskbarOffer { version: string | null; status: TaskbarStatus }
export interface TaskbarBridge {
  offer: () => Promise<TaskbarOffer>;
  request: () => Promise<TaskbarStatus>;
}

const bridge: TaskbarBridge = {
  offer: () => isTauri() ? invoke<TaskbarOffer>('taskbar_offer') : Promise.resolve({ version: null, status: 'hidden' }),
  request: () => invoke<TaskbarStatus>('request_taskbar_pin'),
};
const acknowledgmentKey = 'uac-remote-controller.taskbar-offer.acknowledged-version';
function acknowledged(version: string): boolean {
  try { return localStorage.getItem(acknowledgmentKey) === version; } catch { return false; }
}
function acknowledge(version: string) {
  // This is current-WebView-user presentation preference, never pin authority.
  try { localStorage.setItem(acknowledgmentKey, version); } catch { /* Session dismissal still works. */ }
}

export function TaskbarSuggestion({ client = bridge }: { client?: TaskbarBridge | undefined }) {
  const [offer, setOffer] = useState<TaskbarOffer | null>(null);
  const [dismissed, setDismissed] = useState(false);
  const [busy, setBusy] = useState(false);
  const inFlight = useRef(false);
  const heading = useId();
  const description = useId();
  useEffect(() => {
    let mounted = true;
    let reading = false;
    const refresh = () => {
      if (reading) return;
      reading = true;
      void client.offer().then((value) => {
        if (mounted && value.version && !acknowledged(value.version)) setOffer(value);
      }).catch(() => { /* Retry the optional hint on the next foreground event. */ })
        .finally(() => { reading = false; });
    };
    refresh();
    window.addEventListener('focus', refresh);
    return () => { mounted = false; window.removeEventListener('focus', refresh); };
  }, [client]);
  if (!offer?.version || dismissed || offer.status === 'hidden' || offer.status === 'pinned') return null;
  const unavailable = offer.status === 'unavailable' || offer.status === 'declined';
  function dismiss() {
    if (offer?.version) acknowledge(offer.version);
    setDismissed(true);
  }
  async function request() {
    if (inFlight.current || !offer?.version || offer.status !== 'available') return;
    inFlight.current = true;
    setBusy(true);
    // Remember the user's response even when Windows denies/cancels its prompt;
    // do not repeat the suggestion on the next app launch for this install.
    acknowledge(offer.version);
    try {
      const status = await client.request();
      setOffer({ ...offer, status });
    } catch { setOffer({ ...offer, status: 'unavailable' }); }
    finally { inFlight.current = false; setBusy(false); }
  }
  return <section className="surface pairing-entry auxiliary-card" aria-labelledby={heading} aria-busy={busy}>
    <h2 id={heading}>{tr('작업 표시줄에서 바로 열기')}</h2>
    <p id={description} className="supporting-text" role={unavailable ? 'status' : undefined}>{unavailable
      ? <>{tr(offer.status === 'declined' ? '작업 표시줄에 추가되지 않았어요.' : '지금은 앱에서 작업 표시줄 고정을 마무리할 수 없어요.')} {tr('실행 중인 UAC 원격 승인 아이콘을 마우스 오른쪽 버튼으로 누르고 ‘작업 표시줄에 고정’을 선택할 수 있어요.')}</>
      : tr('설치할 때 선택한 작업 표시줄 고정을 마무리할 수 있어요. 시작 메뉴에 앱이 등록되어 있고 Windows 알림이 켜져 있어야 해요. 아래 버튼을 누르면 Windows가 다시 확인해요.')}</p>
    {!unavailable && <button type="button" className="button primary" disabled={busy}
      aria-describedby={description} onClick={() => { void request(); }}>{tr(busy ? 'Windows에서 확인 중…' : '작업 표시줄에 고정')}</button>}
    <button type="button" className="button quiet" disabled={busy} onClick={dismiss}>{tr(unavailable ? '닫기' : '나중에')}</button>
  </section>;
}
