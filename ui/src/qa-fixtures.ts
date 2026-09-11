// SPDX-License-Identifier: GPL-2.0-or-later
// SYNTHETIC CLIENT STATE ONLY. Imported exclusively by qa-preview and client tests.
// This adapter performs no OS operation, networking, authentication or persistence.
import type { AppSnapshot, ControllerBridge, RequestView, ServiceState } from './contracts';
import type { ClientPage } from './App';

export interface QaCase { readonly snapshot: AppSnapshot; readonly page: ClientPage; readonly scannerFailure?: 'unavailable' }

export function exampleSnapshot(platform: 'windows' | 'android' = 'windows'): AppSnapshot {
  return {
    schemaVersion: 4, platform, computerName: '화면 예시 PC',
    service: platform === 'windows' ? { installed: false, state: null, allowedActions: [], controlHint: 'needs_installer', remoteRequestsReady: false } : null,
    phoneService: platform === 'android' ? { state: 'local_settings_ready', bootEnabled: true, canStart: false, canStop: true, policyOwnerReady: true } : null,
    mobile: platform === 'android' ? { screenLock: 'configured', notifications: 'allowed', canOpenLockSettings: false, canOpenNotificationSettings: false, canOpenPairingScanner: false } : null,
    policy: { schedule: { mode: 'always' }, alert: 'sound' },
    devices: [], relayConfigured: false, requests: [], activity: [],
    requestCatalog: platform === 'android' ? { status: 'ready', revision: '1', peerCount: 1, connectedPeerCount: 1 } : null,
    requestReview: null,
    dataAvailability: { devices: 'available', requests: 'available', activity: 'available' },
    pairing: null,
    canPair: false, canUnpair: false, canClearActivity: false, issue: null,
  };
}

const pendingRequest = {
  id: 'synthetic-request-1', computerName: '화면 예시 PC', programName: '설정 도우미.exe',
  executablePath: 'C:\\Program Files\\화면 예시\\설정 도우미.exe',
  details: '"C:\\Program Files\\화면 예시\\설정 도우미.exe" /example\n화면 확인을 위한 예시 문자열입니다.',
  programElided: false, pathElided: false, hasDetails: true,
  remainingSeconds: 42, refreshAfterMillis: 30000, state: 'pending', canApprove: true, canDeny: true,
} as const;

// Extra body exists only inside this synthetic adapter; the production view DTO
// never contains it. requestDetails below models the separate native read.
function withSyntheticDetails(value: RequestView & { readonly details: string }): RequestView { return value; }

export function qaCase(name: string): QaCase {
  const windows = exampleSnapshot();
  const phone = exampleSnapshot('android');
  switch (name) {
    case 'desktop-running': return { page: 'status', snapshot: { ...windows, service: { installed: true, state: 'running', allowedActions: ['restart', 'stop', 'uninstall'], controlHint: 'available', remoteRequestsReady: false } } };
    case 'desktop-pairing-ready': return { page: 'devices', snapshot: { ...windows, canPair: true, relayConfigured: true,
      service: { installed: true, state: 'running', allowedActions: ['stop'], controlHint: 'available', remoteRequestsReady: false } } };
    case 'desktop-setup-missing': return { page: 'devices', snapshot: { ...windows,
      dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'desktop-unavailable': return { page: 'status', snapshot: { ...windows, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'desktop-devices': return { page: 'devices', snapshot: { ...windows, devices: [{ id: 'synthetic-device', name: '화면 예시 휴대폰', revision: 1, connected: false, routePresent: false, lastSeenLabel: '마지막 연결: 화면 예시' }], canUnpair: true } };
    case 'desktop-history': return { page: 'activity', snapshot: { ...windows, activity: [{ id: 'synthetic-event-1', timestampMillis: Date.UTC(2026, 8, 8, 12, 30), kind: 'service_started' }, { id: 'synthetic-event-2', timestampMillis: Date.UTC(2026, 8, 8, 12, 20), kind: 'cancelled' }], canClearActivity: true } };
    case 'phone-pending': return { page: 'requests', snapshot: { ...phone, requests: [pendingRequest] } };
    case 'phone-terminal': return { page: 'requests', snapshot: { ...phone, requests: [withSyntheticDetails({ ...pendingRequest, programName: 'PowerShell', executablePath: 'C:\\Program Files\\PowerShell\\7\\pwsh.exe', details: `pwsh.exe -NoProfile -Command "Write-Output '화면 예시'"` })] } };
    case 'phone-long-request': return { page: 'requests', snapshot: { ...phone, requests: [withSyntheticDetails({ ...pendingRequest, programName: '화면 예시 · 길이가 긴 프로그램 이름 설치 관리자.exe', executablePath: `C:\\${'한글 경로와 English mixed-direction אבג '.repeat(8)}\\${'unbroken'.repeat(22)}.exe`, details: `${'<img src=x onerror="exampleOnly()">\n'.repeat(4)}${'아주 긴 프로그램 요청의 예시 내용입니다. '.repeat(35)}` })] } };
    case 'phone-empty': return { page: 'requests', snapshot: phone };
    case 'phone-setup-unavailable': return { page: 'requests', snapshot: { ...phone, policy: null, requestCatalog: null,
      phoneService: { state: 'unavailable', bootEnabled: true, canStart: false, canStop: true, policyOwnerReady: false },
      dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' },
    } };
    case 'phone-unpaired': return { page: 'requests', snapshot: { ...phone, requestCatalog: { status: 'ready', revision: '1', peerCount: 0, connectedPeerCount: 0 } } };
    case 'phone-scanner-launch': return { page: 'requests', snapshot: { ...phone,
      mobile: { ...phone.mobile!, canOpenPairingScanner: true },
      requestCatalog: { status: 'ready', revision: '1', peerCount: 0, connectedPeerCount: 0 },
      dataAvailability: { devices: 'unavailable', requests: 'available', activity: 'available' },
    } };
    case 'phone-scanner-unavailable-catalog': return { page: 'requests', snapshot: { ...phone,
      mobile: { ...phone.mobile!, canOpenPairingScanner: true }, requestCatalog: null,
      dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'available' },
    } };
    case 'phone-scanner-launch-error': return { page: 'requests', scannerFailure: 'unavailable', snapshot: { ...phone,
      mobile: { ...phone.mobile!, canOpenPairingScanner: true },
      requestCatalog: { status: 'ready', revision: '1', peerCount: 0, connectedPeerCount: 0 },
      dataAvailability: { devices: 'unavailable', requests: 'available', activity: 'available' },
    } };
    case 'phone-disconnected': return { page: 'requests', snapshot: { ...phone, requestCatalog: { status: 'ready', revision: '1', peerCount: 1, connectedPeerCount: 0 } } };
    case 'phone-reconciling': return { page: 'requests', snapshot: { ...phone, requestCatalog: { status: 'reconciling', revision: '1', peerCount: 1, connectedPeerCount: 1 }, dataAvailability: { ...phone.dataAvailability, requests: 'unavailable' } } };
    case 'phone-authenticating': return { page: 'requests', snapshot: { ...phone, requests: [{ ...pendingRequest, state: 'authenticating', canApprove: false }] } };
    case 'phone-waiting': return { page: 'requests', snapshot: { ...phone, requests: [{ ...pendingRequest, state: 'waiting', canApprove: false, canDeny: false }] } };
    case 'phone-awaiting-outcome': return { page: 'requests', snapshot: { ...phone, requests: [{ ...pendingRequest, state: 'awaiting_outcome', canApprove: false, canDeny: false }] } };
    case 'phone-history': return { page: 'activity', snapshot: { ...phone,
      dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'available' },
      canClearActivity: true,
      activity: [
        { id: 'synthetic-history-1', timestampMillis: Date.UTC(2026, 8, 8, 12, 30), kind: 'pc_completed' },
        { id: 'synthetic-history-2', timestampMillis: Date.UTC(2026, 8, 8, 12, 20), kind: 'expired' },
      ],
    } };
    case 'phone-history-empty': return { page: 'activity', snapshot: { ...phone,
      dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'available' },
    } };
    case 'phone-unavailable': return { page: 'requests', snapshot: { ...phone, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'phone-settings': return { page: 'schedule', snapshot: { ...phone, policy: { schedule: { mode: 'weekly', windows: [{ days: 31, start_minute: 9 * 60, end_minute: 18 * 60 }] }, alert: 'vibrate_only' } } };
    case 'phone-service-ready': return { page: 'schedule', snapshot: phone };
    case 'phone-service-stopped': return { page: 'schedule', snapshot: { ...phone, policy: null, phoneService: { state: 'stopped', bootEnabled: false, canStart: true, canStop: false, policyOwnerReady: false }, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'phone-service-preparing': return { page: 'schedule', snapshot: { ...phone, policy: null, phoneService: { state: 'preparing', bootEnabled: true, canStart: false, canStop: true, policyOwnerReady: false }, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'phone-service-waiting-unlock': return { page: 'schedule', snapshot: { ...phone, policy: null, phoneService: { state: 'waiting_for_unlock', bootEnabled: true, canStart: false, canStop: true, policyOwnerReady: false }, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'phone-service-cleanup': return { page: 'schedule', snapshot: { ...phone, policy: null, phoneService: { state: 'cleanup_pending', bootEnabled: false, canStart: false, canStop: false, policyOwnerReady: false }, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'phone-service-unavailable': return { page: 'schedule', snapshot: { ...phone, policy: null, phoneService: { state: 'unavailable', bootEnabled: null, canStart: false, canStop: false, policyOwnerReady: false }, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'phone-service-error': return { page: 'schedule', snapshot: { ...phone, policy: null, phoneService: { state: 'unavailable', bootEnabled: false, canStart: true, canStop: false, policyOwnerReady: false }, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' }, issue: { code: 'synthetic_service_start_rejected', message: '휴대폰 승인을 켜지 못했어요.', nextAction: '휴대폰 승인 상태를 다시 확인해 주세요.' } } };
    case 'phone-lock-missing': return { page: 'requests', snapshot: { ...phone, mobile: { screenLock: 'missing', notifications: 'allowed', canOpenLockSettings: true, canOpenNotificationSettings: false, canOpenPairingScanner: false } } };
    case 'phone-lock-unknown': return { page: 'requests', snapshot: { ...phone, mobile: { screenLock: 'unavailable', notifications: 'unavailable', canOpenLockSettings: false, canOpenNotificationSettings: false, canOpenPairingScanner: false } } };
    case 'phone-notifications-denied': return { page: 'schedule', snapshot: { ...phone, mobile: { screenLock: 'configured', notifications: 'denied', canOpenLockSettings: false, canOpenNotificationSettings: true, canOpenPairingScanner: false } } };
    case 'errors': return { page: 'requests', snapshot: { ...phone, dataAvailability: { ...phone.dataAvailability, requests: 'unavailable' }, issue: { code: 'synthetic_unavailable', message: '요청 상태를 확인하지 못했어요.', nextAction: '연결을 확인한 뒤 다시 시도해 주세요.' } } };
    default: return { page: 'status', snapshot: windows };
  }
}

export function createQaBridge(initial: AppSnapshot, scannerFailure?: QaCase['scannerFailure']): ControllerBridge {
  let value = initial;
  function reply(next: AppSnapshot): Promise<AppSnapshot> { value = next; return Promise.resolve(value); }
  return {
    snapshot: () => Promise.resolve(value),
    savePolicy: (policy) => reply({ ...value, policy, issue: null }),
    controlService: (action) => {
      if (value.platform === 'android') {
        // Simulated acceptance/pending state ONLY; never synthesize native ready,
        // a successful persisted policy read or history on a start request.
        if (action === 'start' && value.phoneService?.canStart) return reply({ ...value, policy: null, issue: null, canClearActivity: false,
          dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' },
          phoneService: { state: 'preparing', bootEnabled: true, canStart: false, canStop: true, policyOwnerReady: false } });
        if (action === 'stop' && value.phoneService?.canStop) return reply({ ...value, policy: null, issue: null, canClearActivity: false,
          dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' },
          phoneService: { state: 'cleanup_pending', bootEnabled: false, canStart: false, canStop: false, policyOwnerReady: false } });
        return reply({ ...value, issue: { code: 'synthetic_service_unavailable', message: '이 화면 예시에서는 휴대폰 승인의 실행 상태를 바꿀 수 없어요.', nextAction: null } });
      }
      const state: ServiceState = action === 'stop' || action === 'uninstall' ? 'stopped' : 'running';
      return reply({ ...value, service: { installed: action !== 'uninstall', state, allowedActions: state === 'running' ? ['restart', 'stop', 'uninstall'] : ['start', 'uninstall'], controlHint: 'available', remoteRequestsReady: false } });
    },
    beginPairing: () => reply({ ...value, issue: { code: 'synthetic_only', message: '이 화면 예시에서는 실제 기기를 연결하지 않아요.', nextAction: null } }),
    removeDevice: (id) => reply({ ...value, devices: value.devices.filter((device) => device.id !== id) }),
    setRelay: () => reply({ ...value, relayConfigured: true, issue: null }),
    decide: (id) => reply({ ...value, requests: value.requests.map((request) => request.id === id ? { ...request, state: 'sending', canApprove: false, canDeny: false } : request) }),
    requestDetails: (id) => {
      // Synthetic-only extra fixture text. Production snapshots contain no body.
      const request = value.requests.find((item) => item.id === id);
      if (!request) return Promise.reject(new Error('synthetic request unavailable'));
      return Promise.resolve({ version: 1, id, programName: request.programName, executablePath: request.executablePath,
        details: 'details' in request && typeof request.details === 'string' ? request.details : '',
        remainingSeconds: request.remainingSeconds, refreshAfterMillis: request.refreshAfterMillis });
    },
    clearActivity: () => reply({ ...value, activity: [] }),
    openLockSettings: () => Promise.resolve(),
    openNotificationSettings: () => Promise.resolve(),
    // Client/synthetic acknowledgement only; no camera surface or pairing result.
    openPairingScanner: () => scannerFailure
      ? Promise.reject(Object.assign(new Error('Synthetic scanner launch unavailable'), { code: 'pairing_scanner_unavailable' })) : Promise.resolve(),
  };
}
