// SPDX-License-Identifier: GPL-2.0-or-later
// SYNTHETIC CLIENT STATE ONLY. Imported exclusively by qa-preview and client tests.
// This adapter performs no OS operation, networking, authentication or persistence.
import type { AppSnapshot, ControllerBridge, DecisionFeedbackView, ExternalAccessView, PairedDeviceView, PcConnectionView, RequestView, ServiceState } from './contracts';
import type { ClientPage } from './App';

export interface QaCase {
  readonly snapshot: AppSnapshot; readonly page: ClientPage; readonly scannerFailure?: 'unavailable'; readonly diagnosticsExportPending?: true;
  /** Synthetic second observation: every read after the first returns it. */
  readonly later?: AppSnapshot;
}

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

/** Synthetic body-free decision view. Never a native result or timing sample. */
function decisionView(id: string, action: DecisionFeedbackView['action'], phase: DecisionFeedbackView['phase']): DecisionFeedbackView {
  return { id, action, phase, elapsedMillis: 1200, authenticationMillis: null, afterAuthenticationMillis: null, timingAvailable: false };
}
/** A paired phone that is not connected now. Synthetic inventory only. */
const offlinePhones: readonly PairedDeviceView[] = [{ id: 'synthetic-offline-phone', name: '화면 예시 휴대폰', revision: 1, connected: false, routePresent: true, lastSeenLabel: null }];

// Extra body exists only inside this synthetic adapter; the production view DTO
// never contains it. requestDetails below models the separate native read.
function withSyntheticDetails(value: RequestView & { readonly details: string }): RequestView { return value; }

export function qaCase(name: string): QaCase {
  const windows = exampleSnapshot();
  const phone = exampleSnapshot('android');
  const relayRunning: AppSnapshot = { ...windows, relayConfigured: true,
    service: { installed: true, state: 'running', allowedActions: ['restart', 'stop'], controlHint: 'available', remoteRequestsReady: false },
    relayStatus: { mode: 'embedded', state: 'listening' } };
  const externalAccess: ExternalAccessView = { mode: 'automatic', externalPort: null, fixedAddress: null,
    externalAddress: null, source: null, lanAddress: '192.168.0.23', relayPort: 7443, failure: null };
  const relayWithPhone: AppSnapshot = { ...relayRunning, devices: offlinePhones };
  const relayStopped: AppSnapshot = { ...relayRunning, relayConfigured: false,
    service: { ...relayRunning.service!, state: 'stopped', allowedActions: ['start', 'uninstall'] },
    relayStatus: { mode: 'embedded', state: 'stopped' } };
  switch (name) {
    case 'desktop-relay-wan-candidate': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'candidate' } } };
    case 'desktop-relay-wan-lan': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'lan_only' } } };
    case 'desktop-relay-wan-unavailable': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'unavailable' } } };
    case 'desktop-relay-wan-stale': return { page: 'network', snapshot: { ...relayRunning,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'candidate' },
      dataAvailability: { ...relayRunning.dataAvailability, devices: 'unavailable' } } };
    // PC status beside a paired phone that is not connected: the firewall paragraph applies.
    case 'desktop-status-phone-offline': return { page: 'status', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'lan_only' } } };
    case 'desktop-relay-stopped': return { page: 'network', snapshot: relayStopped };
    case 'desktop-relay-listening': return { page: 'network', snapshot: relayRunning };
    case 'desktop-relay-waiting': return { page: 'network', snapshot: { ...relayRunning, relayConfigured: false, relayStatus: { mode: 'embedded', state: 'waiting_network' } } };
    case 'desktop-relay-unknown': return { page: 'network', snapshot: { ...relayRunning, relayConfigured: false,
      service: { ...relayRunning.service!, state: null, allowedActions: [] }, relayStatus: { mode: 'unknown', state: 'unknown' },
      dataAvailability: { ...windows.dataAvailability, devices: 'unavailable' } } };
    case 'desktop-relay-external': return { page: 'network', snapshot: { ...relayRunning, relayStatus: { mode: 'external', state: 'external_configured' } } };
    // Synthetic external-access observations. Documentation addresses only;
    // a candidate here is neither a reachable route nor a native result.
    case 'desktop-network-auto-no-mapping': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'lan_only' },
      externalAccess: { ...externalAccess, failure: 'no_mapping_protocol' } } };
    case 'desktop-network-auto-upnp': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'candidate' },
      externalAccess: { ...externalAccess, externalAddress: '203.0.113.7:7443', source: 'upnp' } } };
    case 'desktop-network-forward-stun': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'candidate' },
      externalAccess: { ...externalAccess, mode: 'router_forward', externalPort: 17443, externalAddress: '198.51.100.24:17443', source: 'stun' } } };
    case 'desktop-network-forward-unavailable': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'lan_only' },
      externalAccess: { ...externalAccess, mode: 'router_forward', externalPort: 7443, failure: 'public_address_unavailable' } } };
    case 'desktop-network-fixed': return { page: 'network', snapshot: { ...relayWithPhone,
      relayStatus: { mode: 'embedded', state: 'listening', internetState: 'candidate' },
      externalAccess: { ...externalAccess, mode: 'fixed', fixedAddress: '203.0.113.7:7443', externalAddress: '203.0.113.7:7443', source: 'fixed' } } };
    case 'desktop-start-failed': return { page: 'status', snapshot: { ...relayStopped,
      service: { ...relayStopped.service!, actionIssue: { code: 'synthetic_start_failed', message: '작업 결과를 확인하지 못했어요. 다시 확인한 뒤 시도해 주세요.', nextAction: null } } } };
    case 'desktop-running': return { page: 'status', snapshot: { ...windows, service: { installed: true, state: 'running', allowedActions: ['restart', 'stop', 'uninstall'], controlHint: 'available', remoteRequestsReady: false } } };
    case 'desktop-connected': return { page: 'status', snapshot: { ...relayRunning,
      devices: [{ id: 'synthetic-connected-phone', name: '화면 예시 휴대폰', revision: 1, connected: true, routePresent: true, lastSeenLabel: null }] } };
    case 'desktop-pairing-ready': return { page: 'devices', snapshot: { ...windows, canPair: true, relayConfigured: true,
      service: { installed: true, state: 'running', allowedActions: ['stop'], controlHint: 'available', remoteRequestsReady: false } } };
    case 'desktop-pairing-relay-first': return { page: 'devices', snapshot: { ...windows, canPair: true, relayConfigured: false,
      service: { installed: true, state: 'running', allowedActions: ['stop'], controlHint: 'available', remoteRequestsReady: false } } };
    case 'desktop-setup-missing': return { page: 'devices', snapshot: { ...windows,
      dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'desktop-unavailable': return { page: 'status', snapshot: { ...windows, dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'unavailable' } } };
    case 'desktop-devices': return { page: 'devices', snapshot: { ...windows, devices: [{ id: 'synthetic-device', name: '화면 예시 휴대폰', revision: 1, connected: false, routePresent: false, lastSeenLabel: '마지막 연결: 화면 예시' }], canUnpair: true } };
    case 'desktop-history': return { page: 'activity', snapshot: { ...windows, activity: [{ id: 'synthetic-event-1', timestampMillis: Date.UTC(2026, 8, 8, 12, 30), kind: 'service_started' }, { id: 'synthetic-event-2', timestampMillis: Date.UTC(2026, 8, 8, 12, 20), kind: 'cancelled' }], canClearActivity: true } };
    case 'phone-pending': return { page: 'requests', snapshot: { ...phone, requests: [pendingRequest] } };
    case 'phone-bidi': return { page: 'requests', snapshot: { ...phone, requests: [withSyntheticDetails({ ...pendingRequest,
      programName: 'report\u202Egpj.exe', executablePath: 'C:\\ملفات\\report\u202Egpj.exe',
      details: '"C:\\ملفات\\report\u202Egpj.exe" --note=\u2066日本語\u2069 --shape=برنامج\u200d\u200c عربي',
    })] } };
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
    case 'phone-devices-pairing': return { page: 'devices', snapshot: { ...phone,
      mobile: { ...phone.mobile!, canOpenPairingScanner: true },
      devices: [{ id: 'synthetic-pc', name: '화면 예시 PC', revision: 1, connected: false, routePresent: true, lastSeenLabel: null }],
      requestCatalog: { status: 'ready', revision: '1', peerCount: 1, connectedPeerCount: 0 },
    } };
    case 'phone-disconnected': return { page: 'requests', snapshot: { ...phone, requestCatalog: { status: 'ready', revision: '1', peerCount: 1, connectedPeerCount: 0 } } };
    case 'phone-reconciling': return { page: 'requests', snapshot: { ...phone, requestCatalog: { status: 'reconciling', revision: '1', peerCount: 1, connectedPeerCount: 1 }, dataAvailability: { ...phone.dataAvailability, requests: 'unavailable' } } };
    case 'phone-authenticating': return { page: 'requests', snapshot: { ...phone, requests: [{ ...pendingRequest, state: 'authenticating', canApprove: false }] } };
    case 'phone-waiting': return { page: 'requests', snapshot: { ...phone, requests: [{ ...pendingRequest, state: 'waiting', canApprove: false, canDeny: false }] } };
    case 'phone-awaiting-outcome': return { page: 'requests', snapshot: { ...phone, requests: [{ ...pendingRequest, state: 'awaiting_outcome', canApprove: false, canDeny: false }] } };
    case 'phone-history-diagnostics-pending': return { ...qaCase('phone-history'), diagnosticsExportPending: true };
    case 'phone-history': return { page: 'activity', snapshot: { ...phone,
      dataAvailability: { devices: 'unavailable', requests: 'unavailable', activity: 'available' },
      canClearActivity: true,
      activity: [
        { id: 'synthetic-history-1', timestampMillis: Date.UTC(2026, 8, 8, 12, 30), kind: 'pc_completed' },
        { id: 'synthetic-history-2', timestampMillis: Date.UTC(2026, 8, 8, 12, 20), kind: 'expired' },
      ],
    } };
    case 'phone-history-results': return { page: 'activity', snapshot: { ...phone,
      activity: (['approved', 'denied', 'failure', 'pc_completed'] as const).map((kind, index) => ({
        id: `synthetic-terminal-${index}`, timestampMillis: Date.UTC(2026, 8, 20, 2, 14 - index), kind,
      })), canClearActivity: true,
    } };
    case 'phone-devices-offline': return { page: 'devices', snapshot: { ...phone,
      devices: [{ id: 'ab'.repeat(32), name: '화면 예시 PC', revision: 1, connected: false, routePresent: true, lastSeenLabel: null }],
      requestCatalog: { status: 'ready', revision: '1', peerCount: 1, connectedPeerCount: 0 },
      canUnpair: true,
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
    default: return feedbackCase(name, phone) ?? { page: 'status', snapshot: windows };
  }
}

const decisionFixtures: Record<string, { readonly action: DecisionFeedbackView['action']; readonly phase: DecisionFeedbackView['phase'];
  /** Present: the request is still listed in this state. Absent: it has left the list. */
  readonly listed?: Pick<RequestView, 'state' | 'canApprove' | 'canDeny'> }> = {
  'phone-decision-authenticating': { action: 'approve', phase: 'authenticating', listed: { state: 'authenticating', canApprove: false, canDeny: true } },
  'phone-decision-preparing': { action: 'deny', phase: 'preparing', listed: { state: 'waiting', canApprove: false, canDeny: false } },
  'phone-decision-sending': { action: 'deny', phase: 'sending', listed: { state: 'sending', canApprove: false, canDeny: false } },
  'phone-decision-awaiting-pc': { action: 'approve', phase: 'awaiting_pc', listed: { state: 'awaiting_outcome', canApprove: false, canDeny: false } },
  'phone-decision-authentication-cancelled': { action: 'approve', phase: 'authentication_cancelled', listed: { state: 'pending', canApprove: true, canDeny: true } },
  'phone-decision-approved': { action: 'approve', phase: 'approved' },
  'phone-decision-denied': { action: 'deny', phase: 'denied' },
  'phone-decision-failed': { action: 'approve', phase: 'failed' },
  'phone-decision-cancelled': { action: 'approve', phase: 'cancelled' },
  'phone-decision-expired': { action: 'approve', phase: 'expired' },
  'phone-decision-pc-completed': { action: 'deny', phase: 'pc_completed' },
  'phone-decision-local-unconfirmed': { action: 'deny', phase: 'local_unconfirmed' },
};

const connectionFixtures: Record<string, PcConnectionView> = {
  'phone-connection-connecting': { dialing: true, lastFailure: null, externalRoute: false },
  'phone-connection-refused': { dialing: false, lastFailure: 'refused', externalRoute: true },
  'phone-connection-no-answer': { dialing: false, lastFailure: 'no_answer', externalRoute: true },
  'phone-connection-unreachable': { dialing: false, lastFailure: 'unreachable', externalRoute: false },
  'phone-connection-unreachable-route': { dialing: false, lastFailure: 'unreachable', externalRoute: true },
  'phone-connection-dialing': { dialing: true, lastFailure: 'unreachable', externalRoute: false },
};

/** Synthetic decision receipts and PC connection diagnoses for the phone shell. */
function feedbackCase(name: string, phone: AppSnapshot): QaCase | null {
  const decision = decisionFixtures[name];
  if (decision) {
    // A request that has left the list keeps no body; only its locator remains in the view.
    const id = decision.listed ? pendingRequest.id : 'synthetic-request-finished';
    return { page: 'requests', snapshot: { ...phone,
      requests: decision.listed ? [{ ...pendingRequest, ...decision.listed }] : [],
      requestCatalog: { ...phone.requestCatalog!, decisions: [decisionView(id, decision.action, decision.phase)] } } };
  }
  const disconnected = (connection?: PcConnectionView): AppSnapshot => ({ ...phone,
    requestCatalog: { status: 'ready', revision: '2', peerCount: 1, connectedPeerCount: 0, ...(connection ? { connection } : {}) } });
  if (name === 'phone-connection-reconnecting') {
    return { page: 'requests', snapshot: phone, later: disconnected({ dialing: true, lastFailure: null, externalRoute: true }) };
  }
  const connection = connectionFixtures[name];
  return connection ? { page: 'requests', snapshot: disconnected(connection) } : null;
}

export function createQaBridge(initial: AppSnapshot, scannerFailure?: QaCase['scannerFailure'], diagnosticsExportPending?: QaCase['diagnosticsExportPending'], later?: AppSnapshot): ControllerBridge {
  let value = initial;
  let next = later;
  function reply(next: AppSnapshot): Promise<AppSnapshot> { value = next; return Promise.resolve(value); }
  return {
    snapshot: () => {
      const current = value;
      if (next) { value = next; next = undefined; }
      return Promise.resolve(current);
    },
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
    // Records the requested mode only. No address, source or reachability is invented.
    setExternalAccess: (input) => reply({ ...value, issue: null, externalAccess: value.externalAccess ? {
      ...value.externalAccess, mode: input.mode, externalAddress: null, source: null, failure: null,
      externalPort: input.mode === 'router_forward' ? input.externalPort : null,
      fixedAddress: input.mode === 'fixed' ? input.fixedAddress : null,
    } : null }),
    // Simulates only the native owner's first reported stage, never a PC result.
    decide: (id, decision) => reply({ ...value,
      requests: value.requests.map((request) => request.id === id ? { ...request, state: decision === 'approve' ? 'authenticating' : 'sending', canApprove: false, canDeny: decision === 'approve' } : request),
      requestCatalog: value.requestCatalog ? { ...value.requestCatalog, decisions: [
        ...(value.requestCatalog.decisions ?? []).filter((view) => view.id !== id),
        decisionView(id, decision, decision === 'approve' ? 'authenticating' : 'sending'),
      ] } : null }),
    requestDetails: (id) => {
      // Synthetic-only extra fixture text. Production snapshots contain no body.
      const request = value.requests.find((item) => item.id === id);
      if (!request) return Promise.reject(new Error('synthetic request unavailable'));
      return Promise.resolve({ version: 1, id, programName: request.programName, executablePath: request.executablePath,
        details: 'details' in request && typeof request.details === 'string' ? request.details : '',
        remainingSeconds: request.remainingSeconds, refreshAfterMillis: request.refreshAfterMillis });
    },
    clearActivity: () => reply({ ...value, activity: [] }),
    // Synthetic client acknowledgement, never a native Explorer claim.
    openDiagnosticsFolder: () => Promise.resolve(),
    // Synthetic acknowledgement only; does not save or share an Android file.
    exportAndroidDiagnostics: () => diagnosticsExportPending ? new Promise<void>(() => { /* Held synthetic owner for pending-state gallery only. */ }) : Promise.resolve(),
    saveAndroidDiagnostics: () => Promise.resolve('saved'),
    openLockSettings: () => Promise.resolve(),
    openNotificationSettings: () => Promise.resolve(),
    // Client/synthetic acknowledgement only; no camera surface or pairing result.
    openPairingScanner: () => scannerFailure
      ? Promise.reject(Object.assign(new Error('Synthetic scanner launch unavailable'), { code: 'pairing_scanner_unavailable' })) : Promise.resolve(),
  };
}
