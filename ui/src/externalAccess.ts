// SPDX-License-Identifier: GPL-2.0-or-later
// Presentation and client-side input checks only. The native owner validates
// every setting again and alone decides whether an address is published.
import type { ExternalAccessFailure, ExternalAccessInput, ExternalAccessMode, ExternalAccessView, ExternalCandidateSource } from './contracts';

/** The embedded relay's fixed port, used only before a view reports it. */
export const DEFAULT_RELAY_PORT = 7443;
export const FIXED_ADDRESS_EXAMPLE = '203.0.113.7:7443';

export const portInvalidText = '포트는 1에서 65535 사이의 숫자로 입력하십시오.';
export const addressInvalidText = '공인 IP와 포트를 203.0.113.7:7443 형식으로 입력하십시오.';

export const sourceText: Record<ExternalCandidateSource, string> = {
  pcp: 'PCP로 공유기에서 받음',
  upnp: 'UPnP로 공유기에서 받음',
  stun: 'STUN 서버로 확인',
  fixed: '직접 입력',
  public_interface: '이 PC의 공인 주소',
};

export const failureText: Record<ExternalAccessFailure, string> = {
  no_mapping_protocol: '공유기가 자동 포트 열기(UPnP·PCP)를 지원하지 않거나 꺼져 있습니다. 공유기에서 포트를 직접 열고 아래에서 그 방법을 고르십시오.',
  private_external_address: '공유기가 받은 주소도 사설 주소입니다. 공유기 앞에 다른 공유기나 통신사 장비가 하나 더 있어, 이 공유기에서 포트를 열어도 외부에서 들어올 수 없습니다.',
  public_address_unavailable: '이 집의 공인 IP를 확인하지 못했습니다. 인터넷 연결을 확인하거나 외부 주소를 직접 입력하십시오.',
};

export const modeText: Record<ExternalAccessMode, { readonly title: string; readonly description: string }> = {
  automatic: { title: '자동', description: '공유기가 UPnP나 PCP를 지원하면 이 PC가 포트를 직접 엽니다.' },
  router_forward: { title: '공유기에서 포트를 직접 열었음', description: '포트포워딩이나 DMZ를 설정한 경우입니다. 공인 IP는 STUN 서버(Google, Cloudflare)에 물어 확인합니다.' },
  fixed: { title: '외부 주소 직접 입력', description: '공인 IP와 포트를 직접 적습니다. 공인 IP가 바뀌면 다시 입력해야 합니다.' },
};

/** A decimal port 1..65535, or null. */
export function parsePort(text: string): number | null {
  const value = text.trim();
  if (!/^[0-9]{1,5}$/u.test(value)) return null;
  const port = Number(value);
  return port >= 1 && port <= 65535 ? port : null;
}

function publicIpv4(text: string): boolean {
  const parts = text.split('.');
  if (parts.length !== 4 || parts.some(part => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return false;
  const octets = parts.map(Number);
  if (octets.some(octet => octet > 255)) return false;
  const [a = 0, b = 0] = octets;
  // Obvious non-public ranges only; the native owner applies the full rule.
  return !(a === 0 || a === 10 || a === 127 || a >= 224
    || (a === 169 && b === 254) || (a === 172 && b >= 16 && b <= 31)
    || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127));
}

function globalIpv6(text: string): boolean {
  if (!/^[0-9A-Fa-f:.]+$/u.test(text) || !text.includes(':')) return false;
  let host: string;
  try { host = new URL(`http://[${text}]/`).hostname; } catch { return false; }
  const first = Number.parseInt(host.slice(1).split(':')[0] ?? '', 16);
  return Number.isInteger(first) && (first & 0xe000) === 0x2000;
}

/** Returns the trimmed address when it has the IPv4:port or [IPv6]:port shape. */
export function parseFixedAddress(text: string): string | null {
  const value = text.trim();
  const v4 = /^([0-9.]+):([0-9]+)$/u.exec(value);
  if (v4) return publicIpv4(v4[1] ?? '') && parsePort(v4[2] ?? '') !== null ? value : null;
  const v6 = /^\[([^\]]+)\]:([0-9]+)$/u.exec(value);
  if (v6) return globalIpv6(v6[1] ?? '') && parsePort(v6[2] ?? '') !== null ? value : null;
  return null;
}

export interface ExternalAccessDraft {
  readonly mode: ExternalAccessMode | null;
  readonly port: string;
  readonly address: string;
}

/** A missing view selects nothing: the saved mode is unknown, not automatic. */
export function draftFromView(view: ExternalAccessView | null | undefined): ExternalAccessDraft {
  return {
    mode: view?.mode ?? null,
    port: String(view?.externalPort ?? view?.relayPort ?? DEFAULT_RELAY_PORT),
    address: view?.fixedAddress ?? '',
  };
}

export function draftChanged(draft: ExternalAccessDraft, view: ExternalAccessView | null | undefined): boolean {
  if (draft.mode === null) return false;
  if (!view || draft.mode !== view.mode) return true;
  if (draft.mode === 'router_forward') return draft.port.trim() !== String(view.externalPort ?? '');
  if (draft.mode === 'fixed') return draft.address.trim() !== (view.fixedAddress ?? '');
  return false;
}

export type DraftResult = { readonly input: ExternalAccessInput } | { readonly error: 'port' | 'address' };

export function inputFromDraft(draft: ExternalAccessDraft & { readonly mode: ExternalAccessMode }): DraftResult {
  switch (draft.mode) {
    case 'automatic': return { input: { mode: 'automatic' } };
    case 'router_forward': {
      const externalPort = parsePort(draft.port);
      return externalPort === null ? { error: 'port' } : { input: { mode: 'router_forward', externalPort } };
    }
    case 'fixed': {
      const fixedAddress = parseFixedAddress(draft.address);
      return fixedAddress === null ? { error: 'address' } : { input: { mode: 'fixed', fixedAddress } };
    }
  }
}

/** `{lan}:{port}` for router instructions; IPv6 gets brackets. */
export function lanEndpoint(view: ExternalAccessView): string | null {
  if (!view.lanAddress) return null;
  return view.lanAddress.includes(':') ? `[${view.lanAddress}]:${String(view.relayPort)}` : `${view.lanAddress}:${String(view.relayPort)}`;
}
