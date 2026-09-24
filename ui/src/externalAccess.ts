// SPDX-License-Identifier: GPL-2.0-or-later
// Presentation and client-side input checks only. The native owner validates
// every setting again and alone decides whether an address is published.
import type { ExternalAccessFailure, ExternalAccessInput, ExternalAccessMode, ExternalAccessView, ExternalCandidateSource } from './contracts';

/** The embedded relay's fixed port, used only before a view reports it. */
export const DEFAULT_RELAY_PORT = 7443;
export const FIXED_ADDRESS_EXAMPLE = '203.0.113.7:7443';

export const portInvalidText = '포트는 1에서 65535 사이의 숫자로 입력하십시오.';
export const addressInvalidText = '공인 IP와 포트를 ‘공인 IP:포트’ 형식으로 입력하십시오.';
/** A well-formed address the PC itself refuses to publish (see `global()`). */
export const addressUnreachableText = '이 주소로는 외부에서 연결할 수 없습니다. 공유기 관리 페이지에 표시된 공인 IP를 입력하십시오.';

export const sourceText: Record<ExternalCandidateSource, string> = {
  pcp: '공유기 자동 포트 열기(PCP)',
  upnp: '공유기 자동 포트 열기(UPnP)',
  stun: '외부 서버에 물어 확인',
  fixed: '직접 입력',
  public_interface: '이 PC의 공인 주소',
};

export const failureText: Record<ExternalAccessFailure, string> = {
  no_mapping_protocol: '공유기가 자동 포트 열기(UPnP·PCP)를 지원하지 않거나 꺼져 있습니다. 공유기에서 포트를 직접 열고 아래에서 그 방법을 고르십시오.',
  private_external_address: '공유기가 받은 주소도 사설 주소입니다. 공유기 앞에 다른 공유기나 통신사 장비가 하나 더 있어, 이 공유기에서 포트를 열어도 외부에서 들어올 수 없습니다. 그 장비에서도 같은 포트를 열거나 외부 중계 서버를 사용하십시오.',
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

/** Dotted-quad octets without leading zeros, as the native parser accepts them. */
function ipv4Octets(text: string): readonly number[] | null {
  const parts = text.split('.');
  if (parts.length !== 4 || parts.some(part => !/^(?:0|[1-9][0-9]{0,2})$/u.test(part))) return null;
  const octets = parts.map(Number);
  return octets.some(octet => octet > 255) ? null : octets;
}

/** Mirrors `direct_network::global` for IPv4 exactly: unspecified, loopback,
 * link-local, multicast, broadcast, private, shared (100.64/10), 192.0.0.0/16,
 * 192.88.99.0/24, benchmarking (198.18/15) and documentation ranges are refused. */
function globalIpv4([a = 0, b = 0, c = 0]: readonly number[]): boolean {
  return a !== 0 && a !== 127 && a < 224 && !(a === 169 && b === 254)
    && a !== 10 && !(a === 172 && b >= 16 && b <= 31) && !(a === 192 && b === 168)
    && !(a === 100 && b >= 64 && b <= 127)
    && !(a === 192 && (b === 0 || (b === 88 && c === 99)))
    && !(a === 198 && (b === 18 || b === 19 || (b === 51 && c === 100)))
    && !(a === 203 && b === 0 && c === 113);
}

/** The eight 16-bit groups of an IPv6 literal without zone, or null. */
function ipv6Segments(text: string): readonly number[] | null {
  if (!/^[0-9A-Fa-f:.]+$/u.test(text) || !text.includes(':')) return null;
  let host: string;
  try { host = new URL(`http://[${text}]/`).hostname; } catch { return null; }
  // The URL serializer writes lowercase hex groups with at most one `::`.
  const [head = '', tail] = host.slice(1, -1).split('::');
  const left = head ? head.split(':') : [];
  const right = tail ? tail.split(':') : [];
  const groups = [...left, ...Array<string>(tail === undefined ? 0 : 8 - left.length - right.length).fill('0'), ...right];
  const segments = groups.map(group => /^[0-9a-f]{1,4}$/u.test(group) ? Number.parseInt(group, 16) : Number.NaN);
  return segments.length === 8 && segments.every(Number.isInteger) ? segments : null;
}

/** Mirrors `direct_network::global` for IPv6 exactly: 2000::/3 without
 * 2001::/23, documentation 2001:db8::/32 and 3fff::/20, and 6to4 2002::/16. */
function globalIpv6([s0 = 0, s1 = 0]: readonly number[]): boolean {
  return (s0 & 0xe000) === 0x2000 && !(s0 === 0x2001 && (s1 <= 0x1ff || s1 === 0xdb8))
    && s0 !== 0x2002 && !(s0 === 0x3fff && s1 < 0x1000);
}

export type FixedAddressResult = { readonly address: string } | { readonly error: 'address' | 'address_unreachable' };

/** A trimmed IPv4:port or [IPv6]:port the PC will publish, or why not: a shape
 * error, or an address the native owner refuses because it is not global. */
export function checkFixedAddress(text: string): FixedAddressResult {
  const value = text.trim();
  const v4 = /^([0-9.]+):([0-9]+)$/u.exec(value);
  const v6 = v4 ? null : /^\[([^\]]+)\]:([0-9]+)$/u.exec(value);
  const match = v4 ?? v6;
  if (!match || parsePort(match[2] ?? '') === null) return { error: 'address' };
  if (v4) {
    const octets = ipv4Octets(v4[1] ?? '');
    if (!octets) return { error: 'address' };
    return globalIpv4(octets) ? { address: value } : { error: 'address_unreachable' };
  }
  const segments = ipv6Segments(match[1] ?? '');
  if (!segments) return { error: 'address' };
  return globalIpv6(segments) ? { address: value } : { error: 'address_unreachable' };
}

/** Returns the trimmed address when the PC will accept it, otherwise null. */
export function parseFixedAddress(text: string): string | null {
  const result = checkFixedAddress(text);
  return 'address' in result ? result.address : null;
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

export type DraftResult = { readonly input: ExternalAccessInput } | { readonly error: 'port' | 'address' | 'address_unreachable' };

export function inputFromDraft(draft: ExternalAccessDraft & { readonly mode: ExternalAccessMode }): DraftResult {
  switch (draft.mode) {
    case 'automatic': return { input: { mode: 'automatic' } };
    case 'router_forward': {
      const externalPort = parsePort(draft.port);
      return externalPort === null ? { error: 'port' } : { input: { mode: 'router_forward', externalPort } };
    }
    case 'fixed': {
      const result = checkFixedAddress(draft.address);
      return 'error' in result ? result : { input: { mode: 'fixed', fixedAddress: result.address } };
    }
  }
}

/** `{lan}:{port}` for router instructions; IPv6 gets brackets. */
export function lanEndpoint(view: ExternalAccessView): string | null {
  if (!view.lanAddress) return null;
  return view.lanAddress.includes(':') ? `[${view.lanAddress}]:${String(view.relayPort)}` : `${view.lanAddress}:${String(view.relayPort)}`;
}
