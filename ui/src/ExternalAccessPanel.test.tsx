// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic presentation tests only. They prove no router mapping, STUN answer,
// reachable address or native setting; the native owner validates every save.
import { act, fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { App } from './App';
import type { AppSnapshot, ControllerBridge, ExternalAccessFailure, ExternalAccessInput, ExternalCandidateSource } from './contracts';
import { ExternalAccessPanel } from './ExternalAccessPanel';
import { checkFixedAddress, parseFixedAddress, parsePort, suggestExternalPort } from './externalAccess';
import { locales, setPreviewLanguage, tr } from './i18n';
import { ko } from './messages';
import { createQaBridge, qaCase } from './qa-fixtures';
import { ServicePanel } from './StatusPanels';

const reasons: Record<ExternalAccessFailure, string> = {
  no_mapping_protocol: '공유기가 자동 포트 열기(UPnP·PCP)를 지원하지 않거나 꺼져 있습니다. 공유기에서 포트를 직접 열고 아래에서 그 방법을 고르십시오.',
  private_external_address: '공유기가 받은 주소도 사설 주소입니다. 공유기 앞에 다른 공유기나 통신사 장비가 하나 더 있어, 이 공유기에서 포트를 열어도 외부에서 들어올 수 없습니다. 그 장비에서도 같은 포트를 열거나 외부 중계 서버를 사용하십시오.',
  public_address_unavailable: '이 집의 공인 IP를 확인하지 못했습니다. 인터넷 연결을 확인하거나 외부 주소를 직접 입력하십시오.',
};
const sources: Record<ExternalCandidateSource, string> = {
  pcp: '공유기 자동 포트 열기(PCP)', upnp: '공유기 자동 포트 열기(UPnP)', stun: '외부 서버에 물어 확인',
  fixed: '직접 입력', public_interface: '이 PC의 공인 주소',
};
const portMessage = '포트는 1에서 65535 사이의 숫자로 입력하십시오.';
const addressMessage = '공인 IP와 포트를 ‘공인 IP:포트’ 형식으로 입력하십시오.';
const unreachableMessage = '이 주소로는 외부에서 연결할 수 없습니다. 공유기 관리 페이지에 표시된 공인 IP를 입력하십시오.';
const forwardTitle = '공유기에서 포트를 직접 열었음';
const suggestHint = '정한 번호가 없으면 무작위로 고르십시오. 이 앱을 쓰는 PC가 집에 여럿이면 PC마다 번호가 달라야 합니다.';
const changeHint = '번호를 바꾸면 공유기의 포트포워딩도 새 번호로 고쳐야 합니다.';
const fixedTitle = '외부 주소 직접 입력';

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((accept, fail) => { resolve = accept; reject = fail; });
  return { promise, resolve, reject };
}

function panel(snapshot: AppSnapshot, onSave = vi.fn<(input: ExternalAccessInput) => Promise<AppSnapshot | null>>(), stale = false) {
  render(<ExternalAccessPanel snapshot={snapshot} disabled={false} stale={stale} onSave={onSave} onSetRelay={vi.fn()} />);
  return onSave;
}

/** The relay form on the same tab has its own Save button. */
function methodSection(): HTMLElement {
  return screen.getByRole('region', { name: '외부에서 연결하는 방법' });
}
function methodSave(name: string = ko.save): HTMLElement {
  return within(methodSection()).getByRole('button', { name });
}

function fact(label: string): HTMLElement {
  const term = screen.getByText(label, { selector: 'dt' });
  return term.nextElementSibling as HTMLElement;
}

function withFailure(failure: ExternalAccessFailure): AppSnapshot {
  const snapshot = qaCase('desktop-network-auto-no-mapping').snapshot;
  return { ...snapshot, externalAccess: { ...snapshot.externalAccess!, failure } };
}

describe('external access status', () => {
  it.each(Object.keys(reasons) as ExternalAccessFailure[])('explains %s only while there is no external address', (failure) => {
    const snapshot = withFailure(failure);
    const view = render(<ExternalAccessPanel snapshot={snapshot} disabled={false} onSave={vi.fn()} onSetRelay={vi.fn()} />);
    expect(screen.getByText(reasons[failure])).toBeVisible();
    for (const other of (Object.keys(reasons) as ExternalAccessFailure[]).filter(item => item !== failure)) {
      expect(screen.queryByText(reasons[other])).not.toBeInTheDocument();
    }
    expect(fact('외부 주소')).toHaveTextContent('없음');
    view.rerender(<ExternalAccessPanel snapshot={{ ...snapshot, externalAccess: { ...snapshot.externalAccess!, externalAddress: '203.0.113.7:7443', source: 'upnp' } }}
      disabled={false} onSave={vi.fn()} onSetRelay={vi.fn()} />);
    expect(screen.queryByText(reasons[failure])).not.toBeInTheDocument();
    expect(fact('외부 주소')).toHaveTextContent('203.0.113.7:7443');
  });

  it.each(Object.keys(sources) as ExternalCandidateSource[])('names the %s source beside the address and LAN endpoint', (source) => {
    const snapshot = qaCase('desktop-network-auto-upnp').snapshot;
    panel({ ...snapshot, externalAccess: { ...snapshot.externalAccess!, source, externalAddress: '198.51.100.24:17443' } });
    const address = fact('외부 주소');
    expect(address).toHaveTextContent('198.51.100.24:17443');
    expect(address.querySelector('bdi')).toHaveAttribute('dir', 'ltr');
    expect(fact('주소를 얻은 방법')).toHaveTextContent(sources[source]);
    const lan = fact('이 PC의 내부 주소');
    expect(lan).toHaveTextContent('192.168.0.23:7443');
    expect(lan.querySelector('bdi')).toHaveAttribute('dir', 'ltr');
    // A published candidate is not success styling or reachability proof.
    expect(document.querySelector('.network-card .is-success:not(.relay-state)')).toBeNull();
  });

  it('shows none for a missing source and unknown for a missing LAN address', () => {
    const snapshot = qaCase('desktop-network-auto-no-mapping').snapshot;
    panel({ ...snapshot, externalAccess: { ...snapshot.externalAccess!, lanAddress: null } });
    expect(fact('주소를 얻은 방법')).toHaveTextContent('없음');
    expect(fact('이 PC의 내부 주소')).toHaveTextContent('확인 불가');
  });

  it.each(['missing', 'stale'] as const)('does not claim an absent address from a %s observation', (condition) => {
    const source = qaCase('desktop-network-auto-no-mapping').snapshot;
    panel(condition === 'missing' ? { ...source, externalAccess: null } : source, undefined, condition === 'stale');
    for (const label of ['외부 주소', '주소를 얻은 방법', '이 PC의 내부 주소']) expect(fact(label)).toHaveTextContent('확인 불가');
    expect(screen.queryByText(reasons.no_mapping_protocol)).not.toBeInTheDocument();
    expect(screen.queryByText('없음')).not.toBeInTheDocument();
  });

  it('keeps sections in the pinned order with the relay controls and firewall guidance last', () => {
    panel(qaCase('desktop-network-auto-upnp').snapshot);
    expect(screen.getAllByRole('heading', { level: 2 }).map(heading => heading.textContent))
      .toEqual(['현재 상태', '외부에서 연결하는 방법', '휴대폰이 접속할 곳']);
    const relay = screen.getByRole('region', { name: '휴대폰이 접속할 곳' });
    expect(within(relay).getByRole('button', { name: '이 PC 사용 중' })).toBeDisabled();
    expect(within(relay).getByRole('form', { name: ko.relayAddress })).toBeInTheDocument();
    const guidance = screen.getByText('휴대폰이 연결되지 않으면 V3나 방화벽이 UAC 원격 승인기 서비스(uac-service.exe)의 연결 허용을 묻고 있는지 확인하십시오.');
    expect(relay.compareDocumentPosition(guidance) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getAllByRole('status').filter(node => node.classList.contains('relay-state'))).toHaveLength(1);
  });
});

describe('external access form', () => {
  it('shows the field that belongs to the selected option', async () => {
    const user = userEvent.setup();
    panel(qaCase('desktop-network-auto-no-mapping').snapshot);
    const group = screen.getByRole('group', { name: '외부에서 연결하는 방법' });
    expect(within(group).getByRole('radio', { name: '자동' })).toBeChecked();
    expect(within(group).getByRole('radio', { name: '자동' })).toHaveAccessibleDescription('공유기가 UPnP나 PCP를 지원하면 이 PC가 포트를 직접 엽니다.');
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
    expect(screen.queryByRole('textbox', { name: '외부 주소' })).not.toBeInTheDocument();
    expect(methodSave()).toBeDisabled();

    await user.click(screen.getByRole('radio', { name: forwardTitle }));
    const port = screen.getByRole('spinbutton', { name: '공유기의 외부 포트' });
    // No port is recommended: the field starts empty and the router step waits for a number.
    expect(port).toHaveValue(null);
    expect(port).toHaveAccessibleDescription(suggestHint);
    expect(screen.queryByText(/공유기 관리 페이지의 포트포워딩에서/u)).not.toBeInTheDocument();
    expect(screen.queryByText(/DMZ/u)).not.toBeInTheDocument();
    expect(screen.getByText('PC의 내부 주소가 바뀌면 포트포워딩이 끊깁니다. 공유기의 DHCP 고정 할당으로 이 PC의 주소를 고정해 두십시오.')).toBeVisible();
    fireEvent.change(port, { target: { value: '17443' } });
    expect(screen.getByText('공유기 관리 페이지의 포트포워딩에서 외부 포트 17443을(를) 192.168.0.23의 7443 포트(TCP)로 연결하십시오.')).toBeVisible();
    expect(methodSave()).toBeEnabled();

    await user.click(screen.getByRole('radio', { name: fixedTitle }));
    expect(screen.queryByRole('spinbutton')).not.toBeInTheDocument();
    expect(screen.queryByText(/공유기 관리 페이지의 포트포워딩에서/u)).not.toBeInTheDocument();
    const address = screen.getByRole('textbox', { name: '외부 주소' });
    expect(address).toHaveAttribute('dir', 'ltr');
    expect(address).toHaveAttribute('placeholder', '203.0.113.7:7443');

    // A draft survives switching away and back.
    await user.click(screen.getByRole('radio', { name: forwardTitle }));
    expect(screen.getByRole('spinbutton', { name: '공유기의 외부 포트' })).toHaveValue(17443);
  });

  it.each(['', '0', '65536', '12.5', '-1'])('rejects the port %j with the pinned message and no bridge call', async (value) => {
    const user = userEvent.setup();
    const onSave = panel(qaCase('desktop-network-auto-no-mapping').snapshot);
    await user.click(screen.getByRole('radio', { name: forwardTitle }));
    const port = screen.getByRole('spinbutton', { name: '공유기의 외부 포트' });
    fireEvent.change(port, { target: { value } });
    await user.click(methodSave());
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByText(portMessage)).toBeVisible();
    expect(port).toHaveAttribute('aria-invalid', 'true');
    expect(port).toHaveAccessibleDescription(`${suggestHint} ${portMessage}`);
    expect(port).toHaveFocus();
    fireEvent.change(port, { target: { value: '7443' } });
    expect(screen.queryByText(portMessage)).not.toBeInTheDocument();
  });

  it.each(['', '203.0.113.7', '203.0.113.7:0', '203.0.113.7:70000', '203.0.113.300:7443', 'router.example:7443',
    '2001:db8::1:7443', '203.0.113.07:7443', '[2001:db8::1]', '[2001:4860:4860::8888]:0', '[2001:4860:4860::8888%3]:7443',
  ])('rejects the address shape %j with the pinned message and no bridge call', async (value) => {
    const user = userEvent.setup();
    const onSave = panel(qaCase('desktop-network-auto-no-mapping').snapshot);
    await user.click(screen.getByRole('radio', { name: fixedTitle }));
    const address = screen.getByRole('textbox', { name: '외부 주소' });
    fireEvent.change(address, { target: { value } });
    await user.click(methodSave());
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByText(addressMessage)).toBeVisible();
    expect(screen.queryByText(unreachableMessage)).not.toBeInTheDocument();
    expect(address).toHaveAttribute('aria-invalid', 'true');
    expect(address).toHaveAccessibleDescription(addressMessage);
  });

  // Every range `direct_network::global` refuses, so the PC never has to refuse
  // an address the form accepted. The placeholder itself is a documentation address.
  it.each([
    '203.0.113.7:7443', '192.0.2.1:7443', '198.51.100.1:7443', '192.0.0.1:7443', '192.0.0.9:7443', '192.0.1.1:7443',
    '192.88.99.1:7443', '198.18.0.1:7443', '198.19.255.254:7443', '192.168.0.23:7443', '10.0.0.5:7443',
    '172.16.0.1:7443', '172.31.255.255:7443', '127.0.0.1:7443', '100.64.1.2:7443', '100.127.255.255:7443',
    '169.254.1.1:7443', '0.1.2.3:7443', '224.0.0.1:7443', '239.1.1.1:7443', '255.255.255.255:7443',
    '[fe80::1]:7443', '[::1]:7443', '[fc00::1]:7443', '[::ffff:8.8.8.8]:7443', '[2001:db8::1]:7443',
    '[2001::1]:7443', '[2001:1ff::1]:7443', '[2002::1]:7443', '[3fff::1]:7443', '[3fff:fff::1]:7443', '[ff02::1]:7443',
  ])('refuses the non-global address %j with the pinned message and no bridge call', async (value) => {
    const user = userEvent.setup();
    const onSave = panel(qaCase('desktop-network-auto-no-mapping').snapshot);
    await user.click(screen.getByRole('radio', { name: fixedTitle }));
    const address = screen.getByRole('textbox', { name: '외부 주소' });
    fireEvent.change(address, { target: { value } });
    await user.click(methodSave());
    expect(onSave).not.toHaveBeenCalled();
    expect(screen.getByText(unreachableMessage)).toBeVisible();
    expect(screen.queryByText(addressMessage)).not.toBeInTheDocument();
    expect(address).toHaveAttribute('aria-invalid', 'true');
    expect(address).toHaveAccessibleDescription(unreachableMessage);
  });

  it.each([
    ['desktop-network-forward-stun', '자동', undefined, { mode: 'automatic' }],
    ['desktop-network-auto-no-mapping', forwardTitle, '17443', { mode: 'router_forward', externalPort: 17443 }],
    ['desktop-network-auto-no-mapping', fixedTitle, ' 1.2.3.4:7443 ', { mode: 'fixed', fixedAddress: '1.2.3.4:7443' }],
    ['desktop-network-auto-no-mapping', fixedTitle, '[2001:4860:4860::8888]:7443', { mode: 'fixed', fixedAddress: '[2001:4860:4860::8888]:7443' }],
  ] as const)('sends the pinned input shape from %s via %s', async (fixture, option, entry, expected) => {
    const user = userEvent.setup();
    const source = qaCase(fixture).snapshot;
    const setExternalAccess = vi.fn<ControllerBridge['setExternalAccess']>((input) => createQaBridge(source).setExternalAccess(input));
    render(<App bridge={{ ...createQaBridge(source), setExternalAccess }} initialPage="network" />);
    await user.click(await screen.findByRole('radio', { name: option }));
    if (entry !== undefined && option === forwardTitle) fireEvent.change(screen.getByRole('spinbutton'), { target: { value: entry } });
    if (entry !== undefined && option === fixedTitle) fireEvent.change(screen.getByRole('textbox', { name: '외부 주소' }), { target: { value: entry } });
    await user.click(methodSave());
    expect(setExternalAccess).toHaveBeenCalledExactlyOnceWith(expected);
  });

  it('disables the form while saving and keeps the draft after a failed save', async () => {
    const user = userEvent.setup();
    const pending = deferred<AppSnapshot>();
    const onSave = vi.fn<(input: ExternalAccessInput) => Promise<AppSnapshot | null>>(() => pending.promise);
    panel(qaCase('desktop-network-auto-no-mapping').snapshot, onSave);
    await user.click(screen.getByRole('radio', { name: forwardTitle }));
    fireEvent.change(screen.getByRole('spinbutton'), { target: { value: '17443' } });
    await user.click(methodSave());
    const saving = methodSave(ko.saving);
    expect(saving).toBeDisabled();
    expect(screen.getByRole('spinbutton')).toBeDisabled();
    expect(screen.getByRole('radio', { name: '자동' })).toBeDisabled();
    fireEvent.submit(saving.closest('form')!);
    expect(onSave).toHaveBeenCalledOnce();
    await act(async () => { pending.reject(new Error('RAW_NATIVE private detail')); await pending.promise.catch(() => undefined); });
    expect(screen.getByRole('alert')).toHaveTextContent(ko.saveFailure);
    expect(screen.queryByText(/RAW_NATIVE/u)).not.toBeInTheDocument();
    expect(screen.getByRole('spinbutton')).toHaveValue(17443);
    expect(screen.getByRole('radio', { name: forwardTitle })).toBeChecked();
  });

  it('keeps the draft through a native refusal and follows the confirmed view after success', async () => {
    const user = userEvent.setup();
    const source = qaCase('desktop-network-auto-no-mapping').snapshot;
    const refusal = { ...source, issue: { code: 'synthetic_cancelled', message: '설정 저장을 취소했어요.', nextAction: null } };
    const setExternalAccess = vi.fn<ControllerBridge['setExternalAccess']>()
      .mockResolvedValueOnce(refusal)
      .mockImplementation((input) => createQaBridge(source).setExternalAccess(input));
    render(<App bridge={{ ...createQaBridge(source), setExternalAccess }} initialPage="network" />);
    await user.click(await screen.findByRole('radio', { name: forwardTitle }));
    fireEvent.change(screen.getByRole('spinbutton'), { target: { value: '17443' } });
    const form = methodSection();
    await user.click(methodSave());
    expect(await screen.findByText('설정 저장을 취소했어요.')).toBeVisible();
    expect(screen.getByRole('spinbutton')).toHaveValue(17443);
    await user.click(methodSave());
    expect(setExternalAccess).toHaveBeenCalledTimes(2);
    // The synthetic owner now reports this mode; the draft is released and Save rests.
    expect(await within(form).findByRole('button', { name: ko.save })).toBeDisabled();
    expect(screen.getByRole('spinbutton')).toHaveValue(17443);
    expect(fact('외부 주소')).toHaveTextContent('없음');
  });

  it('blocks saving when the installed helper cannot be verified', async () => {
    const user = userEvent.setup();
    const source = qaCase('desktop-network-auto-no-mapping').snapshot;
    const onSave = panel({ ...source, service: { ...source.service!, controlHint: 'needs_installer' } });
    await user.click(screen.getByRole('radio', { name: forwardTitle }));
    fireEvent.change(screen.getByRole('spinbutton'), { target: { value: '17443' } });
    const form = methodSection();
    expect(methodSave()).toBeDisabled();
    expect(within(form).getByText(ko.pairingPcInstallFirst)).toBeVisible();
    fireEvent.submit(form.querySelector('form')!);
    expect(onSave).not.toHaveBeenCalled();
  });

  it('selects no option when the saved mode has not been observed', () => {
    panel({ ...qaCase('desktop-relay-listening').snapshot, externalAccess: null });
    for (const radio of screen.getAllByRole('radio')) expect(radio).not.toBeChecked();
    expect(methodSave()).toBeDisabled();
  });

  it('parses only numeric ports and address shapes', () => {
    expect(parsePort(' 443 ')).toBe(443);
    expect(parsePort('1e3')).toBeNull();
    expect(parseFixedAddress('1.2.3.4:7443')).toBe('1.2.3.4:7443');
    expect(parseFixedAddress('198.17.255.255:7443')).toBe('198.17.255.255:7443');
    expect(parseFixedAddress('198.20.0.1:7443')).toBe('198.20.0.1:7443');
    expect(parseFixedAddress('100.63.255.255:7443')).toBe('100.63.255.255:7443');
    expect(parseFixedAddress('172.32.0.1:7443')).toBe('172.32.0.1:7443');
    expect(parseFixedAddress('223.255.255.255:7443')).toBe('223.255.255.255:7443');
    expect(parseFixedAddress('[2001:4860:4860::8888]:443')).toBe('[2001:4860:4860::8888]:443');
    expect(parseFixedAddress('[2001:200::1]:443')).toBe('[2001:200::1]:443');
    expect(parseFixedAddress('[3fff:1000::1]:443')).toBe('[3fff:1000::1]:443');
    expect(parseFixedAddress('[2400:cb00::1]:443')).toBe('[2400:cb00::1]:443');
    expect(checkFixedAddress('203.0.113.7:7443')).toEqual({ error: 'address_unreachable' });
    expect(checkFixedAddress('[2001:db8::10]:443')).toEqual({ error: 'address_unreachable' });
    expect(checkFixedAddress('203.0.113.7:7443:1')).toEqual({ error: 'address' });
    expect(parseFixedAddress('203.0.113.7:7443:1')).toBeNull();
  });
});

describe('navigation into the external access tab', () => {
  it('orders the desktop tabs and leaves phone navigation unchanged', async () => {
    const view = render(<App bridge={createQaBridge(qaCase('desktop-running').snapshot)} />);
    const nav = await screen.findByRole('navigation', { name: ko.navigation });
    expect(within(nav).getAllByRole('button').map(button => button.textContent)).toEqual(['PC 상태', '휴대폰 관리', '외부 연결', '활동 기록']);
    fireEvent.click(within(nav).getByRole('button', { name: '외부 연결' }));
    expect(screen.getByRole('heading', { level: 1, name: '외부 연결' })).toBeVisible();
    expect(screen.getByText('휴대폰이 집 밖에서도 이 PC에 연결할 수 있게 설정합니다.')).toBeVisible();
    expect(within(nav).getByRole('button', { name: '외부 연결' })).toHaveAttribute('aria-current', 'page');
    view.unmount();
    render(<App bridge={createQaBridge(qaCase('phone-empty').snapshot)} />);
    const phoneNav = await screen.findByRole('navigation', { name: ko.navigation });
    expect(within(phoneNav).queryByRole('button', { name: '외부 연결' })).not.toBeInTheDocument();
    expect(within(phoneNav).getAllByRole('button')).toHaveLength(4);
  });

  it.each([
    ['lan_only', true], ['unavailable', true], ['candidate', false], ['discovering', false],
  ] as const)('offers the PC status shortcut for %s: %s', (internetState, offered) => {
    const source = qaCase('desktop-relay-listening').snapshot;
    const onOpenNetwork = vi.fn();
    render(<ServicePanel snapshot={{ ...source, relayStatus: { mode: 'embedded', state: 'listening', internetState } }} disabled={false} onAction={vi.fn()} onOpenNetwork={onOpenNetwork} />);
    const button = screen.queryByRole('button', { name: '외부 연결 설정' });
    if (!offered) { expect(button).not.toBeInTheDocument(); return; }
    expect(screen.getByText(internetState === 'lan_only' ? '외부에서 접속할 주소가 없음'
      : '외부 주소를 확인하지 못했습니다. PC의 인터넷 연결과 공유기 설정을 확인하십시오.')).toBeVisible();
    expect(button).toHaveClass('secondary');
    fireEvent.click(button!);
    expect(onOpenNetwork).toHaveBeenCalledOnce();
  });

  it('navigates from PC status to the tab when there is no outside address', async () => {
    render(<App bridge={createQaBridge(qaCase('desktop-network-auto-no-mapping').snapshot)} initialPage="status" />);
    fireEvent.click(await screen.findByRole('button', { name: '외부 연결 설정' }));
    expect(screen.getByRole('heading', { level: 1, name: '외부 연결' })).toBeVisible();
    expect(screen.getByText(reasons.no_mapping_protocol)).toBeVisible();
  });

  it('points the phone page to the tab when pairing waits for the relay', async () => {
    const source = qaCase('desktop-running').snapshot;
    render(<App bridge={createQaBridge({ ...source, canPair: true, relayConfigured: false })} initialPage="devices" />);
    expect(await screen.findByText('휴대폰이 접속할 준비가 되지 않아 QR 코드를 표시할 수 없습니다. PC의 네트워크 연결과 [외부 연결] 설정을 확인하십시오.')).toBeVisible();
    expect(screen.queryByRole('button', { name: '이 PC 사용' })).not.toBeInTheDocument();
    expect(screen.queryByRole('form', { name: ko.relayAddress })).not.toBeInTheDocument();
    fireEvent.click(within(screen.getByRole('region', { name: ko.pairPhone })).getByRole('button', { name: '외부 연결 설정' }));
    expect(screen.getByRole('heading', { level: 1, name: '외부 연결' })).toBeVisible();
    expect(screen.getByRole('button', { name: '이 PC 사용' })).toBeEnabled();
  });

  it('does not offer the relay shortcut once the relay is configured', async () => {
    render(<App bridge={createQaBridge(qaCase('desktop-pairing-ready').snapshot)} initialPage="devices" />);
    await screen.findByRole('button', { name: ko.pairPhone });
    expect(screen.queryByRole('button', { name: '외부 연결 설정' })).not.toBeInTheDocument();
  });
});

describe('external port suggestion', () => {
  function draws(...values: number[]) {
    const queue = [...values];
    return vi.spyOn(globalThis.crypto, 'getRandomValues').mockImplementation(<T extends ArrayBufferView | null>(array: T): T => {
      (array as unknown as Uint32Array)[0] = queue.shift() ?? 0;
      return array;
    });
  }

  it('maps draws onto 20000..=60999, the range the router mapping uses', () => {
    const spy = draws(0, 40999, 41000);
    expect(suggestExternalPort(null)).toBe(20000);
    expect(suggestExternalPort(null)).toBe(60999);
    expect(suggestExternalPort(null)).toBe(20000);
    spy.mockRestore();
  });

  it('draws again rather than bias the low ports or repeat the current one', () => {
    // 2^32 - 1 lies in the uneven remainder of the 32-bit range and is rejected.
    const spy = draws(0xffffffff, 0, 1);
    expect(suggestExternalPort(20000)).toBe(20001);
    expect(spy).toHaveBeenCalledTimes(3);
    spy.mockRestore();
  });

  it('fills the field and the router step only when asked, and saves nothing', async () => {
    const user = userEvent.setup();
    const spy = draws(14127);
    const onSave = panel(qaCase('desktop-network-auto-no-mapping').snapshot);
    await user.click(screen.getByRole('radio', { name: forwardTitle }));
    expect(spy).not.toHaveBeenCalled();
    await user.click(screen.getByRole('button', { name: '무작위로 고르기' }));
    expect(screen.getByRole('spinbutton', { name: '공유기의 외부 포트' })).toHaveValue(34127);
    expect(screen.getByText('공유기 관리 페이지의 포트포워딩에서 외부 포트 34127을(를) 192.168.0.23의 7443 포트(TCP)로 연결하십시오.')).toBeVisible();
    expect(onSave).not.toHaveBeenCalled();
    expect(methodSave()).toBeEnabled();
    spy.mockRestore();
  });

  it('warns that a saved forward has to change on the router too', () => {
    panel(qaCase('desktop-network-forward-stun').snapshot);
    expect(screen.getByRole('spinbutton', { name: '공유기의 외부 포트' })).toHaveAccessibleDescription(changeHint);
  });
});

describe('external access localization', () => {
  it.each(locales)('translates every visible string of the tab in %s', (locale) => {
    setPreviewLanguage(locale);
    const source = qaCase('desktop-network-forward-unavailable').snapshot;
    const { container } = render(<ExternalAccessPanel snapshot={source} disabled={false} onSave={vi.fn()} onSetRelay={vi.fn()} />);
    expect(container.textContent).toContain(tr(reasons.public_address_unavailable));
    expect(container.textContent).toContain('7443');
    if (locale !== 'ko') expect(container.textContent).not.toMatch(/[가-힣]/u);
    expect(container.textContent).not.toMatch(/\{[a-z]+\}/u);
  });
});
