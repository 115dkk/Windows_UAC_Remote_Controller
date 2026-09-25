// SPDX-License-Identifier: GPL-2.0-or-later
// Presentation of the service's reason for an unbound relay listener. The
// program name comes from another process and is untrusted display text.
import type { ListenerFault } from './contracts';
import { displayText } from './displayText';
import { formatText } from './i18n';

export const listenerFaultText = {
  program: '{program}이(가) {port} 포트를 쓰고 있어 휴대폰 연결을 받지 못합니다. 그 프로그램을 끄거나 그 프로그램의 포트 설정을 바꾸십시오. 포트가 비면 자동으로 다시 받습니다.',
  pid: '다른 프로그램(PID {pid})이 {port} 포트를 쓰고 있어 휴대폰 연결을 받지 못합니다. 작업 관리자의 [세부 정보] 탭에서 이 PID의 프로그램을 확인하십시오. 포트가 비면 자동으로 다시 받습니다.',
  // No holder found: another program, or the previous instance's connections still closing.
  unknown: '{port} 포트를 쓸 수 없어 휴대폰 연결을 받지 못합니다. 다른 프로그램이 쓰고 있거나 직전 연결이 아직 정리되지 않았습니다. 자동으로 다시 시도합니다.',
  reserved: 'Windows가 {port} 포트를 쓰지 못하게 막아 휴대폰 연결을 받지 못합니다. Hyper-V, WSL, Docker 같은 기능이 이 포트를 예약해 두었는지 확인하십시오. 자동으로 다시 시도합니다.',
} as const;

export function listenerFaultMessage(fault: ListenerFault): string {
  const port = String(fault.port);
  if (fault.kind === 'port_reserved') return formatText(listenerFaultText.reserved, { port });
  if (fault.program) return formatText(listenerFaultText.program, { program: displayText(fault.program), port });
  if (fault.pid > 0) return formatText(listenerFaultText.pid, { pid: String(fault.pid), port });
  return formatText(listenerFaultText.unknown, { port });
}
