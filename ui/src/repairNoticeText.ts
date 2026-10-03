// SPDX-License-Identifier: GPL-2.0-or-later
// Installation damage the app found by hashing against the protected copy (ADR 0045).
import type { AppSnapshot } from './contracts';

export const repairNoticeText = {
  damaged: '휴대폰 승인 프로그램 파일 일부가 손상되었습니다. [수리하기]를 누르면 이 PC에 보관된 원본으로 되돌립니다. Windows 관리자 승인이 필요합니다.',
  sourceDamaged: '프로그램 파일과 이 PC에 보관된 원본이 모두 손상되어 여기서는 수리할 수 없습니다. 같은 버전을 다시 설치하십시오.',
} as const;

export type RepairNoticeKind = 'repair' | 'reinstall';

/** What to tell the user about the installation, or null when it is intact or unknown. */
export function repairNoticeKind(snapshot: AppSnapshot, stale: boolean): RepairNoticeKind | null {
  const integrity = snapshot.installationIntegrity;
  if (stale || !integrity) return null;
  if (integrity.state === 'damaged') return 'repair';
  if (integrity.state === 'source_damaged') return 'reinstall';
  return null;
}
