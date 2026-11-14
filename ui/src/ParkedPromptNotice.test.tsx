// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic catalogue observations only. No PC, socket or consent dialog.
import { render, screen } from '@testing-library/react';
import { describe, expect, it, vi } from 'vitest';
import type { AppSnapshot } from './contracts';
import { qaCase } from './qa-fixtures';
import { RequestPanel } from './RequestPanel';

const one = 'PC의 UAC 창이 작업 표시줄에서 기다리고 있습니다';
const several = 'PC의 UAC 창 2개가 작업 표시줄에서 기다리고 있습니다';
const guidance = '이 창은 아직 휴대폰으로 승인할 수 없습니다. PC 앞에서 작업 표시줄의 깜박이는 방패 버튼을 누르면 이 휴대폰에 승인 요청이 옵니다.';

function connected(parkedPrompts?: number): AppSnapshot {
  const phone = qaCase('phone-empty').snapshot;
  return { ...phone, requestCatalog: { status: 'ready', revision: '3', peerCount: 1, connectedPeerCount: 1,
    ...(parkedPrompts !== undefined ? { parkedPrompts } : {}) } };
}
function panel(snapshot: AppSnapshot) {
  return render(<RequestPanel snapshot={snapshot} disabled={false} onDecision={vi.fn()} readDetails={vi.fn()}
    onOpenScanner={vi.fn()} scannerButtonRef={null} />);
}

describe('parked UAC prompt notice', () => {
  it('says nothing when the PC reports none or the field is absent', () => {
    panel(connected());
    expect(screen.queryByText(one)).toBeNull();
    panel(connected(0));
    expect(screen.queryByText(one)).toBeNull();
  });

  it('names one parked prompt and how to wake it, with no decision button', () => {
    panel(connected(1));
    const notice = screen.getByRole('region', { name: one });
    expect(notice).toBeVisible();
    expect(screen.getByText(guidance)).toBeVisible();
    expect(screen.queryByRole('button', { name: /승인|거부/u })).toBeNull();
  });

  it('counts several parked prompts', () => {
    panel(connected(2));
    expect(screen.getByRole('region', { name: several })).toBeVisible();
  });

  it('ignores a value that is not a positive whole number', () => {
    panel(connected(-1));
    panel(connected(1.5));
    expect(screen.queryByRole('region', { name: /작업 표시줄/u })).toBeNull();
  });
});
