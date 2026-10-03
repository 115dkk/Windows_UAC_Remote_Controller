// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic DTO cases, not proof that the native integrity check or repair works.
import { fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppSnapshot, InstallationIntegrity, ServiceAction } from './contracts';
import { locales, setPreviewLanguage, tr } from './i18n';
import { serviceActionText } from './messages';
import { qaCase } from './qa-fixtures';
import { RepairNotice } from './RepairNotice';
import { repairNoticeText } from './repairNoticeText';

const source = qaCase('desktop-relay-listening').snapshot;
function snapshotWith(installationIntegrity: InstallationIntegrity | null, allowRepair = true): AppSnapshot {
  const service = source.service!;
  const allowedActions: ServiceAction[] = allowRepair ? [...service.allowedActions, 'repair'] : service.allowedActions.filter((action) => action !== 'repair');
  return { ...source, installationIntegrity, service: { ...service, allowedActions } };
}
const damaged: InstallationIntegrity = { state: 'damaged', damaged: ['uac-prompt-probe.exe'] };

describe('repair notice', () => {
  afterEach(() => setPreviewLanguage('ko'));

  it('offers repair for a damaged installation and runs it on click', () => {
    const onRepair = vi.fn();
    render(<RepairNotice snapshot={snapshotWith(damaged)} disabled={false} onRepair={onRepair} />);
    expect(screen.getByRole('alert')).toHaveTextContent(repairNoticeText.damaged);
    fireEvent.click(screen.getByRole('button', { name: serviceActionText.repair }));
    expect(onRepair).toHaveBeenCalledTimes(1);
  });

  it('keeps the explanation but no button when the owner does not allow repair', () => {
    render(<RepairNotice snapshot={snapshotWith(damaged, false)} disabled={false} onRepair={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent(repairNoticeText.damaged);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it('disables the button while another command runs', () => {
    render(<RepairNotice snapshot={snapshotWith(damaged)} disabled onRepair={vi.fn()} />);
    expect(screen.getByRole('button', { name: serviceActionText.repair })).toBeDisabled();
  });

  it('advises reinstalling when the protected copy is damaged too', () => {
    render(<RepairNotice snapshot={snapshotWith({ state: 'source_damaged', damaged: ['uac-service.exe'] })} disabled={false} onRepair={vi.fn()} />);
    expect(screen.getByRole('alert')).toHaveTextContent(repairNoticeText.sourceDamaged);
    expect(screen.queryByRole('button')).not.toBeInTheDocument();
  });

  it.each<[string, InstallationIntegrity | null]>([
    ['an unchecked installation', null],
    ['an intact installation', { state: 'intact', damaged: [] }],
    ['an installation without a protected copy', { state: 'unknown', damaged: [] }],
  ])('stays silent for %s', (_, integrity) => {
    const { container } = render(<RepairNotice snapshot={snapshotWith(integrity)} disabled={false} onRepair={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('stays silent on a stale reading', () => {
    const { container } = render(<RepairNotice snapshot={snapshotWith(damaged)} stale disabled={false} onRepair={vi.fn()} />);
    expect(container).toBeEmptyDOMElement();
  });

  it.each(locales)('translates the notice and its button in %s', (locale) => {
    setPreviewLanguage(locale);
    const { container } = render(<RepairNotice snapshot={snapshotWith(damaged)} disabled={false} onRepair={vi.fn()} />);
    expect(container).toHaveTextContent(tr(repairNoticeText.damaged));
    expect(screen.getByRole('button', { name: tr('수리하기') })).toBeInTheDocument();
    if (locale !== 'ko') expect(container.textContent).not.toMatch(/[가-힣]/u);
  });
});
