// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';
import { Icon } from './icons';
import { tr } from './i18n';
import { serviceActionText } from './messages';
import { repairNoticeKind, repairNoticeText } from './repairNoticeText';

/** The repair offer or the reinstall advice. The button is shown only while the
 * native owner lists repair as allowed; it is checked again there. */
export function RepairNotice({ snapshot, stale = false, disabled, onRepair }: {
  snapshot: AppSnapshot; stale?: boolean; disabled: boolean; onRepair: () => void;
}) {
  const kind = repairNoticeKind(snapshot, stale);
  if (!kind) return null;
  const canRepair = kind === 'repair' && snapshot.service?.allowedActions.includes('repair') === true;
  return <section className="notice-box warning repair-notice" role="alert"><Icon name="alert" />
    <div>
      <p>{tr(kind === 'repair' ? repairNoticeText.damaged : repairNoticeText.sourceDamaged)}</p>
      {canRepair && <button type="button" className="button primary" disabled={disabled} onClick={onRepair}>{serviceActionText.repair}</button>}
    </div>
  </section>;
}
