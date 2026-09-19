// SPDX-License-Identifier: GPL-2.0-or-later
import { useId } from 'react';
import type { Ref } from 'react';
import type { AppSnapshot } from './contracts';
import { Icon } from './icons';
import { ko } from './messages';
import { hasNoPairedPc } from './phoneConnection';
import { tr } from './i18n';

export function PairingEntry({ snapshot, disabled, onOpenScanner, onOpenUsb, scannerButtonRef }: {
  snapshot: AppSnapshot; disabled: boolean; onOpenScanner: () => void;
  scannerButtonRef?: Ref<HTMLButtonElement>;
  onOpenUsb?: () => void;
}) {
  const heading = useId();
  const description = useId();
  const unavailable = useId();
  const canScan = snapshot.mobile?.canOpenPairingScanner === true;
  return <section className="surface pairing-entry" aria-labelledby={heading}>
    <div className="service-heading-row"><Icon name="pc" /><h2 id={heading}>{hasNoPairedPc(snapshot) ? ko.noComputers : ko.pairComputer}</h2></div>
    <p id={description} className="supporting-text">{ko.pairingGuide}</p>
    <button ref={scannerButtonRef} data-pairing-scanner="open" type="button" className="button primary"
      disabled={disabled || !canScan} aria-describedby={`${description}${canScan ? '' : ` ${unavailable}`}`}
      onClick={onOpenScanner}>{ko.openPairingScanner}</button>
    {onOpenUsb && <button type="button" className="button secondary" disabled={disabled || !canScan} onClick={onOpenUsb}>{tr('USB로 연결')}</button>}
    {!canScan && <p id={unavailable} className="supporting-text">{snapshot.phoneService?.state === 'unavailable' ? ko.policyRestartOwner : ko.pairingScannerNotReady}</p>}
  </section>;
}
