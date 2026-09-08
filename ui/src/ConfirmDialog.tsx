// SPDX-License-Identifier: GPL-2.0-or-later
import { useEffect, useId, useRef } from 'react';
import { ko } from './messages.ko';

export interface Confirmation {
  readonly title: string;
  readonly body: string;
  readonly subject?: string;
  readonly confirmLabel: string;
  readonly onConfirm: () => void;
}

export function ConfirmDialog({ confirmation, onClose }: { confirmation: Confirmation; onClose: () => void }) {
  const dialog = useRef<HTMLDialogElement>(null);
  const titleId = useId();
  const descriptionId = useId();
  useEffect(() => {
    const element = dialog.current;
    const previousFocus = document.activeElement;
    element?.showModal();
    element?.querySelector<HTMLButtonElement>('.dialog-actions button')?.focus();
    return () => {
      element?.close();
      if (previousFocus instanceof HTMLElement && previousFocus.isConnected && !previousFocus.matches(':disabled')) previousFocus.focus();
      else document.querySelector<HTMLElement>('#main-content h1')?.focus();
    };
  }, []);
  return (
    <dialog ref={dialog} className="confirm-dialog" aria-labelledby={titleId} aria-describedby={descriptionId}
      onCancel={(event) => { event.preventDefault(); onClose(); }}>
      <h2 id={titleId}>{confirmation.title}</h2>
      {confirmation.subject && <p className="dialog-subject"><bdi>{confirmation.subject}</bdi></p>}
      <p id={descriptionId}>{confirmation.body}</p>
      <div className="dialog-actions">
        <button type="button" className="button secondary" onClick={onClose}>{ko.cancel}</button>
        <button type="button" className="button danger" onClick={() => { onClose(); confirmation.onConfirm(); }}>{confirmation.confirmLabel}</button>
      </div>
    </dialog>
  );
}
