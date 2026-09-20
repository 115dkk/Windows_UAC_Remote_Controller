// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic DOM tests; Android system Back is exercised separately in CI.
import { act, fireEvent, render, screen } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, it, vi } from 'vitest';
import { LanguageSettings } from './LanguageSettings';
import * as language from './i18n';

afterEach(() => { vi.restoreAllMocks(); });

it('cancels an uncommitted language choice without persisting it', async () => {
  const save = vi.spyOn(language, 'setLanguage');
  const close = vi.fn();
  render(<LanguageSettings onClose={close} />);
  await userEvent.click(screen.getByRole('radio', { name: 'English' }));
  const event = new Event('cancel', { cancelable: true });
  fireEvent(screen.getByRole('dialog'), event);
  expect(event.defaultPrevented).toBe(true);
  expect(close).toHaveBeenCalledTimes(1);
  expect(save).not.toHaveBeenCalled();
});

it('consumes cancel while a save is pending and permits retry after failure', async () => {
  let reject!: (reason: Error) => void;
  const save = vi.spyOn(language, 'setLanguage').mockImplementation(() =>
    new Promise<void>((_resolve, fail) => { reject = fail; }));
  const close = vi.fn();
  render(<LanguageSettings onClose={close} />);
  await userEvent.click(screen.getByRole('button', { name: '적용' }));
  const event = new Event('cancel', { cancelable: true });
  fireEvent(screen.getByRole('dialog'), event);
  expect(event.defaultPrevented).toBe(true);
  expect(close).not.toHaveBeenCalled();
  expect(save).toHaveBeenCalledTimes(1);
  await act(async () => { reject(new Error('synthetic save failure')); await Promise.resolve(); });
  expect(screen.getByRole('alert')).toBeInTheDocument();
  fireEvent(screen.getByRole('dialog'), new Event('cancel', { cancelable: true }));
  expect(close).toHaveBeenCalledTimes(1);
});
