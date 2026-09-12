// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic presentation checks only: no native authentication or visual device proof.
import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import type { AppSnapshot, ControllerBridge, RequestDetailsView, RequestView } from './contracts';
import { displayText, hasDirectionControls } from './displayText';
import { setPreviewLanguage } from './i18n';
import { ko } from './messages';
import { exampleSnapshot } from './qa-fixtures';
import { RequestPanel } from './RequestPanel';

const directionalControls = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u206f]/u;
const shapingText = 'برنامج\u200d\u200c عربي';

function hostileFixture() {
  const request: RequestView = Object.freeze({
    id: 'synthetic-bidi-request-1',
    computerName: 'PC عربي\u2067 synthetic\u2069',
    programName: `${shapingText} \u202Eextension.exe\u202C`,
    executablePath: 'C:\\ملفات\\invoice\u202Eextension.exe\u202C',
    programElided: true,
    pathElided: true,
    hasDetails: true,
    remainingSeconds: 42,
    refreshAfterMillis: 30000,
    state: 'pending',
    canApprove: true,
    canDeny: true,
  });
  const details: RequestDetailsView = Object.freeze({
    version: 1,
    id: request.id,
    programName: `${shapingText} full \u202Eextension.exe\u202C`,
    executablePath: 'C:\\ملفات\\full\\invoice\u202Eextension.exe\u202C',
    details: `"C:\\ملفات\\invoice\u202Eextension.exe\u202C" --fixture="${shapingText}"\n\u2066synthetic argument\u2069`,
    remainingSeconds: 42,
    refreshAfterMillis: 30000,
  });
  const snapshot: AppSnapshot = Object.freeze({
    ...exampleSnapshot('android'),
    requests: Object.freeze([request]),
    requestReview: Object.freeze({ locator: request.id, revision: 'synthetic-review-1' }),
  });
  return { request, details, snapshot };
}

afterEach(() => {
  cleanup();
  setPreviewLanguage('ko');
});

describe('localized request presentation keeps directional text away from decisions', () => {
  it.each(['ko', 'ar'] as const)('isolates original fields and escapes spoofing controls in %s', async (locale) => {
    setPreviewLanguage(locale);
    const { request, details, snapshot } = hostileFixture();
    const before = JSON.stringify({ request, details, snapshot });
    const onDecision = vi.fn<(id: string, decision: 'approve' | 'deny') => void>();
    const readDetails = vi.fn<ControllerBridge['requestDetails']>().mockResolvedValue(details);
    const { container } = render(<section dir={locale === 'ar' ? 'rtl' : 'ltr'} lang={locale}>
      <RequestPanel snapshot={snapshot} disabled={false} onDecision={onDecision}
        readDetails={readDetails} onOpenScanner={vi.fn()} scannerButtonRef={null} />
    </section>);

    const expectedSummary = `${shapingText} [U+202E]extension.exe[U+202C]`;
    const heading = screen.getByRole('heading', { name: expectedSummary });
    expect(heading.querySelector('bdi')).toHaveAttribute('dir', 'ltr');
    expect(heading.textContent).toBe(expectedSummary);
    const computer = container.querySelector('.request-context bdi');
    expect(computer).toHaveAttribute('dir', 'ltr');
    expect(computer?.textContent).toBe('PC عربي[U+2067] synthetic[U+2069]');
    const summaryPath = container.querySelector('.request-card > .request-facts dd');
    expect(summaryPath).toHaveAttribute('dir', 'ltr');
    expect(summaryPath).toHaveClass('original-text');
    expect(summaryPath?.textContent).toBe('C:\\ملفات\\invoice[U+202E]extension.exe[U+202C]');

    const region = screen.getByRole('region', { name: ko.commandDetails });
    const fullProgram = await within(region).findByText(`${shapingText} full [U+202E]extension.exe[U+202C]`);
    const fullPath = within(region).getByText('C:\\ملفات\\full\\invoice[U+202E]extension.exe[U+202C]');
    const command = region.querySelector('pre');
    for (const field of [fullProgram, fullPath, command]) {
      expect(field).toHaveAttribute('dir', 'ltr');
      expect(field).toHaveClass('original-text');
    }
    expect(command?.textContent).toBe(`"C:\\ملفات\\invoice[U+202E]extension.exe[U+202C]" --fixture="${shapingText}"\n[U+2066]synthetic argument[U+2069]`);
    expect(container.textContent).not.toMatch(directionalControls);
    expect(container.textContent).toContain(shapingText);
    expect(container.textContent).toContain('extension.exe');
    expect(readDetails).toHaveBeenCalledExactlyOnceWith(request.id);
    expect(onDecision).not.toHaveBeenCalled();

    fireEvent.click(screen.getByRole('button', { name: ko.approve }));
    fireEvent.click(screen.getByRole('button', { name: ko.deny }));
    expect(onDecision.mock.calls).toEqual([[request.id, 'approve'], [request.id, 'deny']]);
    expect(JSON.stringify({ request, details, snapshot })).toBe(before);
    expect(request.programName).toContain('\u202E');
    expect(details.details).toContain('\u2066');
  });

  it('escapes every directional control beyond 66k characters without truncating the extension', () => {
    const points = [0x061c, 0x200e, 0x200f, 0x202a, 0x202b, 0x202c, 0x202d, 0x202e,
      0x2066, 0x2067, 0x2068, 0x2069, 0x206a, 0x206b, 0x206c, 0x206d, 0x206e, 0x206f];
    const controls = points.map(point => String.fromCodePoint(point)).join('');
    const visible = points.map(point => `[U+${point.toString(16).toUpperCase().padStart(4, '0')}]`).join('');
    const source = controls.repeat(3700) + shapingText + '.exe';
    const before = source;
    expect(source.length).toBeGreaterThan(66000);
    const rendered = displayText(source);
    expect(rendered).toBe(visible.repeat(3700) + shapingText + '.exe');
    expect(rendered.endsWith('.exe')).toBe(true);
    expect(hasDirectionControls(rendered)).toBe(false);
    expect(source).toBe(before);
  });
});
