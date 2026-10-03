// SPDX-License-Identifier: GPL-2.0-or-later
// Synthetic DTO cases, not proof that the native watcher reports these states.
import { render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import type { AppSnapshot, WatcherStatus } from './contracts';
import { locales, setPreviewLanguage, tr } from './i18n';
import { qaCase } from './qa-fixtures';
import { WatcherNotice } from './WatcherNotice';
import { watcherNoticeText } from './watcherNoticeText';

const running = qaCase('desktop-relay-listening').snapshot;
const withWatcher = (watcherStatus: WatcherStatus | null, source: AppSnapshot = running): AppSnapshot => ({ ...source, watcherStatus });

describe('watcher notice', () => {
  afterEach(() => setPreviewLanguage('ko'));

  it('says the helper file is damaged and what to do', () => {
    render(<WatcherNotice snapshot={withWatcher({ state: 'unavailable', refusal: 'helper_damaged' })} />);
    expect(screen.getByRole('alert')).toHaveTextContent(watcherNoticeText.damaged);
  });

  it('says the helper did not start and that the service retries', () => {
    render(<WatcherNotice snapshot={withWatcher({ state: 'unavailable', refusal: 'helper_failed' })} />);
    expect(screen.getByRole('alert')).toHaveTextContent(watcherNoticeText.failed);
  });

  it.each<[string, WatcherStatus | null]>([
    ['an older service that does not report', null],
    ['a starting watcher', { state: 'starting', refusal: null }],
    ['a running watcher', { state: 'running', refusal: null }],
    ['no signed-in user', { state: 'unavailable', refusal: 'no_signed_in_user' }],
  ])('stays silent for %s', (_, status) => {
    const { container } = render(<WatcherNotice snapshot={withWatcher(status)} />);
    expect(container).toBeEmptyDOMElement();
  });

  it('stays silent on a stale reading or a stopped service', () => {
    const damaged: WatcherStatus = { state: 'unavailable', refusal: 'helper_damaged' };
    const stale = render(<WatcherNotice snapshot={withWatcher(damaged)} stale />);
    expect(stale.container).toBeEmptyDOMElement();
    const stopped = render(<WatcherNotice snapshot={withWatcher(damaged, qaCase('desktop-relay-stopped').snapshot)} />);
    expect(stopped.container).toBeEmptyDOMElement();
  });

  it.each(locales)('translates both notices in %s', (locale) => {
    setPreviewLanguage(locale);
    for (const refusal of ['helper_damaged', 'helper_failed'] as const) {
      const { container, unmount } = render(<WatcherNotice snapshot={withWatcher({ state: 'unavailable', refusal })} />);
      const text = tr(refusal === 'helper_damaged' ? watcherNoticeText.damaged : watcherNoticeText.failed);
      expect(container).toHaveTextContent(text);
      if (locale !== 'ko') expect(container.textContent).not.toMatch(/[가-힣]/u);
      unmount();
    }
  });
});
