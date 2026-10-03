// SPDX-License-Identifier: GPL-2.0-or-later
import type { AppSnapshot } from './contracts';
import { Icon } from './icons';
import { tr } from './i18n';
import { watcherNoticeMessage } from './watcherNoticeText';

export function WatcherNotice({ snapshot, stale = false }: { snapshot: AppSnapshot; stale?: boolean }) {
  const message = watcherNoticeMessage(snapshot, stale);
  if (!message) return null;
  return <section className="notice-box warning watcher-notice" role="alert"><Icon name="alert" /><p>{tr(message)}</p></section>;
}
