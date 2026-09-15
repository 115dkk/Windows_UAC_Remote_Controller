// SPDX-License-Identifier: GPL-2.0-or-later
// Separate build entry. Never import this file from main.tsx or the native bridge.
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createQaBridge, qaCase } from './qa-fixtures';
import { ko } from './messages';
import { isPreference, setPreviewLanguage } from './i18n';
import { PairingCeremony } from './PairingCeremony';
import type { CeremonyScreen } from './PairingCeremony';
import type { TaskbarBridge, TaskbarStatus } from './TaskbarSuggestion';
import './styles.css';
import './i18n.css';

if (import.meta.env.MODE !== 'qa' || '__TAURI_INTERNALS__' in window) {
  throw new Error('This synthetic gallery is only available in the separate browser QA build.');
}

const fixtureName = new URLSearchParams(window.location.search).get('case') ?? 'desktop-empty';
const previewLocale = new URLSearchParams(window.location.search).get('locale');
setPreviewLanguage(isPreference(previewLocale) ? previewLocale : 'ko');
const root = document.getElementById('root');
const banner = <aside className="qa-label" aria-label={ko.exampleDescription}>{ko.example}</aside>;
// The native pairing ceremony is painted by GDI on its own private desktop.
// These two fixtures draw the same geometry and copy in the client so the layout
// can be reviewed. They are not native proof and they carry no invitation.
const ceremony: CeremonyScreen | null = fixtureName === 'pairing-ceremony-introduction' ? 'introduction'
  : fixtureName === 'pairing-ceremony-invitation' ? 'invitation' : null;
if (root && ceremony) {
  createRoot(root).render(<div className="qa-frame">{banner}
    <PairingCeremony screen={ceremony} /></div>);
} else if (root) {
  const taskbarFixture = fixtureName === 'desktop-taskbar-available' || fixtureName === 'desktop-taskbar-unavailable';
  const selected = qaCase(taskbarFixture ? 'desktop-running' : fixtureName);
  const taskbarClient: TaskbarBridge | undefined = taskbarFixture ? {
    offer: () => Promise.resolve({ version: 'synthetic-gallery', status: fixtureName === 'desktop-taskbar-available' ? 'available' : 'unavailable' }),
    request: () => Promise.resolve<TaskbarStatus>('declined'),
  } : undefined;
  const bridge = createQaBridge(selected.snapshot, selected.scannerFailure);
  createRoot(root).render(<div className="qa-frame">{banner}
    <App bridge={bridge} initialPage={selected.page} taskbarClient={taskbarClient} /></div>);
}
