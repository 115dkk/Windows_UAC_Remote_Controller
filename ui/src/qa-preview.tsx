// SPDX-License-Identifier: GPL-2.0-or-later
// Separate build entry. Never import this file from main.tsx or the native bridge.
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createQaBridge, qaCase } from './qa-fixtures';
import { ko } from './messages';
import { isPreference, setPreviewLanguage } from './i18n';
import type { TaskbarBridge, TaskbarStatus } from './TaskbarSuggestion';
import './styles.css';
import './i18n.css';

if (import.meta.env.MODE !== 'qa' || '__TAURI_INTERNALS__' in window) {
  throw new Error('This synthetic gallery is only available in the separate browser QA build.');
}

const fixtureName = new URLSearchParams(window.location.search).get('case') ?? 'desktop-empty';
const previewLocale = new URLSearchParams(window.location.search).get('locale');
setPreviewLanguage(isPreference(previewLocale) ? previewLocale : 'ko');
const taskbarFixture = fixtureName === 'desktop-taskbar-available' || fixtureName === 'desktop-taskbar-unavailable';
const selected = qaCase(taskbarFixture ? 'desktop-running' : fixtureName);
const taskbarClient: TaskbarBridge | undefined = taskbarFixture ? {
  offer: () => Promise.resolve({ version: 'synthetic-gallery', status: fixtureName === 'desktop-taskbar-available' ? 'available' : 'unavailable' }),
  request: () => Promise.resolve<TaskbarStatus>('declined'),
} : undefined;
const bridge = createQaBridge(selected.snapshot, selected.scannerFailure);
const root = document.getElementById('root');
if (root) createRoot(root).render(<div className="qa-frame"><aside className="qa-label" aria-label={ko.exampleDescription}>{ko.example}</aside><App bridge={bridge} initialPage={selected.page} taskbarClient={taskbarClient} /></div>);
