// SPDX-License-Identifier: GPL-2.0-or-later
// Separate build entry. Never import this file from main.tsx or the native bridge.
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { createQaBridge, qaCase } from './qa-fixtures';
import { ko } from './messages.ko';
import './styles.css';

if (import.meta.env.MODE !== 'qa' || '__TAURI_INTERNALS__' in window) {
  throw new Error('This synthetic gallery is only available in the separate browser QA build.');
}

const selected = qaCase(new URLSearchParams(window.location.search).get('case') ?? 'desktop-empty');
const bridge = createQaBridge(selected.snapshot, selected.scannerFailure);
const root = document.getElementById('root');
if (root) createRoot(root).render(<div className="qa-frame"><aside className="qa-label" aria-label={ko.exampleDescription}>{ko.example}</aside><App bridge={bridge} initialPage={selected.page} /></div>);
