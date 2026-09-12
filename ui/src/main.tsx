// SPDX-License-Identifier: GPL-2.0-or-later
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { controllerBridge } from './bridge';
import './styles.css';
import './i18n.css';
import { initializeLanguage } from './i18n';

const root = document.getElementById('root');
if (root) void initializeLanguage().then(() => { createRoot(root).render(<StrictMode><App bridge={controllerBridge} /></StrictMode>); });
