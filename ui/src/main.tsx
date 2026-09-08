// SPDX-License-Identifier: GPL-2.0-or-later
import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from './App';
import { controllerBridge } from './bridge';
import './styles.css';

const root = document.getElementById('root');
if (root) {
  createRoot(root).render(<StrictMode><App bridge={controllerBridge} /></StrictMode>);
}
