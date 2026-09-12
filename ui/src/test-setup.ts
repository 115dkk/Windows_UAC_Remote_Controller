// SPDX-License-Identifier: GPL-2.0-or-later
import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, beforeEach } from 'vitest';
import { setPreviewLanguage } from './i18n';

// Existing Korean consumer-copy fixtures are explicit. Production defaults use OS locale.
beforeEach(() => { setPreviewLanguage('ko'); document.documentElement.lang='ko'; document.documentElement.dir='ltr'; });

afterEach(cleanup);

// JSDOM-only HTML dialog shim. This is not evidence of a native dialog or OS behavior.
if (typeof HTMLDialogElement.prototype.showModal !== 'function') {
  Object.defineProperty(HTMLDialogElement.prototype, 'showModal', {
    configurable: true,
    value(this: HTMLDialogElement) { this.open = true; },
  });
}
if (typeof HTMLDialogElement.prototype.close !== 'function') {
  Object.defineProperty(HTMLDialogElement.prototype, 'close', {
    configurable: true,
    value(this: HTMLDialogElement) { this.open = false; },
  });
}
