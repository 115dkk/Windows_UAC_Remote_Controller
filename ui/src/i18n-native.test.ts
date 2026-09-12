// SPDX-License-Identifier: GPL-2.0-or-later
// Deferred transport mocks exercise presentation ordering, not native OS proof.
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

const native = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke, isTauri: () => true }));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (error: Error) => void;
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
}
const reply = (preference: string) => ({ preference, systemLocales: ['en-US'] });
beforeEach(() => { vi.resetModules(); native.invoke.mockReset(); });
afterEach(() => { vi.useRealTimers(); vi.restoreAllMocks(); });

it('coalesces outstanding reads and runs a manual save after the old reply', async () => {
  const language = await import('./i18n');
  const read = deferred<ReturnType<typeof reply>>();
  const write = deferred<ReturnType<typeof reply>>();
  native.invoke.mockReturnValueOnce(read.promise).mockReturnValueOnce(write.promise);
  const reads = Array.from({ length: 20 }, () => language.refreshLanguage());
  const saving = language.setLanguage('ar');
  await Promise.resolve();
  expect(native.invoke.mock.calls).toEqual([['get_language']]);
  read.resolve(reply('ko'));
  await Promise.all(reads);
  expect(native.invoke.mock.calls).toEqual([['get_language'], ['set_language', { language: 'ar' }]]);
  write.resolve(reply('ar'));
  await saving;
  expect(language.currentLocale()).toBe('ar');
});

it('defers a focus refresh until the manual save has published its result', async () => {
  const language = await import('./i18n');
  const write = deferred<ReturnType<typeof reply>>();
  native.invoke.mockReturnValueOnce(write.promise).mockResolvedValueOnce(reply('de'));
  const saving = language.setLanguage('de');
  const refresh = language.refreshLanguage();
  await Promise.resolve();
  expect(native.invoke.mock.calls).toEqual([['set_language', { language: 'de' }]]);
  write.resolve(reply('de'));
  await saving;
  await refresh;
  expect(native.invoke.mock.calls).toEqual([['set_language', { language: 'de' }], ['get_language']]);
  expect(language.currentLocale()).toBe('de');
});

it('returns an explicit save failure while allowing the next operation to proceed', async () => {
  const language = await import('./i18n');
  const write = deferred<ReturnType<typeof reply>>();
  const failure = new Error('native_write_failed');
  native.invoke.mockReturnValueOnce(write.promise).mockResolvedValueOnce(reply('fr'));
  const failed = expect(language.setLanguage('ar')).rejects.toBe(failure);
  const next = language.setLanguage('fr');
  write.reject(failure);
  await failed;
  await next;
  expect(native.invoke.mock.calls).toEqual([['set_language', { language: 'ar' }], ['set_language', { language: 'fr' }]]);
  expect(language.currentLocale()).toBe('fr');
});

it('uses presentation fallback after a failed read without poisoning later reads', async () => {
  const language = await import('./i18n');
  vi.spyOn(navigator, 'languages', 'get').mockReturnValue(['fr-CA']);
  language.setPreviewLanguage('system', ['ko-KR']);
  native.invoke.mockRejectedValueOnce(new Error('native_read_failed')).mockResolvedValueOnce(reply('ja'));
  await language.refreshLanguage();
  expect(language.currentLocale()).toBe('fr');
  await language.refreshLanguage();
  expect(language.currentLocale()).toBe('ja');
  expect(native.invoke).toHaveBeenCalledTimes(2);
});

it('rejects invalid save replies and recovers the operation sequence', async () => {
  const language = await import('./i18n');
  native.invoke.mockResolvedValueOnce(reply('not-a-locale')).mockResolvedValueOnce(reply('es'));
  await expect(language.setLanguage('ar')).rejects.toThrow('language_reply_invalid');
  await language.setLanguage('es');
  expect(language.currentLocale()).toBe('es');
});

it('keeps first paint bounded when native work and font loading are stalled', async () => {
  vi.useFakeTimers();
  const language = await import('./i18n');
  language.setPreviewLanguage('en');
  const read = deferred<ReturnType<typeof reply>>();
  const fonts = deferred<never[]>();
  const descriptor = Object.getOwnPropertyDescriptor(document, 'fonts');
  Object.defineProperty(document, 'fonts', { configurable: true, value: { load: () => fonts.promise } });
  // This test concerns initialization timing, not persistent browser listeners.
  vi.spyOn(window, 'addEventListener').mockImplementation(() => {});
  native.invoke.mockReturnValueOnce(read.promise).mockResolvedValueOnce(reply('ar'));
  try {
    let ready = false;
    const initialization = language.initializeLanguage().then(() => { ready = true; });
    await vi.advanceTimersByTimeAsync(3000);
    expect(ready).toBe(false);
    await vi.advanceTimersByTimeAsync(3000);
    await initialization;
    expect(ready).toBe(true);
    expect(document.documentElement.lang).toBe('en');
    const saving = language.setLanguage('ar');
    await Promise.resolve();
    expect(native.invoke.mock.calls).toEqual([['get_language']]);
    read.resolve(reply('en'));
    await saving;
    expect(language.currentLocale()).toBe('ar');
  } finally {
    fonts.resolve([]);
    if (descriptor) Object.defineProperty(document, 'fonts', descriptor);
    else Reflect.deleteProperty(document, 'fonts');
  }
});
