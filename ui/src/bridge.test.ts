// SPDX-License-Identifier: GPL-2.0-or-later
// Transport shape only: the Tauri command and its native validation are separate.
import { beforeEach, expect, it, vi } from 'vitest';

const native = vi.hoisted(() => ({ invoke: vi.fn() }));
vi.mock('@tauri-apps/api/core', () => ({ invoke: native.invoke, isTauri: () => true, addPluginListener: vi.fn() }));

beforeEach(() => { native.invoke.mockReset(); native.invoke.mockResolvedValue({}); });

it.each([
  { mode: 'automatic' },
  { mode: 'router_forward', externalPort: 17443 },
  { mode: 'fixed', fixedAddress: '203.0.113.7:7443' },
] as const)('sends $mode external access as the pinned JSON command argument', async (input) => {
  const { controllerBridge } = await import('./bridge');
  await controllerBridge.setExternalAccess(input);
  expect(native.invoke).toHaveBeenCalledExactlyOnceWith('set_external_access', { accessJson: JSON.stringify(input) });
});
