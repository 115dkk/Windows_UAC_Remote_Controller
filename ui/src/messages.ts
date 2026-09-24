// SPDX-License-Identifier: GPL-2.0-or-later
// Keep canonical authored copy separate from mutable locale presentation.
import * as original from './messages.ko';
import { formatText, numberText, tr } from './i18n';
import type { AppSnapshot, PairedDeviceView, PhoneServiceView } from './contracts';

const proxies = new WeakMap<object, object>();
function translated<T extends object>(source: T): T {
  const old = proxies.get(source);
  if (old) return old as T;
  const proxy = new Proxy(source, { get(target, key, receiver): unknown {
    const value: unknown = Reflect.get(target, key, receiver);
    if (typeof value === 'string') return tr(value);
    if (value !== null && typeof value === 'object') return translated(value);
    return value;
  } });
  proxies.set(source, proxy);
  return proxy;
}
export const ko = translated(original.ko);
export const serviceStateText = translated(original.serviceStateText);
export const phoneServiceStateText = translated(original.phoneServiceStateText);
export const serviceActionText = translated(original.serviceActionText);
export const serviceConfirmText = translated(original.serviceConfirmText);
export const alertModeText = translated(original.alertModeText);
export const activityText = translated(original.activityText);
export const weekdayOptions = translated(original.weekdayOptions);
export const devicesUnavailableText = (snapshot: AppSnapshot): string => tr(original.devicesUnavailableText(snapshot));
export const activityUnavailableText = (snapshot: AppSnapshot): string => tr(original.activityUnavailableText(snapshot));
export const connectionUnknownText = (snapshot: AppSnapshot): string => tr(original.connectionUnknownText(snapshot));
export const policyUnavailableText = (service: PhoneServiceView | null): string => tr(original.policyUnavailableText(service));
export const policyUnavailableTitleText = (service: PhoneServiceView | null): string => tr(original.policyUnavailableTitleText(service));
export const timeWindowLabel = (index: number): string => formatText('시간대 {index}', {index:numberText(index+1)});
export const remainingLabel = (seconds: number): string => formatText('마지막 확인 시 {seconds}초 남음', {seconds:numberText(Math.max(0,Math.floor(seconds)))});
/** Windows management has no user-authored friendly name yet; localize only its
 * exact generated ID label, never Android PC or user-supplied names. */
export function deviceLabel(device: PairedDeviceView, pc: boolean): string {
  const id = device.id.slice(0, 8);
  if (pc && /^[a-f0-9]{32}$/u.test(device.id) && device.name === `휴대폰 ${id}`) return formatText('휴대폰 {id}', { id });
  return device.name;
}
