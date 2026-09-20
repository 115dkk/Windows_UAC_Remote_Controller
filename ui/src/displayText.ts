// SPDX-License-Identifier: GPL-2.0-or-later
// Presentation only. Never feed this representation into a request digest,
// signature, executable path, clipboard command, or authorization decision.
const directionControls = /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u206f]/gu;
export function displayText(original: string): string {
  return original.replace(directionControls, value => `[U+${value.codePointAt(0)!.toString(16).toUpperCase().padStart(4, '0')}]`);
}
export function hasDirectionControls(original: string): boolean {
  return /[\u061c\u200e\u200f\u202a-\u202e\u2066-\u206f]/u.test(original);
}
