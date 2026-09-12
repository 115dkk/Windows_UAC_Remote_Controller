// SPDX-License-Identifier: GPL-2.0-or-later
import { describe, expect, it } from 'vitest';
import { displayText, hasDirectionControls } from './displayText';

describe('display-only directional control escaping', () => {
  it('makes extension spoofing and isolation controls visible without mutating the original', () => {
    const original = 'C:\\ملفات\\invoice\u202Egpj.exe\u202C --arg=\u2066value\u2069';
    expect(displayText(original)).toBe('C:\\ملفات\\invoice[U+202E]gpj.exe[U+202C] --arg=[U+2066]value[U+2069]');
    expect(original).toContain('\u202E');
    expect(hasDirectionControls(displayText(original))).toBe(false);
  });
  it('preserves Arabic shaping characters, text, and ordinary path syntax', () => {
    const original = 'برنامج عربي\u200D\u200C 日本語 é.exe --x="a&b"';
    expect(displayText(original)).toBe(original);
  });
  it('escapes all directional controls, including deprecated ones, with no truncation', () => {
    const points = [0x061c,0x200e,0x200f,0x202a,0x202b,0x202c,0x202d,0x202e,0x2066,0x2067,0x2068,0x2069,0x206a,0x206b,0x206c,0x206d,0x206e,0x206f];
    for (const point of points) expect(displayText(String.fromCodePoint(point))).toBe(`[U+${point.toString(16).toUpperCase().padStart(4,'0')}]`);
    expect(displayText('\u202E'.repeat(65536) + '.exe')).toHaveLength(65536 * 8 + 4);
    expect(displayText('\u202E'.repeat(65536) + '.exe')).toMatch(/\.exe$/u);
  });
});
