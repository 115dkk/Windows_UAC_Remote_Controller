// SPDX-License-Identifier: GPL-2.0-or-later
// CI evidence is reconstructed from closed values, never copied from stderr.
import { readFileSync, openSync, fstatSync, readSync, closeSync } from 'node:fs';
const vocabulary = JSON.parse(readFileSync(new URL('./ci-windows-operator/diagnostic-vocabulary.json', import.meta.url), 'utf8'));
const exactKeys = (value, keys) => Object.keys(value).length === keys.length && keys.every(key => Object.hasOwn(value, key));

export function fixtureDiagnostic(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return null;
  if (exactKeys(value, ['state', 'reason', 'identity']) && value.state === 'failed' &&
      value.identity === 'software_ci_fixture' && vocabulary.phoneReasons.includes(value.reason)) {
    return { source: 'phone', stage: 'fixture', reason: value.reason };
  }
  const stages = value.source === 'operator' ? vocabulary.operatorStages : value.source === 'bridge' ? vocabulary.bridgeStages : null;
  if (!stages || !exactKeys(value, ['status', 'source', 'stage', 'gate']) || value.status !== 'failed' ||
      !stages.includes(value.stage) || !vocabulary.gates.includes(value.gate)) return null;
  return { source: value.source, stage: value.stage, reason: value.gate };
}

export function operatorStartupDiagnostic() {
  // Producer creates this fixed path with a protected SY/BA descriptor. This
  // consumer grants no trust/authority and publishes only reconstructed enums.
  let fd;
  try {
    fd = openSync('C:\\ProgramData\\UacRemoteCiE2e\\operator-startup-failure.json', 'r');
    const info = fstatSync(fd);
    if (!info.isFile() || info.size < 1 || info.size > 512) return null;
    const bytes = Buffer.alloc(513);
    const count = readSync(fd, bytes, 0, bytes.length, 0);
    if (count < 1 || count > 512) return null;
    const value = JSON.parse(bytes.subarray(0, count).toString('utf8'));
    const record = fixtureDiagnostic(value);
    return record?.source === 'operator' && ['startup', 'pipe_wait'].includes(record.stage) ? record : null;
  } catch { return null; }
  finally { if (fd !== undefined) { try { closeSync(fd); } catch { /* Diagnostic-only. */ } } }
}
