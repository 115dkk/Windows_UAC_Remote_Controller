// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only Windows PowerShell host; no product endpoint or elevation operation.
import { execFileSync } from 'node:child_process';
import { resolve } from 'node:path';

export function windowsPowerShell(script) {
  if (process.platform !== 'win32') throw new Error('Windows PowerShell requires Windows');
  const shell = resolve(process.env.SystemRoot, 'System32/WindowsPowerShell/v1.0/powershell.exe');
  const env = { ...process.env };
  // pwsh adds its .NET/Core modules to this inherited variable. Windows
  // PowerShell must construct its own stock module path for .NET Framework.
  for (const key of Object.keys(env)) if (key.toLowerCase() === 'psmodulepath') delete env[key];
  return execFileSync(shell, ['-NoProfile', '-NonInteractive', '-Command', `$ErrorActionPreference='Stop';${script}`], {
    // Cold CIM/NetTCPIP module initialization exceeded15s on CI34807865655.
    // This fixed CI subprocess budget is separate from product/consent cutoffs.
    env, windowsHide: true, encoding: 'utf8', timeout: 45000, maxBuffer: 128 * 1024,
  }).trim();
}
