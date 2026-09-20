// SPDX-License-Identifier: GPL-2.0-or-later
// Real stock PowerShell module-load regression; no UAC or ACL modification.
import assert from 'node:assert/strict';
import test from 'node:test';
import { windowsPowerShell } from './windows-ci-powershell.mjs';

test('Windows PowerShell loads its ACL module despite inherited pwsh module paths', { skip: process.platform !== 'win32' }, () => {
  const result = JSON.parse(windowsPowerShell("$acl=Get-Acl -LiteralPath $env:SystemRoot;@{major=$PSVersionTable.PSVersion.Major;aclLoaded=($null -ne $acl -and $null -ne (Get-Command Get-Acl).Module)}|ConvertTo-Json -Compress"));
  assert.deepEqual(result, { major: 5, aclLoaded: true });
});

test('Windows PowerShell reports a command failure as nonzero', { skip: process.platform !== 'win32' }, () => {
  assert.throws(() => windowsPowerShell("Get-Acl -LiteralPath 'C:\\UacRemoteCiDeliberatelyMissing\\absent'"));
});
