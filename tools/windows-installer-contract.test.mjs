// SPDX-License-Identifier: GPL-2.0-or-later
// Source-packaging contracts only. These tests never compile/run NSIS, an
// installer, a service, Win32 calls or UAC; ROOT owns all executable validation.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import test from 'node:test';

const root = fileURLToPath(new URL('../', import.meta.url));
const read = (name) => readFileSync(resolve(root, name), 'utf8').replace(/\r\n?/gu, '\n');
// Ignore whole-line source comments, not quoted SDDL/text or executable lines.
const instructions = (source) => source.split('\n').map((line) => line.trim())
  .filter((line) => line && !line.startsWith(';') && !line.startsWith('# '));
const template = instructions(read('src-tauri/windows/installer.nsi'));
const hooks = instructions(read('src-tauri/windows/packaging-hooks.nsh'));
const base = JSON.parse(read('src-tauri/tauri.conf.json'));
const overlay = JSON.parse(read('src-tauri/windows/package-config.json'));

function position(lines, token, after = -1) {
  const at = lines.findIndex((line, index) => index > after && line === token);
  assert.notEqual(at, -1, `Required source instruction missing: ${token}`);
  return at;
}
function ordered(lines, tokens) {
  let at = -1;
  for (const token of tokens) at = position(lines, token, at);
}
function block(lines, start, end) {
  assert.equal(lines.filter((line) => line === start).length, 1, `Expected one ${start}`);
  const first = position(lines, start);
  return lines.slice(first + 1, position(lines, end, first));
}
const section = (name) => block(template, 'Section ' + name, 'SectionEnd');
const hook = (name) => block(hooks, '!macro NSIS_HOOK_' + name, '!macroend');
const native = (name) => block(hooks, 'Function ${PREFIX}' + name, 'FunctionEnd');
function rejectingGuard(lines, first) {
  const at = position(lines, first);
  const end = position(lines, '!endif', at);
  assert.ok(lines.slice(at + 1, end).some((line) => line.startsWith('!error ')), `Guard must reject: ${first}`);
}
function checkedExec(lines, verb, failure) {
  const command = 'ExecWait \'"$INSTDIR\\uac-service.exe" ' + verb + '\' $0';
  const at = position(lines, command);
  assert.equal(lines[at - 1], 'ClearErrors', `${verb} clears the NSIS error flag before ExecWait`);
  assert.deepEqual(lines.slice(at + 1, at + 5), ['${If} ${Errors}', '${OrIf} $0 <> 0', 'Call ' + failure, '${EndIf}'], `${verb} must reject launch and native nonzero exit`);
  return at;
}

test('source contract fixes per-machine x64 package and protected product names', () => {
  assert.equal(base.bundle.windows.nsis.installMode, 'perMachine');
  assert.equal(base.bundle.windows.allowDowngrades, false);
  assert.equal(base.bundle.windows.nsis.template, 'windows/installer.nsi');
  assert.equal(base.bundle.windows.nsis.installerHooks, 'windows/packaging-hooks.nsh');
  assert.deepEqual(base.bundle.windows.nsis.languages, ['Korean', 'English']);
  for (const guard of ['!if "${INSTALLMODE}" != "perMachine"', '!if "${ARCH}" != "x64"',
    '!if "${MAINBINARYNAME}" != "controller-app"', '!if "${PRODUCTNAME}" != "UAC 원격 승인"']) rejectingGuard(template, guard);
  position(template, '!define INSTALLATIONID "휴대폰 승인"');
  position(template, '!define PLACEHOLDER_INSTALL_DIR "placeholder\\${INSTALLATIONID}"');
  position(template, '!define UNINSTKEY "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\${INSTALLATIONID}"');
  position(template, 'RequestExecutionLevel admin');
  ordered(native('UacFixedLocation'), ['${IfNot} ${RunningX64}', 'Call ${PREFIX}UacFail',
    'StrCpy $UacDirectory "$PROGRAMFILES64\\휴대폰 승인"', '${If} $INSTDIR != "placeholder\\휴대폰 승인"',
    '${AndIf} $INSTDIR != $UacDirectory', 'Call ${PREFIX}UacFail', 'StrCpy $INSTDIR $UacDirectory']);
  assert.ok(!template.some((line) => /MUI_PAGE_DIRECTORY|ReadRegStr.*\$INSTDIR/u.test(line)));
});

test('source contract rejects missing duplicate or extra helper payloads at NSIS preprocessing', () => {
  assert.deepEqual(overlay.bundle.externalBin, ['../target/windows-package/inputs/uac-service', '../target/windows-package/inputs/uac-prompt-probe']);
  const declarations = template.slice(position(template, '{{#each binaries}}'), position(template, '{{/each}}'));
  ordered(declarations, ['!if "{{this}}" == "uac-service.exe"', '!ifdef UAC_SERVICE_INCLUDED',
    '!define UAC_SERVICE_INCLUDED', '!else if "{{this}}" == "uac-prompt-probe.exe"',
    '!ifdef UAC_PROBE_INCLUDED', '!define UAC_PROBE_INCLUDED', '!else']);
  assert.ok(declarations.some((line) => line.includes('!error "Unexpected external executable')));
  rejectingGuard(template, '!ifndef UAC_SERVICE_INCLUDED');
  rejectingGuard(template, '!ifndef UAC_PROBE_INCLUDED');
});

test('branding migration preserves installation identity and only renames owned legacy shortcuts', () => {
  const migration = block(template, '!macro UacMigrateShortcut OLD NEW', '!macroend');
  ordered(migration, ['!insertmacro IsShortcutTarget "${OLD}" "$INSTDIR\\${MAINBINARYNAME}.exe"',
    'Pop $0', '${If} $0 = 1', '${If} ${FileExists} "${NEW}"', 'Call UacFail', '${EndIf}',
    'ClearErrors', 'Rename "${OLD}" "${NEW}"', '${If} ${Errors}', 'Call UacFail']);
  for (const name of ['CreateOrUpdateStartMenuShortcut', 'CreateOrUpdateDesktopShortcut']) {
    const body = block(template, `Function ${name}`, 'FunctionEnd');
    const rename = body.findIndex(line => line.startsWith('!insertmacro UacMigrateShortcut'));
    assert.ok(rename >= 0 && rename < position(body, '${If} $UpdateMode = 1'), 'existing owned shortcut migrates before update creation is skipped');
    assert.ok(position(body, '${If} $NoShortcutMode <> 1') < rename);
  }
  const uninstall = section('Uninstall');
  for (const path of ['$SMPROGRAMS\\$AppStartMenuFolder', '$SMPROGRAMS', '$DESKTOP']) {
    ordered(uninstall, [`!insertmacro IsShortcutTarget "${path}\\\${INSTALLATIONID}.lnk" "$INSTDIR\\\${MAINBINARYNAME}.exe"`,
      'Pop $0', '${If} $0 = 1', `!insertmacro UnpinShortcut "${path}\\\${INSTALLATIONID}.lnk"`,
      'ClearErrors', `Delete "${path}\\\${INSTALLATIONID}.lnk"`, '${If} ${Errors}', 'Call un.UacFail']);
  }
});

test('source contract runs PREINSTALL before destination writes and POSTINSTALL after all packaged files', () => {
  const install = section('Install');
  const before = position(install, '!insertmacro NSIS_HOOK_PREINSTALL');
  const after = position(install, '!insertmacro NSIS_HOOK_POSTINSTALL');
  const writes = install.flatMap((line, index) => /^(?:SetOutPath|File|CreateDirectory|WriteUninstaller)\b/u.test(line) ? [index] : []);
  assert.ok(writes.length >= 4, 'Expected actual destination/payload/uninstaller instructions');
  for (const index of writes) assert.ok(before < index && index < after, `Destination write outside pre/post hooks: ${install[index]}`);
  ordered(install, ['StrCpy $UacFailure "$(UacCopyFailed)"', 'ClearErrors', 'SetOutPath $INSTDIR', '${If} ${Errors}', 'Call UacFail']);
  const pre = hook('PREINSTALL');
  assert.ok(position(pre, 'Call UacInspectFiles') < checkedExec(pre, 'stop', 'UacFail'));
  ordered(pre, ['Call UacPrepare', '${If} $UacDirectoryPin = 0', 'Call UacInspectFiles',
    'Call UacRequireServiceAbsent', 'Call UacReleaseFiles']);
  assert.ok(!pre.includes('Call UacRelease'), 'Parent/directory pins must survive binary replacement');
});

test('source contract restricts elevated child execution to four checked fixed service verbs', () => {
  assert.deepEqual(hooks.filter((line) => line.startsWith('ExecWait ')), ['stop', 'install', 'start', 'uninstall']
    .map((verb) => 'ExecWait \'"$INSTDIR\\uac-service.exe" ' + verb + '\' $0'));
  const post = hook('POSTINSTALL');
  ordered(post, ['Call UacInspectFiles', '${If} $UacServicePin = 0', '${OrIf} $UacProbePin = 0',
    '${OrIf} $UacAppPin = 0', '${OrIf} $UacUninstallerPin = 0', 'Call UacFail']);
  const install = checkedExec(post, 'install', 'UacFail');
  const start = checkedExec(post, 'start', 'UacFail');
  assert.ok(install < start && start < position(post, 'Call UacRelease'));
  checkedExec(hook('PREUNINSTALL'), 'uninstall', 'un.UacFail');
  assert.ok(!template.some((line) => /^(?:Exec|ExecWait|ExecShell)\b/u.test(line)), 'Template itself must not launch an additional process');
  assert.ok(!hooks.some((line) => /^(?:Exec|ExecShell)\b/u.test(line)));
});

test('source contract omits basename process killing and installer-owned app autorun', () => {
  const text = [...template, ...hooks].join('\n');
  for (const forbidden of ['CheckIfAppIsRunning', 'KillProcess', 'taskkill', 'nsProcess::', 'RunAsUser',
    'RunMainBinary', 'MUI_FINISHPAGE_RUN', '/ARGS']) assert.ok(!text.includes(forbidden), `Unexpected execution surface: ${forbidden}`);
  assert.ok(!template.some((line) => line.includes('${GetOptions}') && line.includes('"/R"')));
  assert.ok(!template.some((line) => /^WriteReg/u.test(line) && line.includes('CurrentVersion\\Run')));
});

test('source contract makes WebView2 a machine prerequisite only before installation', () => {
  assert.equal(overlay.bundle.windows.webviewInstallMode.type, 'skip');
  // Actual Tauri bundler rendering uses an empty string for the strict JSON
  // skip overlay; literal "skip" rejected the real 58cbbee CI assembly.
  rejectingGuard(template, '!if "${INSTALLWEBVIEW2MODE}" != ""');
  assert.ok(position(template, 'Section WebView2') < position(template, 'Section Install'));
  const webview = section('WebView2');
  const versionRead = 'ReadRegStr $0 HKLM "SOFTWARE\\Microsoft\\EdgeUpdate\\Clients\\${WEBVIEW2APPGUID}" "pv"';
  ordered(webview, ['SetRegView 32', versionRead, 'SetRegView 64', versionRead,
    '${If} $0 = ""', '${OrIf} $0 = "0.0.0.0"', 'StrCpy $UacFailure "$(UacWebViewRequired)"', 'Call UacFail']);
  assert.ok(!webview.some((line) => /\bHKCU\b|\$TEMP|\$PLUGINSDIR|\b(?:Exec|ExecWait|ExecShell|File|SetOutPath)\b/u.test(line)));
  const text = [...template, ...hooks].join('\n');
  for (const forbidden of ['nsisdl::', 'inetc::', 'msedgeupdate.exe', 'GetLastError()']) assert.ok(!text.includes(forbidden), `Unexpected downloader/updater/last-error reread: ${forbidden}`);
});

test('source contract removes the service before fixed file deletion and retains user data', () => {
  const uninstall = section('Uninstall');
  const pre = position(uninstall, '!insertmacro NSIS_HOOK_PREUNINSTALL');
  const deletes = uninstall.flatMap((line, index) => /^(?:Delete|RMDir)\b/iu.test(line) ? [index] : []);
  assert.ok(deletes.length > 0);
  for (const index of deletes) assert.ok(pre < index, 'File removal must follow PREUNINSTALL');
  ordered(hook('PREUNINSTALL'), ['Call un.UacPrepare', 'Call un.UacInspectFiles',
    'StrCpy $UacFailure "$(UacRemoveFailed)"', 'Call un.UacRequireServiceAbsent', 'Call un.UacReleaseFiles']);
  ordered(hook('POSTUNINSTALL'), ['Call un.UacRelease', 'DetailPrint "$(UacDataRetained)"']);
  const text = [...template, ...hooks].join('\n');
  assert.doesNotMatch(text, /\bRMDir\s+\/r\b/iu);
  assert.ok(!text.includes('DeleteAppDataCheckbox'));
  assert.ok(!text.includes('Delete "$INSTDIR\\$OldMainBinaryName"'));
  for (const line of [...template, ...hooks].filter((value) => /^(?:Delete|RMDir)\b/iu.test(value))) {
    assert.doesNotMatch(line, /\$(?:APPDATA|LOCALAPPDATA|PROFILE|COMMONAPPDATA)|ProgramData|controller-state|devices\.journal|notification-policy/iu);
  }
  assert.ok(!hooks.some((line) => /DeleteFile|RemoveDirectory|Crypt|NCrypt/u.test(line)));
});

test('source contract never reads a registry-selected old executable or uninstaller command', () => {
  const reads = template.filter((line) => /^ReadRegStr\b/u.test(line));
  assert.ok(reads.length > 0);
  for (const line of reads) assert.doesNotMatch(line, /"(?:UninstallString|QuietUninstallString|MainBinaryName|InstallLocation)"/u);
  position(template, 'StrCpy $OldMainBinaryName "${MAINBINARYNAME}.exe"');
  const retainedLocation = block(template, 'Function RestorePreviousInstallLocation', 'FunctionEnd');
  assert.deepEqual(retainedLocation, ['Call UacFixedLocation']);
});

test('source contract checks each concrete copy delete and shortcut error before continuing', () => {
  const tested = template.flatMap((line, index) => (line === 'File "${MAINBINARYSRCPATH}"' ||
    line === 'File /a "/oname={{this}}" "{{no-escape @key}}"' || line.startsWith('WriteUninstaller ') ||
    line.startsWith('CreateShortcut ') || line === 'Delete "$INSTDIR\\${MAINBINARYNAME}.exe"' ||
    line === 'Delete "$INSTDIR\\\\{{this}}"' || line === 'Delete "$INSTDIR\\uninstall.exe"') ? [index] : []);
  assert.ok(tested.length >= 8, 'Expected concrete copy/delete/uninstaller/shortcut operations');
  for (const index of tested) {
    assert.equal(template[index - 1], 'ClearErrors', template[index]);
    assert.equal(template[index + 1], '${If} ${Errors}', template[index]);
    const end = position(template, '${EndIf}', index + 1);
    assert.ok(template.slice(index + 2, end).some((line) => line === 'Call UacFail' || line === 'Call un.UacFail'), template[index]);
  }
});

test('source contract pins the x86 Unicode SECURITY_ATTRIBUTES layout before allocation', () => {
  rejectingGuard(hooks, '!if ${NSIS_PTR_SIZE} != 4');
  rejectingGuard(hooks, '!if ${NSIS_CHAR_SIZE} != 2');
  const pre = hook('PREINSTALL');
  const descriptor = 'System::Call \'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",i 1,*p.r0,p 0)i.r1\'';
  ordered(pre, ['Call UacPrepare', descriptor, 'StrCpy $UacDescriptor $0',
    "System::Call '*(i 12,p $UacDescriptor,i 0)p.r7'", '${If} $7 = 0', 'Call UacFail',
    'System::Call \'kernel32::CreateDirectoryW(w "$INSTDIR",p r7)i.r8\'', 'System::Free $7',
    '${If} $8 = 0', 'Call UacFail', 'StrCpy $UacAllowMissing 0', 'Call UacOpenChecked']);
});

test('source contract captures Win32 errors on the exact CreateFile and OpenService calls', () => {
  const open = native('UacOpenChecked');
  const create = 'System::Call \'kernel32::CreateFileW(w "$UacPath",i 0x00020001,i r0,p 0,i 3,i 0x02200000,p 0)p.r1 ?e\'';
  const index = position(open, create);
  assert.ok(open[index + 1].startsWith('Pop $0'), 'CreateFile error must be captured before any second native call');
  ordered(open, ['${If} $1 = -1', '${If} $UacAllowMissing = 1', '${AndIf} $0 = 2', 'Return', 'Call ${PREFIX}UacFail']);
  assert.ok(!open.includes('${AndIf} $0 = 3'), 'Missing ancestors may not be treated as an absent fresh leaf');
  const absent = native('UacRequireServiceAbsent');
  const service = 'System::Call \'advapi32::OpenServiceW(p r4,w "UacRemoteController",i 4)p.r5 ?e\'';
  assert.equal(absent[position(absent, service) + 1], 'Pop $6');
  ordered(absent, [service, 'Pop $6', "System::Call 'advapi32::CloseServiceHandle(p r4)'",
    '${If} $5 <> 0', 'Call ${PREFIX}UacFail', '${If} $6 <> 1060', 'Call ${PREFIX}UacFail']);
});

test('source contract bounds ACE header and total extent before ACCESS_MASK or SID dereference', () => {
  const open = native('UacOpenChecked');
  ordered(open, ["System::Call 'advapi32::IsValidAcl(p $UacDacl)i.r0'",
    "System::Call 'advapi32::GetAclInformation(p $UacDacl,p $UacAclInfo,i 12,i 2)i.r0'",
    '${If} $0 > 4096', '${OrIf} $1 < 8', '${OrIf} $1 > 65535', 'StrCpy $UacAclBytes $1',
    "System::Call 'advapi32::GetAce(p $UacDacl,i $UacAceIndex,*p.r0)i.r1'", 'StrCpy $UacAce $0',
    'IntOp $0 $UacAce - $UacDacl', 'IntOp $1 $UacAclBytes - 4', '${If} $0 < 8', '${OrIf} $0 > $1',
    'Call ${PREFIX}UacFail', "System::Call '*$UacAce(i.r0)'", '${If} $UacAceType > 1',
    '${OrIf} $UacAceSize < 16', '${OrIf} $UacAceSize > 76', 'Call ${PREFIX}UacFail',
    'IntOp $0 $UacAce - $UacDacl', 'IntOp $0 $0 + $UacAceSize', '${If} $0 > $UacAclBytes',
    'Call ${PREFIX}UacFail', 'IntOp $0 $UacAce + 4', "System::Call '*$0(i.r1)'", 'IntOp $UacSid $UacAce + 8']);
  position(open, 'IntOp $1 $UacAceFlags & 0xE0');
  position(open, 'IntOp $2 $UacAceSize % 4');
  position(open, 'IntOp $1 $UacAceMask & 0x0FE0FE00');
});

test('source contract bounds embedded SID revision/count/length before any SID API helper', () => {
  const open = native('UacOpenChecked');
  const embedded = open.slice(position(open, 'IntOp $UacSid $UacAce + 8'));
  ordered(embedded, ["System::Call '*$UacSid(i.r0)'", '${If} $1 <> 1', '${OrIf} $0 > 15',
    'Call ${PREFIX}UacFail', 'IntOp $0 $0 * 4', 'IntOp $0 $0 + 16', '${If} $0 <> $UacAceSize',
    'Call ${PREFIX}UacFail', 'Call ${PREFIX}UacTrustedSid']);
  const callsBeforeBound = embedded.slice(0, position(embedded, '${If} $0 <> $UacAceSize')).join('\n');
  assert.doesNotMatch(callsBeforeBound, /IsValidSid|EqualSid|UacTrustedSid/u);
  ordered(native('UacTrustedSid'), ['${If} $UacSid = 0', 'Call ${PREFIX}UacFail',
    "System::Call 'advapi32::IsValidSid(p $UacSid)i.r0'", '${If} $0 = 0', 'Call ${PREFIX}UacFail',
    "System::Call 'advapi32::EqualSid(p $UacSid,p $UacSystemSid)i.r0'"]);
});

test('source contract retains checked ancestor pins and differentiates installation inheritance rights', () => {
  const open = native('UacOpenChecked');
  ordered(open, ['StrCpy $0 1', '${If} $UacDirectoryMode = 1', 'StrCpy $0 3']);
  for (const token of ["System::Call 'kernel32::GetFileType(p $UacHandle)i.r0'", 'IntOp $1 $0 & 0x400',
    'IntOp $0 $UacInfo + 40', '${OrIf} $0 >= ${NSIS_MAX_STRLEN}', '${OrIf} $1 != "\\\\?\\$UacPath"',
    'StrCpy $0 0x500D0156', 'StrCpy $0 0x500D0150']) position(open, token);
  ordered(native('UacPrepare'), ['Call ${PREFIX}UacFixedLocation', 'System::Alloc 512', 'Pop $UacPins',
    '${If} $0 <> 3', 'Call ${PREFIX}UacFail', 'StrCpy $UacAllowMissing 0', '${If} $UacPinCount >= 64',
    'Call ${PREFIX}UacFail', 'Call ${PREFIX}UacOpenChecked', "System::Call '*$0(p $UacHandle)'"]);
  ordered(native('UacFail'), ['Call ${PREFIX}UacRelease', 'SetErrorLevel 3', 'MessageBox MB_OK|MB_ICONSTOP "$UacFailure" /SD IDOK', 'Abort "$UacFailure"']);
});

test('source contract defines every custom outcome once in Korean and English without raw native error labels', () => {
  const definitions = new Map();
  for (const line of hooks.filter((value) => value.startsWith('LangString Uac'))) {
    const match = /^LangString (Uac[A-Za-z0-9]+) (1033|1042) "(.+)"$/u.exec(line);
    assert.ok(match, `Unsupported custom language declaration: ${line}`);
    const [, name, language, text] = match;
    const key = name + ':' + language;
    assert.ok(!definitions.has(key), `Duplicate custom translation: ${key}`);
    assert.doesNotMatch(text, /\b(?:TPM|CNG|NCrypt|HRESULT|UnsafePermissions|WindowsCall|JournalUnavailable|RegistryUnavailable|KeyNotFound|ServiceError)\b/u);
    definitions.set(key, text);
  }
  const references = new Set([...([...template, ...hooks].join('\n')).matchAll(/\$\((Uac[A-Za-z0-9]+)\)/gu)].map((match) => match[1]));
  assert.ok(references.size >= 9, 'Expected the actual custom outcome surface');
  for (const key of definitions.keys()) references.add(key.split(':')[0]);
  for (const name of references) for (const language of ['1033', '1042']) assert.ok(definitions.has(name + ':' + language), `Missing ${language}: ${name}`);
  for (const name of ['UacUnsafe', 'UacInstallFailed', 'UacStartFailed', 'UacRemoveFailed', 'UacFileFailed', 'UacCopyFailed', 'UacDataRetained']) {
    const korean = definitions.get(name + ':1042');
    const english = definitions.get(name + ':1033')?.toLowerCase();
    for (const token of ['기록', '설정', '기기 연결 정보']) assert.ok(korean?.includes(token), `${name} must identify retained ${token}`);
    for (const token of ['history', 'settings', 'device connection information']) assert.ok(english?.includes(token), `${name} must identify retained ${token}`);
  }
  assert.ok(definitions.get('UacInstallFailed:1042').includes('남아 있을 수'));
  assert.ok(definitions.get('UacCopyFailed:1042').includes('변경됐거나'));
  assert.ok(definitions.get('UacStartFailed:1042').includes('실행을 확인하지 못'));
  assert.ok(definitions.get('UacDataRetained:1042').includes('다른 파일'));
});
