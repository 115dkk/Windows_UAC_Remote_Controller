; SPDX-License-Identifier: GPL-2.0-or-later
; Reviewed scope: fixed installed files and fixed service CLI only. System.dll
; is NSIS's embedded plugin, never loaded from the destination. Every native
; pointer below originates in a checked Win32 allocation/handle; no caller data.
; Parent directory handles deny delete sharing until the final installer exit.
!include LogicLib.nsh
!if ${NSIS_PTR_SIZE} != 4
  !error "The reviewed native structures require the x86 NSIS engine."
!endif
!if ${NSIS_CHAR_SIZE} != 2
  !error "The reviewed native structures require Unicode NSIS."
!endif

LangString UacUnsafe 1033 "The operation stopped because the fixed program location or its permissions could not be verified. Existing history, settings and device connection information were not removed. Ask an administrator to review the installation."
LangString UacUnsafe 1042 "정해진 프로그램 위치나 권한을 확인하지 못해 작업을 중단했습니다. 기존 기록, 설정과 기기 연결 정보는 삭제하지 않았습니다. 관리자에게 설치 상태 확인을 요청해 주세요."
LangString UacStopFailed 1033 "The existing service could not be confirmed stopped. Its program files were not replaced. Close active operations and retry installation."
LangString UacStopFailed 1042 "기존 서비스가 중지됐는지 확인하지 못했습니다. 프로그램 파일은 교체하지 않았습니다. 진행 중인 작업을 마친 뒤 설치를 다시 시도해 주세요."
LangString UacInstallFailed 1033 "Service setup did not finish. Program files, history, settings and device connection information are retained; service registration or automatic-start settings may remain. Review the service status before retrying."
LangString UacInstallFailed 1042 "서비스 설치를 마치지 못했습니다. 프로그램 파일, 기록, 설정과 기기 연결 정보는 보존했으며, 서비스 등록이나 자동 시작 설정이 남아 있을 수 있습니다. 서비스 상태를 확인한 뒤 다시 시도해 주세요."
LangString UacStartFailed 1033 "Service installation configured automatic start, but starting it was not confirmed. Setup is incomplete; program files, history, settings and device connection information are retained. Review the service status before retrying."
LangString UacStartFailed 1042 "서비스의 자동 시작은 설정했지만 실행을 확인하지 못했습니다. 설치가 완료되지 않았으며 프로그램 파일, 기록, 설정과 기기 연결 정보는 보존했습니다. 서비스 상태를 확인한 뒤 다시 시도해 주세요."
LangString UacRemoveFailed 1033 "Service removal was not confirmed. Program files, history, settings and device connection information are retained. Close active operations and retry removal."
LangString UacRemoveFailed 1042 "서비스가 제거됐는지 확인하지 못했습니다. 프로그램 파일, 기록, 설정과 기기 연결 정보는 보존했습니다. 진행 중인 작업을 마친 뒤 제거를 다시 시도해 주세요."
LangString UacFileFailed 1033 "A program file operation failed. Some program files may remain or have changed. History, settings and device connection information were not removed. Close the app and retry after reviewing service status."
LangString UacFileFailed 1042 "프로그램 파일 처리를 마치지 못했습니다. 일부 프로그램 파일이 남아 있거나 변경됐을 수 있습니다. 기록, 설정과 기기 연결 정보는 삭제하지 않았습니다. 앱을 닫고 서비스 상태를 확인한 뒤 다시 시도해 주세요."
LangString UacCopyFailed 1033 "Program file installation did not finish. Some files may have changed, and previous service registration/automatic-start settings may remain. History, settings and device connection information are retained. Close the app and review service status before retrying."
LangString UacCopyFailed 1042 "프로그램 파일 설치를 마치지 못했습니다. 일부 파일이 변경됐거나 기존 서비스 등록·자동 시작 설정이 남아 있을 수 있습니다. 기록, 설정과 기기 연결 정보는 보존했습니다. 앱을 닫고 서비스 상태를 확인한 뒤 다시 시도해 주세요."
LangString UacDataRetained 1033 "Service registration and packaged program files were removed. History, settings and device connection information are retained. A program folder containing other files is retained."
LangString UacDataRetained 1042 "서비스 등록과 설치한 프로그램 파일을 제거했습니다. 기록, 설정과 기기 연결 정보는 보존했습니다. 다른 파일이 있는 프로그램 폴더도 남겨 둡니다."
LangString UacWebViewRequired 1033 "A machine-installed Microsoft Edge WebView2 Runtime could not be confirmed. Install that component from Microsoft's official website, then run this installer again. No program files were installed."
LangString UacWebViewRequired 1042 "이 컴퓨터에 설치된 Microsoft Edge WebView2 Runtime을 확인하지 못했습니다. Microsoft 공식 웹사이트에서 해당 구성 요소를 설치한 뒤 다시 시도해 주세요. 프로그램 파일은 설치하지 않았습니다."

Var UacFailure
Var UacPath
Var UacWalk
Var UacRoot
Var UacDirectory
Var UacDirectoryPin
Var UacDirectoryMode
Var UacAllowMissing
Var UacHandle
Var UacPolicy
Var UacPins
Var UacPinCount
Var UacInfo
Var UacAclInfo
Var UacDescriptor
Var UacDacl
Var UacSid
Var UacSidTrusted
Var UacSystemSid
Var UacAdminSid
Var UacInstallerSid
Var UacAceCount
Var UacAclBytes
Var UacAceIndex
Var UacAce
Var UacAceSize
Var UacAceType
Var UacAceFlags
Var UacAceMask
Var UacServicePin
Var UacProbePin
Var UacAppPin
Var UacUninstallerPin

!macro UacFunctions PREFIX
Function ${PREFIX}UacTrustedSid
  StrCpy $UacSidTrusted 0
  ${If} $UacSid = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::IsValidSid(p $UacSid)i.r0'
  ${If} $0 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::EqualSid(p $UacSid,p $UacSystemSid)i.r0'
  System::Call 'advapi32::EqualSid(p $UacSid,p $UacAdminSid)i.r1'
  System::Call 'advapi32::EqualSid(p $UacSid,p $UacInstallerSid)i.r2'
  IntOp $0 $0 | $1
  IntOp $0 $0 | $2
  ${If} $0 <> 0
    StrCpy $UacSidTrusted 1
  ${EndIf}
FunctionEnd

Function ${PREFIX}UacReleaseFiles
  ${If} $UacServicePin <> 0
    System::Call 'kernel32::CloseHandle(p $UacServicePin)'
    StrCpy $UacServicePin 0
  ${EndIf}
  ${If} $UacProbePin <> 0
    System::Call 'kernel32::CloseHandle(p $UacProbePin)'
    StrCpy $UacProbePin 0
  ${EndIf}
  ${If} $UacAppPin <> 0
    System::Call 'kernel32::CloseHandle(p $UacAppPin)'
    StrCpy $UacAppPin 0
  ${EndIf}
  ${If} $UacUninstallerPin <> 0
    System::Call 'kernel32::CloseHandle(p $UacUninstallerPin)'
    StrCpy $UacUninstallerPin 0
  ${EndIf}
FunctionEnd

Function ${PREFIX}UacRelease
  Call ${PREFIX}UacReleaseFiles
  ${If} $UacHandle <> 0
    System::Call 'kernel32::CloseHandle(p $UacHandle)'
    StrCpy $UacHandle 0
  ${EndIf}
  ${If} $UacDirectoryPin <> 0
    System::Call 'kernel32::CloseHandle(p $UacDirectoryPin)'
    StrCpy $UacDirectoryPin 0
  ${EndIf}
  ${DoWhile} $UacPinCount > 0
    IntOp $UacPinCount $UacPinCount - 1
    IntOp $0 $UacPinCount * 8
    IntOp $0 $0 + $UacPins
    System::Call '*$0(p.r1)'
    System::Call 'kernel32::CloseHandle(p r1)'
  ${Loop}
  ${If} $UacPins <> 0
    System::Free $UacPins
    StrCpy $UacPins 0
  ${EndIf}
  ${If} $UacInfo <> 0
    System::Free $UacInfo
    StrCpy $UacInfo 0
  ${EndIf}
  ${If} $UacAclInfo <> 0
    System::Free $UacAclInfo
    StrCpy $UacAclInfo 0
  ${EndIf}
  ${If} $UacDescriptor <> 0
    System::Call 'kernel32::LocalFree(p $UacDescriptor)'
    StrCpy $UacDescriptor 0
  ${EndIf}
  ${If} $UacSystemSid <> 0
    System::Call 'kernel32::LocalFree(p $UacSystemSid)'
    StrCpy $UacSystemSid 0
  ${EndIf}
  ${If} $UacAdminSid <> 0
    System::Call 'kernel32::LocalFree(p $UacAdminSid)'
    StrCpy $UacAdminSid 0
  ${EndIf}
  ${If} $UacInstallerSid <> 0
    System::Call 'kernel32::LocalFree(p $UacInstallerSid)'
    StrCpy $UacInstallerSid 0
  ${EndIf}
FunctionEnd

Function ${PREFIX}UacFail
  Call ${PREFIX}UacRelease
  SetErrorLevel 3
  MessageBox MB_OK|MB_ICONSTOP "$UacFailure" /SD IDOK
  Abort "$UacFailure"
FunctionEnd

; Open only an existing fixed path, no-follow final component; each ancestor is
; separately pinned. Directories share writes but not deletion; files share
; only reads until their checked lifecycle command finishes.
Function ${PREFIX}UacOpenChecked
  StrCpy $UacHandle 0
  StrCpy $0 1
  ${If} $UacDirectoryMode = 1
    StrCpy $0 3
  ${EndIf}
  System::Call 'kernel32::CreateFileW(w "$UacPath",i 0x00020001,i r0,p 0,i 3,i 0x02200000,p 0)p.r1 ?e'
  Pop $0 ; Captured by System.dll at the original Win32 call, before marshaling.
  ${If} $1 = -1
    ${If} $UacAllowMissing = 1
    ${AndIf} $0 = 2
      Return
    ${EndIf}
    ; A missing ancestor (ERROR_PATH_NOT_FOUND) is NOT a fresh-install leaf.
    Call ${PREFIX}UacFail
  ${EndIf}
  StrCpy $UacHandle $1
  System::Call 'kernel32::GetFileType(p $UacHandle)i.r0'
  ${If} $0 <> 1
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'kernel32::GetFileInformationByHandle(p $UacHandle,p $UacInfo)i.r0'
  ${If} $0 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call '*$UacInfo(i.r0)'
  IntOp $1 $0 & 0x400
  IntOp $2 $0 & 0x10
  ${If} $1 <> 0
    Call ${PREFIX}UacFail
  ${EndIf}
  ${If} $UacDirectoryMode = 1
    ${If} $2 <> 0x10
      Call ${PREFIX}UacFail
    ${EndIf}
  ${Else}
    ${If} $2 <> 0
      Call ${PREFIX}UacFail
    ${EndIf}
    IntOp $0 $UacInfo + 40
    System::Call '*$0(i.r1)'
    ${If} $1 <> 1
      Call ${PREFIX}UacFail
    ${EndIf}
  ${EndIf}
  System::Call 'kernel32::GetFinalPathNameByHandleW(p $UacHandle,w.r1,i ${NSIS_MAX_STRLEN},i 0)i.r0'
  ${If} $0 = 0
  ${OrIf} $0 >= ${NSIS_MAX_STRLEN}
  ${OrIf} $1 != "\\?\$UacPath"
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::GetSecurityInfo(p $UacHandle,i 1,i 5,*p.r0,p 0,*p.r1,p 0,*p.r2)i.r3'
  ${If} $3 <> 0
    Call ${PREFIX}UacFail
  ${EndIf}
  StrCpy $UacSid $0
  StrCpy $UacDacl $1
  StrCpy $UacDescriptor $2
  ${If} $UacDescriptor = 0
  ${OrIf} $UacDacl = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  Call ${PREFIX}UacTrustedSid
  ${If} $UacSidTrusted = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::IsValidAcl(p $UacDacl)i.r0'
  ${If} $0 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call '*$UacDacl(i.r0)'
  IntOp $0 $0 & 0xFF
  ${If} $0 <> 2
  ${AndIf} $0 <> 4
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::GetAclInformation(p $UacDacl,p $UacAclInfo,i 12,i 2)i.r0'
  ${If} $0 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call '*$UacAclInfo(i.r0,i.r1,i.r2)'
  ${If} $0 > 4096
  ${OrIf} $1 < 8
  ${OrIf} $1 > 65535
    Call ${PREFIX}UacFail
  ${EndIf}
  StrCpy $UacAceCount $0
  StrCpy $UacAclBytes $1
  StrCpy $UacAceIndex 0
  ${DoWhile} $UacAceIndex < $UacAceCount
    System::Call 'advapi32::GetAce(p $UacDacl,i $UacAceIndex,*p.r0)i.r1'
    ${If} $1 = 0
      Call ${PREFIX}UacFail
    ${EndIf}
    StrCpy $UacAce $0
    ; Validate the returned ACE_HEADER extent before reading ACCESS_MASK/SID.
    IntOp $0 $UacAce - $UacDacl
    IntOp $1 $UacAclBytes - 4
    ${If} $0 < 8
    ${OrIf} $0 > $1
      Call ${PREFIX}UacFail
    ${EndIf}
    System::Call '*$UacAce(i.r0)'
    IntOp $UacAceType $0 & 0xFF
    IntOp $UacAceFlags $0 >> 8
    IntOp $UacAceFlags $UacAceFlags & 0xFF
    IntOp $UacAceSize $0 >> 16
    IntOp $1 $UacAceFlags & 0xE0
    IntOp $2 $UacAceSize % 4
    ${If} $UacAceType > 1
    ${OrIf} $UacAceSize < 16
    ${OrIf} $UacAceSize > 76
    ${OrIf} $1 <> 0
    ${OrIf} $2 <> 0
      Call ${PREFIX}UacFail
    ${EndIf}
    IntOp $0 $UacAce - $UacDacl
    IntOp $0 $0 + $UacAceSize
    ${If} $0 > $UacAclBytes
      Call ${PREFIX}UacFail
    ${EndIf}
    IntOp $0 $UacAce + 4
    System::Call '*$0(i.r1)'
    StrCpy $UacAceMask $1
    IntOp $1 $UacAceMask & 0x0FE0FE00
    ${If} $1 <> 0
      Call ${PREFIX}UacFail
    ${EndIf}
    IntOp $UacSid $UacAce + 8
    ; IsValidSid has no buffer-length argument. Establish the SID's declared
    ; extent from its in-ACE 8-byte header before ANY SID equality/validation API.
    System::Call '*$UacSid(i.r0)'
    IntOp $1 $0 & 0xFF
    IntOp $0 $0 >> 8
    IntOp $0 $0 & 0xFF
    ${If} $1 <> 1
    ${OrIf} $0 > 15
      Call ${PREFIX}UacFail
    ${EndIf}
    IntOp $0 $0 * 4
    IntOp $0 $0 + 16
    ${If} $0 <> $UacAceSize
      Call ${PREFIX}UacFail
    ${EndIf}
    Call ${PREFIX}UacTrustedSid
    ${If} $UacAceType = 0
    ${AndIf} $UacSidTrusted = 0
      StrCpy $0 0x500D0156
      ${If} $UacPolicy = 0
        ; Ancestor create-child alone cannot replace a pinned existing child.
        ; Inherit-only rights are checked on each actual descendant instead.
        StrCpy $0 0x500D0150
        IntOp $1 $UacAceFlags & 8
        ${If} $1 <> 0
          StrCpy $0 0
        ${EndIf}
      ${EndIf}
      ; Installation directories also reject dangerous inherit-only grants:
      ; a fresh packaged child must never become writable before its recheck.
      IntOp $0 $UacAceMask & $0
      ${If} $0 <> 0
        Call ${PREFIX}UacFail
      ${EndIf}
    ${EndIf}
    IntOp $UacAceIndex $UacAceIndex + 1
  ${Loop}
  System::Call 'kernel32::LocalFree(p $UacDescriptor)p.r0'
  StrCpy $UacDescriptor 0
  ${If} $0 <> 0
    Call ${PREFIX}UacFail
  ${EndIf}
FunctionEnd

Function ${PREFIX}UacFixedLocation
  StrCpy $UacFailure "$(UacUnsafe)"
  ${IfNot} ${RunningX64}
    Call ${PREFIX}UacFail
  ${EndIf}
  StrCpy $UacDirectory "$PROGRAMFILES64\휴대폰 승인"
  ${If} $INSTDIR != "placeholder\휴대폰 승인"
  ${AndIf} $INSTDIR != $UacDirectory
    Call ${PREFIX}UacFail
  ${EndIf}
  StrCpy $INSTDIR $UacDirectory
FunctionEnd

Function ${PREFIX}UacPrepare
  StrCpy $UacFailure "$(UacUnsafe)"
  Call ${PREFIX}UacFixedLocation
  System::Alloc 512
  Pop $UacPins
  System::Alloc 52
  Pop $UacInfo
  System::Alloc 12
  Pop $UacAclInfo
  ${If} $UacPins = 0
  ${OrIf} $UacInfo = 0
  ${OrIf} $UacAclInfo = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-18",*p.r0)i.r1'
  StrCpy $UacSystemSid $0
  ${If} $1 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-32-544",*p.r0)i.r1'
  StrCpy $UacAdminSid $0
  ${If} $1 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::ConvertStringSidToSidW(w "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464",*p.r0)i.r1'
  StrCpy $UacInstallerSid $0
  ${If} $1 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  ${GetRoot} "$PROGRAMFILES64" $UacRoot
  System::Call 'kernel32::GetDriveTypeW(w "$UacRoot\")i.r0'
  ${If} $0 <> 3
    Call ${PREFIX}UacFail
  ${EndIf}
  StrCpy $UacWalk "$PROGRAMFILES64"
  StrCpy $UacDirectoryMode 1
  StrCpy $UacPolicy 0
  StrCpy $UacAllowMissing 0
  ${Do}
    ${If} $UacPinCount >= 64
      Call ${PREFIX}UacFail
    ${EndIf}
    StrCpy $UacPath $UacWalk
    Call ${PREFIX}UacOpenChecked
    IntOp $0 $UacPinCount * 8
    IntOp $0 $0 + $UacPins
    System::Call '*$0(p $UacHandle)'
    StrCpy $UacHandle 0
    IntOp $UacPinCount $UacPinCount + 1
    ${If} $UacWalk = "$UacRoot\"
      ${ExitDo}
    ${EndIf}
    ${GetParent} "$UacWalk" $UacWalk
    ${If} $UacWalk = $UacRoot
      StrCpy $UacWalk "$UacRoot\"
    ${EndIf}
    ${If} $UacWalk = ""
      Call ${PREFIX}UacFail
    ${EndIf}
  ${Loop}
  StrCpy $UacPath $UacDirectory
  StrCpy $UacPolicy 1
  StrCpy $UacAllowMissing 1
  Call ${PREFIX}UacOpenChecked
  StrCpy $UacDirectoryPin $UacHandle
  StrCpy $UacHandle 0
FunctionEnd

Function ${PREFIX}UacInspectFiles
  StrCpy $UacFailure "$(UacUnsafe)"
  StrCpy $UacDirectoryMode 0
  StrCpy $UacPolicy 1
  StrCpy $UacAllowMissing 1
  StrCpy $UacPath "$INSTDIR\uac-service.exe"
  Call ${PREFIX}UacOpenChecked
  StrCpy $UacServicePin $UacHandle
  StrCpy $UacHandle 0
  StrCpy $UacPath "$INSTDIR\uac-prompt-probe.exe"
  Call ${PREFIX}UacOpenChecked
  StrCpy $UacProbePin $UacHandle
  StrCpy $UacHandle 0
  StrCpy $UacPath "$INSTDIR\controller-app.exe"
  Call ${PREFIX}UacOpenChecked
  StrCpy $UacAppPin $UacHandle
  StrCpy $UacHandle 0
  StrCpy $UacPath "$INSTDIR\uninstall.exe"
  Call ${PREFIX}UacOpenChecked
  StrCpy $UacUninstallerPin $UacHandle
  StrCpy $UacHandle 0
FunctionEnd

Function ${PREFIX}UacRequireServiceAbsent
  System::Call 'advapi32::OpenSCManagerW(p 0,p 0,i 1)p.r4'
  ${If} $4 = 0
    Call ${PREFIX}UacFail
  ${EndIf}
  System::Call 'advapi32::OpenServiceW(p r4,w "UacRemoteController",i 4)p.r5 ?e'
  Pop $6
  System::Call 'advapi32::CloseServiceHandle(p r4)'
  ${If} $5 <> 0
    System::Call 'advapi32::CloseServiceHandle(p r5)'
    Call ${PREFIX}UacFail
  ${EndIf}
  ${If} $6 <> 1060
    Call ${PREFIX}UacFail
  ${EndIf}
FunctionEnd
!macroend

!insertmacro UacFunctions ""
!insertmacro UacFunctions "un."

!macro NSIS_HOOK_PREINSTALL
  Call UacPrepare
  ${If} $UacDirectoryPin = 0
    ; The sole fresh directory is created AFTER all parent checks, with a
    ; protected inheritable ACL. Unknown preexisting directories are never fixed.
    System::Call 'advapi32::ConvertStringSecurityDescriptorToSecurityDescriptorW(w "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;GRGX;;;BU)",i 1,*p.r0,p 0)i.r1'
    ${If} $1 = 0
      Call UacFail
    ${EndIf}
    StrCpy $UacDescriptor $0
    ; NSIS's x86 Unicode engine uses a 12-byte SECURITY_ATTRIBUTES.
    System::Call '*(i 12,p $UacDescriptor,i 0)p.r7'
    ${If} $7 = 0
      Call UacFail
    ${EndIf}
    System::Call 'kernel32::CreateDirectoryW(w "$INSTDIR",p r7)i.r8'
    System::Free $7
    System::Call 'kernel32::LocalFree(p $UacDescriptor)'
    StrCpy $UacDescriptor 0
    ${If} $8 = 0
      Call UacFail
    ${EndIf}
    StrCpy $UacPath $INSTDIR
    StrCpy $UacAllowMissing 0
    Call UacOpenChecked
    StrCpy $UacDirectoryPin $UacHandle
    StrCpy $UacHandle 0
  ${EndIf}
  Call UacInspectFiles
  StrCpy $UacFailure "$(UacStopFailed)"
  ${If} $UacServicePin <> 0
    ClearErrors
    ExecWait '"$INSTDIR\uac-service.exe" stop' $0
    ${If} ${Errors}
    ${OrIf} $0 <> 0
      Call UacFail
    ${EndIf}
  ${Else}
    Call UacRequireServiceAbsent
  ${EndIf}
  ; Protected parent/dir pins remain, but existing files must be closed before
  ; replacement. Their ACLs forbid lower-privilege writes/renames in this gap.
  Call UacReleaseFiles
!macroend

!macro NSIS_HOOK_POSTINSTALL
  Call UacInspectFiles
  ${If} $UacServicePin = 0
  ${OrIf} $UacProbePin = 0
  ${OrIf} $UacAppPin = 0
  ${OrIf} $UacUninstallerPin = 0
    Call UacFail
  ${EndIf}
  StrCpy $UacFailure "$(UacInstallFailed)"
  ClearErrors
  ExecWait '"$INSTDIR\uac-service.exe" install' $0
  ${If} ${Errors}
  ${OrIf} $0 <> 0
    Call UacFail
  ${EndIf}
  StrCpy $UacFailure "$(UacStartFailed)"
  ClearErrors
  ExecWait '"$INSTDIR\uac-service.exe" start' $0
  ${If} ${Errors}
  ${OrIf} $0 <> 0
    Call UacFail
  ${EndIf}
  Call UacRelease
!macroend

!macro NSIS_HOOK_PREUNINSTALL
  Call un.UacPrepare
  ${If} $UacDirectoryPin <> 0
    Call un.UacInspectFiles
  ${EndIf}
  StrCpy $UacFailure "$(UacRemoveFailed)"
  ${If} $UacServicePin <> 0
    ClearErrors
    ExecWait '"$INSTDIR\uac-service.exe" uninstall' $0
    ${If} ${Errors}
    ${OrIf} $0 <> 0
      Call un.UacFail
    ${EndIf}
  ${Else}
    Call un.UacRequireServiceAbsent
  ${EndIf}
  Call un.UacReleaseFiles
!macroend

!macro NSIS_HOOK_POSTUNINSTALL
  Call un.UacRelease
  DetailPrint "$(UacDataRetained)"
!macroend
