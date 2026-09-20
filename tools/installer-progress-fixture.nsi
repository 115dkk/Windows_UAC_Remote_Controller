; SPDX-License-Identifier: GPL-2.0-or-later
; Disposable native MUI geometry fixture. No payload, registry, service or UAC.
Unicode true
RequestExecutionLevel user
ManifestDPIAware true
ManifestDPIAwareness PerMonitorV2
!include MUI2.nsh
!include "..\src-tauri\windows\progress-layout.nsh"
Name "UAC progress layout fixture"
OutFile "${TEST_OUT}"
SetFont "Segoe UI" ${TEST_FONT_SIZE}
BrandingText " "
AutoCloseWindow false
!define MUI_PAGE_CUSTOMFUNCTION_SHOW FixtureShow
!define MUI_PAGE_CUSTOMFUNCTION_LEAVE FixtureComplete
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_LANGUAGE "${TEST_LANGUAGE}"
!insertmacro UAC_PROGRESS_LAYOUT ""
Function FixtureShow
  ; Negative control recreates an oversized bar. The production function must
  ; recover from observed rectangles rather than a special hardcoded test width.
  System::Call 'user32::SetWindowPos(p $mui.InstFilesPage.ProgressBar,p 0,i 0,i 0,i 8192,i 20,i 0x0016)'
  !if ${TEST_REPAIR} == 1
    Call UacFitInstallProgress
  !endif
FunctionEnd
Function FixtureComplete
  !if ${TEST_REPAIR} == 1
    Call UacFitInstallProgress
  !endif
FunctionEnd
Section
  DetailPrint "UI fixture only"
  Sleep 200
SectionEnd
