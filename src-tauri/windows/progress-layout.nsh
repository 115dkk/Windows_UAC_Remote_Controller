; SPDX-License-Identifier: GPL-2.0-or-later
; Uses actual client/control rectangles after MUI creates/scales the page.
; No fixed pixels, dialog units, guessed DPI factor, storage or installer action.
!macro UAC_PROGRESS_LAYOUT PREFIX
Function ${PREFIX}UacFitInstallProgress
  Push $0
  Push $1
  Push $2
  Push $3
  Push $4
  Push $5
  Push $6
  Push $7
  Push $8
  System::Alloc 16
  Pop $0
  ${If} $0 <> 0
    System::Call 'user32::GetClientRect(p $HWNDPARENT,p r0)i.r8'
    ${If} $8 <> 0
      System::Call '*$0(i.r1,i.r2,i.r3,i.r4)'
      System::Call 'user32::GetWindowRect(p $mui.InstFilesPage.ProgressBar,p r0)i.r8'
      ${If} $8 <> 0
        System::Call 'user32::MapWindowPoints(p 0,p $HWNDPARENT,p r0,i 2)'
        System::Call '*$0(i.r1,i.r2,i.r5,i.r6)'
        ; Preserve the observed leading margin symmetrically at the trailing edge.
        IntOp $7 $1 * 2
        IntOp $7 $3 - $7
        ${If} $1 > 0
        ${AndIf} $7 > 0
          System::Call 'user32::GetParent(p $mui.InstFilesPage.ProgressBar)p.r8'
          System::Call 'user32::GetWindowRect(p $mui.InstFilesPage.ProgressBar,p r0)'
          System::Call 'user32::MapWindowPoints(p 0,p r8,p r0,i 2)'
          System::Call '*$0(i.r1,i.r2,i.r5,i.r6)'
          IntOp $6 $6 - $2
          System::Call 'user32::SetWindowPos(p $mui.InstFilesPage.ProgressBar,p 0,i r1,i r2,i r7,i r6,i 0x0014)'
        ${EndIf}
      ${EndIf}
    ${EndIf}
    System::Free $0
  ${EndIf}
  Pop $8
  Pop $7
  Pop $6
  Pop $5
  Pop $4
  Pop $3
  Pop $2
  Pop $1
  Pop $0
FunctionEnd
!macroend
