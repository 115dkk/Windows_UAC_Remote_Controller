; Upstream Tauri bundler 2.9.4 installer.nsi: MIT OR Apache-2.0.
; Retained notice: LICENSE-TAURI-MIT.txt. Local changes GPL-2.0-or-later.
; See docs/packaging-windows.md for the bounded patch inventory.
Unicode true
ManifestDPIAware true
; Add in `dpiAwareness` `PerMonitorV2` to manifest for Windows 10 1607+ (note this should not affect lower versions since they should be able to ignore this and pick up `dpiAware` `true` set by `ManifestDPIAware true`)
; Currently undocumented on NSIS's website but is in the Docs folder of source tree, see
; https://github.com/kichik/nsis/blob/5fc0b87b819a9eec006df4967d08e522ddd651c9/Docs/src/attributes.but#L286-L300
; https://github.com/tauri-apps/tauri/pull/10106
ManifestDPIAwareness PerMonitorV2

!if "{{compression}}" == "none"
  SetCompress off
!else
  ; Set the compression algorithm. We default to LZMA.
  SetCompressor /SOLID "{{compression}}"
!endif

; Keep above !include to stay ahead of any plugin command
; see https://github.com/tauri-apps/tauri/pull/15422#discussion_r3289239624
{{#if signed_plugins_path}}
!addplugindir "{{signed_plugins_path}}"
{{/if}}

!include MUI2.nsh
!include nsDialogs.nsh
!include FileFunc.nsh
!include x64.nsh
!include WordFunc.nsh
!include "utils.nsh"
!include "FileAssociation.nsh"
!include "Win\COM.nsh"
!include "Win\Propkey.nsh"
!include "StrFunc.nsh"
${StrCase}
${StrLoc}

{{#if installer_hooks}}
!include "{{installer_hooks}}"
{{/if}}

!define WEBVIEW2APPGUID "{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"

!define MANUFACTURER "{{manufacturer}}"
!define PRODUCTNAME "{{product_name}}"
; Display branding may change; installed storage, registry identity and the
; protected native path remain compatible with existing alpha installations.
!define INSTALLATIONID "휴대폰 승인"
!define VERSION "{{version}}"
!define VERSIONWITHBUILD "{{version_with_build}}"
!define HOMEPAGE "{{homepage}}"
!define INSTALLMODE "{{install_mode}}"
!define LICENSE "{{license}}"
!define INSTALLERICON "{{installer_icon}}"
!define SIDEBARIMAGE "{{sidebar_image}}"
!define HEADERIMAGE "{{header_image}}"
!define UNINSTALLERICON "{{uninstaller_icon}}"
!define UNINSTALLERHEADERIMAGE "{{uninstaller_header_image}}"
!define MAINBINARYNAME "{{main_binary_name}}"
!define MAINBINARYSRCPATH "{{main_binary_path}}"
!define BUNDLEID "{{bundle_id}}"
!define COPYRIGHT "{{copyright}}"
!define OUTFILE "{{out_file}}"
!define ARCH "{{arch}}"
!define ADDITIONALPLUGINSPATH "{{additional_plugins_path}}"
!define ALLOWDOWNGRADES "{{allow_downgrades}}"
!define DISPLAYLANGUAGESELECTOR "{{display_language_selector}}"
!define INSTALLWEBVIEW2MODE "{{install_webview2_mode}}"
!define WEBVIEW2INSTALLERARGS "{{webview2_installer_args}}"
!define WEBVIEW2BOOTSTRAPPERPATH "{{webview2_bootstrapper_path}}"
!define WEBVIEW2INSTALLERPATH "{{webview2_installer_path}}"
!define MINIMUMWEBVIEW2VERSION "{{minimum_webview2_version}}"
!define UNINSTKEY "Software\Microsoft\Windows\CurrentVersion\Uninstall\${INSTALLATIONID}"
!define MANUKEY "Software\${MANUFACTURER}"
!define MANUPRODUCTKEY "${MANUKEY}\${INSTALLATIONID}"
!define UNINSTALLERSIGNCOMMAND "{{uninstaller_sign_cmd}}"
!define ESTIMATEDSIZE "{{estimated_size}}"
!define STARTMENUFOLDER "{{start_menu_folder}}"

; Tauri's NSIS data maps JSON webviewInstallMode=skip to the empty string, not
; the literal "skip". windows-packaging.mjs separately requires the exact JSON
; skip overlay. Nonempty bootstrapper modes are never accepted by this template.
!if "${INSTALLWEBVIEW2MODE}" != ""
  !error "Use npm run package:windows; this package requires prerequisite-only WebView2."
!endif
{{#each binaries}}
  !if "{{this}}" == "uac-service.exe"
    !ifdef UAC_SERVICE_INCLUDED
      !error "Duplicate service payload."
    !endif
    !define UAC_SERVICE_INCLUDED
  !else if "{{this}}" == "uac-prompt-probe.exe"
    !ifdef UAC_PROBE_INCLUDED
      !error "Duplicate prompt helper payload."
    !endif
    !define UAC_PROBE_INCLUDED
  !else
    !error "Unexpected external executable in the fixed service package."
  !endif
{{/each}}
!ifndef UAC_SERVICE_INCLUDED
  !error "Missing service payload: use npm run package:windows."
!endif
!ifndef UAC_PROBE_INCLUDED
  !error "Missing prompt helper payload: use npm run package:windows."
!endif

!if "${INSTALLMODE}" != "perMachine"
  !error "This service package requires perMachine installation."
!endif
!if "${ARCH}" != "x64"
  !error "Only the x64 Windows service package is currently supported."
!endif
!if "${MAINBINARYNAME}" != "controller-app"
  !error "Unexpected controller executable name."
!endif
!if "${PRODUCTNAME}" != "UAC 원격 승인"
  !error "Unexpected fixed protected installation folder."
!endif

; Exact old/new shortcut paths only. A name collision stops instead of replacing
; an unrelated shortcut. The source link must already point to our fixed binary.
!macro UacMigrateShortcut OLD NEW
  !insertmacro IsShortcutTarget "${OLD}" "$INSTDIR\${MAINBINARYNAME}.exe"
  Pop $0
  ${If} $0 = 1
    ${If} ${FileExists} "${NEW}"
      StrCpy $UacFailure "$(UacCopyFailed)"
      Call UacFail
    ${EndIf}
    ClearErrors
    Rename "${OLD}" "${NEW}"
    ${If} ${Errors}
      StrCpy $UacFailure "$(UacCopyFailed)"
      Call UacFail
    ${EndIf}
    !insertmacro SetLnkAppUserModelId "${NEW}"
  ${EndIf}
!macroend

!macro UacRequireOwnedShortcutOrMissing PATH
  ${If} ${FileExists} "${PATH}"
    !insertmacro IsShortcutTarget "${PATH}" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 <> 1
      StrCpy $UacFailure "$(UacCopyFailed)"
      Call UacFail
    ${EndIf}
  ${EndIf}
!macroend

Var PassiveMode
Var UpdateMode
Var NoShortcutMode
Var WixMode
Var OldMainBinaryName
Var UacExistingInstall
Var UacDesktopChoice
Var UacStartMenuChoice
Var UacTaskbarChoice
Var UacShortcutDialog
Var UacDesktopCheckbox
Var UacStartMenuCheckbox
Var UacTaskbarCheckbox

; Display-only name also feeds NSIS's localized setup/uninstall captions.
; PRODUCTNAME/INSTALLATIONID remain fixed for matching and registry identities.
Name "$(UacProductName)"
BrandingText "${COPYRIGHT}"
OutFile "${OUTFILE}"

; We don't actually use this value as default install path,
; it's just for nsis to append the product name folder in the directory selector
; https://nsis.sourceforge.io/Reference/InstallDir
!define PLACEHOLDER_INSTALL_DIR "placeholder\${INSTALLATIONID}"
InstallDir "${PLACEHOLDER_INSTALL_DIR}"

VIProductVersion "${VERSIONWITHBUILD}"
VIAddVersionKey "ProductName" "${PRODUCTNAME}"
VIAddVersionKey "FileDescription" "${PRODUCTNAME}"
VIAddVersionKey "LegalCopyright" "${COPYRIGHT}"
VIAddVersionKey "FileVersion" "${VERSION}"
VIAddVersionKey "ProductVersion" "${VERSION}"

# additional plugins
!addplugindir "${ADDITIONALPLUGINSPATH}"

; Uninstaller signing command
!if "${UNINSTALLERSIGNCOMMAND}" != ""
  !uninstfinalize '${UNINSTALLERSIGNCOMMAND}'
!endif

; Handle install mode, `perUser`, `perMachine` or `both`
!if "${INSTALLMODE}" == "perMachine"
  RequestExecutionLevel admin
!endif

!if "${INSTALLMODE}" == "currentUser"
  RequestExecutionLevel user
!endif

!if "${INSTALLMODE}" == "both"
  !define MULTIUSER_MUI
  !define MULTIUSER_INSTALLMODE_INSTDIR "${PRODUCTNAME}"
  !define MULTIUSER_INSTALLMODE_COMMANDLINE
  !if "${ARCH}" == "x64"
    !define MULTIUSER_USE_PROGRAMFILES64
  !else if "${ARCH}" == "arm64"
    !define MULTIUSER_USE_PROGRAMFILES64
  !endif
  !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_KEY "${UNINSTKEY}"
  !define MULTIUSER_INSTALLMODE_DEFAULT_REGISTRY_VALUENAME "CurrentUser"
  !define MULTIUSER_INSTALLMODEPAGE_SHOWUSERNAME
  !define MULTIUSER_INSTALLMODE_FUNCTION RestorePreviousInstallLocation
  !define MULTIUSER_EXECUTIONLEVEL Highest
  !include MultiUser.nsh
!endif

; Installer icon
!if "${INSTALLERICON}" != ""
  !define MUI_ICON "${INSTALLERICON}"
!endif

; Installer sidebar image
!if "${SIDEBARIMAGE}" != ""
  !define MUI_WELCOMEFINISHPAGE_BITMAP "${SIDEBARIMAGE}"
!endif

; Enable header images for installer and uninstaller pages when either image is configured.
!if "${HEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE
!else if "${UNINSTALLERHEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE
!endif

; Installer header image
!if "${HEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE_BITMAP "${HEADERIMAGE}"
!endif

; Uninstaller header image
!if "${UNINSTALLERHEADERIMAGE}" != ""
  !define MUI_HEADERIMAGE_UNBITMAP "${UNINSTALLERHEADERIMAGE}"
!endif

; Uninstaller icon
!if "${UNINSTALLERICON}" != ""
  !define MUI_UNICON "${UNINSTALLERICON}"
!endif

; Define registry key to store installer language
!define MUI_LANGDLL_REGISTRY_ROOT "HKLM"
!define MUI_LANGDLL_REGISTRY_KEY "${MANUPRODUCTKEY}"
!define MUI_LANGDLL_REGISTRY_VALUENAME "Installer Language"

; Installer pages, must be ordered as they appear
; 1. Welcome Page
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_WELCOME

; 2. License Page (if defined)
!if "${LICENSE}" != ""
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !insertmacro MUI_PAGE_LICENSE "${LICENSE}"
!endif

; 3. Install mode (if it is set to `both`)
!if "${INSTALLMODE}" == "both"
  !define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
  !insertmacro MULTIUSER_PAGE_INSTALLMODE
!endif

; 4. Custom page to ask user if he wants to reinstall/uninstall
;    only if a previous installation was detected
; Fixed-product upgrades do not execute registry-provided uninstall commands.
; Explicit service stop occurs in PREINSTALL before any binary replacement.

; Fixed native Program Files location; no /D or directory-selection override.

; 6. One explicit page for all shortcut choices. The folder is fixed, not a
; registry-selected or user-entered elevated write destination.
Var AppStartMenuFolder
Page custom UacShortcutPage UacShortcutPageLeave

; 7. Installation page
!insertmacro MUI_PAGE_INSTFILES

; 8. Finish page
;
; Don't auto jump to finish page after installation page,
; because the installation page has useful info that can be used debug any issues with the installer.
!define MUI_FINISHPAGE_NOAUTOCLOSE
; No postinstall app execution from the elevated installer.
!define MUI_PAGE_CUSTOMFUNCTION_PRE SkipIfPassive
!insertmacro MUI_PAGE_FINISH



; Uninstaller Pages
; 1. Confirm uninstall page
; No data/key deletion option: service trust/activity and user settings survive.
!define MUI_PAGE_CUSTOMFUNCTION_PRE un.SkipIfPassive
!insertmacro MUI_UNPAGE_CONFIRM

; 2. Uninstalling Page
!insertmacro MUI_UNPAGE_INSTFILES

;Languages
{{#each languages}}
!insertmacro MUI_LANGUAGE "{{this}}"
{{/each}}
!insertmacro MUI_RESERVEFILE_LANGDLL
{{#each language_files}}
  !include "{{this}}"
{{/each}}

LangString UacProductName 1033 "UAC Remote Approval"
LangString UacProductName 1042 "UAC 원격 승인"
LangString UacProductName 1036 "Approbation UAC à distance"
LangString UacProductName 1031 "UAC-Freigabe aus der Ferne"
LangString UacProductName 1041 "UAC リモート承認"
LangString UacProductName 2052 "UAC 远程批准"
LangString UacProductName 1028 "UAC 遠端核准"
LangString UacProductName 1034 "Aprobación remota de UAC"
LangString UacProductName 1046 "Aprovação remota do UAC"
LangString UacProductName 2070 "Aprovação remota do UAC"
LangString UacProductName 1025 "الموافقة على UAC عن بُعد"

LangString UacShortcutsTitle 1042 "바로가기 선택"
LangString UacShortcutsTitle 1033 "Choose shortcuts"
LangString UacShortcutsSubtitle 1042 "앱을 어디에서 열지 선택하세요."
LangString UacShortcutsSubtitle 1033 "Choose where you will open the app."
LangString UacShortcutsFresh 1042 "새 설치입니다. 원하는 바로가기를 선택해 주세요."
LangString UacShortcutsFresh 1033 "New installation. Choose the shortcuts you want."
LangString UacShortcutsUpgrade 1042 "업그레이드 또는 복구 설치입니다. 선택하지 않은 기존 바로가기는 그대로 둡니다."
LangString UacShortcutsUpgrade 1033 "Upgrade or repair. Existing shortcuts remain unchanged when not selected."
LangString UacShortcutDesktop 1042 "바탕화면에 추가"
LangString UacShortcutDesktop 1033 "Add to desktop"
LangString UacShortcutStartMenu 1042 "시작 메뉴의 앱 목록에 추가"
LangString UacShortcutStartMenu 1033 "Add to the Start menu app list"
LangString UacShortcutTaskbar 1042 "작업표시줄에 추가 (앱에서 Windows 확인)"
LangString UacShortcutTaskbar 1033 "Add to taskbar — confirm with Windows in the app"
LangString UacShortcutHint 1042 "작업표시줄 추가에는 시작 메뉴 바로가기도 필요해 함께 선택됩니다. 설치 후 앱을 열면 고정 방법을 안내합니다. Windows 버전에 따라 직접 고정해야 할 수 있어요."
LangString UacShortcutHint 1033 "Taskbar pinning also needs a Start menu shortcut, so both are selected together. Open the app after setup for pinning instructions. Some Windows versions require manual pinning."

LangString UacShortcutsTitle 1036 "Choisir les raccourcis"
LangString UacShortcutsTitle 1031 "Verknüpfungen auswählen"
LangString UacShortcutsTitle 1041 "ショートカットの選択"
LangString UacShortcutsTitle 2052 "选择快捷方式"
LangString UacShortcutsTitle 1028 "選擇捷徑"
LangString UacShortcutsTitle 1034 "Elegir accesos directos"
LangString UacShortcutsTitle 1046 "Escolher atalhos"
LangString UacShortcutsTitle 2070 "Escolher atalhos"
LangString UacShortcutsTitle 1025 "اختيار الاختصارات"
LangString UacShortcutsSubtitle 1036 "Choisissez où ouvrir l’application."
LangString UacShortcutsSubtitle 1031 "Wählen Sie, wo Sie die App öffnen möchten."
LangString UacShortcutsSubtitle 1041 "アプリを開く場所を選んでください。"
LangString UacShortcutsSubtitle 2052 "选择从哪里打开应用。"
LangString UacShortcutsSubtitle 1028 "選擇從哪裡開啟應用程式。"
LangString UacShortcutsSubtitle 1034 "Elija desde dónde abrir la aplicación."
LangString UacShortcutsSubtitle 1046 "Escolha de onde abrir o app."
LangString UacShortcutsSubtitle 2070 "Escolha de onde abrir a aplicação."
LangString UacShortcutsSubtitle 1025 "اختر من أين تريد فتح التطبيق."
LangString UacShortcutsFresh 1036 "Nouvelle installation. Choisissez les raccourcis souhaités."
LangString UacShortcutsFresh 1031 "Neuinstallation. Wählen Sie die gewünschten Verknüpfungen."
LangString UacShortcutsFresh 1041 "新規インストールです。必要なショートカットを選んでください。"
LangString UacShortcutsFresh 2052 "这是全新安装。请选择所需的快捷方式。"
LangString UacShortcutsFresh 1028 "這是全新安裝。請選擇所需的捷徑。"
LangString UacShortcutsFresh 1034 "Instalación nueva. Elija los accesos directos que desee."
LangString UacShortcutsFresh 1046 "Nova instalação. Escolha os atalhos desejados."
LangString UacShortcutsFresh 2070 "Nova instalação. Escolha os atalhos pretendidos."
LangString UacShortcutsFresh 1025 "تثبيت جديد. اختر الاختصارات التي تريدها."
LangString UacShortcutsUpgrade 1036 "Mise à niveau ou réparation. Les raccourcis existants non sélectionnés restent inchangés."
LangString UacShortcutsUpgrade 1031 "Upgrade oder Reparatur. Nicht ausgewählte vorhandene Verknüpfungen bleiben unverändert."
LangString UacShortcutsUpgrade 1041 "更新または修復インストールです。選択しない既存のショートカットはそのまま残ります。"
LangString UacShortcutsUpgrade 2052 "升级或修复安装。未选中的现有快捷方式将保持不变。"
LangString UacShortcutsUpgrade 1028 "升級或修復安裝。未選取的現有捷徑將保持不變。"
LangString UacShortcutsUpgrade 1034 "Actualización o reparación. Los accesos directos existentes no seleccionados se conservan."
LangString UacShortcutsUpgrade 1046 "Atualização ou reparo. Os atalhos existentes não selecionados permanecem inalterados."
LangString UacShortcutsUpgrade 2070 "Atualização ou reparação. Os atalhos existentes não selecionados permanecem inalterados."
LangString UacShortcutsUpgrade 1025 "ترقية أو إصلاح. تبقى الاختصارات الحالية غير المحددة دون تغيير."
LangString UacShortcutDesktop 1036 "Ajouter au bureau"
LangString UacShortcutDesktop 1031 "Zum Desktop hinzufügen"
LangString UacShortcutDesktop 1041 "デスクトップに追加"
LangString UacShortcutDesktop 2052 "添加到桌面"
LangString UacShortcutDesktop 1028 "新增至桌面"
LangString UacShortcutDesktop 1034 "Añadir al escritorio"
LangString UacShortcutDesktop 1046 "Adicionar à área de trabalho"
LangString UacShortcutDesktop 2070 "Adicionar ao ambiente de trabalho"
LangString UacShortcutDesktop 1025 "إضافة إلى سطح المكتب"
LangString UacShortcutStartMenu 1036 "Ajouter à la liste d’applications du menu Démarrer"
LangString UacShortcutStartMenu 1031 "Zur App-Liste im Startmenü hinzufügen"
LangString UacShortcutStartMenu 1041 "スタートメニューのアプリ一覧に追加"
LangString UacShortcutStartMenu 2052 "添加到开始菜单的应用列表"
LangString UacShortcutStartMenu 1028 "新增至開始功能表的應用程式清單"
LangString UacShortcutStartMenu 1034 "Añadir a la lista de aplicaciones de Inicio"
LangString UacShortcutStartMenu 1046 "Adicionar à lista de apps do menu Iniciar"
LangString UacShortcutStartMenu 2070 "Adicionar à lista de aplicações do menu Iniciar"
LangString UacShortcutStartMenu 1025 "إضافة إلى قائمة التطبيقات في قائمة ابدأ"
LangString UacShortcutTaskbar 1036 "Ajouter à la barre des tâches — confirmer dans l’application"
LangString UacShortcutTaskbar 1031 "Zur Taskleiste hinzufügen — in der App mit Windows bestätigen"
LangString UacShortcutTaskbar 1041 "タスクバーに追加（アプリ内で Windows に確認）"
LangString UacShortcutTaskbar 2052 "添加到任务栏（在应用中由 Windows 确认）"
LangString UacShortcutTaskbar 1028 "新增至工作列（在應用程式中由 Windows 確認）"
LangString UacShortcutTaskbar 1034 "Añadir a la barra de tareas — confirmar con Windows en la aplicación"
LangString UacShortcutTaskbar 1046 "Adicionar à barra de tarefas — confirmar com o Windows no app"
LangString UacShortcutTaskbar 2070 "Adicionar à barra de tarefas — confirmar com o Windows na aplicação"
LangString UacShortcutTaskbar 1025 "إضافة إلى شريط المهام — التأكيد مع Windows داخل التطبيق"
LangString UacShortcutHint 1036 "L’épinglage à la barre des tâches nécessite aussi un raccourci Démarrer : les deux sont sélectionnés ensemble. Ouvrez l’application après l’installation pour les instructions. Selon Windows, l’épinglage peut être manuel."
LangString UacShortcutHint 1031 "Für die Taskleiste wird auch eine Startmenü-Verknüpfung benötigt; beide werden gemeinsam ausgewählt. Öffnen Sie die App nach der Installation für Hinweise. Je nach Windows-Version ist manuelles Anheften nötig."
LangString UacShortcutHint 1041 "タスクバーへのピン留めにはスタートメニューのショートカットも必要なため、両方を選択します。インストール後にアプリを開くと手順を確認できます。Windows のバージョンによっては手動でのピン留めが必要です。"
LangString UacShortcutHint 2052 "固定到任务栏还需要开始菜单快捷方式，因此会同时选中两项。安装后请打开应用查看固定说明。某些 Windows 版本需要手动固定。"
LangString UacShortcutHint 1028 "釘選至工作列還需要開始功能表捷徑，因此會同時選取兩項。安裝後請開啟應用程式查看釘選說明。部分 Windows 版本需要手動釘選。"
LangString UacShortcutHint 1034 "La barra de tareas también necesita un acceso en Inicio; ambos se seleccionan juntos. Abra la aplicación tras instalar para ver las instrucciones. Algunas versiones de Windows requieren anclar manualmente."
LangString UacShortcutHint 1046 "Fixar na barra de tarefas também exige um atalho no menu Iniciar; ambos são selecionados juntos. Abra o app após a instalação para ver as instruções. Algumas versões do Windows exigem fixação manual."
LangString UacShortcutHint 2070 "Fixar na barra de tarefas também exige um atalho no menu Iniciar; ambos são selecionados em conjunto. Abra a aplicação após a instalação para ver as instruções. Algumas versões do Windows exigem fixação manual."
LangString UacShortcutHint 1025 "يتطلب التثبيت في شريط المهام اختصارًا في قائمة ابدأ أيضًا، لذا يُحددان معًا. افتح التطبيق بعد التثبيت للاطلاع على التعليمات. قد يلزم التثبيت يدويًا في بعض إصدارات Windows."

Function UacInitializeShortcutChoices
  ; Evaluate once before registration/payload writes. A partial installation is
  ; an upgrade too; /UPDATE is an additional conservative signal, not the only one.
  StrCpy $AppStartMenuFolder "${STARTMENUFOLDER}"
  StrCpy $UacExistingInstall 0
  ClearErrors
  EnumRegValue $0 HKLM "${UNINSTKEY}" 0
  ${IfNot} ${Errors}
    StrCpy $UacExistingInstall 1
  ${EndIf}
  ClearErrors
  EnumRegValue $0 HKLM "${MANUPRODUCTKEY}" 0
  ${IfNot} ${Errors}
    StrCpy $UacExistingInstall 1
  ${EndIf}
  ${If} ${FileExists} "$INSTDIR\${MAINBINARYNAME}.exe"
  ${OrIf} ${FileExists} "$INSTDIR\uac-service.exe"
  ${OrIf} $UpdateMode = 1
    StrCpy $UacExistingInstall 1
  ${EndIf}
  StrCpy $UacDesktopChoice ${BST_CHECKED}
  StrCpy $UacStartMenuChoice ${BST_CHECKED}
  StrCpy $UacTaskbarChoice ${BST_CHECKED}
  ${If} $UacExistingInstall = 1
  ${OrIf} $NoShortcutMode = 1
    StrCpy $UacDesktopChoice ${BST_UNCHECKED}
    StrCpy $UacStartMenuChoice ${BST_UNCHECKED}
    StrCpy $UacTaskbarChoice ${BST_UNCHECKED}
  ${EndIf}
  ; Unattended setup never requests a later taskbar prompt without a choice.
  ${If} $PassiveMode = 1
  ${OrIf} ${Silent}
    StrCpy $UacTaskbarChoice ${BST_UNCHECKED}
  ${EndIf}
FunctionEnd

Function UacShortcutPage
  ${If} $PassiveMode = 1
  ${OrIf} $NoShortcutMode = 1
    Abort
  ${EndIf}
  !insertmacro MUI_HEADER_TEXT "$(UacShortcutsTitle)" "$(UacShortcutsSubtitle)"
  nsDialogs::Create 1018
  Pop $UacShortcutDialog
  ${If} $UacShortcutDialog == error
    StrCpy $UacFailure "$(UacCopyFailed)"
    Call UacFail
  ${EndIf}
  ${If} $UacExistingInstall = 1
    ${NSD_CreateLabel} 0 0 100% 24u "$(UacShortcutsUpgrade)"
  ${Else}
    ${NSD_CreateLabel} 0 0 100% 24u "$(UacShortcutsFresh)"
  ${EndIf}
  Pop $0
  ${NSD_CreateCheckbox} 0 24u 100% 24u "$(UacShortcutDesktop)"
  Pop $UacDesktopCheckbox
  ${NSD_SetState} $UacDesktopCheckbox $UacDesktopChoice
  ${NSD_OnClick} $UacDesktopCheckbox UacShortcutChanged
  ${NSD_CreateCheckbox} 0 48u 100% 24u "$(UacShortcutStartMenu)"
  Pop $UacStartMenuCheckbox
  ${NSD_SetState} $UacStartMenuCheckbox $UacStartMenuChoice
  ${NSD_OnClick} $UacStartMenuCheckbox UacShortcutChanged
  ${NSD_CreateCheckbox} 0 72u 100% 24u "$(UacShortcutTaskbar)"
  Pop $UacTaskbarCheckbox
  ${NSD_SetState} $UacTaskbarCheckbox $UacTaskbarChoice
  ${NSD_OnClick} $UacTaskbarCheckbox UacShortcutChanged
  ; Keep the whole localized hint within the 140u custom-page client area.
  ${NSD_CreateLabel} 0 100u 100% 40u "$(UacShortcutHint)"
  Pop $0
  nsDialogs::Show
FunctionEnd

Function UacShortcutChanged
  Pop $0
  ${NSD_GetState} $UacDesktopCheckbox $UacDesktopChoice
  ${NSD_GetState} $UacStartMenuCheckbox $UacStartMenuChoice
  ${NSD_GetState} $UacTaskbarCheckbox $UacTaskbarChoice
  ${If} $0 = $UacTaskbarCheckbox
  ${AndIf} $UacTaskbarChoice = ${BST_CHECKED}
    StrCpy $UacStartMenuChoice ${BST_CHECKED}
    ${NSD_SetState} $UacStartMenuCheckbox $UacStartMenuChoice
  ${ElseIf} $UacStartMenuChoice <> ${BST_CHECKED}
    StrCpy $UacTaskbarChoice ${BST_UNCHECKED}
    ${NSD_SetState} $UacTaskbarCheckbox $UacTaskbarChoice
  ${EndIf}
FunctionEnd

Function UacShortcutPageLeave
  ; OnClick already retains changes when navigating Back. Capture again on Next.
  ${NSD_GetState} $UacDesktopCheckbox $UacDesktopChoice
  ${NSD_GetState} $UacStartMenuCheckbox $UacStartMenuChoice
  ${NSD_GetState} $UacTaskbarCheckbox $UacTaskbarChoice
FunctionEnd

Function UacSaveTaskbarPreference
  ; This is a version-scoped app suggestion, never permission to pin silently.
  ; HKLM avoids writing another administrator's HKCU during alternate-user UAC.
  ClearErrors
  WriteRegDWORD HKLM "${UNINSTKEY}" "TaskbarPinRequested" 0
  ${If} ${Errors}
    StrCpy $UacFailure "$(UacCopyFailed)"
    Call UacFail
  ${EndIf}
  ClearErrors
  WriteRegStr HKLM "${UNINSTKEY}" "TaskbarPinRequestVersion" "${VERSION}"
  ${If} ${Errors}
    StrCpy $UacFailure "$(UacCopyFailed)"
    Call UacFail
  ${EndIf}
  ${If} $NoShortcutMode <> 1
  ${AndIf} $PassiveMode <> 1
  ${AndIfNot} ${Silent}
  ${AndIf} $UacStartMenuChoice = ${BST_CHECKED}
  ${AndIf} $UacTaskbarChoice = ${BST_CHECKED}
    ClearErrors
    WriteRegDWORD HKLM "${UNINSTKEY}" "TaskbarPinRequested" 1
    ${If} ${Errors}
      StrCpy $UacFailure "$(UacCopyFailed)"
      Call UacFail
    ${EndIf}
  ${EndIf}
FunctionEnd

Function .onInit
  ${GetOptions} $CMDLINE "/P" $PassiveMode
  ${IfNot} ${Errors}
    StrCpy $PassiveMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/NS" $NoShortcutMode
  ${IfNot} ${Errors}
    StrCpy $NoShortcutMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
  ${IfNot} ${Errors}
    StrCpy $UpdateMode 1
  ${EndIf}

  ; Cosmetic override only: absent/unknown tags retain NSIS's OS-selected
  ; language. Never show a startup language picker or accept a language file.
  ; Use parameters (not the executable path) and assign compiled LANGIDs only.
  ${GetParameters} $0
  ClearErrors
  ${GetOptions} $0 "/LANG=" $1
  ${IfNot} ${Errors}
    ${If} $1 == "en"
      StrCpy $LANGUAGE 1033
    ${ElseIf} $1 == "ko"
      StrCpy $LANGUAGE 1042
    ${ElseIf} $1 == "fr"
      StrCpy $LANGUAGE 1036
    ${ElseIf} $1 == "de"
      StrCpy $LANGUAGE 1031
    ${ElseIf} $1 == "ja"
      StrCpy $LANGUAGE 1041
    ${ElseIf} $1 == "zh-Hans"
      StrCpy $LANGUAGE 2052
    ${ElseIf} $1 == "zh-Hant"
      StrCpy $LANGUAGE 1028
    ${ElseIf} $1 == "es"
      StrCpy $LANGUAGE 1034
    ${ElseIf} $1 == "pt-BR"
      StrCpy $LANGUAGE 1046
    ${ElseIf} $1 == "pt-PT"
      StrCpy $LANGUAGE 2070
    ${ElseIf} $1 == "ar"
      StrCpy $LANGUAGE 1025
    ${EndIf}
  ${EndIf}
  ClearErrors

  !insertmacro SetContext

  Call UacFixedLocation
  SetRegView 64
  Call UacInitializeShortcutChoices

  !if "${INSTALLMODE}" == "both"
    !insertmacro MULTIUSER_INIT
  !endif
FunctionEnd


Section EarlyChecks
  ; Downgrades of a registered package remain refused, also in silent mode.
  ReadRegStr $0 HKLM "${UNINSTKEY}" "DisplayVersion"
  ${If} $0 != ""
    nsis_tauri_utils::SemverCompare "${VERSION}" $0
    Pop $0
    ${If} $0 != 0
    ${AndIf} $0 != 1
      StrCpy $UacFailure "$(UacUnsafe)"
      Call UacFail
    ${EndIf}
  ${EndIf}
SectionEnd

Section WebView2
  ; Prerequisite only: no elevated TEMP bootstrapper or registry-supplied updater.
  ; Read fixed machine registration in BOTH views, never HKCU executable paths.
  SetRegView 32
  ReadRegStr $0 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  SetRegView 64
  ${If} $0 = ""
    ReadRegStr $0 HKLM "SOFTWARE\Microsoft\EdgeUpdate\Clients\${WEBVIEW2APPGUID}" "pv"
  ${EndIf}
  ${If} $0 = ""
  ${OrIf} $0 = "0.0.0.0"
    StrCpy $UacFailure "$(UacWebViewRequired)"
    Call UacFail
  ${EndIf}
  ${VersionCompare} "$0" "86.0.616.0" $1
  ${If} $1 != 0
  ${AndIf} $1 != 1
    StrCpy $UacFailure "$(UacWebViewRequired)"
    Call UacFail
  ${EndIf}
SectionEnd

Section Install
  ; Native path/owner/DACL checks and prior-service stop precede SetOutPath.
  !insertmacro NSIS_HOOK_PREINSTALL
  StrCpy $UacFailure "$(UacCopyFailed)"
  ClearErrors
  SetOutPath $INSTDIR
  ${If} ${Errors}
    Call UacFail
  ${EndIf}

  ; Never kill a process by filename; checked file operations refuse busy files.

  ; Copy main executable
  ClearErrors
  File "${MAINBINARYSRCPATH}"
  ${If} ${Errors}
    Call UacFail
  ${EndIf}

  ; Copy resources
  {{#each resources_dirs}}
    CreateDirectory "$INSTDIR\\{{this}}"
  {{/each}}
  {{#each resources}}
    File /a "/oname={{this.[1]}}" "{{no-escape @key}}"
  {{/each}}

  ; Copy external binaries
  {{#each binaries}}
    ClearErrors
    File /a "/oname={{this}}" "{{no-escape @key}}"
    ${If} ${Errors}
      Call UacFail
    ${EndIf}
  {{/each}}

  ; Create file associations
  {{#each file_associations as |association| ~}}
    {{#each association.ext as |ext| ~}}
       !insertmacro APP_ASSOCIATE "{{ext}}" "{{or association.name ext}}" "{{association-description association.description ext}}" "$INSTDIR\${MAINBINARYNAME}.exe,0" "Open with ${PRODUCTNAME}" "$INSTDIR\${MAINBINARYNAME}.exe $\"%1$\""
    {{/each}}
  {{/each}}

  ; Register deep links
  {{#each deep_link_protocols as |protocol| ~}}
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "URL Protocol" ""
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}" "" "URL:${BUNDLEID} protocol"
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}\DefaultIcon" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\",0"
    WriteRegStr SHCTX "Software\Classes\\{{protocol}}\shell\open\command" "" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
  {{/each}}

  ; Create uninstaller
  ClearErrors
  WriteUninstaller "$INSTDIR\uninstall.exe"
  ${If} ${Errors}
    Call UacFail
  ${EndIf}

  ; Save $INSTDIR in registry for future installations
  WriteRegStr SHCTX "${MANUPRODUCTKEY}" "" $INSTDIR

  !if "${INSTALLMODE}" == "both"
    ; Save install mode to be selected by default for the next installation such as updating
    ; or when uninstalling
    WriteRegStr SHCTX "${UNINSTKEY}" $MultiUser.InstallMode 1
  !endif

  ; Never delete a registry-supplied old binary path.
  StrCpy $OldMainBinaryName "${MAINBINARYNAME}.exe"

  ; Save current MAINBINARYNAME for future updates
  WriteRegStr SHCTX "${UNINSTKEY}" "MainBinaryName" "${MAINBINARYNAME}.exe"

  ; Registry information for add/remove programs
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayName" "${PRODUCTNAME}"
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayIcon" "$\"$INSTDIR\${MAINBINARYNAME}.exe$\""
  WriteRegStr SHCTX "${UNINSTKEY}" "DisplayVersion" "${VERSION}"
  WriteRegStr SHCTX "${UNINSTKEY}" "Publisher" "${MANUFACTURER}"
  WriteRegStr SHCTX "${UNINSTKEY}" "InstallLocation" "$\"$INSTDIR$\""
  WriteRegStr SHCTX "${UNINSTKEY}" "UninstallString" "$\"$INSTDIR\uninstall.exe$\""
  WriteRegDWORD SHCTX "${UNINSTKEY}" "NoModify" "1"
  WriteRegDWORD SHCTX "${UNINSTKEY}" "NoRepair" "1"

  ${GetSize} "$INSTDIR" "/M=uninstall.exe /S=0K /G=0" $0 $1 $2
  IntOp $0 $0 + ${ESTIMATEDSIZE}
  IntFmt $0 "0x%08X" $0
  WriteRegDWORD SHCTX "${UNINSTKEY}" "EstimatedSize" "$0"

  !if "${HOMEPAGE}" != ""
    WriteRegStr SHCTX "${UNINSTKEY}" "URLInfoAbout" "${HOMEPAGE}"
    WriteRegStr SHCTX "${UNINSTKEY}" "URLUpdateInfo" "${HOMEPAGE}"
    WriteRegStr SHCTX "${UNINSTKEY}" "HelpLink" "${HOMEPAGE}"
  !endif

  Call CreateOrUpdateStartMenuShortcut
  Call CreateOrUpdateDesktopShortcut

  !ifmacrodef NSIS_HOOK_POSTINSTALL
    !insertmacro NSIS_HOOK_POSTINSTALL
  !endif
  Call UacSaveTaskbarPreference

  ; Auto close this page for passive mode
  ${If} $PassiveMode = 1
    SetAutoClose true
  ${EndIf}
SectionEnd

; No silent/passive /R autorun or elevated launch fallback.


Function un.onInit
  !insertmacro SetContext
  Call un.UacFixedLocation
  StrCpy $AppStartMenuFolder "${STARTMENUFOLDER}"

  !if "${INSTALLMODE}" == "both"
    !insertmacro MULTIUSER_UNINIT
  !endif

  !insertmacro MUI_UNGETLANGUAGE

  ${GetOptions} $CMDLINE "/P" $PassiveMode
  ${IfNot} ${Errors}
    StrCpy $PassiveMode 1
  ${EndIf}

  ${GetOptions} $CMDLINE "/UPDATE" $UpdateMode
  ${IfNot} ${Errors}
    StrCpy $UpdateMode 1
  ${EndIf}
FunctionEnd

Section Uninstall

  !ifmacrodef NSIS_HOOK_PREUNINSTALL
    !insertmacro NSIS_HOOK_PREUNINSTALL
  !endif

  ; Never kill a process by filename; checked file operations refuse busy files.

  ; Delete the app directory and its content from disk
  ; Fixed file deletion follows confirmed SCM removal; no recursive cleanup.
  StrCpy $UacFailure "$(UacFileFailed)"
  ClearErrors
  Delete "$INSTDIR\${MAINBINARYNAME}.exe"
  ${If} ${Errors}
    Call un.UacFail
  ${EndIf}

  ; Delete resources
  {{#each resources}}
    Delete "$INSTDIR\\{{this.[1]}}"
  {{/each}}

  ; Delete external binaries
  {{#each binaries}}
    ClearErrors
    Delete "$INSTDIR\\{{this}}"
    ${If} ${Errors}
      Call un.UacFail
    ${EndIf}
  {{/each}}

  ; Delete app associations
  {{#each file_associations as |association| ~}}
    {{#each association.ext as |ext| ~}}
      !insertmacro APP_UNASSOCIATE "{{ext}}" "{{or association.name ext}}"
    {{/each}}
  {{/each}}

  ; Delete deep links
  {{#each deep_link_protocols as |protocol| ~}}
    ReadRegStr $R7 SHCTX "Software\Classes\\{{protocol}}\shell\open\command" ""
    ${If} $R7 == "$\"$INSTDIR\${MAINBINARYNAME}.exe$\" $\"%1$\""
      DeleteRegKey SHCTX "Software\Classes\\{{protocol}}"
    ${EndIf}
  {{/each}}


  ; Delete uninstaller
  ClearErrors
  Delete "$INSTDIR\uninstall.exe"
  ${If} ${Errors}
    Call un.UacFail
  ${EndIf}

  {{#each resources_ancestors}}
  RMDir /REBOOTOK "$INSTDIR\\{{this}}"
  {{/each}}
  ; Keep parent pins, release only the directory being removed.
  ${If} $UacDirectoryPin <> 0
    System::Call 'kernel32::CloseHandle(p $UacDirectoryPin)'
    StrCpy $UacDirectoryPin 0
  ${EndIf}
  RMDir "$INSTDIR" ; Nonempty (unowned) contents are deliberately retained.

  ; Remove shortcuts if not updating
  ${If} $UpdateMode <> 1
    !insertmacro DeleteAppUserModelId

    ; Remove start menu shortcut
    !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
      Delete "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
      RMDir "$SMPROGRAMS\$AppStartMenuFolder"
    ${EndIf}
    !insertmacro IsShortcutTarget "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk"
      Delete "$SMPROGRAMS\${PRODUCTNAME}.lnk"
    ${EndIf}

    ; Remove desktop shortcuts
    !insertmacro IsShortcutTarget "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$DESKTOP\${PRODUCTNAME}.lnk"
      Delete "$DESKTOP\${PRODUCTNAME}.lnk"
    ${EndIf}

    ; /NOSHORTCUTS may intentionally preserve legacy names during an upgrade.
    ; Remove them on uninstall only when they still target this exact binary.
    !insertmacro IsShortcutTarget "$SMPROGRAMS\$AppStartMenuFolder\${INSTALLATIONID}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\$AppStartMenuFolder\${INSTALLATIONID}.lnk"
      ClearErrors
      Delete "$SMPROGRAMS\$AppStartMenuFolder\${INSTALLATIONID}.lnk"
      ${If} ${Errors}
        StrCpy $UacFailure "$(UacFileFailed)"
        Call un.UacFail
      ${EndIf}
      RMDir "$SMPROGRAMS\$AppStartMenuFolder"
    ${EndIf}
    !insertmacro IsShortcutTarget "$SMPROGRAMS\${INSTALLATIONID}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$SMPROGRAMS\${INSTALLATIONID}.lnk"
      ClearErrors
      Delete "$SMPROGRAMS\${INSTALLATIONID}.lnk"
      ${If} ${Errors}
        StrCpy $UacFailure "$(UacFileFailed)"
        Call un.UacFail
      ${EndIf}
    ${EndIf}
    !insertmacro IsShortcutTarget "$DESKTOP\${INSTALLATIONID}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    Pop $0
    ${If} $0 = 1
      !insertmacro UnpinShortcut "$DESKTOP\${INSTALLATIONID}.lnk"
      ClearErrors
      Delete "$DESKTOP\${INSTALLATIONID}.lnk"
      ${If} ${Errors}
        StrCpy $UacFailure "$(UacFileFailed)"
        Call un.UacFail
      ${EndIf}
    ${EndIf}
  ${EndIf}

  ; Remove registry information for add/remove programs
  !if "${INSTALLMODE}" == "both"
    DeleteRegKey SHCTX "${UNINSTKEY}"
  !else if "${INSTALLMODE}" == "perMachine"
    DeleteRegKey HKLM "${UNINSTKEY}"
  !else
    DeleteRegKey HKCU "${UNINSTKEY}"
  !endif

  ; Removes the Autostart entry for ${PRODUCTNAME} from the HKCU Run key if it exists.
  ; This ensures the program does not launch automatically after uninstallation if it exists.
  ; If it doesn't exist, it does nothing.
  ; We do this when not updating (to preserve the registry value on updates)
  ${If} $UpdateMode <> 1
    DeleteRegValue HKCU "Software\Microsoft\Windows\CurrentVersion\Run" "${PRODUCTNAME}"
  ${EndIf}

  ; Existing app settings, ProgramData and native keys are NEVER deleted.

  !ifmacrodef NSIS_HOOK_POSTUNINSTALL
    !insertmacro NSIS_HOOK_POSTUNINSTALL
  !endif

  ; Auto close if passive mode or updating
  ${If} $PassiveMode = 1
  ${OrIf} $UpdateMode = 1
    SetAutoClose true
  ${EndIf}
SectionEnd

Function RestorePreviousInstallLocation
  Call UacFixedLocation
FunctionEnd

Function Skip
  Abort
FunctionEnd

Function SkipIfPassive
  ${IfThen} $PassiveMode = 1  ${|} Abort ${|}
FunctionEnd
Function un.SkipIfPassive
  ${IfThen} $PassiveMode = 1  ${|} Abort ${|}
FunctionEnd

Function CreateOrUpdateStartMenuShortcut
  ${If} $NoShortcutMode = 1
  ${OrIf} $UacStartMenuChoice <> ${BST_CHECKED}
    Return
  ${EndIf}
  !insertmacro UacMigrateShortcut "$SMPROGRAMS\${INSTALLATIONID}.lnk" "$SMPROGRAMS\${PRODUCTNAME}.lnk"

  !if "${STARTMENUFOLDER}" != ""
    !insertmacro UacMigrateShortcut "$SMPROGRAMS\$AppStartMenuFolder\${INSTALLATIONID}.lnk" "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
    !insertmacro UacRequireOwnedShortcutOrMissing "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
    ClearErrors
    CreateDirectory "$SMPROGRAMS\$AppStartMenuFolder"
    ${If} ${Errors}
      StrCpy $UacFailure "$(UacCopyFailed)"
      Call UacFail
    ${EndIf}
    ClearErrors
    CreateShortcut "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    ${If} ${Errors}
      StrCpy $UacFailure "$(UacCopyFailed)"
      Call UacFail
    ${EndIf}
    !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\$AppStartMenuFolder\${PRODUCTNAME}.lnk"
  !else
    !insertmacro UacRequireOwnedShortcutOrMissing "$SMPROGRAMS\${PRODUCTNAME}.lnk"
    ClearErrors
    CreateShortcut "$SMPROGRAMS\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
    ${If} ${Errors}
      StrCpy $UacFailure "$(UacCopyFailed)"
      Call UacFail
    ${EndIf}
    !insertmacro SetLnkAppUserModelId "$SMPROGRAMS\${PRODUCTNAME}.lnk"
  !endif
FunctionEnd

Function CreateOrUpdateDesktopShortcut
  ${If} $NoShortcutMode = 1
  ${OrIf} $UacDesktopChoice <> ${BST_CHECKED}
    Return
  ${EndIf}
  !insertmacro UacMigrateShortcut "$DESKTOP\${INSTALLATIONID}.lnk" "$DESKTOP\${PRODUCTNAME}.lnk"

  !insertmacro UacRequireOwnedShortcutOrMissing "$DESKTOP\${PRODUCTNAME}.lnk"
  ClearErrors
  CreateShortcut "$DESKTOP\${PRODUCTNAME}.lnk" "$INSTDIR\${MAINBINARYNAME}.exe"
  ${If} ${Errors}
    StrCpy $UacFailure "$(UacCopyFailed)"
    Call UacFail
  ${EndIf}
  !insertmacro SetLnkAppUserModelId "$DESKTOP\${PRODUCTNAME}.lnk"
FunctionEnd
