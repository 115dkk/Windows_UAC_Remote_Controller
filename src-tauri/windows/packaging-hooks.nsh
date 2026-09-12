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
LangString UacInstallFailed 1042 "서비스 설치를 마치지 못했습니다. 프로그램 파일, 기록, 설정과 기기 연결 정보는 보존했으며 서비스 등록이나 자동 시작 설정이 남아 있을 수 있습니다. 서비스 상태를 확인한 뒤 다시 시도해 주세요."
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

LangString UacUnsafe 1036 "L’opération s’est arrêtée : l’emplacement fixe du programme ou ses permissions n’ont pas pu être vérifiés. L’historique, les réglages et les associations d’appareils n’ont pas été supprimés. Demandez à un administrateur de vérifier l’installation."
LangString UacUnsafe 1031 "Der feste Programmpfad oder seine Berechtigungen konnten nicht geprüft werden. Der Vorgang wurde beendet. Verlauf, Einstellungen und Geräteverbindungen wurden nicht gelöscht. Lassen Sie die Installation von einem Administrator prüfen."
LangString UacUnsafe 1041 "固定のプログラム保存先またはアクセス権を確認できず、処理を中断しました。既存の履歴、設定、機器の接続情報は削除していません。管理者にインストール状態の確認を依頼してください。"
LangString UacUnsafe 2052 "无法验证固定程序位置或其权限，操作已停止。现有历史记录、设置和设备连接信息未被删除。请管理员检查安装情况。"
LangString UacUnsafe 1028 "無法驗證固定程式位置或其權限，已停止操作。現有記錄、設定和裝置連線資訊未被刪除。請管理員檢查安裝狀態。"
LangString UacUnsafe 1034 "La operación se detuvo porque no se pudo verificar la ubicación fija del programa o sus permisos. No se eliminaron el historial, los ajustes ni las conexiones de dispositivos. Pida a un administrador que revise la instalación."
LangString UacUnsafe 1046 "A operação foi interrompida porque o local fixo do programa ou suas permissões não puderam ser verificados. Histórico, configurações e conexões de dispositivos não foram removidos. Peça a um administrador para revisar a instalação."
LangString UacUnsafe 2070 "A operação foi interrompida porque não foi possível verificar a localização fixa do programa ou as permissões. O histórico, as definições e as ligações dos dispositivos não foram removidos. Peça a um administrador para rever a instalação."
LangString UacUnsafe 1025 "توقفت العملية لتعذّر التحقق من موقع البرنامج المحدد أو أذوناته. لم يُحذف السجل أو الإعدادات أو معلومات اتصال الأجهزة. اطلب من مسؤول مراجعة التثبيت."
LangString UacStopFailed 1036 "L’arrêt du service existant n’a pas pu être confirmé. Ses fichiers n’ont pas été remplacés. Terminez les opérations en cours et relancez l’installation."
LangString UacStopFailed 1031 "Das Ende des bestehenden Dienstes konnte nicht bestätigt werden. Seine Programmdateien wurden nicht ersetzt. Beenden Sie laufende Vorgänge und versuchen Sie die Installation erneut."
LangString UacStopFailed 1041 "既存のサービスの停止を確認できませんでした。プログラムファイルは置き換えていません。進行中の処理を終了してからインストールを再度お試しください。"
LangString UacStopFailed 2052 "无法确认现有服务已停止。程序文件未被替换。请结束正在进行的操作后重新安装。"
LangString UacStopFailed 1028 "無法確認現有服務已停止。程式檔案未被取代。請結束進行中的操作後重新安裝。"
LangString UacStopFailed 1034 "No se pudo confirmar que el servicio existente se detuviera. Sus archivos no se reemplazaron. Termine las operaciones activas y vuelva a instalar."
LangString UacStopFailed 1046 "Não foi possível confirmar a parada do serviço existente. Os arquivos do programa não foram substituídos. Encerre as operações em andamento e tente instalar novamente."
LangString UacStopFailed 2070 "Não foi possível confirmar a paragem do serviço existente. Os ficheiros do programa não foram substituídos. Termine as operações em curso e tente instalar novamente."
LangString UacStopFailed 1025 "تعذّر تأكيد توقف الخدمة الحالية. لم تُستبدل ملفات البرنامج. أنهِ العمليات الجارية وحاول التثبيت مجددًا."
LangString UacInstallFailed 1036 "La configuration du service est incomplète. Les fichiers, l’historique, les réglages et les associations sont conservés ; l’enregistrement du service ou son démarrage automatique peuvent subsister. Vérifiez l’état du service avant de réessayer."
LangString UacInstallFailed 1031 "Die Diensteinrichtung ist unvollständig. Programmdateien, Verlauf, Einstellungen und Geräteverbindungen bleiben erhalten. Dienstregistrierung oder Autostart-Einstellungen können bestehen bleiben. Prüfen Sie den Dienststatus vor einem erneuten Versuch."
LangString UacInstallFailed 1041 "サービスの設定が完了しませんでした。プログラムファイル、履歴、設定、機器の接続情報は保持しています。サービス登録や自動起動設定が残っている可能性があります。サービスの状態を確認してから再度お試しください。"
LangString UacInstallFailed 2052 "服务设置未完成。程序文件、历史记录、设置和设备连接信息已保留；服务注册或自动启动设置可能仍然存在。请检查服务状态后重试。"
LangString UacInstallFailed 1028 "服務設定未完成。程式檔案、記錄、設定和裝置連線資訊已保留；服務註冊或自動啟動設定可能仍然存在。請檢查服務狀態後重試。"
LangString UacInstallFailed 1034 "La configuración del servicio no terminó. Se conservan archivos, historial, ajustes y conexiones; pueden permanecer el registro del servicio o el inicio automático. Revise el estado del servicio antes de reintentar."
LangString UacInstallFailed 1046 "A configuração do serviço não terminou. Arquivos, histórico, configurações e conexões foram mantidos; o registro do serviço ou a inicialização automática podem permanecer. Verifique o status do serviço antes de tentar novamente."
LangString UacInstallFailed 2070 "A configuração do serviço não terminou. Ficheiros, histórico, definições e ligações foram mantidos; o registo do serviço ou o arranque automático podem permanecer. Verifique o estado do serviço antes de tentar novamente."
LangString UacInstallFailed 1025 "لم يكتمل إعداد الخدمة. تم الاحتفاظ بالملفات والسجل والإعدادات واتصالات الأجهزة؛ قد يبقى تسجيل الخدمة أو التشغيل التلقائي. راجع حالة الخدمة قبل المحاولة مجددًا."
LangString UacStartFailed 1036 "Le démarrage automatique est configuré, mais le démarrage du service n’a pas été confirmé. L’installation est incomplète. Fichiers, historique, réglages et associations sont conservés. Vérifiez l’état du service avant de réessayer."
LangString UacStartFailed 1031 "Der Autostart ist eingerichtet, aber der Dienststart wurde nicht bestätigt. Die Installation ist unvollständig. Programmdateien, Verlauf, Einstellungen und Geräteverbindungen bleiben erhalten. Prüfen Sie den Dienststatus vor einem erneuten Versuch."
LangString UacStartFailed 1041 "自動起動は設定しましたが、サービスの起動を確認できませんでした。インストールは未完了です。プログラムファイル、履歴、設定、機器の接続情報は保持しています。サービスの状態を確認してから再度お試しください。"
LangString UacStartFailed 2052 "已配置自动启动，但无法确认服务已启动。安装未完成；程序文件、历史记录、设置和设备连接信息已保留。请检查服务状态后重试。"
LangString UacStartFailed 1028 "已設定自動啟動，但無法確認服務已啟動。安裝未完成；程式檔案、記錄、設定和裝置連線資訊已保留。請檢查服務狀態後重試。"
LangString UacStartFailed 1034 "Se configuró el inicio automático, pero no se confirmó el arranque del servicio. La instalación está incompleta; se conservan archivos, historial, ajustes y conexiones. Revise el estado del servicio antes de reintentar."
LangString UacStartFailed 1046 "A inicialização automática foi configurada, mas o início do serviço não foi confirmado. A instalação está incompleta; arquivos, histórico, configurações e conexões foram mantidos. Verifique o status do serviço antes de tentar novamente."
LangString UacStartFailed 2070 "O arranque automático foi configurado, mas o início do serviço não foi confirmado. A instalação está incompleta; ficheiros, histórico, definições e ligações foram mantidos. Verifique o estado do serviço antes de tentar novamente."
LangString UacStartFailed 1025 "تم إعداد التشغيل التلقائي، لكن لم يتأكد بدء الخدمة. التثبيت غير مكتمل؛ تم الاحتفاظ بالملفات والسجل والإعدادات واتصالات الأجهزة. راجع حالة الخدمة قبل المحاولة مجددًا."
LangString UacRemoveFailed 1036 "La suppression du service n’a pas été confirmée. Les fichiers, l’historique, les réglages et les associations sont conservés. Terminez les opérations en cours et réessayez la suppression."
LangString UacRemoveFailed 1031 "Die Dienstentfernung wurde nicht bestätigt. Programmdateien, Verlauf, Einstellungen und Geräteverbindungen bleiben erhalten. Beenden Sie laufende Vorgänge und versuchen Sie die Entfernung erneut."
LangString UacRemoveFailed 1041 "サービスの削除を確認できませんでした。プログラムファイル、履歴、設定、機器の接続情報は保持しています。進行中の処理を終了してから削除を再度お試しください。"
LangString UacRemoveFailed 2052 "无法确认服务已移除。程序文件、历史记录、设置和设备连接信息已保留。请结束正在进行的操作后重试移除。"
LangString UacRemoveFailed 1028 "無法確認服務已移除。程式檔案、記錄、設定和裝置連線資訊已保留。請結束進行中的操作後重試移除。"
LangString UacRemoveFailed 1034 "No se confirmó la eliminación del servicio. Se conservan archivos, historial, ajustes y conexiones. Termine las operaciones activas y vuelva a intentar la eliminación."
LangString UacRemoveFailed 1046 "A remoção do serviço não foi confirmada. Arquivos, histórico, configurações e conexões foram mantidos. Encerre as operações em andamento e tente remover novamente."
LangString UacRemoveFailed 2070 "A remoção do serviço não foi confirmada. Ficheiros, histórico, definições e ligações foram mantidos. Termine as operações em curso e tente remover novamente."
LangString UacRemoveFailed 1025 "لم تتأكد إزالة الخدمة. تم الاحتفاظ بالملفات والسجل والإعدادات واتصالات الأجهزة. أنهِ العمليات الجارية وحاول الإزالة مجددًا."
LangString UacFileFailed 1036 "Une opération sur les fichiers a échoué. Certains fichiers peuvent rester ou avoir changé. L’historique, les réglages et les associations n’ont pas été supprimés. Fermez l’application, vérifiez le service et réessayez."
LangString UacFileFailed 1031 "Ein Dateivorgang ist fehlgeschlagen. Einige Programmdateien können verbleiben oder verändert sein. Verlauf, Einstellungen und Geräteverbindungen wurden nicht gelöscht. Schließen Sie die App, prüfen Sie den Dienststatus und versuchen Sie es erneut."
LangString UacFileFailed 1041 "プログラムファイルの処理に失敗しました。一部のファイルが残っているか変更された可能性があります。履歴、設定、機器の接続情報は削除していません。アプリを閉じてサービスの状態を確認してから再度お試しください。"
LangString UacFileFailed 2052 "程序文件操作失败。部分文件可能仍然存在或已更改。历史记录、设置和设备连接信息未被删除。请关闭应用、检查服务状态后重试。"
LangString UacFileFailed 1028 "程式檔案操作失敗。部分檔案可能仍然存在或已變更。記錄、設定和裝置連線資訊未被刪除。請關閉應用程式、檢查服務狀態後重試。"
LangString UacFileFailed 1034 "Falló una operación de archivos. Algunos archivos pueden permanecer o haber cambiado. No se eliminaron el historial, los ajustes ni las conexiones. Cierre la aplicación, revise el estado del servicio y reintente."
LangString UacFileFailed 1046 "Uma operação de arquivos falhou. Alguns arquivos podem permanecer ou ter mudado. Histórico, configurações e conexões não foram removidos. Feche o app, verifique o status do serviço e tente novamente."
LangString UacFileFailed 2070 "Uma operação de ficheiros falhou. Alguns ficheiros podem permanecer ou ter sido alterados. O histórico, as definições e as ligações não foram removidos. Feche a aplicação, verifique o estado do serviço e tente novamente."
LangString UacFileFailed 1025 "فشلت عملية على ملفات البرنامج. قد تبقى بعض الملفات أو تكون قد تغيّرت. لم يُحذف السجل أو الإعدادات أو اتصالات الأجهزة. أغلق التطبيق وراجع حالة الخدمة ثم حاول مجددًا."
LangString UacCopyFailed 1036 "L’installation des fichiers est incomplète. Certains fichiers peuvent avoir changé ; l’enregistrement du service ou son démarrage automatique peuvent subsister. L’historique, les réglages et les associations sont conservés. Fermez l’application et vérifiez le service avant de réessayer."
LangString UacCopyFailed 1031 "Die Installation der Programmdateien ist unvollständig. Einige Dateien können verändert sein; Dienstregistrierung oder Autostart können bestehen bleiben. Verlauf, Einstellungen und Geräteverbindungen bleiben erhalten. Schließen Sie die App und prüfen Sie den Dienststatus vor einem erneuten Versuch."
LangString UacCopyFailed 1041 "プログラムファイルのインストールが完了しませんでした。一部のファイルが変更されたか、既存のサービス登録や自動起動設定が残っている可能性があります。履歴、設定、機器の接続情報は保持しています。アプリを閉じてサービスの状態を確認してから再度お試しください。"
LangString UacCopyFailed 2052 "程序文件安装未完成。部分文件可能已更改，先前的服务注册或自动启动设置可能仍然存在。历史记录、设置和设备连接信息已保留。请关闭应用并检查服务状态后重试。"
LangString UacCopyFailed 1028 "程式檔案安裝未完成。部分檔案可能已變更，先前的服務註冊或自動啟動設定可能仍然存在。記錄、設定和裝置連線資訊已保留。請關閉應用程式並檢查服務狀態後重試。"
LangString UacCopyFailed 1034 "La instalación de archivos no terminó. Algunos pueden haber cambiado y pueden permanecer el registro del servicio o el inicio automático anteriores. Se conservan historial, ajustes y conexiones. Cierre la aplicación y revise el servicio antes de reintentar."
LangString UacCopyFailed 1046 "A instalação dos arquivos não terminou. Alguns arquivos podem ter mudado e o registro do serviço ou a inicialização automática anteriores podem permanecer. Histórico, configurações e conexões foram mantidos. Feche o app e verifique o serviço antes de tentar novamente."
LangString UacCopyFailed 2070 "A instalação dos ficheiros não terminou. Alguns ficheiros podem ter sido alterados e o registo do serviço ou o arranque automático anteriores podem permanecer. O histórico, as definições e as ligações foram mantidos. Feche a aplicação e verifique o serviço antes de tentar novamente."
LangString UacCopyFailed 1025 "لم يكتمل تثبيت الملفات. ربما تغيّرت بعض الملفات وقد يبقى تسجيل الخدمة أو التشغيل التلقائي السابق. تم الاحتفاظ بالسجل والإعدادات واتصالات الأجهزة. أغلق التطبيق وراجع حالة الخدمة قبل المحاولة مجددًا."
LangString UacDataRetained 1036 "L’enregistrement du service et les fichiers installés ont été supprimés. L’historique, les réglages et les associations sont conservés. Un dossier contenant d’autres fichiers est également conservé."
LangString UacDataRetained 1031 "Dienstregistrierung und installierte Programmdateien wurden entfernt. Verlauf, Einstellungen und Geräteverbindungen bleiben erhalten. Ein Programmordner mit anderen Dateien bleibt ebenfalls bestehen."
LangString UacDataRetained 1041 "サービス登録とインストールしたプログラムファイルを削除しました。履歴、設定、機器の接続情報は保持しています。他のファイルを含むプログラムフォルダーも残しています。"
LangString UacDataRetained 2052 "已移除服务注册和安装的程序文件。历史记录、设置和设备连接信息已保留。包含其他文件的程序文件夹也会保留。"
LangString UacDataRetained 1028 "已移除服務註冊及安裝的程式檔案。記錄、設定和裝置連線資訊已保留。包含其他檔案的程式資料夾也會保留。"
LangString UacDataRetained 1034 "Se eliminaron el registro del servicio y los archivos instalados. Se conservan el historial, los ajustes y las conexiones. También se conserva la carpeta del programa si contiene otros archivos."
LangString UacDataRetained 1046 "O registro do serviço e os arquivos instalados foram removidos. Histórico, configurações e conexões foram mantidos. Uma pasta do programa que contenha outros arquivos também é mantida."
LangString UacDataRetained 2070 "O registo do serviço e os ficheiros instalados foram removidos. O histórico, as definições e as ligações foram mantidos. Uma pasta do programa com outros ficheiros também é mantida."
LangString UacDataRetained 1025 "أُزيل تسجيل الخدمة وملفات البرنامج المثبّتة. تم الاحتفاظ بالسجل والإعدادات واتصالات الأجهزة. يُحتفظ أيضًا بمجلد البرنامج إذا كان يحتوي على ملفات أخرى."
LangString UacWebViewRequired 1036 "La présence de Microsoft Edge WebView2 Runtime installé pour cet ordinateur n’a pas pu être confirmée. Installez ce composant depuis le site officiel de Microsoft, puis relancez l’installation. Aucun fichier du programme n’a été installé."
LangString UacWebViewRequired 1031 "Eine systemweite Installation von Microsoft Edge WebView2 Runtime konnte nicht bestätigt werden. Installieren Sie diese Komponente von der offiziellen Microsoft-Website und starten Sie das Installationsprogramm erneut. Es wurden keine Programmdateien installiert."
LangString UacWebViewRequired 1041 "この PC にインストールされた Microsoft Edge WebView2 Runtime を確認できませんでした。Microsoft 公式サイトからこのコンポーネントをインストールしてから再度お試しください。プログラムファイルはインストールしていません。"
LangString UacWebViewRequired 2052 "无法确认此电脑已安装 Microsoft Edge WebView2 Runtime。请从 Microsoft 官方网站安装此组件，然后重新运行安装程序。未安装任何程序文件。"
LangString UacWebViewRequired 1028 "無法確認此電腦已安裝 Microsoft Edge WebView2 Runtime。請從 Microsoft 官方網站安裝此元件，再重新執行安裝程式。未安裝任何程式檔案。"
LangString UacWebViewRequired 1034 "No se pudo confirmar una instalación de Microsoft Edge WebView2 Runtime para este equipo. Instálelo desde el sitio oficial de Microsoft y vuelva a ejecutar el instalador. No se instalaron archivos del programa."
LangString UacWebViewRequired 1046 "Não foi possível confirmar a instalação do Microsoft Edge WebView2 Runtime para este computador. Instale o componente pelo site oficial da Microsoft e execute o instalador novamente. Nenhum arquivo do programa foi instalado."
LangString UacWebViewRequired 2070 "Não foi possível confirmar a instalação do Microsoft Edge WebView2 Runtime para este computador. Instale o componente a partir do site oficial da Microsoft e volte a executar o instalador. Não foram instalados ficheiros do programa."
LangString UacWebViewRequired 1025 "تعذّر تأكيد تثبيت Microsoft Edge WebView2 Runtime على هذا الكمبيوتر. ثبّت هذا المكوّن من موقع Microsoft الرسمي، ثم شغّل برنامج التثبيت مجددًا. لم تُثبّت أي ملفات للبرنامج."

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
