// SPDX-License-Identifier: GPL-2.0-or-later
// Mechanical insertion of reviewed, authored USB transport labels.
import { readFileSync, writeFileSync } from 'node:fs';
const labels = { ko: 'USB로 연결', en: 'Connect by USB', fr: 'Connexion USB', de: 'Über USB verbinden', ja: 'USBで接続', 'zh-Hans': '通过 USB 连接', 'zh-Hant': '透過 USB 連線', es: 'Conectar por USB', 'pt-BR': 'Conectar por USB', 'pt-PT': 'Ligar por USB', ar: 'الاتصال عبر USB' };
const failureKey = 'USB 연결을 사용할 수 없습니다. USB 드라이버와 케이블을 확인하거나 QR 코드로 연결하십시오.';
const failures = {
  ko: failureKey, en: 'USB connection is unavailable. Check the USB driver and cable, or connect by QR code.',
  fr: 'Connexion USB indisponible. Vérifiez le pilote et le câble USB, ou utilisez le code QR.',
  de: 'USB-Verbindung nicht verfügbar. Prüfen Sie USB-Treiber und Kabel oder verbinden Sie sich per QR-Code.',
  ja: 'USB接続を利用できません。USBドライバーとケーブルを確認するか、QRコードで接続してください。',
  'zh-Hans': 'USB 连接不可用。请检查 USB 驱动程序和数据线，或通过二维码连接。',
  'zh-Hant': 'USB 連線無法使用。請檢查 USB 驅動程式和傳輸線，或透過 QR 碼連線。',
  es: 'Conexión USB no disponible. Compruebe el controlador y el cable USB, o conecte mediante QR.',
  'pt-BR': 'Conexão USB indisponível. Verifique o driver e o cabo USB ou conecte pelo código QR.',
  'pt-PT': 'Ligação USB indisponível. Verifique o controlador e o cabo USB ou ligue pelo código QR.',
  ar: 'اتصال USB غير متاح. تحقق من برنامج تشغيل USB والكابل أو اتصل باستخدام رمز QR.',
};
const guide = 'PC의 UAC 원격 승인 앱에서 ‘휴대폰 관리’ → ‘UAC 원격 승인’을 눌러 QR 코드를 여세요. 아래 버튼을 누르면 이 앱에서 카메라가 열려요.';
const keys = ['USB 연결 대기', '휴대폰에서 USB 연결을 허용하십시오. 연결 후 두 기기의 비교 코드를 확인하십시오.',
  '휴대폰 승인이 켜져 있는지 확인하지 못했어요.', '휴대폰 승인을 켜거나 끈 결과를 확인하지 못했어요.',
  '현재 상태와 자동 시작 설정을 확인한 뒤 다시 시도해 주세요.', '본인 확인을 진행해 주세요.'];
const translated = {
  ko: ['USB 연결 대기', '휴대폰에서 USB 연결을 허용하십시오. 연결 후 두 기기의 비교 코드를 확인하십시오.', '휴대폰 서비스 상태를 확인하지 못했습니다.', '휴대폰 서비스 변경 결과를 확인하지 못했습니다.', '현재 상태와 자동 실행 설정을 확인한 뒤 다시 시도하십시오.', '본인 확인을 진행하십시오.'],
  en: ['Waiting for USB connection', 'Allow USB access on the phone. Then compare the codes on both devices.', 'Could not check the phone service status.', 'Could not confirm the phone service change.', 'Check the current state and automatic startup setting, then try again.', 'Complete identity verification.'],
  fr: ['En attente de la connexion USB', 'Autorisez l’accès USB sur le téléphone, puis comparez les codes des deux appareils.', 'Impossible de vérifier le service du téléphone.', 'Modification du service du téléphone non confirmée.', 'Vérifiez l’état actuel et le démarrage automatique, puis réessayez.', 'Effectuez la vérification d’identité.'],
  de: ['Warten auf USB-Verbindung', 'Erlauben Sie den USB-Zugriff am Telefon. Vergleichen Sie dann die Codes beider Geräte.', 'Der Telefondienststatus konnte nicht geprüft werden.', 'Die Änderung des Telefondienstes konnte nicht bestätigt werden.', 'Prüfen Sie Status und Autostart-Einstellung und versuchen Sie es erneut.', 'Bestätigen Sie Ihre Identität.'],
  ja: ['USB接続待機中', 'スマートフォンでUSBアクセスを許可し、両方の端末の比較コードを確認してください。', 'スマートフォンのサービス状態を確認できませんでした。', 'スマートフォンのサービス変更結果を確認できませんでした。', '現在の状態と自動起動設定を確認して再試行してください。', '本人確認を行ってください。'],
  'zh-Hans': ['等待 USB 连接', '在手机上允许 USB 访问，然后核对两台设备的验证码。', '无法确认手机服务状态。', '无法确认手机服务变更结果。', '请检查当前状态和自动启动设置，然后重试。', '请完成身份验证。'],
  'zh-Hant': ['等待 USB 連線', '在手機上允許 USB 存取，然後核對兩台裝置的驗證碼。', '無法確認手機服務狀態。', '無法確認手機服務變更結果。', '請檢查目前狀態和自動啟動設定，然後重試。', '請完成身分驗證。'],
  es: ['Esperando conexión USB', 'Permita el acceso USB en el teléfono y compare los códigos de ambos dispositivos.', 'No se pudo comprobar el servicio del teléfono.', 'No se pudo confirmar el cambio del servicio del teléfono.', 'Compruebe el estado y el inicio automático e inténtelo de nuevo.', 'Complete la verificación de identidad.'],
  'pt-BR': ['Aguardando conexão USB', 'Permita o acesso USB no celular e compare os códigos nos dois dispositivos.', 'Não foi possível verificar o serviço do celular.', 'Não foi possível confirmar a alteração do serviço do celular.', 'Verifique o estado atual e a inicialização automática e tente novamente.', 'Conclua a verificação de identidade.'],
  'pt-PT': ['A aguardar ligação USB', 'Permita o acesso USB no telemóvel e compare os códigos nos dois dispositivos.', 'Não foi possível verificar o serviço do telemóvel.', 'Não foi possível confirmar a alteração do serviço do telemóvel.', 'Verifique o estado atual e o arranque automático e tente novamente.', 'Conclua a verificação de identidade.'],
  ar: ['بانتظار اتصال USB', 'اسمح بالوصول عبر USB على الهاتف ثم قارن الرمزين على الجهازين.', 'تعذر التحقق من حالة خدمة الهاتف.', 'تعذر تأكيد تغيير خدمة الهاتف.', 'تحقق من الحالة الحالية وإعداد بدء التشغيل التلقائي ثم أعد المحاولة.', 'أكمل التحقق من الهوية.'],
};
const androidCopy = {
  fr: ['Connexion USB au PC', 'Branchez le câble et choisissez USB sur le PC. Autorisez l’accès sur Android. Attente maximale : 30 secondes.', 'Impossible de lire les informations USB. Vérifiez le câble et l’autorisation USB, ou utilisez le code QR.'],
  de: ['PC über USB verbinden', 'Verbinden Sie das Kabel und wählen Sie USB am PC. Erlauben Sie den Zugriff unter Android. Wartezeit: höchstens 30 Sekunden.', 'USB-Verbindungsdaten konnten nicht gelesen werden. Prüfen Sie Kabel und USB-Berechtigung oder verwenden Sie den QR-Code.'],
  ja: ['USBでPCに接続', 'ケーブルを接続してPCでUSBを選択し、Androidでアクセスを許可してください。最大30秒待機します。', 'USB接続情報を読み取れませんでした。ケーブルとUSB権限を確認するか、QRコードで接続してください。'],
  'zh-Hans': ['通过 USB 连接 PC', '连接数据线，在 PC 上选择 USB，并在 Android 上允许访问。最多等待 30 秒。', '无法读取 USB 连接信息。请检查数据线和 USB 权限，或通过二维码连接。'],
  'zh-Hant': ['透過 USB 連線至 PC', '連接傳輸線，在 PC 上選擇 USB，並在 Android 上允許存取。最多等待 30 秒。', '無法讀取 USB 連線資訊。請檢查傳輸線和 USB 權限，或透過 QR 碼連線。'],
  es: ['Conectar PC por USB', 'Conecte el cable, elija USB en el PC y permita el acceso en Android. Espera máxima: 30 segundos.', 'No se pudieron leer los datos USB. Compruebe el cable y el permiso USB, o conecte mediante QR.'],
  'pt-BR': ['Conectar PC por USB', 'Conecte o cabo, selecione USB no PC e permita o acesso no Android. Espera máxima: 30 segundos.', 'Não foi possível ler os dados USB. Verifique o cabo e a permissão USB ou conecte pelo código QR.'],
  'pt-PT': ['Ligar PC por USB', 'Ligue o cabo, selecione USB no PC e permita o acesso no Android. Espera máxima: 30 segundos.', 'Não foi possível ler os dados USB. Verifique o cabo e a permissão USB ou ligue pelo código QR.'],
  ar: ['توصيل الكمبيوتر عبر USB', 'وصّل الكابل واختر USB على الكمبيوتر واسمح بالوصول في Android. الانتظار لمدة 30 ثانية كحد أقصى.', 'تعذرت قراءة بيانات اتصال USB. تحقق من الكابل وإذن USB أو اتصل باستخدام رمز QR.'],
};
for (const [locale, label] of Object.entries(labels)) {
  const path = `locales/${locale}.json`;
  const catalog = JSON.parse(readFileSync(path, 'utf8'));
  catalog['USB로 연결'] = label;
  catalog[failureKey] = failures[locale];
  keys.forEach((key, index) => { catalog[key] = translated[locale][index]; });
  if (locale !== 'ko') {
    // The source key stays stable. Update the quoted action, not the app name.
    const oldName = catalog['UAC 원격 승인'];
    const last = catalog[guide].lastIndexOf(oldName);
    if (last >= 0) catalog[guide] = catalog[guide].slice(0, last) + catalog['QR 코드 보기'] + catalog[guide].slice(last + oldName.length);
  }
  writeFileSync(path, JSON.stringify(catalog, null, 2) + '\n');
  if (androidCopy[locale]) {
    const qualifier = { 'zh-Hans': 'b+zh+Hans', 'zh-Hant': 'b+zh+Hant', 'pt-BR': 'pt-rBR', 'pt-PT': 'pt-rPT' }[locale] ?? locale;
    const xmlPath = `src-tauri/gen/android/app/src/main/res/values-${qualifier}/strings.xml`;
    let xml = readFileSync(xmlPath, 'utf8');
    const names = ['pairing_usb_title', 'pairing_usb_waiting', 'pairing_usb_unavailable'];
    for (let index = 0; index < names.length; index += 1) {
      if (xml.includes(`name="${names[index]}"`)) continue;
      const value = androidCopy[locale][index].replaceAll('&', '&amp;').replaceAll("'", "\\'");
      xml = xml.replace('</resources>', `    <string name="${names[index]}">${value}</string>\n</resources>`);
    }
    writeFileSync(xmlPath, xml);
  }
}
