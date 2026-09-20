// SPDX-License-Identifier: GPL-2.0-or-later
// CI-only standard Win32 button adapter. Not linked or shipped in the product.
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class InstallerOptionsNative {
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetClassNameW(IntPtr hwnd, StringBuilder name, int size);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] private static extern int GetWindowTextW(IntPtr hwnd, StringBuilder text, int size);
    [DllImport("user32.dll")] private static extern uint GetWindowThreadProcessId(IntPtr hwnd, out uint pid);
    [DllImport("user32.dll")] private static extern bool IsWindowEnabled(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern bool IsWindowVisible(IntPtr hwnd);
    [DllImport("user32.dll")] private static extern int GetDlgCtrlID(IntPtr hwnd);
    [DllImport("user32.dll", EntryPoint="GetWindowLongW")] private static extern int GetWindowStyle(IntPtr hwnd, int index);
    [DllImport("user32.dll", SetLastError=true)] private static extern IntPtr SendMessageTimeoutW(IntPtr hwnd, uint message, UIntPtr wparam, IntPtr lparam, uint flags, uint timeout, out UIntPtr result);

    private static string CheckButton(IntPtr hwnd, uint expectedPid) {
        uint actualPid;
        if (hwnd == IntPtr.Zero || expectedPid == 0 || GetWindowThreadProcessId(hwnd, out actualPid) == 0 || actualPid != expectedPid || !IsWindowEnabled(hwnd) || !IsWindowVisible(hwnd)) throw new InvalidOperationException("Owned visible enabled wizard button required");
        var name = new StringBuilder(64);
        if (GetClassNameW(hwnd, name, name.Capacity) == 0 || !name.ToString().Equals("Button", StringComparison.OrdinalIgnoreCase)) throw new InvalidOperationException("Standard wizard button required");
        var text = new StringBuilder(256);
        if (GetWindowTextW(hwnd, text, text.Capacity) == 0) throw new InvalidOperationException("Button label unavailable");
        return text.ToString().Replace("&", "");
    }

    private static ulong Message(IntPtr hwnd, uint message) {
        UIntPtr result;
        if (SendMessageTimeoutW(hwnd, message, UIntPtr.Zero, IntPtr.Zero, 2, 3000, out result) == IntPtr.Zero) throw new Win32Exception(Marshal.GetLastWin32Error());
        return result.ToUInt64();
    }

    // Closed source-known NSIS ^NextBtn/^AgreeBtn labels after accelerator
    // removal. No caller-supplied regex or prefix, and no Install/Finish label.
    private static string[] NavigationLabels(string locale) {
        switch (locale) {
            case "en": return new[] { "Next >", "I Agree" };
            case "ko": return new[] { "다음 >", "동의함" };
            case "fr": return new[] { "Suivant >", "J'accepte" };
            case "de": return new[] { "Weiter >", "Annehmen" };
            case "ja": return new[] { "次へ(N) >", "同意する(A)" };
            case "zh-Hans": return new[] { "下一步(N) >", "我接受(I)" };
            case "zh-Hant": return new[] { "下一步(N) >", "我同意(A)" };
            case "es": return new[] { "Siguiente >", "Acepto" };
            case "pt-BR": return new[] { "Próximo >", "Eu Concordo" };
            case "pt-PT": return new[] { "Seguinte >", "Aceito" };
            case "ar": return new[] { "التالي >", "موافق" };
            default: throw new InvalidOperationException("Unknown gallery locale");
        }
    }

    private static string[] ShortcutLabels(string locale) {
        switch (locale) {
            case "en": return new[] { "Add to desktop", "Add to the Start menu app list", "Add to taskbar — confirm with Windows in the app" };
            case "ko": return new[] { "바탕화면에 추가", "시작 메뉴의 앱 목록에 추가", "작업표시줄에 추가 (앱에서 Windows 확인)" };
            case "fr": return new[] { "Ajouter au bureau", "Ajouter à la liste d’applications du menu Démarrer", "Ajouter à la barre des tâches — confirmer dans l’application" };
            case "de": return new[] { "Zum Desktop hinzufügen", "Zur App-Liste im Startmenü hinzufügen", "Zur Taskleiste hinzufügen — in der App mit Windows bestätigen" };
            case "ja": return new[] { "デスクトップに追加", "スタートメニューのアプリ一覧に追加", "タスクバーに追加（アプリ内で Windows に確認）" };
            case "zh-Hans": return new[] { "添加到桌面", "添加到开始菜单的应用列表", "添加到任务栏（在应用中由 Windows 确认）" };
            case "zh-Hant": return new[] { "新增至桌面", "新增至開始功能表的應用程式清單", "新增至工作列（在應用程式中由 Windows 確認）" };
            case "es": return new[] { "Añadir al escritorio", "Añadir a la lista de aplicaciones de Inicio", "Añadir a la barra de tareas — confirmar con Windows en la aplicación" };
            case "pt-BR": return new[] { "Adicionar à área de trabalho", "Adicionar à lista de apps do menu Iniciar", "Adicionar à barra de tarefas — confirmar com o Windows no app" };
            case "pt-PT": return new[] { "Adicionar ao ambiente de trabalho", "Adicionar à lista de aplicações do menu Iniciar", "Adicionar à barra de tarefas — confirmar com o Windows na aplicação" };
            case "ar": return new[] { "إضافة إلى سطح المكتب", "إضافة إلى قائمة التطبيقات في قائمة ابدأ", "إضافة إلى شريط المهام — التأكيد مع Windows داخل التطبيق" };
            default: throw new InvalidOperationException("Unknown gallery locale");
        }
    }

    public static bool IsNextLabel(string text, string locale) {
        string normalized = text.Replace("&", "");
        foreach (string known in NavigationLabels(locale)) if (normalized.Equals(known, StringComparison.Ordinal)) return true;
        return false;
    }

    public static int ShortcutIndex(string text, string locale) {
        string[] labels = ShortcutLabels(locale);
        for (int index = 0; index < labels.Length; index++) if (text.Equals(labels[index], StringComparison.Ordinal)) return index;
        return -1;
    }

    public static void Next(IntPtr hwnd, uint expectedPid, string locale) {
        string text = CheckButton(hwnd, expectedPid);
        int style = GetWindowStyle(hwnd, -16) & 0xF;
        if (GetDlgCtrlID(hwnd) != 1 || (style != 0 && style != 1) || !IsNextLabel(text, locale)) throw new InvalidOperationException("Only pre-install Next/Agree is allowed");
        Message(hwnd, 0x00F5); // BM_CLICK. Never the Install or Finish button.
    }

    public static bool Checked(IntPtr hwnd, uint expectedPid, string locale, int expectedChoice) {
        string text = CheckButton(hwnd, expectedPid);
        // GWL_STYLE is a 32-bit value even in an x64 host. Only standard
        // BS_CHECKBOX/BS_AUTOCHECKBOX are read; radio/push/3-state are refused.
        int style = GetWindowStyle(hwnd, -16) & 0xF;
        if ((style != 2 && style != 3) || expectedChoice < 0 || expectedChoice > 2 || ShortcutIndex(text, locale) != expectedChoice) throw new InvalidOperationException("Known standard shortcut checkbox required");
        ulong value = Message(hwnd, 0x00F0); // BM_GETCHECK, actual Win32 state.
        if (value > 1) throw new InvalidOperationException("Unexpected checkbox state");
        return value == 1;
    }
}
