// SPDX-License-Identifier: GPL-2.0-or-later
// Source contracts supplement, never replace, Android Gradle/native UI proof.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
const read = path => readFileSync(new URL(`../${path}`, import.meta.url), 'utf8');

test('diagnostics remain bounded app-owned tokens before explicit export', () => {
  const store = read('src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/AndroidDiagnosticStore.kt');
  assert.match(store, /createDeviceProtectedStorageContext\(\)\.noBackupFilesDir/u);
  assert.match(store, /MAX_FILE_BYTES = 128 \* 1024L/u);
  assert.match(store, /persistedTags = setOf\("UacBoot", "UacNative"\)/u);
  assert.match(store, /line\.startsWith\("UAC_NATIVE_"\)/u);
  assert.doesNotMatch(read('src-tauri/gen/android/app/src/main/AndroidManifest.xml'), /READ_LOGS/u);
});

test('export writes user-visible Downloads and shares only a content URI', () => {
  const source = read('src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/AndroidDiagnosticExporter.kt');
  assert.match(source, /MediaStore\.Downloads\.EXTERNAL_CONTENT_URI/u);
  assert.match(source, /Environment\.DIRECTORY_DOWNLOADS/u);
  assert.match(source, /Intent\.ACTION_SEND/u);
  assert.match(source, /Intent\.FLAG_GRANT_READ_URI_PERMISSION/u);
  assert.match(source, /ClipData\.newRawUri/u);
  assert.match(source, /putExtra\(Intent\.EXTRA_STREAM, exported\.uri\)/u);
  assert.doesNotMatch(source, /Uri\.fromFile|READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE/u);
});

test('renderer supplies no path, contents, recipient or authority', () => {
  const bridge = read('ui/src/bridge.ts');
  assert.match(bridge, /exportAndroidDiagnostics: \(\) => native<void>\('export_android_diagnostics'\)/u);
  const commands = read('src-tauri/src/commands.rs');
  const declaration = commands.split('pub(crate) async fn export_android_diagnostics(')[1];
  assert.ok(declaration);
  assert.match(declaration, /_arguments: crate::mobile::EmptyArguments/u);
  assert.match(declaration, /state\.admission\.try_enter\(\)/u);
  const native = read('src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/DeviceStateActivityCommands.kt');
  const scope = native.split('fun exportAndroidDiagnostics(invoke: Invoke)')[1].split('private fun deviceSecure()')[0];
  assert.match(scope, /AndroidDiagnosticExporter\.begin\(activity, ::isForeground\)/u);
  assert.doesNotMatch(scope, /AndroidDiagnosticExporter\.(?:acquire|execute|create|share|discard)/u);
  assert.doesNotMatch(scope, /postDelayed|MediaStore|ACTION_SEND|contentResolver|Lease/u);
});

test('export ownership is process-wide and provider cleanup is worker-owned', () => {
  const exporter = read('src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/AndroidDiagnosticExporter.kt');
  assert.match(exporter, /fun begin\(\s*activity: Activity,\s*stillForeground: \(\) -> Boolean,\s*completion: \(DiagnosticExportOutcome\) -> Unit/u);
  assert.match(exporter, /AtomicReference<Lease\?>/u);
  assert.match(exporter, /active\.compareAndSet\(this, null\)/u);
  assert.match(exporter, /ThreadPoolExecutor\(1, 1/u);
  assert.match(exporter, /unreapedLogcat\?\.isAlive == true/u);
  assert.match(exporter, /--uid=\$\{android\.os\.Process\.myUid\(\)\}/u);
  assert.match(exporter, /postDelayed\(timeout, PolicyOwnerBounds\.RESPONSE_TIMEOUT_MILLIS\)/u);
  assert.match(exporter, /foreground\(stillForeground\)/u);
  assert.match(exporter, /if \(handoff\.deleteDocument && exported != null\) discard\(context, exported\)/u);
  assert.match(exporter, /finally \{\s*lease\.release\(\)/u);
});

test('closed Rust diagnostic labels remain represented in the export grammar', () => {
  const store = read('src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/AndroidDiagnosticStore.kt');
  for (const file of ['crates/android-bindings/src/native_log.rs', 'crates/android-bindings/src/startup_diagnostics.rs']) {
    const labels = [...read(file).matchAll(/"([A-Z][A-Z_]+)"/gu)].map(match => match[1]);
    for (const label of labels) assert.ok(store.includes(`"${label}"`), `Export grammar missing ${label}`);
  }
});

test('save uses the native document picker without the share chooser or broad storage grants', () => {
  const exporter = read('src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/AndroidDiagnosticExporter.kt');
  const save = exporter.split('internal class SaveOperation')[1].split('The single production Interface')[0];
  assert.match(save, /Intent\.ACTION_CREATE_DOCUMENT/u);
  assert.match(save, /Intent\.CATEGORY_OPENABLE/u);
  assert.match(save, /type = "text\/plain"/u);
  assert.match(save, /uri\?\.scheme != "content"/u);
  assert.match(save, /openOutputStream\(uri, "wt"\)/u);
  assert.match(save, /output\.write\(bytes\)/u);
  assert.match(save, /snapshotBytes\(\)/u);
  assert.match(save, /!execute \{/u);
  assert.match(save, /finally \{ release\(\) \}/u);
  assert.match(save, /val lease = acquire\(\) \?: return null/u);
  assert.doesNotMatch(save, /ACTION_SEND|createChooser|takePersistableUriPermission|FLAG_GRANT_PERSISTABLE_URI_PERMISSION/u);
  const manifest = read('src-tauri/gen/android/app/src/main/AndroidManifest.xml');
  assert.doesNotMatch(manifest, /READ_EXTERNAL_STORAGE|WRITE_EXTERNAL_STORAGE|MANAGE_EXTERNAL_STORAGE/u);
});

test('save picker stays attached to its original physical adapter and reports cancellation separately', () => {
  const native = read('src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/DeviceStateActivityCommands.kt');
  const save = native.split('fun saveAndroidDiagnostics(invoke: Invoke)')[1].split('private fun deviceSecure()')[0];
  assert.match(save, /acceptsNoArguments\(invoke\)/u);
  assert.match(save, /AndroidDiagnosticExporter\.beginSave\(activity, ::isForeground\)/u);
  assert.match(save, /activity\.activityResultRegistry\.register/u);
  assert.match(save, /ActivityResultContracts\.StartActivityForResult\(\)/u);
  assert.match(save, /UUID\.randomUUID\(\)/u);
  assert.match(save, /diagnosticSave !== operation/u);
  assert.match(save, /!matches\(webView\)/u);
  assert.match(save, /cancelled = result\.resultCode == Activity\.RESULT_CANCELED/u);
  assert.match(save, /invoke\.resolveObject\("saved"\)/u);
  assert.match(save, /invoke\.resolveObject\("cancelled"\)/u);
  assert.match(native, /diagnosticSave\?\.retire\(\)/u);
  assert.match(native, /diagnosticSaveLauncher\?\.unregister\(\)/u);
  const commands = read('src-tauri/src/commands.rs').split('pub(crate) async fn save_android_diagnostics(')[1].split('#[tauri::command]')[0];
  assert.match(commands, /_arguments: crate::mobile::EmptyArguments/u);
  assert.match(commands, /origin: crate::mobile::CommandOrigin/u);
  assert.match(commands, /state\.admission\.try_enter\(\)/u);
  assert.match(commands, /spawn_blocking/u);
});

test('native save/provider instrumentation is required on the guarded lifecycle AVD', () => {
  const runner = read('tools/android-language-ci.mjs');
  assert.match(runner, /process\.env\.CI !== 'true' \|\| process\.env\.GITHUB_ACTIONS !== 'true'/u);
  assert.match(runner, /uac-lifecycle-ci-36-x86_64/u);
  assert.match(runner, /dev\.dkk115\.uacremote\.AndroidDiagnosticSaveInstrumentationTest/u);
  assert.match(runner, /diagnostic-save-tests\.txt/u);
  assert.match(runner, /assert\.match\(saveOutput/u);
  assert.match(runner, /assert\.doesNotMatch\(saveOutput/u);
  const native = read('src-tauri/gen/android/app/src/androidTest/java/dev/dkk115/uacremote/AndroidDiagnosticSaveInstrumentationTest.kt');
  assert.match(native, /AndroidDiagnosticExporter\.beginSave/u);
  assert.match(native, /AndroidDiagnosticExporter\.saveDocumentIntent\(\)/u);
  assert.match(native, /ActivityResultContracts\.StartActivityForResult\(\)/u);
  assert.match(native, /KEYCODE_BACK/u);
  assert.match(native, /DiagnosticSaveOutcome\.CANCELLED/u);
  assert.match(native, /DiagnosticSaveOutcome\.SAVED/u);
  assert.match(native, /contentResolver\.openInputStream\(uri\)/u);
});
