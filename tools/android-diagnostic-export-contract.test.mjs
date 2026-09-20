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
