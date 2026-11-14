// SPDX-License-Identifier: GPL-2.0-or-later
// Runs only on the same explicit disposable AVD after lifecycle/scanner checks.
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync } from 'node:fs';
import { resolve } from 'node:path';
import assert from 'node:assert/strict';
if (process.env.CI !== 'true' || process.env.GITHUB_ACTIONS !== 'true') throw new Error('Hosted CI only');
const sdk = process.env.ANDROID_HOME ?? process.env.ANDROID_SDK_ROOT;
if (!sdk) throw new Error('Configured Android SDK required');
const adb = args => execFileSync(resolve(sdk, 'platform-tools/adb'), ['-s','emulator-5554',...args], {encoding:'utf8',timeout:120000,maxBuffer:2*1024*1024});
assert.match(adb(['emu','avd','name']), /^uac-lifecycle-ci-36-x86_64\r?\n/u);
assert.equal(adb(['shell','getprop','ro.kernel.qemu']).trim(),'1');
assert.equal(adb(['shell','getprop','ro.build.version.sdk']).trim(),'36');
const output = adb(['shell','am','instrument','-w','-r','-e','class','dev.dkk115.uacremote.LanguagePresentationInstrumentationTest','dev.dkk115.uacremote.test/androidx.test.runner.AndroidJUnitRunner']);
writeFileSync('target/android-lifecycle-ci/language-tests.txt',output);
assert.match(output,/OK \(2 tests\)/u);
assert.doesNotMatch(output,/FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed/u);
process.stdout.write('Actual Android locale resources, RTL and BidiFormatter display-only tests passed. No physical authentication claim.\n');
const backOutput = adb(['shell','am','instrument','-w','-r','-e','class','dev.dkk115.uacremote.LanguageBackInstrumentationTest','dev.dkk115.uacremote.test/androidx.test.runner.AndroidJUnitRunner']);
writeFileSync('target/android-lifecycle-ci/language-back-tests.txt',backOutput);
assert.match(backOutput,/OK \(1 test\)/u);
assert.doesNotMatch(backOutput,/FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed/u);
process.stdout.write('Actual Android Back cancelled unsaved language drafts, restored focus, kept the Activity and preserved normal Back without a dialog.\n');
let saveOutput;
const captureRun = String(Date.now());
try {
  saveOutput = adb(['shell','am','instrument','-w','-r','-e','diagnosticCapture','uac-lifecycle-ci-36-x86_64','-e','diagnosticCaptureRun',captureRun,'-e','class','dev.dkk115.uacremote.AndroidDiagnosticSaveInstrumentationTest','dev.dkk115.uacremote.test/androidx.test.runner.AndroidJUnitRunner']);
} finally {
  // Optional bounded DocumentsUI captures survive selector/test failure. Pull
  // only exact synthetic names; do not change the instrumentation result.
  for (const stage of ['picker-ready', 'before-save', 'picker-failure']) {
    for (const extension of ['txt', 'png']) {
      const filename = 'diagnostic-save-' + stage + '.' + extension;
      try {
        if (extension === 'png') {
          const summary = readFileSync(resolve('target/android-lifecycle-ci', 'diagnostic-save-' + stage + '.txt'), 'utf8');
          assert.ok(summary.includes('\ncapture_run=' + captureRun + '\n') && summary.endsWith('screenshot=ready\n'),
            'A current-run successful capture is required before pulling PNG');
        }
        adb(['pull', '/sdcard/Android/data/dev.dkk115.uacremote/files/' + filename,
          resolve('target/android-lifecycle-ci', filename)]);
      } catch {
        process.stderr.write('Optional document-picker capture unavailable: ' + stage + '.' + extension + '\n');
      }
    }
  }
  // An app that stopped answering reaches the instrumentation as one line, and
  // this process runs after the lifecycle driver that reads failure evidence.
  // On a failure only, keep what the disposable AVD recorded: the same closed
  // log tags the lifecycle driver reads, and the system's own ANR entries with
  // the thread that was not answering. Neither changes the result below.
  if (saveOutput === undefined || !/OK \(1 test\)/u.test(saveOutput)) {
    const evidence = [
      ['failure-logcat', ['shell', 'logcat', '-d', '-v', 'threadtime', 'AndroidRuntime:E', 'System.err:W', 'RustStdoutStderr:I',
        'UacNative:I', 'ActivityManager:I', 'ActivityTaskManager:I', 'InputDispatcher:W', '*:S']],
      ['failure-anr', ['shell', 'dumpsys', 'dropbox', '--print', 'data_app_anr']],
    ];
    for (const [name, args] of evidence) {
      try {
        const text = execFileSync(resolve(sdk, 'platform-tools/adb'), ['-s', 'emulator-5554', ...args],
          { encoding: 'utf8', timeout: 60000, maxBuffer: 32 * 1024 * 1024 });
        // The failure is the newest thing in either; keep the end.
        writeFileSync(resolve('target/android-lifecycle-ci', 'diagnostic-save-' + name + '.txt'), text.slice(-2 * 1024 * 1024));
      } catch {
        process.stderr.write('Optional failure evidence unavailable: ' + name + '\n');
      }
    }
  }
}
writeFileSync('target/android-lifecycle-ci/diagnostic-save-tests.txt',saveOutput);
assert.match(saveOutput,/OK \(1 test\)/u);
assert.doesNotMatch(saveOutput,/FAILURES!!!|INSTRUMENTATION_FAILED|Process crashed/u);
process.stdout.write('Actual Android document-picker Back cancellation and selected-provider diagnostic bytes passed through the production exporter. No JS-bridge or physical-phone claim.\n');
