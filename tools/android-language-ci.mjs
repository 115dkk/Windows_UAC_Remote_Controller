// SPDX-License-Identifier: GPL-2.0-or-later
// Runs only on the same explicit disposable AVD after lifecycle/scanner checks.
import { execFileSync } from 'node:child_process';
import { writeFileSync } from 'node:fs';
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
