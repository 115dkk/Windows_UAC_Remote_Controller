<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# Windows service installer

The package builds the desktop application, fixed `uac-service.exe` and fixed
`uac-prompt-probe.exe` into one **per-machine x64 NSIS installer**. Running the
build/inspection scripts does not execute an installer or service. Installation
and UAC acceptance require a separately authorized native test; this document
does not claim that those tests passed.

## Build and passive inspection

On a Windows x64 build host with the repository-pinned Rust/Node dependencies,
Windows SDK, Tauri's NSIS dependencies and `7z` available, ROOT can run:

```text
node --test tools/windows-packaging.test.mjs tools/windows-installer-contract.test.mjs
node tools/windows-packaging.mjs build --dry-run
node tools/windows-packaging.mjs build
node tools/windows-packaging.mjs inspect
```

`stage` builds just the two native payloads with `cargo build --locked --release`
and stages them; `build` additionally invokes the existing Tauri CLI/frontend
build with `windows/package-config.json`. The supported target is explicitly
`x86_64-pc-windows-msvc`; other targets fail. `CARGO_TARGET_DIR` may select the
Cargo build directory, but generated package outputs stay at:

- `target/windows-package/controller-setup.exe`
- `target/windows-package/manifest.json`
- `target/windows-package/inspection.json`
- `target/windows-package/inputs/` with the two target-suffixed sidecars.

The generated namespace has a strict marker and entry allowlist. Unknown files,
links or unsupported staged shapes are not cleaned up or adopted. Cargo's normal
hardlinked build output is accepted only at the known build-source read; staged
and published files must be regular single-link copies. Each new stage first
invalidates any previous successful inspection record.

`inspect` reads the assembled file as data: bounded PE executable/stub checks,
exactly one outer NSIS archive descriptor, unique root names and exact hashes of
all three executable payloads extracted by `7z` **to stdout**, never executed.
Its receipt binds the actual installer, manifest and payload hashes and labels
its scope `passive-nsis-payload-only`. A generated manifest is build provenance,
not an Authenticode publisher identity or permission to execute an old file.
Inspection also invalidates its old receipt before starting, so a failed run
cannot leave a prior `passed:true` result in place.

Ordinary `tauri build` without the Windows overlay must fail NSIS compilation:
the template requires both exact service sidecars and prerequisite-only WebView2.
Linux/Android builds do not acquire these Windows sidecar requirements.
Tauri renders the JSON `webviewInstallMode: { type: "skip" }` choice as an empty
NSIS mode string. The build script enforces the exact JSON overlay; the template
rejects nonempty bootstrapper modes. The JSON and rendered representations must
not be compared as if they were the same string.

## Installed lifecycle

The only destination is the native Program Files folder plus `휴대폰 승인`.
There is no directory selection, `/D` override, registry-selected old uninstaller,
WiX migration execution, post-install app launch or silent `/R` launch. Users
open the non-elevated desktop application through normal shortcuts afterwards.

The custom template preserves Tauri's NSIS OS chrome and Korean/English resources.
Before any program-folder write or execution of an existing service helper it:

1. Requires 64-bit Windows and the fixed installation location. The installer
   itself is compile-locked to NSIS's x86 Unicode engine; its native structure
   layouts are not assumed to work under a different engine.
2. Pins each existing Program Files ancestor using actual read-category handles
   without delete sharing; checks local fixed-disk type, normalized same-handle
   path, directory type and absence of reparse points.
3. Checks same-handle owner/DACL. Owners are limited to SYSTEM, Administrators
   and TrustedInstaller. Only bounded standard allow/deny ACEs are interpreted;
   unknown flags/rights/shapes fail. Existing ancestors permit child creation but
   not replacement/metadata/delete/DACL/owner rights for untrusted principals.
   The installation directory is stricter and also refuses dangerous inherited
   child grants. No unsafe existing ACL is repaired.
4. If genuinely absent beneath those pinned parents, creates only the fixed
   product directory with an explicit protected inheritable SYSTEM/Admin full,
   Users read/execute descriptor, then validates/pins it. Existing executable
   leaves must be regular, single-link, non-reparse files with protected ownership
   and permissions before any old helper is executed.

ACE record and SID-declared lengths are checked **before** reading mask/SID data
or invoking SID comparison APIs. Original `CreateFileW`/`OpenServiceW` errors are
captured with System plug-in `?e`, not a later unrelated GetLastError call.
Allocated descriptors/SIDs and owned handles are bounded and released. Directory
pins remain during path-based file operations; old executable pins remain during
the old helper command, then close before file replacement.

Installation runs only these fixed installed CLI operations:

```text
"<fixed Program Files>\휴대폰 승인\uac-service.exe" stop
"<fixed Program Files>\휴대폰 승인\uac-service.exe" install
"<fixed Program Files>\휴대폰 승인\uac-service.exe" start
```

An existing service must stop before its binaries are replaced. A missing old
helper is accepted only with actual SCM service absence; no temporary helper is
launched as a fallback. The existing Rust `install` operation starts disabled,
hardens the service DACL, configures Restricted service SID, provisions the fixed
activity/trust directories, and **only then** configures AutoStart. `start` must
return success before NSIS finishes successfully. The service's runtime can
still fail TPM/key/registry initialization; those gates are not bypassed.

Failure does not imply rollback. Program files may have been partially changed;
service registration or AutoStart settings may remain. The installer aborts with
a nonzero result and outcome-specific instructions, retaining data/keys instead
of claiming completion. File replacement failures ask the user to close the app;
the installer never kills processes by a matching filename.

Uninstall validates the same fixed location/helper, calls the existing `uninstall`
CLI (bounded stop, delete service registration, confirm SCM absence), and only
then deletes the known packaged executables/uninstaller. File deletion failures
stop the operation. Nonempty folders containing other files remain. **ProgramData
activity/trust data, user settings and TPM identity keys are never deleted.**
Retained state is not silently initialized afresh on reinstall.

## WebView2 and signing boundaries

This installer only checks fixed **machine-installed** WebView2 registration and
a numeric minimum version (`86.0.616.0`). It never executes a downloaded TEMP
bootstrapper, an HKCU updater path, or an embedded runtime installer. Missing or
unsupported registration fails before program-folder mutation and directs the
user to Microsoft's official distribution. Registration inspection is not an
execution test or signature verification of WebView2 itself.

There is no new signing credential, automatic release publication or account
setup. Before public release, ROOT must configure and verify the intended
publisher signatures/timestamps for the executable payloads and installer,
review update/downgrade policy, and retain exact-source build evidence. The
manifest's `signing: not-attested` must not be presented as signed distribution.
Registered package downgrade checks do not provide hardware anti-rollback or
identify the version of an unregistered manual development installation.

## Upstream and local patch ownership

`src-tauri/windows/installer.nsi` originates from the installed
`tauri-bundler 2.9.4` NSIS template, under MIT OR Apache-2.0; this copy retains the
MIT notice in `LICENSE-TAURI-MIT.txt`. Local changes are GPL-2.0-or-later:
fixed destination; early protected preflight; exact service/helper assertions;
checked lifecycle/file/shortcut calls; no registry-command maintenance, recursive
app-data deletion, basename process kill or elevated app-launch fallback;
prerequisite-only WebView2. Current resources, file-association and deep-link
collections are empty and the build helper refuses unsupported expansion.

Relevant primary contracts: [Tauri NSIS customization](https://v2.tauri.app/distribute/windows-installer/#customizing-the-nsis-installer),
[NSIS System plug-in](https://nsis.sourceforge.io/Docs/System/System.html), and
[NSIS engine-size predefines](https://nsis.sourceforge.io/Docs/Chapter5.html#5.2).
ROOT owns executable verification, native install/update/uninstall acceptance and
visual evidence. Passing source-contract tests does not prove Windows ACL,
sharing, service, WebView2, installer UI or power-loss behavior.
