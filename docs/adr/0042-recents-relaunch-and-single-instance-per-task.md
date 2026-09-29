<!-- SPDX-License-Identifier: GPL-2.0-or-later -->
# ADR 0042: The phone app is singleInstancePerTask, and Android 12 is the floor

Status: implemented source with unit coverage. The Recents launch itself is
not reproduced in CI: the refusal needs the vendor interception described
below, which the API 36 emulator does not have.

## Evidence

On a Galaxy S26 running One UI 9, tapping the app's card in Recents showed the
launcher toast "앱을 열지 못했어요." and nothing opened. The launcher icon and
notifications still worked, and other sideloaded apps opened from Recents.
A full bug report from 2026-09-30 shows the same sequence for every one of 18
attempts between 07:10 and 07:43:

```text
AASA_ActivityStartInterceptor: shouldInterceptFromRecents : dev.dkk115.uacremote, 0
ASKSManager: isPhishingThreatApps[Ex] is true.
AASA_ActivityTaskManager: shouldIntercept is true
AASA_ActivityStartInterceptor: Package is allowed: dev.dkk115.uacremote
E ActivityTaskManager: java.lang.IllegalArgumentException: Caller with mInTask
  Task{… A=10532:dev.dkk115.uacremote} has root ActivityRecord{… MainActivity t9485}
  but target is singleInstance/Task
  at com.android.server.wm.ActivityStarter.computeLaunchingTaskFlags
  at com.android.server.wm.ActivityStartController.startActivityInPackage
  at com.android.server.wm.ActivityTaskSupervisor.startActivityFromRecents
I ActivityTaskManager: START u0 {act=android.intent.action.MAIN … flg=0x10304000 …
  cmp=dev.dkk115.uacremote/.MainActivity} with LAUNCH_SINGLE_TASK … result code=-96
```

Samsung's anti-phishing check flags this app, and for a flagged app a Recents
tap is no longer a plain move of the live task to the front. It is a full
start of the task's base intent into that same task, so that the interceptor
can inspect it. The interceptor allowed it. AOSP's `computeLaunchingTaskFlags`
then rejects any start into an explicit task that already has a root when the
target is `singleTask` or `singleInstance`, and `MainActivity` was
`singleTask`. The other apps on the device were not flagged, so their Recents
taps took the ordinary path. Which property of this app sets the flag is not
known and is not ours to change.

## Decision

**`MainActivity` is `singleInstancePerTask`.** It keeps what `singleTask` gave
the app: the activity is always the root of its own task, launcher,
notification and shell starts find that task and deliver `onNewIntent` to the
one instance after clearing anything above it, and a second live instance never
appears, which the single-window attachment in `android_window.rs` depends on.
AOSP's rejection names only `singleTask` and `singleInstance`, so the
intercepted Recents start goes on to the existing instance and succeeds.

**Android 12 (API 31) is the minimum.** `singleInstancePerTask` does not exist
on Android 11. There the value would be read as `standard`, and a launcher tap
on a task that a notification created would stack a second `MainActivity` that
never receives the window. Keeping Android 11 would have needed a separate
guard with no emulator in CI to run it. The user chose to drop Android 11
(2026-09-30).

**A replayed base intent never acts.** The intercepted path hands the task's
base intent to `onNewIntent`, and a task that a notification created has that
notification's `uac-request` intent as its base. Android marks every Recents
start with `FLAG_ACTIVITY_LAUNCHED_FROM_HISTORY`, and
`NativeRequestRules.mayRouteActivity` now refuses such an intent the same way
it refuses restored state. This also covers the older path that recreates a
destroyed activity from its Recents card.

## Scope

Unchanged: notification intents, the service, the request routing rules other
than the history flag, and the Rust side. The `SDK_INT >= 31` branches that
are now always true were left as they are.
