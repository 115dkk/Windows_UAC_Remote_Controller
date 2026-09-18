# Add project specific ProGuard rules here.
# You can control the set of applied configuration files using the
# proguardFiles setting in build.gradle.
#
# For more details, see
#   http://developer.android.com/guide/developing/tools/proguard.html

# If your project uses WebView with JS, uncomment the following
# and specify the fully qualified class name to the JavaScript interface
# class:
#-keepclassmembers class fqcn.of.javascript.interface.for.webview {
#   public *;
#}

# Shrinking and optimization stay on; only renaming goes.
#
# This tree is public and GPL-2.0-or-later, so renaming hides names that are
# already published with their comments. It also cannot reach the part worth
# hiding if hiding were the goal: R8 only rewrites dex, and the protocol, the
# key handling and the state machine live in the Rust .so, which is 52% of the
# APK against dex's 5%. The security here rests on keys, attestation, the secure
# desktop and Windows policy, and a tool that asks for UAC approvals is better
# for being readable.
#
# What it cost: every stack frame from a real device had to be carried back
# through a 32 MB mapping artifact by hand, and that artifact expires with the
# workflow run. Line numbers are kept for the same reason.
-dontobfuscate
-keepattributes SourceFile,LineNumberTable

# Deliberately left off: that would hide the source file name this build is
# keeping on purpose.
#-renamesourcefileattribute SourceFile

# UniFFI/JNA is a native ABI, not just statically reachable Kotlin code. Rust
# symbol lookup and JNA Structure/callback reflection depend on original names,
# fields, constructors and method shapes. Debug APKs do not exercise R8.
# Keep this generated ABI and its native loader; the rest of release stays shrunk.
-keep class dev.dkk115.uacremote.nativecore.** { *; }
-keep class com.sun.jna.** { *; }
# NativeMappedConverter reflectively constructs ByReference/IntegerType and
# other derived values even when Kotlin never explicitly invokes their ctor.
-keep class * extends com.sun.jna.* { *; }
-keepclassmembers class * extends com.sun.jna.* { public *; }
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod

# JNA's documented Android configuration excludes optional desktop AWT types.
# Keep this list limited to the four types reported by the real release R8 job;
# no missing Android/native ABI class or general warning is suppressed.
# https://github.com/java-native-access/jna/blob/master/www/FrequentlyAskedQuestions.md#jna-on-android
-dontwarn java.awt.Component
-dontwarn java.awt.GraphicsEnvironment
-dontwarn java.awt.HeadlessException
-dontwarn java.awt.Window
