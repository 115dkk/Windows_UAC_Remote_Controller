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

# Uncomment this to preserve the line number information for
# debugging stack traces.
#-keepattributes SourceFile,LineNumberTable

# If you keep the line number information, uncomment this to
# hide the original source file name.
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
