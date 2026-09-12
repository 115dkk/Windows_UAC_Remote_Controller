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
-keepattributes *Annotation*,Signature,InnerClasses,EnclosingMethod
