import java.util.Properties
import java.io.File
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("rust")
}

val tauriProperties = Properties().apply {
    val propFile = file("tauri.properties")
    if (propFile.exists()) {
        propFile.inputStream().use { load(it) }
    }
}

android {
    compileSdk = 36
    ndkVersion = "28.2.13676358"
    namespace = "dev.dkk115.uacremote"
    defaultConfig {
        manifestPlaceholders["usesCleartextTraffic"] = "false"
        applicationId = "dev.dkk115.uacremote"
        minSdk = 30
        targetSdk = 36
        // The second native component is currently built for this ABI only.
        // Never package an ABI that would start without its policy owner.
        ndk { abiFilters += "arm64-v8a" }
        versionCode = tauriProperties.getProperty("tauri.android.versionCode", "1").toInt()
        versionName = tauriProperties.getProperty("tauri.android.versionName", "1.0")
    }
    buildTypes {
        getByName("debug") {
            manifestPlaceholders["usesCleartextTraffic"] = "true"
            isDebuggable = true
            isJniDebuggable = true
            isMinifyEnabled = false
            packaging {                jniLibs.keepDebugSymbols.add("*/arm64-v8a/*.so")
                jniLibs.keepDebugSymbols.add("*/armeabi-v7a/*.so")
                jniLibs.keepDebugSymbols.add("*/x86/*.so")
                jniLibs.keepDebugSymbols.add("*/x86_64/*.so")
            }
        }
        getByName("release") {
            isMinifyEnabled = true
            proguardFiles(
                *fileTree(".") { include("**/*.pro") }
                    .plus(getDefaultProguardFile("proguard-android-optimize.txt"))
                    .toList().toTypedArray()
            )
        }
    }
    buildFeatures {
        buildConfig = true
    }
    packaging {
        // JNA boot loading is restricted to the package-owned native directory.
        // Extract installed libraries there instead of enabling cache fallback.
        jniLibs.useLegacyPackaging = true
    }
}

rust {
    rootDirRel = "../../../"
}

dependencies {
    // Android AAR, not the desktop JNA jar; required by generated UniFFI types.
    implementation("net.java.dev.jna:jna:5.19.1@aar")
    implementation("androidx.webkit:webkit:1.14.0")
    implementation("androidx.appcompat:appcompat:1.7.1")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.lifecycle:lifecycle-process:2.10.0")
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.4")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.0")
}

kotlin {
    compilerOptions {
        jvmTarget.set(JvmTarget.JVM_1_8)
        allWarningsAsErrors.set(true)
    }
}

// This separate native component is packaged alongside, not instead of, the
// original Tauri library. Its generation and APK staging share one dependency.
// The primary Tauri packaging path/permission requirements remain unchanged.
val controllerRepository = rootProject.projectDir.resolve("../../..").canonicalFile
val controllerCargoTarget = providers.environmentVariable("CARGO_TARGET_DIR").map { configured ->
    val selected = File(configured)
    (if (selected.isAbsolute) selected else controllerRepository.resolve(configured)).canonicalFile
}.orElse(controllerRepository.resolve("target"))
listOf("debug", "release").forEach { variant ->
    val title = variant.replaceFirstChar { it.uppercaseChar() }
    val generateControllerBindings = tasks.register<Exec>("generate${title}ControllerBindings") {
        workingDir(controllerRepository)
        commandLine("node", "tools/build-android-bindings.mjs", "--abi", "arm64-v8a", "--variant", variant)
        inputs.files(fileTree(controllerRepository.resolve("crates")) { include("**/*.rs", "**/Cargo.toml") })
        inputs.dir(controllerRepository.resolve("tools/controller-uniffi-bindgen/src"))
        inputs.files(controllerRepository.resolve("Cargo.toml"), controllerRepository.resolve("Cargo.lock"),
            controllerRepository.resolve("rust-toolchain.toml"),
            controllerRepository.resolve("tools/build-android-bindings.mjs"), controllerRepository.resolve("tools/android-core-check.mjs"))
        outputs.dir(layout.buildDirectory.dir("generated/controllerUniffi/$variant/arm64-v8a/kotlin"))
        outputs.file(controllerCargoTarget.map { it.resolve("aarch64-linux-android/$variant/libuac_android_controller.so") })
    }
    android.sourceSets.getByName(variant).java.srcDir(
        layout.buildDirectory.dir("generated/controllerUniffi/$variant/arm64-v8a/kotlin"),
    )
    tasks.matching { it.name.startsWith("compile") && it.name.endsWith("${title}Kotlin") }
        .configureEach { dependsOn(generateControllerBindings) }
    val stageControllerLibrary = tasks.register<Copy>("stage${title}ControllerLibrary") {
        dependsOn(generateControllerBindings)
        from(controllerCargoTarget.map { it.resolve("aarch64-linux-android/$variant/libuac_android_controller.so") })
        into(layout.buildDirectory.dir("generated/controllerNative/$variant/arm64-v8a"))
        doFirst {
            check(controllerCargoTarget.get().resolve("aarch64-linux-android/$variant/libuac_android_controller.so").isFile) {
                "The matching controller library is missing; do not package an incomplete app."
            }
        }
    }
    android.sourceSets.getByName(variant).jniLibs.srcDir(layout.buildDirectory.dir("generated/controllerNative/$variant"))
    tasks.matching { it.name.startsWith("merge") &&
        (it.name.endsWith("${title}JniLibFolders") || it.name.endsWith("${title}NativeLibs")) }
        .configureEach { dependsOn(stageControllerLibrary) }
}

apply(from = "tauri.build.gradle.kts")
