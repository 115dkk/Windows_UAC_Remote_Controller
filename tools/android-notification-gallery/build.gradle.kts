// SPDX-License-Identifier: GPL-2.0-or-later
import org.jetbrains.kotlin.gradle.dsl.JvmTarget
import java.io.File
import java.security.MessageDigest

plugins {
    id("com.android.application") version "8.11.0"
    id("org.jetbrains.kotlin.android") version "2.2.21"
}

val repository = projectDir.resolve("../..").canonicalFile
val product = repository.resolve("src-tauri/gen/android/app/src/main")
val rendererSources = listOf("RequestNotificationRenderer.kt", "ControllerStatusNotificationRenderer.kt",
    "BootServicePolicy.kt", "PolicyOwnerRules.kt", "UntrustedDisplayText.kt")
val localeSources = listOf("AppLanguage.kt")
val localizedStrings = listOf("values", "values-ko", "values-fr", "values-de", "values-ja", "values-b+zh+Hans",
    "values-b+zh+Hant", "values-es", "values-pt", "values-pt-rBR", "values-pt-rPT", "values-ar").map { "$it/strings.xml" }
val rendererResources = localizedStrings + listOf("xml/locale_config.xml", "values/request_colors.xml", "values-night/request_colors.xml",
    "drawable/ic_request_notice.xml", "drawable/ic_request_approve.xml", "drawable/ic_request_deny.xml",
    "drawable/ic_request_details.xml", "drawable/ic_controller_service.xml")
val sharedSource = tasks.register<Sync>("copyExactProductRenderer") {
    // Existing lightweight policy/type files supply ControllerServiceState;
    // never duplicate its enum or include the Service/Application/native owner.
    from(product.resolve("java/dev/dkk115/uacremote/background")) { include(rendererSources) }
    from(product.resolve("java/dev/dkk115/uacremote")) { include(localeSources) }
    into(layout.buildDirectory.dir("generated/renderer"))
}
val sharedResources = tasks.register<Sync>("copyExactProductResources") {
    from(product.resolve("res")) {
        include(rendererResources)
    }
    into(layout.buildDirectory.dir("generated/renderer-res"))
}
val sharedReceipt = tasks.register("writeExactRendererSourceReceipt") {
    dependsOn(sharedSource, sharedResources)
    inputs.dir(sharedSource.map { it.destinationDir })
    inputs.dir(sharedResources.map { it.destinationDir })
    inputs.files(rendererSources.map { product.resolve("java/dev/dkk115/uacremote/background/$it") })
    inputs.files(localeSources.map { product.resolve("java/dev/dkk115/uacremote/$it") })
    inputs.files(rendererResources.map { product.resolve("res/$it") })
    outputs.dir(layout.buildDirectory.dir("generated/renderer-assets"))
    doLast {
        val rows = mutableListOf<String>()
        fun record(path: String, copied: File) {
            val original = repository.resolve(path)
            check(path.matches(Regex("[A-Za-z0-9_./+-]+")))
            check(original.isFile && copied.isFile && original.length() in 1L..1_048_576L && copied.length() == original.length())
            val bytes = copied.readBytes()
            check(bytes.contentEquals(original.readBytes())) { "Shared renderer copy differs from product source" }
            val digest = MessageDigest.getInstance("SHA-256").digest(bytes).joinToString("") { "%02x".format(it) }
            rows.add("{\"path\":\"$path\",\"sha256\":\"$digest\"}")
        }
        for (name in rendererSources) record("src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/background/$name", sharedSource.get().destinationDir.resolve(name))
        for (name in localeSources) record("src-tauri/gen/android/app/src/main/java/dev/dkk115/uacremote/$name", sharedSource.get().destinationDir.resolve(name))
        for (name in rendererResources) record("src-tauri/gen/android/app/src/main/res/$name", sharedResources.get().destinationDir.resolve(name))
        val directory = layout.buildDirectory.dir("generated/renderer-assets").get().asFile
        check(directory.isDirectory || directory.mkdirs())
        directory.resolve("gallery-source-receipt.json").writeText(
            "{\"schema\":1,\"scope\":\"exact-shared-renderer-inputs\",\"files\":[${rows.joinToString(",")}]}")
    }
}

android {
    namespace = "dev.dkk115.uacremote" // Shared renderer imports the exact product R namespace.
    compileSdk = 36
    defaultConfig {
        applicationId = "dev.dkk115.uacremote.gallery"
        minSdk = 30
        targetSdk = 36
        versionCode = 1
        versionName = "renderer-only"
    }
    sourceSets.getByName("main") {
        java.srcDir(sharedSource.map { it.destinationDir })
        res.srcDir(sharedResources.map { it.destinationDir })
        assets.srcDir(layout.buildDirectory.dir("generated/renderer-assets"))
    }
    buildTypes.getByName("debug") { isDebuggable = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}
tasks.named("preBuild") { dependsOn(sharedSource, sharedResources, sharedReceipt) }
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8); allWarningsAsErrors.set(true) } }
dependencies {
    // Same product dependency, not a replacement renderer or new runtime package.
    implementation("androidx.appcompat:appcompat:1.7.1")
}
