// SPDX-License-Identifier: GPL-2.0-or-later
import org.jetbrains.kotlin.gradle.dsl.JvmTarget

plugins {
    id("com.android.application") version "8.11.0"
    id("org.jetbrains.kotlin.android") version "2.2.21"
}

val repository = projectDir.resolve("../..").canonicalFile
val product = repository.resolve("src-tauri/gen/android/app/src/main")
val sharedSource = tasks.register<Sync>("copyExactProductRenderer") {
    from(product.resolve("java/dev/dkk115/uacremote/background")) { include("RequestNotificationRenderer.kt") }
    into(layout.buildDirectory.dir("generated/renderer"))
}
val sharedResources = tasks.register<Sync>("copyExactProductResources") {
    from(product.resolve("res")) {
        include("values/strings.xml", "values/request_colors.xml", "values-night/request_colors.xml", "drawable/ic_request_*.xml")
    }
    into(layout.buildDirectory.dir("generated/renderer-res"))
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
    }
    buildTypes.getByName("debug") { isDebuggable = true }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_1_8
        targetCompatibility = JavaVersion.VERSION_1_8
    }
}
tasks.named("preBuild") { dependsOn(sharedSource, sharedResources) }
kotlin { compilerOptions { jvmTarget.set(JvmTarget.JVM_1_8); allWarningsAsErrors.set(true) } }
dependencies {
    // Same product dependency, not a replacement renderer or new runtime package.
    implementation("androidx.appcompat:appcompat:1.7.1")
}
