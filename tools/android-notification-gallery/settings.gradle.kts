// SPDX-License-Identifier: GPL-2.0-or-later
// Maven Central answers 429 to CI runners; the mirror holds the same artifacts.
pluginManagement { repositories { google(); maven { name = "MavenCentralGoogleMirror"; url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }; gradlePluginPortal(); mavenCentral() } }
dependencyResolutionManagement { repositories { google(); maven { name = "MavenCentralGoogleMirror"; url = uri("https://maven-central.storage-download.googleapis.com/maven2/") }; mavenCentral() } }
rootProject.name = "notification-renderer-gallery-only"
