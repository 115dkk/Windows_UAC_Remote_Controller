// The kotlin-dsl plugin's own dependencies (kotlin-stdlib and the Kotlin Gradle plugin) resolve
// through the plugin repositories. With no settings file here that is the Gradle Plugin Portal
// alone, which redirects them to Maven Central, and Maven Central answers 429 to CI runners.
// The mirror holds the same Maven Central artifacts; the portal still serves the plugin itself.
pluginManagement {
    repositories {
        maven {
            name = "MavenCentralGoogleMirror"
            url = uri("https://maven-central.storage-download.googleapis.com/maven2/")
        }
        gradlePluginPortal()
        mavenCentral()
    }
}
