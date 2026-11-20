plugins {
    `kotlin-dsl`
}

gradlePlugin {
    plugins {
        create("pluginsForCoolKids") {
            id = "rust"
            implementationClass = "RustPlugin"
        }
    }
}

repositories {
    google()
    // Maven Central answers 429 to CI runners; this mirror holds the same artifacts.
    maven {
        name = "MavenCentralGoogleMirror"
        url = uri("https://maven-central.storage-download.googleapis.com/maven2/")
    }
    mavenCentral()
}

dependencies {
    compileOnly(gradleApi())
    implementation("com.android.tools.build:gradle:8.11.0")
}
