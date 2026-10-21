plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.sentinelsafeguard.sphinx"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.sentinelsafeguard.sphinx"
        minSdk = 26
        targetSdk = 34
        versionCode = 5
        versionName = "0.4.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    // No AndroidX, no runtime dependencies: the filter core is pure Kotlin.
    testImplementation("junit:junit:4.13.2")
}
