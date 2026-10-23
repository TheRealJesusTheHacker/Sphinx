plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

// ---------------------------------------------------------------------------
// Release signing — the owner's keystore only, never the debug key.
//
// Signing material comes ONLY from the environment; nothing secret is
// stored in this repo:
//   SPHINX_ANDROID_KEYSTORE           path to the owner's keystore file
//   SPHINX_ANDROID_KEYSTORE_PASSWORD  keystore password
//   SPHINX_ANDROID_KEY_ALIAS          key alias inside the keystore
//   SPHINX_ANDROID_KEY_PASSWORD       key password
//
// All four set  -> the release build is signed with the owner's key.
// Some set      -> configuration fails with the message below: a
//                  half-set signing setup is a mistake, not a mode,
//                  and a release build must never quietly fall back
//                  to the debug key.
// None set      -> the release build stays UNSIGNED. That output
//                  (app-release-unsigned.apk) is a compile proof
//                  only; the `signedRelease` task below refuses to
//                  run, so no path presents it as a release.
// ---------------------------------------------------------------------------
val signingEnvNames = listOf(
    "SPHINX_ANDROID_KEYSTORE",
    "SPHINX_ANDROID_KEYSTORE_PASSWORD",
    "SPHINX_ANDROID_KEY_ALIAS",
    "SPHINX_ANDROID_KEY_PASSWORD",
)
val signingEnv = signingEnvNames.associateWith { System.getenv(it) }
val presentSigningEnv = signingEnv.filterValues { !it.isNullOrBlank() }
val releaseSigningReady = presentSigningEnv.size == signingEnvNames.size

if (presentSigningEnv.isNotEmpty() && !releaseSigningReady) {
    throw GradleException(
        "Sphinx release signing is only partly configured. Set all four of " +
            signingEnvNames.joinToString(", ") + " — or none of them. " +
            "A signed release needs the owner's keystore; there is no fallback key."
    )
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

    signingConfigs {
        if (releaseSigningReady) {
            create("release") {
                storeFile = file(signingEnv.getValue("SPHINX_ANDROID_KEYSTORE")!!)
                storePassword = signingEnv.getValue("SPHINX_ANDROID_KEYSTORE_PASSWORD")
                keyAlias = signingEnv.getValue("SPHINX_ANDROID_KEY_ALIAS")
                keyPassword = signingEnv.getValue("SPHINX_ANDROID_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            if (releaseSigningReady) {
                signingConfig = signingConfigs.getByName("release")
            }
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
        // The WireGuard tunnel library uses Java 8+ APIs (and
        // records in its statistics classes); desugaring keeps
        // them working back to minSdk. Recommended by the
        // library's own embedding notes.
        isCoreLibraryDesugaringEnabled = true
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

val verifyReleaseSigning by tasks.registering {
    group = "verification"
    description = "Fails unless the owner's release signing is fully configured in the environment."
    doLast {
        if (!releaseSigningReady) {
            throw GradleException(
                "No signed Sphinx release can be built here: the signing environment is not set. " +
                    "Set SPHINX_ANDROID_KEYSTORE, SPHINX_ANDROID_KEYSTORE_PASSWORD, " +
                    "SPHINX_ANDROID_KEY_ALIAS and SPHINX_ANDROID_KEY_PASSWORD from the owner's " +
                    "release keystore secrets, then run signedRelease again. Unsigned and " +
                    "debug-signed builds are compile proofs only — never releases."
            )
        }
    }
}

tasks.register("signedRelease") {
    group = "build"
    description = "Builds the signed release APK with the owner's keystore (refuses without it)."
    dependsOn(verifyReleaseSigning, "assembleRelease")
}

tasks.configureEach {
    // AGP registers its variant tasks after this script runs, so
    // match by name whenever the task appears.
    if (name == "assembleRelease") {
        mustRunAfter(verifyReleaseSigning)
    }
}

dependencies {
    // The filter core is pure Kotlin with no runtime dependencies.
    // VPN (TUNNEL) mode adds exactly two, both license-verified
    // from primary sources before pinning (2026-10-23) and both
    // attributed in assets/third-party/THIRD-PARTY-NOTICES.txt:
    //  - com.wireguard.android:tunnel — Apache-2.0 (Maven POM +
    //    the wireguard-android repo's COPYING file); its
    //    userspace backend wireguard-go is MIT (its LICENSE).
    //  - com.google.zxing:core — Apache-2.0 (POM header + the
    //    ZXing repo's LICENSE); QR import/export of the same
    //    WireGuard config text, no second format.
    // Exact versions only — no dynamic ranges, ever.
    implementation("com.wireguard.android:tunnel:1.0.20250531")
    implementation("com.google.zxing:core:3.5.3")
    coreLibraryDesugaring("com.android.tools:desugar_jdk_libs:2.1.4")
    testImplementation("junit:junit:4.13.2")
}
