plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("com.chaquo.python")
}

android {
    namespace = "shop.spacecop.vpn"
    compileSdk = 34

    defaultConfig {
        applicationId = "shop.spacecop.vpn"
        minSdk = 24
        targetSdk = 34
        versionCode = 5
        versionName = "0.3.2"
        ndk { abiFilters += listOf("arm64-v8a", "x86_64") }
    }
    // Native ChaCha20-Poly1305 (native/spacecop_crypto.c) — loaded by Python
    // through ctypes from the app's nativeLibraryDir; falls back to pure
    // Python if missing.
    ndkVersion = "26.1.10909125"
    externalNativeBuild {
        cmake {
            path = file("../../native/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    buildTypes {
        release { isMinifyEnabled = false }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
}

chaquopy {
    defaultConfig {
        version = "3.11"
        // Python used at build time (CI installs 3.11 via actions/setup-python).
        buildPython("python3")
        // The SpaceCopVPN package is stdlib-only, so it is bundled as plain
        // sources from app/src/main/python (Chaquopy's default source set).
        // Run ../sync_python.sh (CI does) to copy ../../spacecop there.
        // NOTE: do not `pip install` the repository root — Gradle then treats
        // the whole tree (including build outputs) as a task input and fails.
    }
}

dependencies {
    implementation("androidx.core:core-ktx:1.13.1")
    implementation("androidx.appcompat:appcompat:1.7.0")
    implementation("com.google.android.material:material:1.12.0")
    implementation("androidx.constraintlayout:constraintlayout:2.1.4")
}
