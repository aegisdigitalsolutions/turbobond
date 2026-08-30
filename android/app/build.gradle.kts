plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "com.aegisdigital.turbobond"
    compileSdk = 34

    defaultConfig {
        applicationId = "com.aegisdigital.turbobond"
        minSdk = 26
        // Deliberately 33. Targeting 34 brings in foreground-service type
        // enforcement, whose correct declaration for a VPN cannot be verified
        // without a device to run it on, and getting it wrong crashes the
        // service on launch. 33 installs and runs on current Android.
        targetSdk = 33
        versionCode = 1
        versionName = "1.0.0"
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
    implementation(project(":core"))
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
}
