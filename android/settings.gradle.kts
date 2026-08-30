pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "turbobond-android"

// The wire protocol lives in a plain JVM module so it can be tested on a build
// machine, with no emulator and no device. Only :app needs the Android SDK.
include(":core")
include(":app")
