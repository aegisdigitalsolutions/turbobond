plugins {
    id("org.jetbrains.kotlin.jvm")
    application
}

application {
    mainClass.set("com.aegisdigital.turbobond.core.LiveCheck")
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    // Blake2b with personalisation and ChaCha20-Poly1305. The JDK has the
    // cipher but not the digest, and the key derivation needs both to match
    // the Python implementation byte for byte.
    implementation("org.bouncycastle:bcprov-jdk18on:1.78.1")
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    testLogging { events("passed", "failed", "skipped") }
}
