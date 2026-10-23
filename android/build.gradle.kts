group = "dev.digitalcredentials.flutter_wallet"
version = "1.0-SNAPSHOT"

buildscript {
    val kotlinVersion = "2.4.0"
    repositories {
        google()
        mavenCentral()
    }

    dependencies {
        classpath("com.android.tools.build:gradle:9.1.0")
        classpath("org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlinVersion")
        classpath("org.jetbrains.kotlin:kotlin-serialization:$kotlinVersion")
    }
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}

plugins {
    id("com.android.library")
}

apply(plugin = "org.jetbrains.kotlin.plugin.serialization")

android {
    namespace = "dev.digitalcredentials.flutter_wallet"

    compileSdk = 36

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            java.srcDirs("src/main/kotlin")
        }
        getByName("test") {
            java.srcDirs("src/test/kotlin")
        }
    }

    defaultConfig {
        // 28, not the template's 24: BiometricPrompt needs the
        // setDeviceCredentialAllowed branch that only exists on API 28-29.
        minSdk = 28
    }

    testOptions {
        unitTests {
            isIncludeAndroidResources = true
            all {
                it.useJUnitPlatform()

                it.outputs.upToDateWhen { false }

                it.testLogging {
                    events("passed", "skipped", "failed", "standardOut", "standardError")
                    showStandardStreams = true
                }
            }
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget = org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17
    }
}

dependencies {
    val credentials = "1.7.0-alpha05"
    val registry = "1.0.0-alpha05"

    implementation("androidx.credentials:credentials:$credentials")
    implementation("androidx.credentials:credentials-play-services-auth:$credentials")
    implementation("androidx.credentials.registry:registry-provider:$registry")
    // Load-bearing: its manifest contributes the REGISTRY_MANAGER_PROVIDER_KEY
    // meta-data that RegistryManager.create() discovers. Without it,
    // registration fails at runtime rather than at compile time.
    implementation("androidx.credentials.registry:registry-provider-play-services:$registry")
    implementation("androidx.credentials.registry:registry-digitalcredentials-mdoc:$registry")
    implementation("androidx.credentials.registry:registry-digitalcredentials-openid:$registry")

    // Declared explicitly rather than relied on transitively.
    implementation("androidx.biometric:biometric:1.1.0")
    implementation("androidx.fragment:fragment-ktx:1.8.5")

    implementation("org.jetbrains.kotlinx:kotlinx-serialization-json:1.7.3")

    // OpenID4VCI talks HTTP to the issuer.
    val ktor = "3.0.1"
    implementation("io.ktor:ktor-client-core:$ktor")
    implementation("io.ktor:ktor-client-cio:$ktor")
    implementation("io.ktor:ktor-client-content-negotiation:$ktor")
    implementation("io.ktor:ktor-serialization-kotlinx-json:$ktor")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.mockito:mockito-core:5.0.0")
}
