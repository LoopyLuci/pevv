plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.android)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

/** Build-time config: a -P property, then an environment variable of the same name. Empty means off. */
fun cfg(prop: String, env: String): String =
    ((findProperty(prop) as String?) ?: System.getenv(env) ?: "").trim().replace("\"", "")

android {
    namespace = "dev.pevv.app"
    compileSdk = 36

    defaultConfig {
        applicationId = "dev.pevv.app"
        // 26 = Android 8.0: the first release with the AutofillService API and java.util.Base64.
        // BiometricPrompt needs 28, the Credential Manager provider 34; both are optional features.
        minSdk = 26
        targetSdk = 36
        versionCode = 3
        versionName = "0.2.1"

        // The same values as VITE_PEVV_SYNC_URL / VITE_PEVV_SYNC_ANON_KEY / PEVV_RP_ID. Empty = that feature is off.
        buildConfigField("String", "SYNC_URL", "\"${cfg("pevv.syncUrl", "VITE_PEVV_SYNC_URL").trimEnd('/')}\"")
        buildConfigField("String", "SYNC_ANON_KEY", "\"${cfg("pevv.syncAnonKey", "VITE_PEVV_SYNC_ANON_KEY")}\"")
        buildConfigField("String", "PUBLIC_URL", "\"${cfg("pevv.publicUrl", "VITE_PEVV_PUBLIC_URL")}\"")
        buildConfigField("String", "RP_ID", "\"${cfg("pevv.rpId", "PEVV_RP_ID")}\"")
        resourceConfigurations += listOf("en", "es")
    }

    buildFeatures {
        compose = true
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }

    // Signing comes only from the environment, never from a file in the repository. Without it the release APK is unsigned.
    val ksFile = System.getenv("PEVV_KEYSTORE_FILE")
    signingConfigs {
        if (!ksFile.isNullOrBlank()) {
            create("release") {
                storeFile = file(ksFile)
                storePassword = System.getenv("PEVV_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("PEVV_KEY_ALIAS")
                keyPassword = System.getenv("PEVV_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        debug {
            applicationIdSuffix = ".debug"
            versionNameSuffix = "-debug"
        }
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"), "proguard-rules.pro")
            if (!ksFile.isNullOrBlank()) signingConfig = signingConfigs.getByName("release")
        }
    }

    lint {
        abortOnError = true
        warningsAsErrors = false
        checkReleaseBuilds = false
        lintConfig = file("lint.xml")
    }

    testOptions { unitTests.isReturnDefaultValues = true }

    packaging { resources.excludes += setOf("META-INF/versions/**", "META-INF/*.kotlin_module", "META-INF/DEPENDENCIES") }
}

tasks.withType<Test>().configureEach {
    useJUnit()
    // The golden tests run real Argon2id (64 MiB) a few times.
    maxHeapSize = "1g"
    systemProperty("pevv.vectors", layout.projectDirectory.dir("src/test/resources/vectors").asFile.absolutePath)
    // The cross-client sync scenarios are shared with the TypeScript tests (tests/sync-scenarios at the repo root).
    systemProperty("pevv.scenarios", layout.projectDirectory.dir("../../tests/sync-scenarios").asFile.absolutePath)
    // Set PEVV_WRITE_FIXTURES=1 to refresh the Kotlin-made fixture the TypeScript tests read back.
    environment("PEVV_WRITE_FIXTURES", System.getenv("PEVV_WRITE_FIXTURES") ?: "")
}

dependencies {
    implementation(libs.androidx.core.ktx)
    implementation(libs.androidx.activity.compose)
    implementation(libs.androidx.lifecycle.runtime.compose)
    implementation(libs.androidx.lifecycle.viewmodel.compose)
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.icons.core)
    implementation(libs.kotlinx.coroutines.android)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.okhttp)
    implementation(libs.bouncycastle)
    implementation(libs.camerax.core)
    implementation(libs.camerax.camera2)
    implementation(libs.camerax.lifecycle)
    implementation(libs.camerax.view)
    implementation(libs.zxing.core)
    implementation(libs.androidx.credentials)
    implementation(libs.androidx.autofill)
    implementation(libs.androidx.work)

    testImplementation(libs.junit)
    testImplementation(libs.kotlinx.serialization.json)
}
