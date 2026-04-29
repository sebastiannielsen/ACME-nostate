plugins {
    alias(libs.plugins.android.application)
    alias(libs.plugins.kotlin.compose)
    alias(libs.plugins.kotlin.serialization)
}

android {
    namespace = "eu.sebbe.acme_nostate"
    compileSdk {
        version = release(36) {
            minorApiLevel = 1
        }
    }

    defaultConfig {
        applicationId = "eu.sebbe.acme_nostate"
        minSdk = 30
        targetSdk = 36
        versionCode = 2
        versionName = "2.0"
        androidResources {
            @Suppress("UnstableApiUsage")
            localeFilters += "en"
        }
        ndk {
            abiFilters.add("arm64-v8a")
            abiFilters.add("x86_64")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"))
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }
    buildFeatures {
        compose = true
    }
    packaging {
        resources.excludes += "org/bouncycastle/pkix/CertPathReviewerMessages_de.properties"
        resources.excludes += "org/bouncycastle/pkix/CertPathReviewerMessages.properties"
        resources.excludes += "DebugProbesKt.bin"
        resources.excludes += "META-INF/**"
        androidResources {
            ignoreAssetsPatterns.add("PublicSuffixDatabase.list")
        }
    }
}

dependencies {
    implementation(libs.androidx.activity.compose)
    implementation(platform(libs.androidx.compose.bom))
    implementation(libs.androidx.compose.ui)
    implementation(libs.androidx.compose.material3)
    implementation(libs.androidx.compose.foundation)
    implementation(libs.retrofit)
    implementation(libs.okhttp)
    implementation(libs.nimbus.jose.jwt)
    implementation(libs.bouncycastle.bcprov)
    implementation(libs.bouncycastle.bcpkix)
    implementation(libs.kotlinx.serialization.json)
    implementation(libs.retrofit.converter.kotlinx)
    implementation(libs.androidx.compose.ui.tooling.preview)
    debugImplementation(libs.androidx.compose.ui.tooling)
    compileOnly(libs.error.prone.annotations)
}
