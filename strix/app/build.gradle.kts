import java.util.Properties
import java.io.FileInputStream

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("com.google.dagger.hilt.android")
    id("org.jetbrains.kotlin.kapt")
}

val keystorePropsFile = file("${System.getProperty("user.home")}/.strix/keystore.properties")
val keystoreProps = Properties().apply {
    if (keystorePropsFile.exists()) FileInputStream(keystorePropsFile).use { load(it) }
}

android {
    namespace = "org.csploit.strix"
    compileSdk = 35

    defaultConfig {
        applicationId = "org.csploit.strix"
        minSdk = 29
        targetSdk = 34
        versionCode = 3
        versionName = "0.2.0"
    }

    signingConfigs {
        create("release") {
            if (keystorePropsFile.exists()) {
                storeFile = file(keystoreProps.getProperty("storeFile"))
                storePassword = keystoreProps.getProperty("storePassword")
                keyAlias = keystoreProps.getProperty("keyAlias")
                keyPassword = keystoreProps.getProperty("keyPassword")
            }
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    buildFeatures {
        compose = true
    }

    androidResources {
        // Bundle archives are already gzip'd: store them, don't deflate again.
        // noCompress matches file-name suffixes, so ".tar.gz" never matched ".tar.gz.bin".
        noCompress += ".tar.gz.bin"
        // Metasploit is downloaded at runtime (GitHub releases). A locally built
        // ruby-msf-bundle.tar.gz.bin in assets/ must never be packaged.
        // The rest is aapt's default ignore pattern.
        ignoreAssetsPattern =
            "!ruby-msf-bundle.*:!.svn:!.git:!.ds_store:!*.scc:.*:<dir>_*:!CVS:!thumbs.db:!picasa.ini:!*~"
    }

    testOptions {
        // Logger calls android.util.Log; stub it out on the JVM
        unitTests.isReturnDefaultValues = true
    }

    packaging {
        resources {
            excludes += "META-INF/LICENSE.txt"
            excludes += "META-INF/NOTICE.txt"
        }
    }

    sourceSets {
        getByName("main") {
            assets.srcDirs("src/main/assets")
        }
    }

    buildTypes {
        debug {
            isMinifyEnabled = false
        }
        release {
            isMinifyEnabled = true
            signingConfig = if (keystorePropsFile.exists()) signingConfigs.getByName("release") else null
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro",
            )
        }
    }
}

dependencies {
    // Compose BOM
    val composeBom = platform("androidx.compose:compose-bom:2024.12.01")
    implementation(composeBom)
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.ui:ui-graphics")
    implementation("androidx.compose.ui:ui-tooling-preview")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    debugImplementation("androidx.compose.ui:ui-tooling")

    // AndroidX
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.8.7")
    implementation("androidx.lifecycle:lifecycle-runtime-compose:2.8.7")
    implementation("androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7")
    implementation("androidx.activity:activity-compose:1.9.3")
    implementation("androidx.navigation:navigation-compose:2.8.5")

    // Hilt
    implementation("com.google.dagger:hilt-android:2.53.1")
    kapt("com.google.dagger:hilt-android-compiler:2.53.1")
    implementation("androidx.hilt:hilt-navigation-compose:1.2.0")

    // Apache commons-compress for tar.gz extraction
    implementation("org.apache.commons:commons-compress:1.26.1")

    // MessagePack for MSF RPC protocol
    implementation("org.msgpack:msgpack-core:0.9.8")

    testImplementation("junit:junit:4.13.2")
    // android.jar's org.json is a stub on the JVM; bundle manifest/release parsing tests need the real one
    testImplementation("org.json:json:20240303")
}

kapt {
    correctErrorTypes = true
}
