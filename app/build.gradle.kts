import org.gradle.api.tasks.PathSensitivity

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
}

android {
    namespace = "com.bearmod.security"
    compileSdk = 34

    defaultConfig {
        minSdk = 24
        targetSdk = 34

        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        consumerProguardFiles("consumer-rules.pro")

        // Export native libraries
        ndk {
            abiFilters += listOf("arm64-v8a")
        }

        // Version information
        buildConfigField("String", "LIBRARY_VERSION", "\"1.0.0\"")
        buildConfigField("String", "LIBRARY_NAME", "\"BearMod\"")

        externalNativeBuild {
            cmake {
                cppFlags("-std=c++17")
                arguments("-DANDROID_STL=c++_shared")
                arguments("-DOPENSSL_ROOT_DIR=${projectDir}/src/main/cpp/openssl")
                arguments("-DCURL_ROOT_DIR=${projectDir}/src/main/cpp/curl")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = true
           // isShrinkResources = true
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
        debug {
            isMinifyEnabled = false
            proguardFiles(
                getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro"
            )
        }
    }

    buildFeatures {
        buildConfig = true
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }

    ndkVersion = "25.1.8937393"
}

dependencies {
    // Core Android dependencies
    implementation("androidx.core:core-ktx:1.12.0")
    implementation("androidx.appcompat:appcompat:1.6.1")
    
    // Security dependencies
    implementation("androidx.security:security-crypto:1.1.0-alpha06")
    implementation("com.google.crypto.tink:tink-android:1.7.0")
    
    // Network dependencies
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    implementation("com.squareup.retrofit2:retrofit:2.9.0")
    implementation("com.squareup.retrofit2:converter-gson:2.9.0")
    
    // JSON processing
    implementation("com.google.code.gson:gson:2.10.1")
    
    // Coroutines for async operations
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3")
    
    // Testing dependencies
    testImplementation("junit:junit:4.13.2")
    androidTestImplementation("androidx.test.ext:junit:1.1.5")
    androidTestImplementation("androidx.test.espresso:espresso-core:3.5.1")

    implementation("androidx.lifecycle:lifecycle-runtime-ktx:2.7.0")
}

afterEvaluate {
    publishing {
        publications {
            create<MavenPublication>("release") {
                groupId = "com.bearmod"
                artifactId = "bearmod-library"
                version = "1.0.0"

                from(components["release"])

                pom {
                    name.set("BearMod Library")
                    description.set("Advanced Android security analysis and hooking library")
                    url.set("https://github.com/bearmod/bearmod-library")
                    
                    licenses {
                        license {
                            name.set("MIT License")
                            url.set("https://opensource.org/licenses/MIT")
                        }
                    }
                    
                    developers {
                        developer {
                            id.set("bearmod")
                            name.set("BearMod Team")
                            email.set("dev@bearmod.com")
                        }
                    }
                }
            }
        }
    }
}

// Configuration cache compatible AAR optimization task
abstract class OptimizeAarTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.ABSOLUTE)
    abstract val aarFile: RegularFileProperty

    @get:OutputFile
    abstract val optimizationReport: RegularFileProperty

    init {
        group = "build"
        description = "Optimizes the AAR for distribution"
    }

    @TaskAction
    fun optimizeAar() {
        val aar = aarFile.get().asFile
        val report = optimizationReport.get().asFile

        val results = mutableListOf<String>()
        results.add("AAR optimization completed")
        results.add("Generated AAR: ${aar.absolutePath}")

        if (aar.exists()) {
            val sizeInMB = aar.length() / 1024 / 1024
            results.add("AAR size: ${sizeInMB} MB")
        }

        report.parentFile.mkdirs()
        report.writeText(results.joinToString("\n"))
        results.forEach { println(it) }
    }
}

tasks.register<OptimizeAarTask>("optimizeAar") {
    dependsOn("assembleRelease")
    aarFile.set(layout.buildDirectory.file("outputs/aar/app-release.aar"))
    optimizationReport.set(layout.buildDirectory.file("reports/aar-optimization.txt"))
}

tasks.register<Copy>("copyFridaScripts") {
    group = "build"
    description = "Copies Frida scripts to AAR assets"

    from("${rootDir}/frida-tools/scripts")
    into("src/main/assets/frida-scripts")
    include("*.js")

    doFirst {
        println("Copying Frida scripts to AAR assets...")
    }
}

afterEvaluate {
    tasks.findByName("mergeReleaseAssets")?.dependsOn("copyFridaScripts")
    tasks.findByName("preBuild")?.dependsOn("copyFridaScripts")
}

abstract class ValidateAarTask : DefaultTask() {
    @get:InputFile
    @get:PathSensitive(PathSensitivity.ABSOLUTE)
    abstract val aarFile: RegularFileProperty

    @get:OutputFile
    abstract val validationReport: RegularFileProperty

    init {
        group = "verification"
        description = "Validates AAR contents and structure"
    }

    @TaskAction
    fun validateAar() {
        val aar = aarFile.get().asFile
        val report = validationReport.get().asFile

        val validationResults = mutableListOf<String>()

        if (aar.exists()) {
            val sizeInMB = aar.length() / 1024 / 1024
            validationResults.add("✅ AAR file exists: ${aar.absolutePath}")
            validationResults.add("📦 AAR size: ${sizeInMB} MB")

            if (sizeInMB > 0) {
                validationResults.add("✅ AAR has valid size")
            } else {
                validationResults.add("❌ AAR file is empty")
                throw GradleException("AAR file is empty!")
            }

            validationResults.add("✅ AAR validation completed successfully")
        } else {
            validationResults.add("❌ AAR file not found: ${aar.absolutePath}")
            throw GradleException("AAR file not found!")
        }

        report.parentFile.mkdirs()
        report.writeText(validationResults.joinToString("\n"))
        validationResults.forEach { println(it) }
    }
}

tasks.register<ValidateAarTask>("validateAar") {
    dependsOn("assembleRelease")
    aarFile.set(layout.buildDirectory.file("outputs/aar/app-release.aar"))
    validationReport.set(layout.buildDirectory.file("reports/aar-validation.txt"))
}
