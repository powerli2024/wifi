plugins { id("com.android.application"); kotlin("android") }
android {
    namespace = "dev.proxyaudit.android"
    compileSdk = 35
    defaultConfig {
        applicationId = "dev.proxyaudit.android"; minSdk = 29; targetSdk = 35
        versionCode = 7; versionName = "0.7.0"
        testInstrumentationRunner = "dev.proxyaudit.android.DeviceSmokeInstrumentation"
    }
    compileOptions { sourceCompatibility = JavaVersion.VERSION_17; targetCompatibility = JavaVersion.VERSION_17 }
    kotlinOptions { jvmTarget = "17" }
    buildFeatures { buildConfig = true }
    testOptions { unitTests.isIncludeAndroidResources = true }
    buildTypes { release { isMinifyEnabled = false } }
}
dependencies {
    implementation(project(":core"))
    implementation("com.google.android.material:material:1.13.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("org.robolectric:robolectric:4.14.1")
}
tasks.withType<Test>().configureEach {
    // Forward only build transport properties, never credentials, to the local framework-test JVM.
    listOf("http.proxyHost", "http.proxyPort", "https.proxyHost", "https.proxyPort", "javax.net.ssl.trustStore", "javax.net.ssl.trustStoreType").forEach { key ->
        System.getProperty(key)?.let { systemProperty(key, it) }
    }
    val isolatedTestHome = rootProject.layout.projectDirectory.dir(".gradle/framework-test-home").asFile
    doFirst { isolatedTestHome.mkdirs() }
    systemProperty("user.home", isolatedTestHome.absolutePath)
    systemProperty("robolectric.dependency.repo.url", "https://repo.maven.apache.org/maven2")
    testLogging { events("passed", "skipped", "failed") }
}
