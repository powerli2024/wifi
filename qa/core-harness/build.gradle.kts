plugins { kotlin("jvm") version "2.1.20" }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
tasks.withType<JavaCompile>().configureEach { sourceCompatibility = "17"; targetCompatibility = "17" }
kotlin.sourceSets.getByName("main").kotlin.srcDir("../../core/src/main/kotlin")
kotlin.sourceSets.getByName("test").kotlin.srcDir("../../core/src/test/kotlin")
kotlin.sourceSets.getByName("test").kotlin.srcDir("../src/test/kotlin")
dependencies {
    implementation("org.yaml:snakeyaml:2.7")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("junit:junit:4.13.2")
    testImplementation("com.squareup.okhttp3:mockwebserver:4.12.0")
    testImplementation("com.squareup.okhttp3:okhttp-tls:4.12.0")
}
tasks.test {
    useJUnit()
    // Keep new executions in build/; qa/results is the imported v0.1.0 evidence snapshot.
    testLogging { events("passed", "skipped", "failed") }
}
