plugins { kotlin("jvm") version "2.1.20" }
kotlin { compilerOptions { jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_17) } }
tasks.withType<JavaCompile>().configureEach { sourceCompatibility = "17"; targetCompatibility = "17" }
val copyController = tasks.register<Copy>("copyControllerUnderTest") {
    from("../../app/src/main/kotlin/dev/proxyaudit/android/DiagnosticsController.kt")
    from("../../app/src/main/kotlin/dev/proxyaudit/android/AppIdentity.kt")
    into(layout.buildDirectory.dir("generated/controller"))
}
val generateBuildIdentity = tasks.register("generateBuildIdentity") {
    val source = file("../../app/build.gradle.kts")
    val output = layout.buildDirectory.file("generated/identity/BuildConfig.kt")
    inputs.file(source)
    outputs.file(output)
    doLast {
        val version = Regex("versionName\\s*=\\s*\"([^\"]+)\"").find(source.readText())!!.groupValues[1]
        output.get().asFile.apply { parentFile.mkdirs(); writeText("package dev.proxyaudit.android\nobject BuildConfig { const val VERSION_NAME = \"$version\" }\n") }
    }
}
kotlin.sourceSets.getByName("main").kotlin.srcDir("../../core/src/main/kotlin")
kotlin.sourceSets.getByName("main").kotlin.srcDir(layout.buildDirectory.dir("generated/controller"))
kotlin.sourceSets.getByName("main").kotlin.srcDir(layout.buildDirectory.dir("generated/identity"))
tasks.named("compileKotlin") { dependsOn(copyController, generateBuildIdentity) }
dependencies {
    implementation("org.yaml:snakeyaml:2.7")
    implementation("com.squareup.okhttp3:okhttp:4.12.0")
    testImplementation("junit:junit:4.13.2")
}
tasks.test { useJUnit(); maxParallelForks = 1; testLogging { events("passed", "skipped", "failed") } }
