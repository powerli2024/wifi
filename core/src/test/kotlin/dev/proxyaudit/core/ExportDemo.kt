package dev.proxyaudit.core

import java.io.File

/** Developer-only JVM entry point. Fabricated examples are never collected from a device. */
fun main(args: Array<String>) {
    require(args.size == 1) { "Provide one local output directory" }
    val directory = File(args[0]).apply { mkdirs() }
    val demo = DemoFixture.report()
    File(directory, "DEMO-full-evidence.json").writeText(ReportExporter.toJson(demo, true))
    File(directory, "DEMO-redacted-evidence.json").writeText(ReportExporter.toJson(demo, false))
    println("Wrote synthetic documentation examples. No network or device test was performed.")
}
