package dev.proxyaudit.android

/** Release identity has one source: the Android build configuration. */
object AppIdentity {
    val version: String get() = BuildConfig.VERSION_NAME
}
