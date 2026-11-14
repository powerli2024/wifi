package android.os
/** Deliberately minimal fake API surface for controller-only logic tests. */
object Build { object VERSION { const val SDK_INT = 35 } }
object SystemClock {
    @Volatile var testOffsetMillis: Long = 0
    fun elapsedRealtime(): Long = System.nanoTime() / 1_000_000 + testOffsetMillis
}
class Looper { companion object { fun getMainLooper() = Looper() } }
class Handler(@Suppress("UNUSED_PARAMETER") looper: Looper) { fun post(action: () -> Unit): Boolean { action(); return true } }
class CancellationSignal {
    @Volatile var isCanceled: Boolean = false
        private set
    fun cancel() { isCanceled = true }
}
