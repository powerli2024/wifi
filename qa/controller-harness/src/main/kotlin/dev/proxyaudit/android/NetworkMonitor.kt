package dev.proxyaudit.android

import android.content.Context
import dev.proxyaudit.core.NetworkSnapshot
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicLong

/** Stable, fabricated network metadata. Android NetworkMonitor is reviewed separately. */
class NetworkMonitor(@Suppress("UNUSED_PARAMETER") context: Context) {
    val generation = AtomicLong(0)
    fun snapshot(): NetworkSnapshot {
        snapshotGate?.let {
            it.calls.incrementAndGet()
            it.entered.countDown()
            it.release.await(10, TimeUnit.SECONDS)
        }
        return snapshotValue
    }
    class SnapshotGate {
        val entered = CountDownLatch(1)
        val release = CountDownLatch(1)
        val calls = AtomicInteger()
    }
    companion object {
        @Volatile var snapshotGate: SnapshotGate? = null
        @Volatile var snapshotValue = NetworkSnapshot("FAKE-NETWORK", listOf("WIFI"), false, true, true, emptyList(), emptyList(), null, null, true)
    }
}
