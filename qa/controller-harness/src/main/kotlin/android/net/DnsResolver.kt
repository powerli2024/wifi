package android.net

import android.os.CancellationSignal
import java.net.InetAddress
import java.util.concurrent.Executor
import java.util.concurrent.atomic.AtomicInteger

/** Network-free DNS fake. No address or hostname is ever resolved. */
class DnsResolver {
    interface Callback<T> { fun onAnswer(answer: T, rcode: Int); fun onError(error: DnsException) }
    class DnsException(val code: Int = ERROR_SYSTEM, cause: Throwable? = null) : Exception(cause)
    data class Call(val executor: Executor, val signal: CancellationSignal, val callback: Callback<List<InetAddress>>)
    fun query(network: Any?, host: String, flags: Int, executor: Executor, signal: CancellationSignal, callback: Callback<List<InetAddress>>) {
        require(network == null && host.endsWith(".test") && flags == FLAG_EMPTY)
        val call = Call(executor, signal, callback)
        lastCall = call
        calls.incrementAndGet()
        queryException?.let { throw it }
        if (autoAnswer) executor.execute { callback.onAnswer(listOf(InetAddress.getByAddress(byteArrayOf(192.toByte(), 0, 2, 5))), 0) }
    }
    companion object {
        const val FLAG_EMPTY = 0
        const val ERROR_PARSE = 0
        const val ERROR_SYSTEM = 1
        private val instance = DnsResolver()
        val calls = AtomicInteger(0)
        @Volatile var autoAnswer = false
        @Volatile var lastCall: Call? = null
        @Volatile var queryException: Exception? = null
        fun getInstance() = instance
        fun reset() { calls.set(0); autoAnswer = false; lastCall = null; queryException = null }
    }
}
