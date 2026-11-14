package dev.proxyaudit.android

import android.content.Context
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import dev.proxyaudit.core.NetworkSnapshot
import java.util.concurrent.atomic.AtomicLong

/** Snapshot observation only. Never binds this process or requests a bypass network. */
class NetworkMonitor(context: Context) {
    private val manager = context.getSystemService(ConnectivityManager::class.java)
    val generation = AtomicLong(0)
    @Volatile private var callbackAvailable = false
    private val callback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) { generation.incrementAndGet() }
        override fun onLost(network: Network) { generation.incrementAndGet() }
        override fun onCapabilitiesChanged(network: Network, capabilities: NetworkCapabilities) { generation.incrementAndGet() }
        override fun onLinkPropertiesChanged(network: Network, properties: LinkProperties) { generation.incrementAndGet() }
    }
    init {
        try { manager.registerDefaultNetworkCallback(callback); callbackAvailable = true }
        catch (_: RuntimeException) { callbackAvailable = false }
    }
    fun snapshot(): NetworkSnapshot = try {
        val network = manager.activeNetwork
        if (network == null) emptySnapshot() else {
            val caps = manager.getNetworkCapabilities(network)
            val links = manager.getLinkProperties(network)
            val transports = listOf(
                NetworkCapabilities.TRANSPORT_WIFI to "WIFI", NetworkCapabilities.TRANSPORT_CELLULAR to "CELLULAR",
                NetworkCapabilities.TRANSPORT_ETHERNET to "ETHERNET", NetworkCapabilities.TRANSPORT_VPN to "VPN",
                NetworkCapabilities.TRANSPORT_BLUETOOTH to "BLUETOOTH"
            ).filter { caps?.hasTransport(it.first) == true }.map { it.second }
            NetworkSnapshot(network.toString(), transports, caps?.hasTransport(NetworkCapabilities.TRANSPORT_VPN),
                caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET), caps?.hasCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED),
                links?.linkAddresses?.mapNotNull { it.address.hostAddress }?.take(32) ?: emptyList(),
                links?.dnsServers?.mapNotNull { it.hostAddress }?.take(16) ?: emptyList(),
                links?.isPrivateDnsActive, links?.privateDnsServerName,
                callbackAvailable && caps != null && links != null)
        }
    } catch (_: RuntimeException) { emptySnapshot() }
    private fun emptySnapshot() = NetworkSnapshot(null, emptyList(), null, null, null, emptyList(), emptyList(), null, null, false)
}
