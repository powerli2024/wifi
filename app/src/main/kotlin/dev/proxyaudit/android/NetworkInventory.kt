package dev.proxyaudit.android

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.ProxyInfo
import android.net.Uri
import android.os.Build
import org.json.JSONObject
import java.time.Instant
import java.util.concurrent.TimeUnit

data class InventoryProxy(val host: String?, val port: Int?, val pacPresent: Boolean,
    val pacUrl: String?, val exclusions: List<String>)
data class InventoryRoute(val destination: String?, val gateway: String?, val interfaceName: String?,
    val defaultRoute: Boolean)
data class InventoryNetwork(
    val networkId: String, val isDefault: Boolean, val observedAtUtc: String,
    val transports: List<String>, val capabilities: Map<String, Boolean>?,
    val downstreamKbps: Int?, val upstreamKbps: Int?, val signalStrength: Int?,
    val interfaceName: String?, val addresses: List<String>, val routes: List<InventoryRoute>,
    val dnsServers: List<String>, val dnsSearchDomains: String?, val mtu: Int?,
    val privateDnsActive: Boolean?, val privateDnsServerName: String?, val httpProxy: InventoryProxy?,
    val issues: List<String>
)
data class NetworkInventoryReport(
    val capturedAtUtc: String, val finishedAtUtc: String, val durationMillis: Long, val androidApi: Int,
    val accessNetworkStateGranted: Boolean, val internetPermissionGranted: Boolean,
    val activeNetworkId: String?, val boundNetworkId: String?, val defaultProxy: InventoryProxy?,
    val networks: List<InventoryNetwork>, val issues: List<String>
) {
    val summary: String get() = when {
        !accessNetworkStateGranted -> "未取得读取网络状态权限；没有请求新增权限。"
        networks.isEmpty() -> "未取得本应用可见的网络信息；请查看缺失原因。"
        else -> "已记录 ${networks.size} 个本应用可见网络的系统快照；不证明代理路径或外网可达。"
    }
}

/** Read-only framework inventory. No DNS query, ProxySelector/PAC execution, binding or new permission request. */
object NetworkInventory {
    private const val LIMIT = 64
    val limitations = listOf(
        "只记录 Android 向本应用公开的网络状态；可见网络不等于全部物理网络。",
        "各字段在采集期间分别读取，不是同一瞬间的原子快照；系统状态可能变化。",
        "VPN 标签缺失不表示代理客户端关闭；HTTP 代理配置不证明本次请求使用了它。",
        "不读取其他应用的分应用规则、私有文件或订阅；本应用是否纳入客户端规则仍需用户确认。",
        "带宽是系统估计值而非测速；信号强度的单位依承载类型而定，未提供时为 null。",
        "不读取 SSID、BSSID、定位或蜂窝身份信息，不执行 PAC，不请求新增敏感权限。"
    )

    fun collect(context: Context): NetworkInventoryReport {
        val start = System.nanoTime()
        val captured = Instant.now().toString()
        val issues = mutableListOf<String>()
        fun permitted(permission: String) = context.checkSelfPermission(permission) == PackageManager.PERMISSION_GRANTED
        val access = permitted(Manifest.permission.ACCESS_NETWORK_STATE)
        val internet = permitted(Manifest.permission.INTERNET)
        var active: Network? = null
        var bound: Network? = null
        var defaultHttpProxy: InventoryProxy? = null
        var entries = emptyList<InventoryNetwork>()
        fun <T> read(label: String, block: () -> T): T? = try { block() }
        catch (_: SecurityException) { issues += "$label:PERMISSION_DENIED"; null }
        catch (_: RuntimeException) { issues += "$label:SYSTEM_UNAVAILABLE"; null }
        if (!access) issues += "ACCESS_NETWORK_STATE:PERMISSION_NOT_GRANTED"
        else {
            val manager = read("CONNECTIVITY_SERVICE") { context.getSystemService(ConnectivityManager::class.java) }
            if (manager == null) issues += "CONNECTIVITY_SERVICE:UNAVAILABLE"
            else {
                active = read("DEFAULT_NETWORK") { manager.activeNetwork }
                if (active == null) issues += "DEFAULT_NETWORK:NONE_OR_UNAVAILABLE"
                bound = read("BOUND_NETWORK") { manager.boundNetworkForProcess }
                defaultHttpProxy = read("DEFAULT_HTTP_PROXY") { manager.defaultProxy?.let(::proxy) }
                @Suppress("DEPRECATION")
                val visible = read("VISIBLE_NETWORKS") { manager.allNetworks.toList() } ?: emptyList()
                val all = (listOfNotNull(active) + visible).distinct()
                if (all.size > LIMIT) issues += "VISIBLE_NETWORKS:TRUNCATED"
                entries = all.take(LIMIT).mapNotNull { read("NETWORK_DETAILS") { inspect(manager, it, active) } }
                val after = read("DEFAULT_NETWORK_RECHECK") { manager.activeNetwork }
                if (active != after) issues += "DEFAULT_NETWORK:CHANGED_DURING_COLLECTION"
            }
        }
        return NetworkInventoryReport(captured, Instant.now().toString(),
            TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - start), Build.VERSION.SDK_INT,
            access, internet, active?.toString(), bound?.toString(), defaultHttpProxy, entries, issues.distinct())
    }

    private fun inspect(manager: ConnectivityManager, network: Network, active: Network?): InventoryNetwork {
        val observedAt = Instant.now().toString()
        val issues = mutableListOf<String>()
        fun <T> read(label: String, block: () -> T): T? = try { block() }
        catch (_: SecurityException) { issues += "$label:PERMISSION_DENIED"; null }
        catch (_: RuntimeException) { issues += "$label:SYSTEM_UNAVAILABLE"; null }
        fun <T> bounded(label: String, value: List<T>): List<T> {
            if (value.size > LIMIT) issues += "$label:TRUNCATED"
            return value.take(LIMIT)
        }
        val caps = read("CAPABILITIES") { manager.getNetworkCapabilities(network) }
        val links = read("LINK_PROPERTIES") { manager.getLinkProperties(network) }
        if (caps == null) issues += "CAPABILITIES:NOT_PROVIDED"
        if (links == null) issues += "LINK_PROPERTIES:NOT_PROVIDED"
        val transports = caps?.let { value -> transportNames.filter { value.hasTransport(it.first) }.map { it.second } } ?: emptyList()
        val capabilities = caps?.let { value -> capabilityNames.associate { it.second to value.hasCapability(it.first) } }
        val down = caps?.linkDownstreamBandwidthKbps?.takeIf { it > 0 }
        val up = caps?.linkUpstreamBandwidthKbps?.takeIf { it > 0 }
        if (caps != null && (down == null || up == null)) issues += "BANDWIDTH_ESTIMATE:NOT_PROVIDED_OR_ZERO"
        val signal = read("SIGNAL_STRENGTH") { caps?.signalStrength?.takeIf { it != Int.MIN_VALUE } }
        if (caps != null && signal == null) issues += "SIGNAL_STRENGTH:NOT_PROVIDED"
        val addresses = bounded("ADDRESSES", links?.linkAddresses?.map { it.toString() } ?: emptyList())
        val dns = bounded("DNS_SERVERS", links?.dnsServers?.mapNotNull { it.hostAddress } ?: emptyList())
        val routes = bounded("ROUTES", links?.routes?.map { route -> InventoryRoute(
            route.destination?.toString(), route.gateway?.hostAddress, route.`interface`, route.isDefaultRoute) } ?: emptyList())
        return InventoryNetwork(network.toString(), network == active, observedAt, transports, capabilities,
            down, up, signal, links?.interfaceName, addresses, routes, dns, links?.domains,
            links?.mtu?.takeIf { it > 0 }, links?.isPrivateDnsActive, links?.privateDnsServerName,
            links?.httpProxy?.let(::proxy), issues.distinct())
    }

    private fun proxy(info: ProxyInfo): InventoryProxy {
        val pac = info.pacFileUrl?.takeUnless { it == Uri.EMPTY || it.toString().isEmpty() }?.toString()
        return InventoryProxy(info.host?.takeIf { it.isNotEmpty() }, info.port.takeIf { it > 0 }, pac != null,
            pac, info.exclusionList?.toList()?.take(LIMIT) ?: emptyList())
    }

    fun toJson(report: NetworkInventoryReport, includeNetworkIdentifiers: Boolean = false): String {
        fun id(value: String?): String? = value?.let { if (includeNetworkIdentifiers) it else "[REDACTED]" }
        fun proxyMap(value: InventoryProxy?) = value?.let { linkedMapOf(
            "host" to id(it.host), "port" to it.port, "pacPresent" to it.pacPresent,
            "pacUrl" to id(it.pacUrl), "exclusions" to it.exclusions.map(::id)) }
        val result = linkedMapOf<String, Any?>(
            "schemaVersion" to 1, "artifactType" to "ANDROID_NETWORK_INVENTORY",
            "networkIdentifiersIncluded" to includeNetworkIdentifiers,
            "capturedAtUtc" to report.capturedAtUtc, "finishedAtUtc" to report.finishedAtUtc,
            "durationMillis" to report.durationMillis, "androidApi" to report.androidApi,
            "accessNetworkStateGranted" to report.accessNetworkStateGranted,
            "internetPermissionGranted" to report.internetPermissionGranted,
            "activeNetworkId" to id(report.activeNetworkId), "boundNetworkId" to id(report.boundNetworkId),
            "defaultHttpProxy" to proxyMap(report.defaultProxy), "summary" to report.summary,
            "issues" to report.issues, "limitations" to limitations,
            "networks" to report.networks.map { entry -> linkedMapOf(
                "networkId" to id(entry.networkId), "isDefault" to entry.isDefault,
                "observedAtUtc" to entry.observedAtUtc, "transports" to entry.transports,
                "capabilities" to entry.capabilities, "estimatedDownstreamKbps" to entry.downstreamKbps,
                "estimatedUpstreamKbps" to entry.upstreamKbps, "bearerSpecificSignalStrength" to entry.signalStrength,
                "interfaceName" to id(entry.interfaceName), "addresses" to entry.addresses.map(::id),
                "routes" to entry.routes.map { route -> linkedMapOf(
                    "destination" to id(route.destination), "gateway" to id(route.gateway),
                    "interfaceName" to id(route.interfaceName), "defaultRoute" to route.defaultRoute) },
                "dnsServers" to entry.dnsServers.map(::id), "dnsSearchDomains" to id(entry.dnsSearchDomains),
                "mtu" to entry.mtu, "privateDnsActive" to entry.privateDnsActive,
                "privateDnsServerName" to id(entry.privateDnsServerName), "httpProxy" to proxyMap(entry.httpProxy),
                "issues" to entry.issues) }
        )
        return JSONObject(result).toString(2) + "\n"
    }

    private val transportNames = listOf(
        NetworkCapabilities.TRANSPORT_WIFI to "WIFI", NetworkCapabilities.TRANSPORT_CELLULAR to "CELLULAR",
        NetworkCapabilities.TRANSPORT_ETHERNET to "ETHERNET", NetworkCapabilities.TRANSPORT_VPN to "VPN",
        NetworkCapabilities.TRANSPORT_BLUETOOTH to "BLUETOOTH", NetworkCapabilities.TRANSPORT_WIFI_AWARE to "WIFI_AWARE",
        NetworkCapabilities.TRANSPORT_LOWPAN to "LOWPAN")
    private val capabilityNames = listOf(
        NetworkCapabilities.NET_CAPABILITY_INTERNET to "INTERNET",
        NetworkCapabilities.NET_CAPABILITY_VALIDATED to "VALIDATED",
        NetworkCapabilities.NET_CAPABILITY_CAPTIVE_PORTAL to "CAPTIVE_PORTAL",
        NetworkCapabilities.NET_CAPABILITY_NOT_METERED to "NOT_METERED",
        NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED to "NOT_RESTRICTED",
        NetworkCapabilities.NET_CAPABILITY_NOT_VPN to "NOT_VPN",
        NetworkCapabilities.NET_CAPABILITY_TRUSTED to "TRUSTED",
        NetworkCapabilities.NET_CAPABILITY_NOT_ROAMING to "NOT_ROAMING",
        NetworkCapabilities.NET_CAPABILITY_NOT_SUSPENDED to "NOT_SUSPENDED",
        NetworkCapabilities.NET_CAPABILITY_NOT_CONGESTED to "NOT_CONGESTED")
}
