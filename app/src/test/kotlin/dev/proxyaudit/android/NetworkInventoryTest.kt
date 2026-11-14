package dev.proxyaudit.android

import android.Manifest
import android.app.Application
import android.net.ConnectivityManager
import android.net.IpPrefix
import android.net.LinkAddress
import android.net.LinkProperties
import android.net.NetworkCapabilities
import android.net.NetworkInfo
import android.net.ProxyInfo
import android.net.RouteInfo
import android.net.Uri
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.RuntimeEnvironment
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowNetwork
import org.robolectric.shadows.ShadowNetworkCapabilities
import org.robolectric.shadows.ShadowNetworkInfo
import org.robolectric.util.ReflectionHelpers
import org.robolectric.util.ReflectionHelpers.ClassParameter
import java.net.InetAddress
import java.net.Proxy
import java.net.ProxySelector
import java.net.SocketAddress
import java.net.URI

/** Framework fixtures only: no public DNS, PAC download, real interface changes or public request. */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [29, 35])
class NetworkInventoryTest {
    private lateinit var app: Application
    private lateinit var manager: ConnectivityManager
    @Before fun setup() {
        app = RuntimeEnvironment.getApplication()
        shadowOf(app).grantPermissions(Manifest.permission.ACCESS_NETWORK_STATE, Manifest.permission.INTERNET)
        manager = app.getSystemService(ConnectivityManager::class.java)
        shadowOf(manager).clearAllNetworks()
        shadowOf(manager).setActiveNetworkInfo(null)
    }

    @Test fun collects_visible_default_network_details_without_binding_or_executing_proxy_selection() {
        val info = wifiInfo()
        shadowOf(manager).setActiveNetworkInfo(info)
        val network = manager.activeNetwork!!
        val caps = ShadowNetworkCapabilities.newInstance()
        shadowOf(caps).addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
        shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
        shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_VALIDATED)
        shadowOf(caps).addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_METERED)
        shadowOf(manager).setNetworkCapabilities(network, caps)
        val links = LinkProperties().apply {
            interfaceName = "private-iface"
            // Framework setters/constructors are hidden from the public compile SDK.
            // Reflection is confined to test fixtures executed inside Robolectric.
            val link = ReflectionHelpers.callConstructor(LinkAddress::class.java,
                ClassParameter.from(InetAddress::class.java, ip(192, 0, 2, 7)),
                ClassParameter.from(Int::class.javaPrimitiveType, 24))
            ReflectionHelpers.callInstanceMethod<Boolean>(this, "addLinkAddress", ClassParameter.from(LinkAddress::class.java, link))
            ReflectionHelpers.callInstanceMethod<Boolean>(this, "addDnsServer", ClassParameter.from(InetAddress::class.java, ip(192, 0, 2, 53)))
            val route = ReflectionHelpers.callConstructor(RouteInfo::class.java,
                ClassParameter.from(IpPrefix::class.java, IpPrefix(ip(0, 0, 0, 0), 0)),
                ClassParameter.from(InetAddress::class.java, ip(192, 0, 2, 1)),
                ClassParameter.from(String::class.java, "private-iface"))
            addRoute(route)
            mtu = 1400
            domains = "internal.example"
            httpProxy = ProxyInfo.buildDirectProxy("proxy.internal.example", 8888, listOf("bypass.internal.example"))
        }
        shadowOf(manager).setLinkProperties(network, links)
        val second = ShadowNetwork.newInstance(72)
        shadowOf(manager).addNetwork(second, info)
        val oldSelector = ProxySelector.getDefault()
        ProxySelector.setDefault(object : ProxySelector() {
            override fun select(uri: URI?): List<Proxy> = throw AssertionError("Inventory must not run target proxy/PAC selection")
            override fun connectFailed(uri: URI?, sa: SocketAddress?, ioe: java.io.IOException?) = Unit
        })
        try {
            val beforeBound = manager.boundNetworkForProcess
            val report = NetworkInventory.collect(app)
            assertEquals(beforeBound, manager.boundNetworkForProcess)
            assertEquals(network.toString(), report.activeNetworkId)
            assertTrue(report.accessNetworkStateGranted)
            assertTrue(report.internetPermissionGranted)
            assertEquals(2, report.networks.size)
            val entry = report.networks.single { it.isDefault }
            assertEquals(listOf("WIFI"), entry.transports)
            assertEquals(true, entry.capabilities!!["VALIDATED"])
            assertEquals(true, entry.capabilities!!["NOT_METERED"])
            assertEquals("private-iface", entry.interfaceName)
            assertEquals(listOf("192.0.2.7/24"), entry.addresses)
            assertEquals(listOf("192.0.2.53"), entry.dnsServers)
            assertEquals(1400, entry.mtu)
            assertTrue(entry.routes.single().defaultRoute)
            assertEquals("proxy.internal.example", entry.httpProxy!!.host)
            assertFalse(entry.httpProxy.pacPresent)
            assertTrue(report.networks.single { !it.isDefault }.issues.contains("LINK_PROPERTIES:NOT_PROVIDED"))
            assertTrue(report.summary.contains("不证明代理路径"))
            assertTrue(report.durationMillis >= 0)
            assertTrue(report.finishedAtUtc >= report.capturedAtUtc)
        } finally { ProxySelector.setDefault(oldSelector) }
    }

    @Test fun missing_permission_is_reported_and_not_requested_or_converted_to_empty_success() {
        shadowOf(app).denyPermissions(Manifest.permission.ACCESS_NETWORK_STATE)
        val report = NetworkInventory.collect(app)
        assertFalse(report.accessNetworkStateGranted)
        assertTrue(report.networks.isEmpty())
        assertTrue(report.issues.contains("ACCESS_NETWORK_STATE:PERMISSION_NOT_GRANTED"))
        assertTrue(report.summary.contains("未取得"))
        assertFalse(NetworkInventory.toJson(report).contains("SecurityException"))
    }

    @Test fun absent_network_and_missing_capabilities_have_explicit_reasons() {
        val empty = NetworkInventory.collect(app)
        assertNull(empty.activeNetworkId)
        assertTrue(empty.issues.contains("DEFAULT_NETWORK:NONE_OR_UNAVAILABLE"))
        shadowOf(manager).addNetwork(ShadowNetwork.newInstance(73), wifiInfo())
        val entry = NetworkInventory.collect(app).networks.single()
        assertNull(entry.capabilities)
        assertTrue(entry.issues.contains("CAPABILITIES:NOT_PROVIDED"))
        assertTrue(entry.issues.contains("LINK_PROPERTIES:NOT_PROVIDED"))
        assertNull(entry.privateDnsActive)
    }

    @Test fun default_export_redacts_all_network_identifiers_but_preserves_observable_properties() {
        val proxy = InventoryProxy("proxy.private.test", 8787, true, "https://private.test/pac?secret=sample", listOf("exclude.private.test"))
        val entry = InventoryNetwork("network-private-id", true, "2026-10-22T01:00:00Z", listOf("VPN", "WIFI"),
            mapOf("VALIDATED" to true), 1000, 500, -60, "iface-private", listOf("192.0.2.88/24"),
            listOf(InventoryRoute("198.51.100.0/24", "192.0.2.99", "route-iface-private", false)),
            listOf("192.0.2.53"), "search.private.test", 1400, true, "dns.private.test", proxy, emptyList())
        val report = NetworkInventoryReport("2026-10-22T01:00:00Z", "2026-10-22T01:00:00Z", 2, 35,
            true, true, "active-private", "bound-private", proxy, listOf(entry), emptyList())
        val redacted = NetworkInventory.toJson(report)
        val full = JSONObject(NetworkInventory.toJson(report, true))
        val json = JSONObject(redacted)
        fun identifiers(value: JSONObject): List<String> {
            val network = value.getJSONArray("networks").getJSONObject(0)
            val route = network.getJSONArray("routes").getJSONObject(0)
            fun proxyValues(proxy: JSONObject) = listOf(proxy.getString("host"), proxy.getString("pacUrl"),
                proxy.getJSONArray("exclusions").getString(0))
            return listOf(value.getString("activeNetworkId"), value.getString("boundNetworkId"),
                network.getString("networkId"), network.getString("interfaceName"), network.getJSONArray("addresses").getString(0),
                route.getString("destination"), route.getString("gateway"), route.getString("interfaceName"),
                network.getJSONArray("dnsServers").getString(0), network.getString("dnsSearchDomains"),
                network.getString("privateDnsServerName")) + proxyValues(value.getJSONObject("defaultHttpProxy")) +
                proxyValues(network.getJSONObject("httpProxy"))
        }
        val expected = listOf("active-private", "bound-private", "network-private-id", "iface-private", "192.0.2.88/24",
            "198.51.100.0/24", "192.0.2.99", "route-iface-private", "192.0.2.53", "search.private.test", "dns.private.test") +
            List(2) { listOf("proxy.private.test", "https://private.test/pac?secret=sample", "exclude.private.test") }.flatten()
        assertEquals(expected, identifiers(full))
        assertEquals(List(expected.size) { "[REDACTED]" }, identifiers(json))
        assertFalse(json.getBoolean("networkIdentifiersIncluded"))
        assertEquals("ANDROID_NETWORK_INVENTORY", json.getString("artifactType"))
        assertTrue(json.getJSONObject("defaultHttpProxy").getBoolean("pacPresent"))
        assertEquals(1400, json.getJSONArray("networks").getJSONObject(0).getInt("mtu"))
    }

    @Test fun pac_presence_is_read_without_fetching_the_script() {
        shadowOf(manager).setActiveNetworkInfo(wifiInfo())
        val network = manager.activeNetwork!!
        shadowOf(manager).setLinkProperties(network, LinkProperties().apply {
            httpProxy = ProxyInfo.buildPacProxy(Uri.parse("https://not-contacted.invalid/script.pac"))
        })
        val proxy = NetworkInventory.collect(app).networks.single().httpProxy!!
        assertTrue(proxy.pacPresent)
        assertEquals("https://not-contacted.invalid/script.pac", proxy.pacUrl)
    }

    @Suppress("DEPRECATION")
    private fun wifiInfo() = ShadowNetworkInfo.newInstance(NetworkInfo.DetailedState.CONNECTED,
        ConnectivityManager.TYPE_WIFI, 0, true, true)
    private fun ip(vararg octets: Int) = InetAddress.getByAddress(octets.map(Int::toByte).toByteArray())
}
