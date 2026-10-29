package org.csploit.strix.data

import android.content.Context
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.wifi.WifiManager
import dagger.hilt.android.qualifiers.ApplicationContext
import org.csploit.strix.core.Logger
import org.csploit.strix.domain.model.NetworkInfo
import java.net.Inet4Address
import java.net.NetworkInterface
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class NetworkManager @Inject constructor(
    @ApplicationContext private val context: Context,
) {
    private val connectivityManager: ConnectivityManager =
        context.getSystemService(Context.CONNECTIVITY_SERVICE) as ConnectivityManager
    private val wifiManager: WifiManager =
        context.applicationContext.getSystemService(Context.WIFI_SERVICE) as WifiManager

    fun isWifiConnected(): Boolean = findWifiNetwork() != null

    /**
     * The physical Wi-Fi network. With a VPN up, activeNetwork is the VPN and
     * its caps may also report TRANSPORT_WIFI (underlying transport), so its
     * LinkProperties would be tun0's: require NET_CAPABILITY_NOT_VPN too.
     */
    private fun findWifiNetwork(): Network? {
        fun isPhysicalWifi(network: Network): Boolean {
            val caps = connectivityManager.getNetworkCapabilities(network) ?: return false
            return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) &&
                caps.hasCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
        }
        connectivityManager.activeNetwork?.takeIf(::isPhysicalWifi)?.let { return it }
        @Suppress("DEPRECATION") // No callback-free replacement for a one-shot lookup.
        return connectivityManager.allNetworks.firstOrNull(::isPhysicalWifi)
    }

    /**
     * Detect current WiFi network info using modern Android API (LinkProperties).
     * Port of Network.java constructor, using API 29+ (no deprecated DhcpInfo.netmask).
     */
    fun detectNetwork(): NetworkInfo? {
        val wifiNetwork = findWifiNetwork() ?: run {
            Logger.warning("NetworkManager: not connected to WiFi")
            return null
        }
        val linkProperties = connectivityManager.getLinkProperties(wifiNetwork) ?: return null

        // Find IPv4 address and prefix length from LinkProperties
        var localIp: String? = null
        var prefixLength = 24
        for (linkAddress in linkProperties.linkAddresses) {
            if (linkAddress.address is Inet4Address) {
                localIp = linkAddress.address.hostAddress
                prefixLength = linkAddress.prefixLength
                break
            }
        }

        if (localIp == null) {
            Logger.error("NetworkManager: no IPv4 address found")
            return null
        }

        // Gateway from LinkProperties routes
        val gatewayIp = linkProperties.routes
            .firstOrNull { it.isDefaultRoute && it.gateway is Inet4Address }
            ?.gateway?.hostAddress

        if (gatewayIp == null) {
            // Fallback to DhcpInfo for gateway
            val dhcp = wifiManager.dhcpInfo
            val gw = dhcp.gateway
            if (gw == 0) {
                Logger.error("NetworkManager: no gateway found")
                return null
            }
            // DhcpInfo stores IPs as little-endian ints
        }

        val gateway = gatewayIp ?: run {
            val gw = wifiManager.dhcpInfo.gateway
            intToIp(gw)
        }

        // Compute netmask from prefix length
        val netmask = prefixToNetmask(prefixLength)

        // Interface name
        val interfaceName = linkProperties.interfaceName
            ?: try {
                val inetAddr = Inet4Address.getByName(localIp)
                NetworkInterface.getByInetAddress(inetAddr)?.displayName ?: "wlan0"
            } catch (e: Exception) {
                "wlan0"
            }

        // SSID
        val wifiInfo = wifiManager.connectionInfo
        val ssid = wifiInfo?.ssid?.removeSurrounding("\"") ?: "<unknown>"
        val bssid = wifiInfo?.bssid

        val info = NetworkInfo(
            ssid = ssid,
            bssid = bssid,
            localIp = localIp,
            gatewayIp = gateway,
            netmask = netmask,
            prefixLength = prefixLength,
            interfaceName = interfaceName,
        )

        Logger.info("NetworkManager: detected network $info")
        return info
    }
}
