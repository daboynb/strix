package org.csploit.strix.data

import android.content.Context
import android.net.ConnectivityManager
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

    fun isWifiConnected(): Boolean {
        val active = connectivityManager.activeNetwork ?: return false
        val caps = connectivityManager.getNetworkCapabilities(active) ?: return false
        return caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI)
    }

    /**
     * Detect current WiFi network info using modern Android API (LinkProperties).
     * Port of Network.java constructor, using API 29+ (no deprecated DhcpInfo.netmask).
     */
    fun detectNetwork(): NetworkInfo? {
        if (!isWifiConnected()) {
            Logger.warning("NetworkManager: not connected to WiFi")
            return null
        }

        val activeNetwork = connectivityManager.activeNetwork ?: return null
        val linkProperties = connectivityManager.getLinkProperties(activeNetwork) ?: return null

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
        val mask = if (prefixLength == 0) 0 else -1 shl (32 - prefixLength)
        val netmask = "%d.%d.%d.%d".format(
            (mask shr 24) and 0xFF,
            (mask shr 16) and 0xFF,
            (mask shr 8) and 0xFF,
            mask and 0xFF,
        )

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

    /**
     * Convert little-endian int (DhcpInfo format) to IP string.
     */
    private fun intToIp(ip: Int): String = "%d.%d.%d.%d".format(
        ip and 0xFF,
        (ip shr 8) and 0xFF,
        (ip shr 16) and 0xFF,
        (ip shr 24) and 0xFF,
    )
}
