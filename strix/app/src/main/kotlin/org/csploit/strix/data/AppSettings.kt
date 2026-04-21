package org.csploit.strix.data

import android.content.Context
import android.content.SharedPreferences
import dagger.hilt.android.qualifiers.ApplicationContext
import javax.inject.Inject
import javax.inject.Singleton

@Singleton
class AppSettings @Inject constructor(
    @ApplicationContext context: Context,
) {
    private val prefs: SharedPreferences =
        context.getSharedPreferences("strix_settings", Context.MODE_PRIVATE)

    var nmapTiming: Int
        get() = prefs.getInt("nmap_timing", 4)
        set(value) = prefs.edit().putInt("nmap_timing", value.coerceIn(1, 5)).apply()

    var hydraThreads: Int
        get() = prefs.getInt("hydra_threads", 4)
        set(value) = prefs.edit().putInt("hydra_threads", value.coerceIn(1, 16)).apply()

    var defaultPortRange: String
        get() = prefs.getString("default_port_range", "") ?: ""
        set(value) = prefs.edit().putString("default_port_range", value).apply()

    var socketTimeoutSec: Int
        get() = prefs.getInt("socket_timeout_sec", 5)
        set(value) = prefs.edit().putInt("socket_timeout_sec", value.coerceIn(1, 30)).apply()

    var dnsServer: String
        get() = prefs.getString("dns_server", "") ?: ""
        set(value) = prefs.edit().putString("dns_server", value).apply()

    var customNmapArgs: String
        get() = prefs.getString("custom_nmap_args", "") ?: ""
        set(value) = prefs.edit().putString("custom_nmap_args", value).apply()

    // --- MSF RPC Settings ---

    var msfRpcHost: String
        get() = prefs.getString("msf_rpc_host", "127.0.0.1") ?: "127.0.0.1"
        set(value) = prefs.edit().putString("msf_rpc_host", value).apply()

    var msfRpcPort: Int
        get() = prefs.getInt("msf_rpc_port", 55553)
        set(value) = prefs.edit().putInt("msf_rpc_port", value.coerceIn(1, 65535)).apply()

    var msfRpcUser: String
        get() = prefs.getString("msf_rpc_user", "msf") ?: "msf"
        set(value) = prefs.edit().putString("msf_rpc_user", value).apply()

    var msfRpcPassword: String
        get() = prefs.getString("msf_rpc_password", "msf") ?: "msf"
        set(value) = prefs.edit().putString("msf_rpc_password", value).apply()

    var msfRpcSsl: Boolean
        get() = prefs.getBoolean("msf_rpc_ssl", false)
        set(value) = prefs.edit().putBoolean("msf_rpc_ssl", value).apply()
}
