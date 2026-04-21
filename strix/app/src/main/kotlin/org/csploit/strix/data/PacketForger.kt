package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeout
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.Socket
import javax.inject.Inject
import javax.inject.Singleton

data class ForgeResult(
    val success: Boolean,
    val response: String? = null,
    val error: String? = null,
)

@Singleton
class PacketForger @Inject constructor() {

    suspend fun sendTcp(
        ip: String,
        port: Int,
        data: ByteArray,
        waitResponse: Boolean,
        timeoutMs: Long = 5000,
    ): ForgeResult = withContext(Dispatchers.IO) {
        try {
            Socket(ip, port).use { socket ->
                socket.soTimeout = timeoutMs.toInt()

                val out = socket.getOutputStream()
                out.write(data)
                out.flush()

                val response = if (waitResponse) {
                    try {
                        val reader = socket.getInputStream().bufferedReader()
                        val sb = StringBuilder()
                        val buf = CharArray(4096)
                        var n: Int
                        while (reader.read(buf).also { n = it } != -1) {
                            sb.append(buf, 0, n)
                        }
                        sb.toString()
                    } catch (_: java.net.SocketTimeoutException) {
                        null
                    }
                } else null

                ForgeResult(success = true, response = response)
            }
        } catch (e: Exception) {
            ForgeResult(success = false, error = e.message ?: e.javaClass.simpleName)
        }
    }

    suspend fun sendUdp(
        ip: String,
        port: Int,
        data: ByteArray,
        waitResponse: Boolean,
        timeoutMs: Long = 5000,
    ): ForgeResult = withContext(Dispatchers.IO) {
        try {
            val address = InetAddress.getByName(ip)
            val socket = DatagramSocket()
            socket.soTimeout = timeoutMs.toInt()

            val packet = DatagramPacket(data, data.size, address, port)
            socket.send(packet)

            val response = if (waitResponse) {
                try {
                    val buf = ByteArray(4096)
                    val resp = DatagramPacket(buf, buf.size)
                    socket.receive(resp)
                    String(buf, 0, resp.length)
                } catch (_: java.net.SocketTimeoutException) {
                    "(timeout — no response)"
                }
            } else null

            socket.close()
            ForgeResult(success = true, response = response)
        } catch (e: Exception) {
            ForgeResult(success = false, error = e.message ?: e.javaClass.simpleName)
        }
    }

    fun buildWolPacket(mac: String): ByteArray {
        val macBytes = mac.split(":")
            .map { it.toInt(16).toByte() }
            .toByteArray()
        val packet = ByteArray(6 + 16 * macBytes.size)
        // 6 bytes of 0xFF
        for (i in 0 until 6) packet[i] = 0xFF.toByte()
        // 16 repetitions of MAC
        for (i in 0 until 16) {
            System.arraycopy(macBytes, 0, packet, 6 + i * macBytes.size, macBytes.size)
        }
        return packet
    }
}
