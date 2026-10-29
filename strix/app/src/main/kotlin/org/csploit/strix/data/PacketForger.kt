package org.csploit.strix.data

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.SocketTimeoutException
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
    ): ForgeResult = try {
        Socket().useCancellable { socket ->
            // Socket(ip, port) would connect with the OS default timeout
            // (~75-130 s); bound the connect by the same timeout as reads.
            socket.connect(InetSocketAddress(ip, port), timeoutMs.toInt())
            socket.soTimeout = timeoutMs.toInt()

            val out = socket.getOutputStream()
            out.write(data)
            out.flush()

            val response = if (waitResponse) readUntilEofOrTimeout(socket) else null
            ForgeResult(success = true, response = response)
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        // Closing the socket on cancellation surfaces as an IOException here:
        // rethrow as cancellation instead of reporting a bogus error.
        currentCoroutineContext().ensureActive()
        ForgeResult(success = false, error = e.message ?: e.javaClass.simpleName)
    }

    suspend fun sendUdp(
        ip: String,
        port: Int,
        data: ByteArray,
        waitResponse: Boolean,
        timeoutMs: Long = 5000,
    ): ForgeResult = try {
        DatagramSocket().useCancellable { socket ->
            val address = InetAddress.getByName(ip)
            socket.soTimeout = timeoutMs.toInt()
            socket.send(DatagramPacket(data, data.size, address, port))

            val response = if (waitResponse) {
                try {
                    val buf = ByteArray(4096)
                    val resp = DatagramPacket(buf, buf.size)
                    socket.receive(resp)
                    String(buf, 0, resp.length)
                } catch (_: SocketTimeoutException) {
                    "(timeout — no response)"
                }
            } else null

            ForgeResult(success = true, response = response)
        }
    } catch (e: CancellationException) {
        throw e
    } catch (e: Exception) {
        // Closing the socket on cancellation surfaces as an IOException here:
        // rethrow as cancellation instead of reporting a bogus error.
        currentCoroutineContext().ensureActive()
        ForgeResult(success = false, error = e.message ?: e.javaClass.simpleName)
    }

    /**
     * Builds a magic packet (6 x 0xFF + 16 x MAC). Returns null when [mac] is
     * not a valid unicast MAC (e.g. the "manual" placeholder of manual hosts).
     */
    fun buildWolPacket(mac: String): ByteArray? {
        val normalized = normalizeMac(mac) ?: return null
        val macBytes = normalized.split(":")
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

    companion object {
        private val MAC_REGEX =
            Regex("^[0-9A-Fa-f]{2}([:-])[0-9A-Fa-f]{2}(?:\\1[0-9A-Fa-f]{2}){4}$")

        /**
         * Validates a MAC written with ':' or '-' separators and returns it as
         * upper-case colon-separated, or null if invalid / all-zero / broadcast.
         */
        fun normalizeMac(mac: String?): String? {
            val trimmed = mac?.trim() ?: return null
            if (!MAC_REGEX.matches(trimmed)) return null
            val normalized = trimmed.replace('-', ':').uppercase()
            if (normalized == "00:00:00:00:00:00" || normalized == "FF:FF:FF:FF:FF:FF") return null
            return normalized
        }
    }
}
