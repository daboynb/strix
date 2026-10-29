package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.csploit.strix.data.DnsWire.QTYPE_A
import org.csploit.strix.data.DnsWire.buildSpoofedReply
import org.csploit.strix.data.DnsWire.parseQName
import org.csploit.strix.data.DnsWire.qNameEnd
import org.csploit.strix.data.DnsWire.readU16
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.net.InetSocketAddress

private const val UPSTREAM_TIMEOUT_MS = 3000

/**
 * Answer one query: spoof an A record for a matching [entries] name, else
 * forward to [upstreamDns] and relay the reply to [client].
 */
internal suspend fun handleDnsQuery(
    sock: DatagramSocket,
    client: InetSocketAddress,
    req: ByteArray,
    entries: List<DnsEntry>,
    upstreamDns: String,
    stats: DnsSpoofServer.Stats,
    onEvent: (String) -> Unit,
) = withContext(Dispatchers.IO) {
    if (req.size < 12) {
        stats.incFailed()
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
            stats.incSpoofed()
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
            stats.incForwarded()
        }
    } catch (e: Exception) {
        stats.incFailed()
        onEvent("[dns] forward error for ${qName ?: "<parse-fail>"}: ${e.message}")
    }
}
