package org.csploit.strix.data

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.csploit.strix.core.Logger
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.net.SocketTimeoutException
import java.util.concurrent.atomic.AtomicInteger
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
        private const val RECEIVE_POLL_MS = 500
    }

    private val lock = Any()
    private var scope: CoroutineScope? = null
    private var serverJob: Job? = null
    private var socket: DatagramSocket? = null

    @Volatile
    private var entries: List<DnsEntry> = emptyList()

    /** Counters are bumped from concurrent per-query coroutines, hence atomic. */
    class Stats {
        private val _spoofed = AtomicInteger()
        private val _forwarded = AtomicInteger()
        private val _failed = AtomicInteger()

        val spoofed: Int get() = _spoofed.get()
        val forwarded: Int get() = _forwarded.get()
        val failed: Int get() = _failed.get()

        internal fun incSpoofed() { _spoofed.incrementAndGet() }
        internal fun incForwarded() { _forwarded.incrementAndGet() }
        internal fun incFailed() { _failed.incrementAndGet() }

        internal fun reset() {
            _spoofed.set(0)
            _forwarded.set(0)
            _failed.set(0)
        }
    }

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
        synchronized(lock) { startLocked(entries, upstreamDns, port, onEvent) }
    }

    private fun startLocked(
        entries: List<DnsEntry>,
        upstreamDns: String,
        port: Int,
        onEvent: (String) -> Unit,
    ) {
        // The previous server job releases its socket in its finally block;
        // the new one joins it before binding so the port is guaranteed free.
        val previous = serverJob
        stop()
        this.entries = entries
        stats.reset()

        val newScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        scope = newScope

        serverJob = newScope.launch {
            previous?.join()
            var sock: DatagramSocket? = null
            try {
                val bound = DatagramSocket(InetSocketAddress("0.0.0.0", port))
                sock = bound
                // Finite timeout so the loop re-checks cancellation even if
                // close() from stop() is somehow missed.
                bound.soTimeout = RECEIVE_POLL_MS
                synchronized(lock) {
                    // stop() may have run while we were binding: it could not
                    // close a socket it never saw, so bail out and close it here.
                    if (!isActive) return@launch
                    socket = bound
                }
                onEvent("[dns] listening on 0.0.0.0:$port, upstream=$upstreamDns, entries=${entries.size}")

                val buffer = ByteArray(4096)
                while (isActive && !bound.isClosed) {
                    val request = DatagramPacket(buffer, buffer.size)
                    try {
                        bound.receive(request)
                    } catch (_: SocketTimeoutException) {
                        continue
                    } catch (_: Exception) {
                        break
                    }
                    val data = request.data.copyOf(request.length)
                    val client = request.socketAddress as InetSocketAddress
                    newScope.launch {
                        handleDnsQuery(
                            bound, client, data, this@DnsSpoofServer.entries, upstreamDns, stats, onEvent,
                        )
                    }
                }
            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                onEvent("[dns] server error: ${e.message}")
                Logger.error("DnsSpoofServer failed", e)
            } finally {
                sock?.runCatching { close() }
                synchronized(lock) { if (socket === sock) socket = null }
                onEvent("[dns] stopped")
            }
        }
    }

    fun stop() {
        synchronized(lock) {
            socket?.runCatching { close() }
            socket = null
            serverJob?.cancel()
            serverJob = null
            scope?.coroutineContext?.get(Job)?.cancel()
            scope = null
        }
    }

}
