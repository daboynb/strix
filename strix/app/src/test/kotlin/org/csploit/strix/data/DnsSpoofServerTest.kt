package org.csploit.strix.data

import kotlinx.coroutines.runBlocking
import org.junit.Assert.assertTrue
import org.junit.Test
import java.net.DatagramSocket
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

/**
 * Regression tests for the socket lifecycle bug: if stop() ran before the IO
 * job assigned `socket`, the socket was never closed and the next start()
 * failed with BindException on the port. The finally-block close + join-the-
 * previous-job fix must make start/stop cycles rebind cleanly.
 */
class DnsSpoofServerTest {

    // A free high port unlikely to collide with the default 15353.
    private val port = 15454

    private fun waitForListening(server: DnsSpoofServer, entries: List<DnsEntry>): Boolean {
        val latch = CountDownLatch(1)
        server.start(entries, upstreamDns = "127.0.0.1", port = port) { line ->
            if (line.contains("listening")) latch.countDown()
        }
        return latch.await(5, TimeUnit.SECONDS)
    }

    @Test
    fun startStopStartRebindsWithoutBindException() = runBlocking {
        val server = DnsSpoofServer()
        val entries = listOf(DnsEntry("example.com", "1.2.3.4"))
        assertTrue("first bind should succeed", waitForListening(server, entries))
        server.stop()
        // Without the join-the-previous-job fix the port may still be held here.
        assertTrue("rebind after stop should succeed", waitForListening(server, entries))
        server.stop()
    }

    @Test
    fun stopReleasesPortEvenWhenCalledImmediatelyAfterStart() = runBlocking {
        val server = DnsSpoofServer()
        val entries = listOf(DnsEntry("example.com", "1.2.3.4"))
        // Race stop() against an in-flight start several times.
        repeat(5) {
            server.start(entries, upstreamDns = "127.0.0.1", port = port) {}
            server.stop()
        }
        // Confirm the port is free by binding it ourselves, retrying briefly to
        // absorb the asynchronous teardown.
        var bound = false
        var attempts = 0
        while (!bound && attempts < 50) {
            attempts++
            try {
                DatagramSocket(InetSocketAddress("0.0.0.0", port)).use { bound = true }
            } catch (_: Exception) {
                Thread.sleep(100)
            }
        }
        assertTrue("port $port should be free after stop()", bound)
    }
}
