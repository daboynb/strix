package org.csploit.strix.data

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.runBlocking
import org.csploit.strix.domain.model.Host
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The session stores are written from many threads at once (DnsSpoofServer
 * fires onEvent from per-query IO coroutines, hydra output from IO readers).
 * Before switching to MutableStateFlow.update {} the read-modify-write on
 * `_x.value = current + ...` dropped concurrent writes. These tests hammer the
 * stores from many threads and assert nothing is lost.
 */
class SessionStoreConcurrencyTest {

    private val ip = "10.0.0.5"

    @Test
    fun mitmAppendLogFromManyThreadsLosesNothing() = runBlocking(Dispatchers.Default) {
        val store = MitmSessionStore()
        val writers = 16
        // LOG_LIMIT is 200, so keep the total well under it to count exactly.
        val lines = 10
        (0 until writers).map { w ->
            async { repeat(lines) { i -> store.appendLog(ip, "w$w-$i") } }
        }.awaitAll()
        val logged = store.sessionOf(ip)!!.logLines
        assertEquals(writers * lines, logged.size)
        assertEquals((writers * lines), logged.toSet().size) // all distinct, none merged away
    }

    @Test
    fun mitmAddCredentialIsAtomicAndDedups() = runBlocking(Dispatchers.Default) {
        val store = MitmSessionStore()
        val distinct = 50
        val added = (0 until distinct).flatMap { i ->
            // same credential submitted twice concurrently — exactly one add
            listOf(
                async { store.addCredential(ip, MitmCapturedCredential("HTTP", "POST", "u$i", "p$i")) },
                async { store.addCredential(ip, MitmCapturedCredential("HTTP", "POST", "u$i", "p$i")) },
            )
        }.awaitAll()
        assertEquals(distinct, store.sessionOf(ip)!!.credentials.size)
        assertEquals(distinct, added.count { it })
    }

    @Test
    fun bruteForceAppendLogFromManyThreadsLosesNothing() = runBlocking(Dispatchers.Default) {
        val store = BruteForceSessionStore()
        val key = BruteForceSessionStore.keyFor(ip, 22, "ssh")
        store.resetForNewRun(key, ip, 22, "ssh")
        val writers = 16
        val lines = 3 // LOG_LIMIT is 50
        (0 until writers).map { w ->
            async { repeat(lines) { i -> store.appendLog(key, "w$w-$i") } }
        }.awaitAll()
        assertEquals(writers * lines, store.sessionOf(key)!!.logLines.size)
    }

    @Test
    fun targetRepositoryConcurrentAddOrUpdateKeepsEveryHost() = runBlocking(Dispatchers.Default) {
        val repo = TargetRepository()
        val count = 300
        (0 until count).map { i ->
            async { repo.addOrUpdate("192.168.1.$i", "aa:bb:cc:00:00:$i", "host$i") }
        }.awaitAll()
        val hosts = repo.hosts.value
        assertEquals(count, hosts.size)
        assertTrue(hosts.all { it.connected })
        assertEquals(count, hosts.map(Host::ip).toSet().size)
    }
}
