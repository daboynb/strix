package org.csploit.strix.data

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.ByteArrayOutputStream
import java.io.Closeable
import java.net.Socket
import java.net.SocketTimeoutException

/** Reads until EOF; on read timeout keeps whatever was already received. */
internal fun readUntilEofOrTimeout(socket: Socket): String? {
    val input = socket.getInputStream()
    val received = ByteArrayOutputStream()
    val buf = ByteArray(4096)
    try {
        while (true) {
            val n = input.read(buf)
            if (n == -1) break
            received.write(buf, 0, n)
        }
    } catch (_: SocketTimeoutException) {
        // Server kept the connection open: return the partial response.
    }
    return if (received.size() == 0) null else received.toString(Charsets.UTF_8.name())
}

/**
 * Runs the blocking [block] on IO and closes the resource when done or when
 * the calling coroutine is cancelled — closing unblocks connect/read/receive,
 * which don't react to coroutine cancellation on their own.
 */
internal suspend fun <C : Closeable, R> C.useCancellable(block: (C) -> R): R {
    val resource = this
    return coroutineScope {
        val closer = launch(start = CoroutineStart.UNDISPATCHED) {
            try {
                awaitCancellation()
            } finally {
                resource.close()
            }
        }
        try {
            withContext(Dispatchers.IO) { block(resource) }
        } finally {
            closer.cancel()
            resource.close()
        }
    }
}
