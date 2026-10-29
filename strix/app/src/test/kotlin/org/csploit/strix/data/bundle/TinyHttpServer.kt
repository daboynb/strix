package org.csploit.strix.data.bundle

import java.io.OutputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.SocketException
import kotlin.concurrent.thread

/**
 * Minimal HTTP/1.1 server for downloader tests (com.sun.net.httpserver is not
 * on the Android unit-test compile classpath). One request per connection.
 */
class TinyHttpServer(private val handler: (path: String, headers: Map<String, String>, out: Response) -> Unit) {
    class Response(private val out: OutputStream) {
        fun send(code: Int, headers: Map<String, String> = emptyMap(), body: ByteArray = ByteArray(0), off: Int = 0, len: Int = body.size - off) {
            val sb = StringBuilder("HTTP/1.1 $code X\r\nConnection: close\r\nContent-Length: $len\r\n")
            headers.forEach { (k, v) -> sb.append("$k: $v\r\n") }
            sb.append("\r\n")
            out.write(sb.toString().toByteArray())
            out.write(body, off, len)
            out.flush()
        }
    }

    private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    val port: Int get() = socket.localPort

    init {
        thread(isDaemon = true) {
            while (!socket.isClosed) {
                val client = try { socket.accept() } catch (_: SocketException) { break }
                thread(isDaemon = true) {
                    client.use { c ->
                        val reader = c.getInputStream().bufferedReader()
                        val requestLine = reader.readLine() ?: return@use
                        val headers = mutableMapOf<String, String>()
                        while (true) {
                            val line = reader.readLine() ?: break
                            if (line.isEmpty()) break
                            val i = line.indexOf(':')
                            if (i > 0) headers[line.substring(0, i).trim().lowercase()] = line.substring(i + 1).trim()
                        }
                        handler(requestLine.split(' ')[1], headers, Response(c.getOutputStream()))
                    }
                }
            }
        }
    }

    fun stop() = socket.close()
}
