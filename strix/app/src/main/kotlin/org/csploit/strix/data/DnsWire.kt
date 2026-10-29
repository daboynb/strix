package org.csploit.strix.data

/** DNS wire-format helpers for [DnsSpoofServer]: question parsing and spoofed A replies. */
internal object DnsWire {
    const val QTYPE_A = 1
    private const val QCLASS_IN = 1
    private const val SPOOF_TTL = 60

    /**
     * Parse the QNAME label sequence starting at offset.
     * Format: length-prefixed labels, terminated by 0 byte.
     * Returns the dotted name. No compression support (queries don't use it).
     */
    fun parseQName(data: ByteArray, offset: Int): String {
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
    fun qNameEnd(data: ByteArray, offset: Int): Int {
        var i = offset
        while (i < data.size) {
            val len = data[i].toInt() and 0xff
            if (len == 0) return i + 1
            if (len and 0xc0 != 0) return i + 2
            i += len + 1
        }
        throw IllegalStateException("QNAME not terminated")
    }

    fun readU16(data: ByteArray, offset: Int): Int =
        ((data[offset].toInt() and 0xff) shl 8) or (data[offset + 1].toInt() and 0xff)

    /**
     * Build a DNS response:
     *  - copy header, set QR=1, RA=1, rcode=0, ancount=1
     *  - keep the question section
     *  - append one A answer with the spoofed IP
     */
    fun buildSpoofedReply(req: ByteArray, spoofIp: String): ByteArray? {
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

    fun parseIpv4(s: String): ByteArray? {
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
