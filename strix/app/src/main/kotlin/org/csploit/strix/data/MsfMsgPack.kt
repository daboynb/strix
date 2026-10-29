package org.csploit.strix.data

import org.msgpack.core.MessagePack
import org.msgpack.core.MessageUnpacker
import org.msgpack.value.ValueType
import java.io.ByteArrayOutputStream

/** MessagePack serialization of msfrpcd requests and responses. */
internal object MsfMsgPack {

    fun packRequest(method: String, vararg args: Any?): ByteArray {
        val baos = ByteArrayOutputStream()
        val packer = MessagePack.newDefaultPacker(baos)

        // RPC request is an array: [method, args...]
        packer.packArrayHeader(1 + args.size)
        packer.packString(method)

        for (arg in args) {
            packValue(packer, arg)
        }

        packer.flush()
        return baos.toByteArray()
    }

    private fun packValue(packer: org.msgpack.core.MessagePacker, value: Any?) {
        when (value) {
            null -> packer.packNil()
            is String -> packer.packString(value)
            is Int -> packer.packInt(value)
            is Long -> packer.packLong(value)
            is Boolean -> packer.packBoolean(value)
            is Float -> packer.packFloat(value)
            is Double -> packer.packDouble(value)
            is ByteArray -> {
                packer.packBinaryHeader(value.size)
                packer.writePayload(value)
            }
            is Map<*, *> -> {
                packer.packMapHeader(value.size)
                for ((k, v) in value) {
                    packValue(packer, k)
                    packValue(packer, v)
                }
            }
            is List<*> -> {
                packer.packArrayHeader(value.size)
                for (item in value) {
                    packValue(packer, item)
                }
            }
            is Array<*> -> {
                packer.packArrayHeader(value.size)
                for (item in value) {
                    packValue(packer, item)
                }
            }
            else -> packer.packString(value.toString())
        }
    }

    fun unpackResponse(data: ByteArray): Any? {
        val unpacker = MessagePack.newDefaultUnpacker(data)
        return if (unpacker.hasNext()) unpackValue(unpacker) else null
    }

    private fun unpackValue(unpacker: MessageUnpacker): Any? {
        val format = unpacker.nextFormat
        return when (format.valueType) {
            ValueType.NIL -> { unpacker.unpackNil(); null }
            ValueType.BOOLEAN -> unpacker.unpackBoolean()
            ValueType.INTEGER -> {
                val v = unpacker.unpackValue()
                if (v.isIntegerValue) {
                    val lv = v.asIntegerValue().toLong()
                    if (lv in Int.MIN_VALUE..Int.MAX_VALUE) lv.toInt() else lv
                } else v
            }
            ValueType.FLOAT -> unpacker.unpackDouble()
            ValueType.STRING -> unpacker.unpackString()
            ValueType.BINARY -> {
                // MSF often sends strings as binary
                val len = unpacker.unpackBinaryHeader()
                val bytes = ByteArray(len)
                unpacker.readPayload(bytes)
                String(bytes, Charsets.UTF_8)
            }
            ValueType.ARRAY -> {
                val size = unpacker.unpackArrayHeader()
                (0 until size).map { unpackValue(unpacker) }
            }
            ValueType.MAP -> {
                val size = unpacker.unpackMapHeader()
                val map = LinkedHashMap<String, Any?>(size)
                repeat(size) {
                    val key = unpackValue(unpacker)?.toString() ?: ""
                    val value = unpackValue(unpacker)
                    map[key] = value
                }
                map
            }
            ValueType.EXTENSION -> {
                val ext = unpacker.unpackValue()
                ext.toString()
            }
            else -> {
                unpacker.skipValue()
                null
            }
        }
    }
}
