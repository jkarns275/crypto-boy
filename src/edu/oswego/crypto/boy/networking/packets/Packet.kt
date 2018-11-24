package edu.oswego.crypto.boy.networking.packets

import java.io.Serializable
import java.nio.ByteBuffer

abstract class Packet {
    object Packet {
        val OP_HELLO: Int = 0
        val OP_CIPHER_TEXT: Int = 1
        val OP_GOODBYE: Int = 2
    }

    abstract fun toBytes(): ByteArray
    abstract fun fromBytes(bytes: ByteBuffer)
}