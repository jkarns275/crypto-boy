package edu.oswego.crypto.boy.networking.packets

import java.io.Serializable
import java.nio.ByteBuffer

abstract class Packet {
    object Packet {
        val OP_HELLO: Int = 0
        val OP_PUB_KEY: Int = 1
        val OP_CIPHER_TEXT: Int = 2
        val OP_GOODBYE: Int = 3
    }

    abstract fun toBytes(): ByteBuffer
    abstract fun fromBytes(bytes: ByteBuffer)
}