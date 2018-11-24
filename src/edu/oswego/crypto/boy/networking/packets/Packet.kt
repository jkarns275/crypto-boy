package edu.oswego.crypto.boy.networking.packets

import java.io.Serializable
import java.nio.ByteBuffer

abstract class Packet {
    object Packet {
        val OP_HELLO: Short = 0
        val OP_CIPHER_TEXT: Short = 1
        val OP_GOODBYE: Short = 2
    }

    abstract fun toBytes(): ByteArray
}