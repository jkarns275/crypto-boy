package edu.oswego.crypto.boy.packets.crypto

abstract class CryptoPacket {
    object Ops {
        val OP_HELLO: Short = 0
        val OP_CIPHER_TEXT: Short = 1
        val OP_GOODBYE: Short = 2
    }

    abstract fun toBytes(): ByteArray
}