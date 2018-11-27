package edu.oswego.crypto.boy.packets.chat

abstract class ChatPacket {
    object Ops {
        val OP_JOIN: Byte = 0
        val OP_JOIN_ACK: Byte = 1
        val OP_REJECT: Byte = 2
        val OP_MSG: Byte = 3
        val OP_LEAVING: Byte = 4
        val OP_BYE: Byte = 5
    }

    abstract fun toBytes(): ByteArray
}