package edu.oswego.crypto.boy.packets.chat

import java.nio.ByteBuffer
import java.util.*

class JoinAckPacket(val servername: String) : ChatPacket() {
    override fun toBytes(): ByteArray {
        assert(servername.length < 128)
        val bb = ByteBuffer.allocate(1 + 1 + servername.length)
        bb.put(ChatPacket.Ops.OP_JOIN_ACK)
        bb.put(servername.length.toByte())
        bb.put(servername.toByteArray())
        return bb.array()
    }
}