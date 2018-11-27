package edu.oswego.crypto.boy.packets.chat

import java.nio.ByteBuffer

object ByePacket : ChatPacket() {
    override fun toBytes(): ByteArray {
        val bb = ByteBuffer.allocate(1)
        bb.put(ChatPacket.Ops.OP_BYE)
        return bb.array()
    }
}