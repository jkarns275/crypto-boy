package edu.oswego.crypto.boy.packets.chat

import java.nio.ByteBuffer

class RejectPacket(val reason: Byte) : ChatPacket() {
    object RejectionReasons {
        val DUPLICATE_USERNAME: Byte = 0
    }

    override fun toBytes(): ByteArray {
        val bb = ByteBuffer.allocate(1 + 1)
        bb.put(ChatPacket.Ops.OP_REJECT)
        bb.put(RejectionReasons.DUPLICATE_USERNAME)
        return bb.array()
    }
}