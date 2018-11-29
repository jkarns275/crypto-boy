package edu.oswego.crypto.boy.packets.chat

import java.nio.ByteBuffer
import java.util.*

class LeavingPacket(val username: String) : ChatPacket() {
    override fun toBytes(): ByteArray {
        assert(username.length < 128)
        val bb = ByteBuffer.allocate(1 + 1 + username.length)
        bb.put(ChatPacket.Ops.OP_LEAVING)
        bb.put(username.length.toByte())
        bb.put(username.toByteArray())
        return bb.array()
    }
}