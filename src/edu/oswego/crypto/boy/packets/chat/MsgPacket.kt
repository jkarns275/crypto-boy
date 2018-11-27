package edu.oswego.crypto.boy.packets.chat

import java.nio.ByteBuffer

class MsgPacket(val sender: String, val msg: String) : ChatPacket() {
    override fun toBytes(): ByteArray {
        assert(msg.length < 65536 / 2)
        assert(sender.length < 128)
        val bb = ByteBuffer.allocate(1 + 1 + sender.length + 2 + msg.length)
        bb.put(ChatPacket.Ops.OP_MSG)
        bb.put(sender.length.toByte())
        bb.put(sender.toByteArray())
        bb.putShort(msg.length.toShort())
        bb.put(msg.toByteArray())
        return bb.array()
    }
}