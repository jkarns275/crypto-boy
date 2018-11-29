package edu.oswego.crypto.boy.packets.chat

import java.nio.ByteBuffer

class MsgPacket(val sender: String, val msg: String) : ChatPacket() {
    override fun toBytes(): ByteArray {
        assert(msg.length < 65536 / 2)
        assert(sender.length < 128)
        val bb = ByteBuffer.allocate(1 + 1 + sender.length + 4 + msg.length)
        bb.put(ChatPacket.Ops.OP_MSG)
        bb.put(sender.length.toByte())
        bb.put(sender.toByteArray())
        val msg_bytes = msg.toByteArray()
        bb.putInt(msg_bytes.size)
        bb.put(msg_bytes)
        return bb.array()
    }
}