package edu.oswego.crypto.boy.packets.crypto

import java.nio.ByteBuffer

object GoodbyePacket: CryptoPacket() {

    object GoodbyePacket {
        val MAGIC: Long = 0x420DEADBEEF
    }

    override fun toBytes(): ByteArray {
        val bo = ByteBuffer.allocate(2)
        bo.putShort(Ops.OP_HELLO)
        return bo.array()
    }

}