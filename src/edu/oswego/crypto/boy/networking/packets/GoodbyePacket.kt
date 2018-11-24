package edu.oswego.crypto.boy.networking.packets

import edu.oswego.crypto.boy.cryptosystems.Key
import java.nio.ByteBuffer

class GoodbyePacket: Packet() {

    object GoodbyePacket {
        val MAGIC: Long = 0x420DEADBEEF
    }

    override fun toBytes(): ByteArray {
        val bo = ByteBuffer.allocate(2)
        bo.putShort(Packet.OP_HELLO)
        return bo.array()
    }

}