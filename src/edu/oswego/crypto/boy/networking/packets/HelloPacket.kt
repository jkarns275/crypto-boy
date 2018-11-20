package edu.oswego.crypto.boy.networking.packets

import java.nio.ByteBuffer

class HelloPacket(val publicKey: Long): Packet() {

    object HelloPacket {
        val MAGIC: Long = 0xDEADBEEFCAFE
    }

    override fun fromBytes(bi: ByteBuffer) {
        assert(bi.getInt(0) == Packet.OP_HELLO)
        assert(bi.getLong(4) == HelloPacket.MAGIC)
    }

    override fun toBytes(): ByteBuffer {
        val bo = ByteBuffer.allocate(4 + 8 + 8)
        bo.putInt(Packet.OP_HELLO)
        bo.putLong(HelloPacket.MAGIC)
        bo.putLong(this.publicKey)
        return bo
    }

}