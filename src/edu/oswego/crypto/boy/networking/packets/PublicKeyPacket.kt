package edu.oswego.crypto.boy.networking.packets

import java.nio.ByteBuffer

class PublicKeyPacket(var keyBytes: ByteBuffer): Packet() {
    override fun toBytes(): ByteBuffer {
        val bo = ByteBuffer.allocate(keyBytes.capacity() + 4 + 4)
        bo.putInt(Packet.OP_PUB_KEY)
        bo.putInt(keyBytes.capacity())
        bo.put(keyBytes)
        return bo
    }

    override fun fromBytes(bytes: ByteBuffer) {
        assert(Packet.OP_PUB_KEY == bytes.getInt(0))
        val capacity = bytes.getInt(4)
        val ba = ByteArray(capacity)
        bytes.get(ba, 8, capacity)
        keyBytes = ByteBuffer.wrap(ba)
    }

}