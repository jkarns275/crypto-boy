package edu.oswego.crypto.boy.packets.crypto

import edu.oswego.crypto.boy.cryptosystems.Key
import java.nio.ByteBuffer

class HelloPacket<PuK: Key>(val publicKey: PuK): CryptoPacket() {

    object HelloPacket {
        val MAGIC: Long = 0x420BEEFCAFE
    }

    override fun toBytes(): ByteArray {
        val bo = ByteBuffer.allocate(2 + 8 + 2 + publicKey.length())
        bo.putShort(Ops.OP_HELLO)
        bo.putLong(HelloPacket.MAGIC)
        bo.putShort(publicKey.length().toShort())
        bo.put(this.publicKey.bytes())
        return bo.array()
    }

}