package edu.oswego.crypto.boy.packets.crypto

import edu.oswego.crypto.boy.UI
import edu.oswego.crypto.boy.cryptosystems.AsymmetricCryptosystem
import edu.oswego.crypto.boy.cryptosystems.Key
import java.nio.ByteBuffer

class CryptoPacketFactory<PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>>(
        val crypto: Crypto,
        val keygen: (ByteArray) -> PuK) {

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun cipherTextPacket(bytes: ByteArray): CipherTextPacket<PuK, PrK, Crypto>? {
        if (bytes.size < 5) { return null }

        val bb = ByteBuffer.wrap(bytes)

        val op = bb.getShort(0)
        assert(op == CryptoPacket.Ops.OP_CIPHER_TEXT)

        val len = bb.getShort(2).toInt()

        val buf = ByteArray(len)
        for (i in 0 until len)
            buf[i] = bb[4 + i]

        return CipherTextPacket(buf, crypto)
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun helloPacket(bytes: ByteArray): HelloPacket<PuK>? {
        if (bytes.size < 13) { return null }

        val bb = ByteBuffer.wrap(bytes)

        val op = bb.getShort(0)
        assert(op == CryptoPacket.Ops.OP_HELLO)

        val magic = bb.getLong(2)
        assert(magic == HelloPacket.HelloPacket.MAGIC)

        val len = bb.getShort(10).toInt()

        val buf = ByteBuffer.allocate(len)
        buf.put(bytes, 12, len)

        return HelloPacket(keygen(buf.array()))
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun goodbyePacket(bytes: ByteArray): GoodbyePacket? {
        if (bytes.size < 10) { return null }

        val bb = ByteBuffer.wrap(bytes)

        val op = bb.getShort(0)
        assert(op == CryptoPacket.Ops.OP_GOODBYE)

        val magic = bb.getLong(2)
        assert(magic == GoodbyePacket.GoodbyePacket.MAGIC)

        return GoodbyePacket
    }

    fun fromBytes(bytes: ByteArray): CryptoPacket? {
        try {
            when (bytes[1].toShort()) {
                CryptoPacket.Ops.OP_HELLO -> return helloPacket(bytes)
                CryptoPacket.Ops.OP_CIPHER_TEXT -> return cipherTextPacket(bytes)
                CryptoPacket.Ops.OP_GOODBYE -> return goodbyePacket(bytes)
            }
        } catch (e: Exception) {
            UI.log("CryptoPacketFactory", "Encountered the following exception: \n" + e.toString())
            e.printStackTrace()
        }
        return null
    }
}