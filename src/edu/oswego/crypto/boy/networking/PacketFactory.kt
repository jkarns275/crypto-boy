package edu.oswego.crypto.boy.networking

import edu.oswego.crypto.boy.cryptosystems.AsymmetricCryptosystem
import edu.oswego.crypto.boy.cryptosystems.Key
import edu.oswego.crypto.boy.networking.packets.CipherTextPacket
import edu.oswego.crypto.boy.networking.packets.GoodbyePacket
import edu.oswego.crypto.boy.networking.packets.HelloPacket
import edu.oswego.crypto.boy.networking.packets.Packet
import java.nio.ByteBuffer

class PacketFactory<PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>>() {

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun cipherTextPacket(bytes: ByteArray, crypto: Crypto): CipherTextPacket<PuK, PrK, Crypto>? {
        if (bytes.size < 5) { return null }

        val bb = ByteBuffer.wrap(bytes)

        val op = bb.getShort(0)
        assert(op == Packet.Packet.OP_CIPHER_TEXT)

        val len = bb.getShort(2).toInt()

        val buf = ByteBuffer.allocate(len)
        bb.get(bytes, 4, len)

        return CipherTextPacket(buf.array(), crypto)
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun helloPacket(bytes: ByteArray, keygen: (ByteArray) -> PuK): HelloPacket<PuK>? {
        if (bytes.size < 13) { return null }

        val bb = ByteBuffer.wrap(bytes)

        val op = bb.getShort(0)
        assert(op == Packet.Packet.OP_HELLO)

        val magic = bb.getLong(2)
        assert(magic == HelloPacket.HelloPacket.MAGIC)

        val len = bb.getShort(10).toInt()

        val buf = ByteBuffer.allocate(len)
        bb.get(bytes, 12, len)

        return HelloPacket(keygen(buf.array()))
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun goodbyePaket(bytes: ByteArray): GoodbyePacket? {
        if (bytes.size < 10) { return null }

        val bb = ByteBuffer.wrap(bytes)

        val op = bb.getShort(0)
        assert(op == Packet.Packet.OP_GOODBYE)

        val magic = bb.getLong(2)
        assert(magic == GoodbyePacket.GoodbyePacket.MAGIC)

        return GoodbyePacket()
    }
}