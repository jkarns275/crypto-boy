package edu.oswego.crypto.boy.networking.packets

import edu.oswego.crypto.boy.cryptosystems.AsymmetricCryptosystem
import edu.oswego.crypto.boy.cryptosystems.Key
import java.nio.ByteBuffer


class CipherTextPacket<PuK: Key, PrK: Key, C: AsymmetricCryptosystem<PuK, PrK>>(
        plaintext: ByteArray, val crypto: AsymmetricCryptosystem<PuK, PrK>): Packet() {

    val ciphertext = crypto.encrypt(plaintext)

    override fun fromBytes(bi: ByteBuffer) {
        assert(bi.getInt(0) == Packet.OP_HELLO)

    }

    override fun toBytes(): ByteArray {
        val bo = ByteBuffer.allocate(4 + 2 + ciphertext.size)
        bo.putInt(Packet.OP_CIPHER_TEXT)

        val ciphertex = crypto.encrypt(ciphertext)

        return bo.array()
    }

    fun decrypt(privateKey: PrK): ByteArray {
        return crypto.decrypt(ciphertext, privateKey)
    }

}