package edu.oswego.crypto.boy.networking.packets

import edu.oswego.crypto.boy.cryptosystems.AsymmetricCryptosystem
import edu.oswego.crypto.boy.cryptosystems.Key
import java.nio.ByteBuffer


class CipherTextPacket<PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>>(
        val ciphertext: ByteArray, val crypto: Crypto): Packet() {

    override fun toBytes(): ByteArray {
        val bo = ByteBuffer.allocate(2 + 2 + ciphertext.size)
        bo.putShort(Packet.OP_CIPHER_TEXT)
        bo.putShort(ciphertext.size.toShort())
        val ciphertex = crypto.encrypt(ciphertext)

        return bo.array()
    }

    fun decrypt(privateKey: PrK): ByteArray {
        return crypto.decrypt(ciphertext, privateKey)
    }

}