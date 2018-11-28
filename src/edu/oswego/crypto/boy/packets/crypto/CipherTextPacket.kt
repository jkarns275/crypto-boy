package edu.oswego.crypto.boy.packets.crypto

import edu.oswego.crypto.boy.cryptosystems.AsymmetricCryptosystem
import edu.oswego.crypto.boy.cryptosystems.Key
import java.nio.ByteBuffer


class CipherTextPacket<PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>>(
        val ciphertext: ByteArray, val crypto: Crypto): CryptoPacket() {

    override fun toBytes(): ByteArray {
        val ciphertext: ByteArray = crypto.encrypt(ciphertext)
        val bo = ByteBuffer.allocate(2 + 2 + ciphertext.size)
        bo.putShort(Ops.OP_CIPHER_TEXT)
        bo.putShort(ciphertext.size.toShort())
        bo.put(ciphertext)

        return bo.array()
    }

    fun decrypt(privateKey: PrK): ByteArray {
        return crypto.decrypt(ciphertext, privateKey)
    }

}