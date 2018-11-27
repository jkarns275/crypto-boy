package edu.oswego.crypto.boy.cryptosystems

import java.math.BigInteger
import java.nio.ByteBuffer

class RSA<N: Key, E: Key, PuK: RSAKey<N, E>, PrK: RSAKey<N, E>>(publicKey: PuK)
    : AsymmetricCryptosystem<PuK, PrK>(publicKey) {
    override fun publicKeyBytes(): ByteArray {
        return publicKey.bytes
    }

    override fun cryptosystemInfo(): String {
        return "${publicKey.bytes.size}-bit RSA"
    }

    // TODO: Add zeroes as padding. Zeroes will be ignored by protocols, and if they aren't change the protocol
    override fun encrypt(plaintext: ByteArray): ByteArray {
        val n = BigInteger(publicKey.n.bytes)
        val e = BigInteger(publicKey.e.bytes)
        val junk = ByteArray(0)
        var ciphertext = Array<ByteArray>(plaintext.size / publicKey.n.length() + 1) { _ -> junk }
        var i = 0
        for (byte in plaintext) {
            val num = byte.toInt().toBigInteger()
            ciphertext[i] = num.modPow(e, n).toByteArray()
            i++
        }

        var buff: ByteBuffer
        return ciphertext
    }

    override fun decrypt(ciphertext: ByteArray, privateKey: PrK): ByteArray {
        var plaintext = ByteArray(ciphertext.size)
        var i = 0
        for(num in ciphertext){
            val bigNum = num.toBigInteger()
            val numDec = bigNum.pow(d.toInt()).mod(n)
            plaintext[i] = numDec.toByte()
            i++

        }
        return plaintext
    }
}