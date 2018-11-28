package edu.oswego.crypto.boy.cryptosystems

import java.lang.Integer.min
import java.math.BigInteger
import java.nio.ByteBuffer
import java.util.*

class RSA<PuK, PrK>(publicKey: PuK)
    : AsymmetricCryptosystem<PuK, PrK>(publicKey) where PuK: RSAKey<Key, Key>, PrK: Key {

    companion object {
        fun <PuK: RSAKey<Key, Key>, PrK: Key> rsaFactory():
                (PuK) -> AsymmetricCryptosystem<PuK, PrK> = { p -> RSA(p) }
    }

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
        val blocksize = BigInteger(publicKey.n.bytes).bitLength() / 8 + 1
        // The width of the output of encryption in bytes.1
        // The width of the chunks, in bytes, that will be encrypted
        val blockwidth = blocksize - 2
        var nblocks = plaintext.size / blockwidth
        if (blockwidth * nblocks < plaintext.size)
            nblocks += 1
        var cipherBlocks = Array(plaintext.size / publicKey.n.length() + 1) { _ -> ByteArray(blocksize) }
        val tmp = ByteArray(blocksize)
        val bb = ByteBuffer.wrap(plaintext)
        for (i in 0 until nblocks) {
            tmp.fill(0)
            val ind = min(blockwidth, plaintext.size - blockwidth * i)
            bb.get(tmp, blockwidth * i, min(blockwidth, plaintext.size - blockwidth * i))
            val num = BigInteger(tmp)
            val res = num.modPow(e, n).toByteArray()
            val a = cipherBlocks[i]
            ByteBuffer.wrap(res).get(cipherBlocks[i], 0, res.size)
        }

        var ciphertext: ByteBuffer = ByteBuffer.allocate(blocksize * nblocks)
        for (block in cipherBlocks)
            ciphertext.put(block)
        return ciphertext.array()
    }

    override fun decrypt(ciphertext: ByteArray, privateKey: PrK): ByteArray {
        var i = 0
        val blocksize = BigInteger(publicKey.n.bytes).bitLength() / 8 + 1
        val blockwidth = blocksize - 2
        var nblocks = ciphertext.size / blocksize
        if (blocksize * nblocks < ciphertext.size)
            nblocks += 1
        val plaintext = ByteBuffer.allocate(nblocks * blockwidth)
        val tmp = ByteArray(blocksize)
        val bb = ByteBuffer.wrap(ciphertext)
        val d = BigInteger(privateKey.bytes)
        val n = BigInteger(publicKey.n.bytes)
        for (i in 0 until nblocks) {
            tmp.fill(0)
            val endIndex = min(ciphertext.size, blocksize * (i + 1))
            val offset = blocksize * i
            for (i in 0 until endIndex)
                tmp[i] = bb[offset + i]
            val res = BigInteger(tmp).modPow(d, n).toByteArray()
            plaintext.put(res, blockwidth * i, res.size)
        }
        return plaintext.array()
    }
}