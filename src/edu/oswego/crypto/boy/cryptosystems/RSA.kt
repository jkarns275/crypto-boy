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

    private fun blockSizeAndNBlocks(plaintext: ByteArray): Pair<Int, Int> {
        val blocksize = BigInteger(publicKey.n.bytes).bitLength() / 8
        val nblocks = plaintext.size / blocksize
        return if (nblocks * blocksize < plaintext.size)
            Pair(blocksize, nblocks + 1)
        else
            Pair(blocksize, nblocks)
    }

    // TODO: Add zeroes as padding. Zeroes will be ignored by protocols, and if they aren't change the protocol
    override fun encrypt(plaintext: ByteArray): ByteArray {
        val n = BigInteger(publicKey.n.bytes)
        val e = BigInteger(publicKey.e.bytes)
        val blocksizeAndNBlocks = blockSizeAndNBlocks(plaintext)
        val blocksize = blocksizeAndNBlocks.first
        val nblocks = blocksizeAndNBlocks.second
        var cipherBlocks = Array(plaintext.size / publicKey.n.length() + 1) { _ -> ByteArray(blocksize) }
        val tmp = ByteArray(blocksize)
        val bb = ByteBuffer.wrap(plaintext)
        for (i in 0 until nblocks) {
            tmp.fill(0)
            val ind = min(blocksize, plaintext.size - blocksize * i)
            bb.get(tmp, blocksize * i, min(blocksize, plaintext.size - blocksize * i))
            val num = BigInteger(tmp)
            val res = num.modPow(e, n).toByteArray()
            ByteBuffer.wrap(res).get(cipherBlocks[i])
        }

        var ciphertext: ByteBuffer = ByteBuffer.allocate(blocksize * nblocks)
        for (block in cipherBlocks)
            ciphertext.put(block)
        return ciphertext.array()
    }

    override fun decrypt(ciphertext: ByteArray, privateKey: PrK): ByteArray {
        val plaintext = ByteBuffer.allocate(ciphertext.size)
        var i = 0
        val blocksizeAndNBlocks = blockSizeAndNBlocks(ciphertext)
        val blocksize = blocksizeAndNBlocks.first
        val nblocks = blocksizeAndNBlocks.second
        val tmp = ByteArray(blocksize)
        val bb = ByteBuffer.wrap(ciphertext)
        val d = BigInteger(privateKey.bytes)
        val n = BigInteger(publicKey.n.bytes)
        for (i in 0 until nblocks) {
            tmp.fill(0)
            bb.get(tmp, blocksize * i, min(blocksize, ciphertext.size - blocksize * i))
            plaintext.put(BigInteger(tmp).modPow(d, n).toByteArray(), blocksize * i, blocksize)
        }
        return plaintext.array()
    }
}