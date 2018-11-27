package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer


abstract class AsymmetricCryptosystem<PuK: Key, PrK: Key>(var publicKey: PuK) {

    /**
     * Encrpyts the supplied plaintext with the public key
     */
    abstract fun encrypt(plaintext: ByteArray): ByteArray

    /**
     * Decrypts the given ciphertext.
     */
    abstract fun decrypt(ciphertext: ByteArray, privateKey: PrK): ByteArray

    /**
     * Return a short description of this cryptosystem.
     */
    abstract fun cryptosystemInfo(): String

    abstract fun publicKeyBytes(): ByteArray
}