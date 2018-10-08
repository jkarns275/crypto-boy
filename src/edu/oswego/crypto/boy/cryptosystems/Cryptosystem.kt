package edu.oswego.crypto.boy.cryptosystems

abstract class Cryptosystem<PuKey, PrKey>(val publicKey: PuKey, val privateKey: PrKey) {

    /**
     * Encrpyts the supplied plaintext with the public key
     */
    abstract fun encrypt(plaintext: ArrayList<Byte>): ArrayList<Byte>

    /**
     * Decrypts the given ciphertext.
     */
    abstract fun decrypt(ciphertext: ArrayList<Byte>): ArrayList<Byte>

    /**
     * Return a short description of this cryptosystem.
     */
    abstract fun cryptosystemInfo(): String

    abstract override fun toString(): String
}