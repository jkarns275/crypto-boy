package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer


interface Cryptosystem {

    /**
     * Encrpyts the supplied plaintext with the public key
     */
    fun encrypt(plaintext: ArrayList<Byte>): ArrayList<Byte>

    /**
     * Decrypts the given ciphertext.
     */
    fun decrypt(ciphertext: ArrayList<Byte>): ArrayList<Byte>

    /**
     * Return a short description of this cryptosystem.
     */
    fun cryptosystemInfo(): String

    fun publicKeyBytes(): ByteBuffer
}