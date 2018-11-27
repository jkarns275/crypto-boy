package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer

open class Key(val bytes: ByteArray) {
    companion object {
        val keygen = { bytes: ByteArray -> Key(bytes) }
    }
    fun length(): Int = bytes.size
}