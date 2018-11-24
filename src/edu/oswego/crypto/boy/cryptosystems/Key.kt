package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer

abstract class Key(val bytes: ByteBuffer) {
    abstract fun bytes(): ByteBuffer
    abstract fun length(): Int
}