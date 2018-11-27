package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer

abstract class Key(val bytes: ByteArray) {
    abstract fun length(): Int
}