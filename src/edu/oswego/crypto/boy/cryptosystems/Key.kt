package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer

interface Key {
    fun bytes(): ByteBuffer
}