package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer

private fun combine(b1: ByteArray, b2: ByteArray): ByteArray {
   val bb = ByteBuffer.allocate(b1.size + b2.size)
    bb.put(b1)
    bb.put(b2)
    return bb.array()
}

class RSAKey<N: Key, E: Key>(val n: N, val e: E) : Key(combine(n.bytes, e.bytes)) {
    override fun length(): Int { return n.length() + e.length() }
}
