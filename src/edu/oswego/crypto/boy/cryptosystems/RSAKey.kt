package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer

private fun combine(b1: ByteArray, b2: ByteArray): ByteArray {
   val bb = ByteBuffer.allocate(b1.size + b2.size)
    bb.put(b1)
    bb.put(b2)
    return bb.array()
}

class RSAKey<N: Key, E: Key>(val n: N, val e: E) : Key(combine(n.bytes, e.bytes)) {
    companion object {
        fun <N: Key, E: Key> keygengen(nlen: Int, nkeygen: (ByteArray) -> N, elen: Int, ekeygen: (ByteArray) -> E):
                (ByteArray) -> RSAKey<N, E> {
            return { bytes ->
                assert(nlen + elen <= bytes.size)
                val nbytes = ByteArray(nlen)
                var bb = ByteBuffer.wrap(nbytes)
                bb.put(bytes, 0, nlen)

                val ebytes = ByteArray(elen)
                bb = ByteBuffer.wrap(ebytes)
                bb.put(bytes, nlen, elen)

                RSAKey(nkeygen(nbytes), ekeygen(ebytes ))
            }
        }
    }
}
