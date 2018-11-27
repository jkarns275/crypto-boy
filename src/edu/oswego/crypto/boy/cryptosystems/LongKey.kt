package edu.oswego.crypto.boy.cryptosystems

import java.nio.ByteBuffer

class LongKey(val key: Long): Key(ByteBuffer.allocate(8).putLong(key).array()) {
    companion object {
        val keygen: (ByteArray) -> LongKey =
                { bytes ->
                    assert(bytes.size >= 8)
                    val bb = ByteBuffer.wrap(bytes)
                    LongKey(bb.getLong(0))
                }
    }
}