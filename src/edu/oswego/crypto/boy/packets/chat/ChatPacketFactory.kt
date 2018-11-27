package edu.oswego.crypto.boy.packets.chat

import edu.oswego.crypto.boy.UI
import java.nio.ByteBuffer

object ChatPacketFactory {

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun joinPacket(bytes: ByteArray): JoinPacket {
        assert(bytes[0] == ChatPacket.Ops.OP_JOIN)
        val length = bytes[1].toInt()
        val sbytes = ByteArray(length)
        for (i in 0..length) {
            sbytes[i] = bytes[2 + i]
        }
        return JoinPacket(String(sbytes))
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun joinAckPacket(bytes: ByteArray): JoinAckPacket {
        assert(bytes[0] == ChatPacket.Ops.OP_JOIN_ACK)
        val length = bytes[1].toInt()
        val sbytes = ByteArray(length)
        for (i in 0..length) {
            sbytes[i] = bytes[2 + i]
        }
        return JoinAckPacket(String(sbytes))
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    private fun rejectPacket(bytes: ByteArray): RejectPacket {
        assert(bytes[0] == ChatPacket.Ops.OP_REJECT)
        val reason = bytes[1]
        return RejectPacket(reason)
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun msgPacket(bytes: ByteArray): MsgPacket{
        assert(bytes[0] == ChatPacket.Ops.OP_MSG)
        val bb = ByteBuffer.wrap(bytes)
        val usernameLength = bb[1].toInt()
        val ubytes = ByteArray(usernameLength)
        bb.get(ubytes, 2, usernameLength)
        val length = bb.getShort(2 + usernameLength).toInt()
        val sbytes = ByteArray(length)
        bb.get(sbytes, 4 + usernameLength, length)
        return MsgPacket(String(ubytes), String(sbytes))
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun leavingPacket(bytes: ByteArray): LeavingPacket {
        assert(bytes.get(0) == ChatPacket.Ops.OP_LEAVING)
        val length = bytes[1].toInt()
        val sbytes = ByteArray(length)
        for (i in 0..length) {
            sbytes[i] = sbytes[2 + i]
        }
        return LeavingPacket(String(sbytes))
    }

    @Throws(java.nio.BufferOverflowException::class, java.lang.IndexOutOfBoundsException::class)
    fun byePacket(bytes: ByteArray): ByePacket {
        assert(bytes.get(0) == ChatPacket.Ops.OP_BYE)
        return ByePacket
    }

    fun fromBytes(bytes: ByteArray): ChatPacket? {
        try {
            when (bytes[0]) {
                ChatPacket.Ops.OP_JOIN      -> return joinPacket(bytes)
                ChatPacket.Ops.OP_JOIN_ACK  -> return joinPacket(bytes)
                ChatPacket.Ops.OP_REJECT    -> return rejectPacket(bytes)
                ChatPacket.Ops.OP_MSG       -> return msgPacket(bytes)
                ChatPacket.Ops.OP_LEAVING   -> return leavingPacket(bytes)
                ChatPacket.Ops.OP_BYE       -> return byePacket(bytes)
            }
        } catch (e: Exception) {
            UI.log("ChatPacketFactory", "Encountered the following exception: \n" + e.toString())
        }
        return null
    }
}