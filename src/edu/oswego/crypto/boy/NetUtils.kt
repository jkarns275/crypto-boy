package edu.oswego.crypto.boy

import edu.oswego.crypto.boy.cryptosystems.AsymmetricCryptosystem
import edu.oswego.crypto.boy.cryptosystems.Key
import edu.oswego.crypto.boy.packets.chat.ChatPacket
import edu.oswego.crypto.boy.packets.crypto.CipherTextPacket
import edu.oswego.crypto.boy.packets.crypto.CryptoPacket
import edu.oswego.crypto.boy.packets.crypto.CryptoPacketFactory
import java.io.InputStream
import java.io.OutputStream
import java.nio.ByteBuffer
import java.util.*

object NetUtils {

    fun readChunk(inputStream: InputStream): ByteArray {
        var bytes = inputStream.readNBytes(4)
        if (bytes.size < 4) throw Exception("Unexpected end of stream")
        var bb = ByteBuffer.wrap(bytes)
        val len = bb.getInt(0)
        if (len > MAX_PACKET_SIZE) throw Exception("Received packet larger than MAX_PACKET_SIZE = $MAX_PACKET_SIZE bytes. $len")
        val res = inputStream.readNBytes(len)
        if (res.size < len) throw Exception("Unexpected end of stream")
        println("Received chunk of size ${res.size}; ${Arrays.toString(res)}")
        return res
    }

    fun writeChunk(outputStream: OutputStream, chunk: ByteArray) {
        println("Sending chunk of size ${chunk.size}; ${Arrays.toString(chunk)}")
        outputStream.write(ByteBuffer.allocate(4).putInt(chunk.size).array())
        outputStream.write(chunk)
    }

    fun <PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>> sendEncrypted(outputStream: OutputStream,
                                                                           packet: ChatPacket, crypto: Crypto) {
        println("Sending chunk $packet (encrypteD) of size ${packet.toBytes().size}; ${Arrays.toString(packet.toBytes())}")
        writeChunk(outputStream, CipherTextPacket(packet.toBytes(), crypto).toBytes())
    }

    fun <PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>>
            recvPlainText(inputStream: InputStream, cryptoPacketFactory: CryptoPacketFactory<PuK, PrK, Crypto>,
                          crypto: Crypto, prk: PrK): ByteArray {
        val chunk = readChunk(inputStream)
        val packet = cryptoPacketFactory.fromBytes(chunk)
        if (packet == null) throw Exception("Unexpected end of stream") // Invalid packet, terminate connection
        if (packet !is CipherTextPacket<*, *, *>) throw Exception("Expected CipherTextPacket, instead got $packet")// End connection after encountering non app data
        val cipherTextPacket = packet as CipherTextPacket<PuK, PrK, Crypto>
        val de = cipherTextPacket.decrypt(prk)
        println("Recieved unencrypted chunk: ${Arrays.toString(de)}")
        return de
    }


    val pubN: IntArray = intArrayOf(
            0x00, 0xb7, 0x4a, 0x84, 0x9e, 0x3a, 0x8d, 0x02, 0xf8, 0x85, 0x64, 0xdc, 0x22, 0xae, 0xe9, 0x47, 0x69, 0xb3,
            0x46, 0xff, 0xe6, 0x90, 0xc5, 0xfd, 0xe4, 0x87, 0x8d, 0x5d, 0x0e, 0x44, 0x35, 0x10, 0x37, 0x9c, 0xa9, 0x92,
            0xa7, 0x80, 0x6c, 0x9b, 0x0c, 0xef, 0x07, 0x0f, 0xd5, 0x66, 0xb7, 0xc1, 0x77, 0x59, 0x37, 0xfa, 0x7e, 0xd9,
            0x6f, 0x6c, 0x37, 0x70, 0xe2, 0xfa, 0x59, 0x1f, 0xb2, 0xb6, 0x2b)
    val pubE: ByteArray = ByteBuffer.allocate(4).putInt(0x10001).array()

    val prvExpr: IntArray = intArrayOf(
            0x7a, 0x4c, 0xa5, 0x9a, 0xb2, 0x74, 0xbe, 0xa3, 0xb6, 0xd6, 0x2a,
            0xb0, 0x95, 0xc7, 0x20, 0x18, 0x5e, 0x40, 0x24, 0xa5, 0xe2, 0xb9,
            0xc9, 0x84, 0x40, 0x12, 0x4a, 0x22, 0x27, 0xce, 0xc4, 0x47, 0x46,
            0x0c, 0xd4, 0x31, 0x44, 0x1d, 0xeb, 0x32, 0x18, 0xd0, 0x2c, 0x93,
            0x02, 0x95, 0x62, 0x88, 0x1c, 0xe8, 0x4a, 0x54, 0x90, 0x3f, 0x33,
            0x48, 0xa3, 0x90, 0x20, 0x43, 0x7f, 0xd5, 0xf2, 0x29)
    val pukByteArray = ByteArray(pubN.size) { i -> pubN[i].toByte() }
    val prvByteArray = ByteArray(prvExpr.size) { i -> prvExpr[i].toByte() }
}