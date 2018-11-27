package edu.oswego.crypto.boy

import edu.oswego.crypto.boy.cryptosystems.*
import edu.oswego.crypto.boy.packets.chat.*
import edu.oswego.crypto.boy.packets.crypto.CipherTextPacket
import edu.oswego.crypto.boy.packets.crypto.CryptoPacketFactory
import edu.oswego.crypto.boy.packets.crypto.GoodbyePacket
import edu.oswego.crypto.boy.packets.crypto.HelloPacket
import java.io.BufferedOutputStream
import java.io.InputStream
import java.io.OutputStream
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.regex.Pattern
import kotlin.concurrent.thread

val SERVER_PORT: Int = 42069
val MAX_PACKET_SIZE: Int = (1 shl 16) + 1
var serverName = ""

fun readChunk(inputStream: InputStream): ByteArray {
    var bytes = inputStream.readNBytes(4)
    if (bytes.size < 4) throw Exception("Unexpected end of stream")
    var bb = ByteBuffer.wrap(bytes)
    val len = bb.getInt(0)
    if (len > MAX_PACKET_SIZE) throw Exception("Received packet larger than MAX_PACKET_SIZE = $MAX_PACKET_SIZE bytes")
    val res = inputStream.readNBytes(len)
    if (res.size < len) throw Exception("Unexpected end of stream")
    return res
}

fun writeChunk(outputStream: OutputStream, chunk: ByteArray) {
    outputStream.write(chunk.size)
    outputStream.write(chunk)
}

fun <PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>>
        recvPlainText(inputStream: InputStream, cryptoPacketFactory: CryptoPacketFactory<PuK, PrK, Crypto>,
                       crypto: Crypto, prk: PrK): ByteArray? {
    val chunk = readChunk(inputStream)
    val packet = cryptoPacketFactory.fromBytes(chunk)
    if (packet == null) return null // Invalid packet, terminate connection
    if (packet !is CipherTextPacket<*, *, *>) return null // End connection after encountering non app data
    val cipherTextPacket = packet as CipherTextPacket<PuK, PrK, Crypto>
    return cipherTextPacket.decrypt(prk)
}

fun <PuK: Key, PrK: Key, Crypto: AsymmetricCryptosystem<PuK, PrK>>
        serve(messageQueues: ConcurrentHashMap<String, ConcurrentLinkedQueue<ChatPacket>>, sock: Socket,
              keygen: (ByteArray) -> PuK, cryptoFactory: (PuK) -> Crypto, puk: PuK, prk: PrK) {
    val serverCrypto = cryptoFactory(puk)
    var username: String? = null
    try {
        val cryptoPacketFactory = CryptoPacketFactory(serverCrypto, keygen)
        val inputStream = sock.getInputStream()
        val outputStream = sock.getOutputStream()

        var chunk: ByteArray = readChunk(inputStream)

        // Key exchange
        var packet = cryptoPacketFactory.fromBytes(chunk)
        if (packet == null || packet !is HelloPacket<*>) throw Exception("Expected HelloPacket, instead got $packet")
        val helloPacket = packet as HelloPacket<PuK>
        val clientPublicKey = helloPacket.publicKey
        val serverHello = HelloPacket(puk)
        writeChunk(outputStream, serverHello.toBytes())
        val clientCrypto = cryptoFactory(clientPublicKey)

        // Client sends Join request
        var plaintext: ByteArray = recvPlainText(inputStream, cryptoPacketFactory, serverCrypto, prk) ?: return
        var chatPacket = ChatPacketFactory.fromBytes(plaintext) ?: return
        if (chatPacket !is JoinPacket) return
        username = chatPacket.username
        val q = ConcurrentLinkedQueue<ChatPacket>()
        // Username is taken, send rejection
        if (messageQueues.putIfAbsent(chatPacket.username, q) != q) {
            val rejectPacket = RejectPacket(RejectPacket.RejectionReasons.DUPLICATE_USERNAME)
            val ciphertext = CipherTextPacket(rejectPacket.toBytes(), clientCrypto).toBytes()
            writeChunk(outputStream, ciphertext)
            return
        } else {
            // Otherwise forward this to everyone else
            messageQueues.forEach({ k, v -> assert(v.offer(chatPacket)) })
        }

        // Server sends join ACK with the server name
        val joinAckPacket = JoinAckPacket(serverName)
        val ciphertext = CipherTextPacket(joinAckPacket.toBytes(), clientCrypto).toBytes()
        writeChunk(outputStream, ciphertext)

        // Until the client disconnects:
        // - Send messages from user to all other users (including self) by adding to queue
        // - Send messages from every other user to user by emptying the queue
        while (true) {
            if (inputStream.available() > 4) {
                val plaintext = recvPlainText(inputStream, cryptoPacketFactory, serverCrypto, prk) ?: return
                val packet = ChatPacketFactory.fromBytes(plaintext)
                if (packet is ByePacket) break
                else if (packet is MsgPacket) {
                    // Name spoofing!
                    if (!packet.sender.equals(username)) break
                    messageQueues.forEach({ k, v -> assert(v.offer(packet)) })
                } else {
                    // That is all that the user should be sending... disconnect since they're doing something funky.
                    break
                }
            }
            while (q.isNotEmpty()) {
                val packet = q.poll()
                val ciphertext = CipherTextPacket(packet.toBytes(), clientCrypto).toBytes()
                writeChunk(outputStream, ciphertext)
            }
        }

    } catch (e: Exception) {
        UI.log("serve", "Caught exception in server: $e")
    }

    if (username != null) {
        val leavePacket = LeavingPacket(username)
        messageQueues.forEach( { k, v -> assert(v.offer(leavePacket)) } )
    }
}

val pubN: IntArray = intArrayOf(
        0x00, 0xb7, 0x4a, 0x84, 0x9e, 0x3a, 0x8d, 0x02, 0xf8, 0x85, 0x64, 0xdc, 0x22, 0xae, 0xe9, 0x47, 0x69, 0xb3,
        0x46, 0xff, 0xe6, 0x90, 0xc5, 0xfd, 0xe4, 0x87, 0x8d, 0x5d, 0x0e, 0x44, 0x35, 0x10, 0x37, 0x9c, 0xa9, 0x92,
        0xa7, 0x80, 0x6c, 0x9b, 0x0c, 0xef, 0x07, 0x0f, 0xd5, 0x66, 0xb7, 0xc1, 0x77, 0x59, 0x37, 0xfa, 0x7e, 0xd9,
        0x6f, 0x6c, 0x37, 0x70, 0xe2, 0xfa, 0x59, 0x1f, 0xb2, 0xb6, 0x2b)
val pubE: Int = 0x10001

val prvExpr: IntArray = intArrayOf(
        0x7a, 0x4c, 0xa5, 0x9a, 0xb2, 0x74, 0xbe, 0xa3, 0xb6, 0xd6, 0x2a,
        0xb0, 0x95, 0xc7, 0x20, 0x18, 0x5e, 0x40, 0x24, 0xa5, 0xe2, 0xb9,
        0xc9, 0x84, 0x40, 0x12, 0x4a, 0x22, 0x27, 0xce, 0xc4, 0x47, 0x46,
        0x0c, 0xd4, 0x31, 0x44, 0x1d, 0xeb, 0x32, 0x18, 0xd0, 0x2c, 0x93,
        0x02, 0x95, 0x62, 0x88, 0x1c, 0xe8, 0x4a, 0x54, 0x90, 0x3f, 0x33,
        0x48, 0xa3, 0x90, 0x20, 0x43, 0x7f, 0xd5, 0xf2, 0x29)

fun main(args: Array<String>) {
    val pukByteArray = ByteArray(pubN.size, { i -> pubN[i].toByte() })
    val prvByteArray = ByteArray(prvExpr.size, { i -> prvExpr[i].toByte() })
    println("Key size: ${pukByteArray.size}")
    val puk = RSAKey(Key(pukByteArray), Key(ByteBuffer.allocate(4).putInt(pubE).array())) as RSAKey<Key, Key>
    val prk = Key(prvByteArray)

    val rsa = RSA<RSAKey<Key, Key>, Key>(puk)
    val plain = "Can i text u -HH".toByteArray()
    println("Plain = ${Arrays.toString(plain)}")
    val a = rsa.encrypt(plain)
    println("Cipher = ${Arrays.toString(a)}")
    val b = rsa.decrypt(a, prk)
    println("Decrypted = ${Arrays.toString(b)}")
/*
    var name = ""
    while (true) {
        name = UI.prompt("What is your name?")
        if (name == "") {
            UI.putMessage("client", "Please enter a non-empty name", UI.MessageTy.Err)
        } else {
            break
        }
    }
    serverName = ""
    while (true) {
        serverName = UI.prompt("What will the server be named?")
        if (serverName == "") {
            UI.putMessage("server", "Please enter a non-empty name", UI.MessageTy.Err)
        } else {
            break
        }
    }

    val map = ConcurrentHashMap<String, ConcurrentLinkedQueue<ChatPacket>>()
    val serverSocket = ServerSocket(SERVER_PORT)

    val a = RSA.rsaFactory<RSAKey<Key, Key>, Key>() as (RSAKey<out Key, out Key>) -> AsymmetricCryptosystem<RSAKey<out Key, out Key>, LongKey>

    while (true) {
        val socket = serverSocket.accept()
        thread { serve(map, socket, RSAKey.keygengen(65, Key.keygen, 8, Key.keygen),
                RSA.rsaFactory<RSAKey<Key, Key>, Key>() as (RSAKey<out Key, out Key>) -> AsymmetricCryptosystem<RSAKey<out Key, out Key>, LongKey>,
                puk, prk) }
    }*/
}