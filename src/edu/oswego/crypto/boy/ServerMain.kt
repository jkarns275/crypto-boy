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

fun main(args: Array<String>) {
    val puk = RSAKey(LongKey(0), LongKey(0)) as RSAKey<Key, Key>
    val prk = LongKey(1)

    var name = ""
    while (true) {
        name = UI.prompt("What is your name?")
        if (name.equals("")) {
            UI.putMessage("client", "Please enter a non-empty name", UI.MessageTy.Err)
        } else {
            break
        }
    }
    serverName = ""
    while (true) {
        serverName = UI.prompt("What will the server be named?")
        if (serverName.equals("")) {
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
        thread { serve(map, socket, RSAKey.keygengen(8, LongKey.keygen, 8, LongKey.keygen),
                RSA.rsaFactory<RSAKey<Key, Key>, Key>() as (RSAKey<out Key, out Key>) -> AsymmetricCryptosystem<RSAKey<out Key, out Key>, LongKey>,
                puk, prk) }
    }
}