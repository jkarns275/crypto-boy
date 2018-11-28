package edu.oswego.crypto.boy

import edu.oswego.crypto.boy.NetUtils.prvByteArray
import edu.oswego.crypto.boy.NetUtils.prvExpr
import edu.oswego.crypto.boy.NetUtils.pubE
import edu.oswego.crypto.boy.NetUtils.pubN
import edu.oswego.crypto.boy.NetUtils.pukByteArray
import edu.oswego.crypto.boy.NetUtils.readChunk
import edu.oswego.crypto.boy.NetUtils.recvPlainText
import edu.oswego.crypto.boy.NetUtils.sendEncrypted
import edu.oswego.crypto.boy.NetUtils.writeChunk
import edu.oswego.crypto.boy.cryptosystems.*
import edu.oswego.crypto.boy.packets.chat.*
import edu.oswego.crypto.boy.packets.crypto.CipherTextPacket
import edu.oswego.crypto.boy.packets.crypto.CryptoPacketFactory
import edu.oswego.crypto.boy.packets.crypto.HelloPacket
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.concurrent.thread

val SERVER_PORT: Int = 42069
val MAX_PACKET_SIZE: Int = (1 shl 16) + 1
var serverName = ""


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
        if (messageQueues.putIfAbsent(chatPacket.username, q) != null) {
            val rejectPacket = RejectPacket(RejectPacket.RejectionReasons.DUPLICATE_USERNAME)
            sendEncrypted(outputStream, rejectPacket, clientCrypto)
            return
        } else {
            // Otherwise forward this to everyone else
            messageQueues.forEach({ k, v -> assert(v.offer(chatPacket)) })
        }

        // Server sends join ACK with the server name
        val joinAckPacket = JoinAckPacket(serverName)
        sendEncrypted(outputStream, joinAckPacket, clientCrypto)

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
            while (q.isNotEmpty()) sendEncrypted(outputStream, q.poll(), clientCrypto)
        }

    } catch (e: Exception) {
        UI.log("serve", "Caught exception in server: $e")
        e.printStackTrace()
    }

    if (username != null) {
        val leavePacket = LeavingPacket(username)
        messageQueues.forEach( { k, v -> assert(v.offer(leavePacket)) } )
    }
}

fun main(args: Array<String>) {

    val puk = RSAKey(Key(pukByteArray), Key(pubE)) as RSAKey<Key, Key>
    val prk = Key(prvByteArray)
     // /*
    val pukByteArray = ByteArray(pubN.size, { i -> pubN[i].toByte() })
    val prvByteArray = ByteArray(prvExpr.size, { i -> prvExpr[i].toByte() })
    println("Key size: ${pukByteArray.size}")

    val rsa = RSA<RSAKey<Key, Key>, Key>(puk)
    val plain = "Can i text u kjh;ashjjkljkl;j;klj;kj;ljkljmkl m90981     -HH".toByteArray()
    println("Plain = ${Arrays.toString(plain)}")
    val a = rsa.encrypt(plain)
    println("Cipher = ${Arrays.toString(a)}")
    val b = rsa.decrypt(a, prk)
    println("Decrypted = ${Arrays.toString(b)}")
    return
    // */
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

    while (true) {
        val socket = serverSocket.accept()
        thread {
            serve(map, socket, RSAKey.keygengen(65, Key.keygen, 4, Key.keygen),
                RSA.rsaFactory<RSAKey<Key, Key>, Key>() as (RSAKey<out Key, out Key>) -> AsymmetricCryptosystem<RSAKey<out Key, out Key>, Key>,
                puk, prk)
            println("Done")
        }
    }
}