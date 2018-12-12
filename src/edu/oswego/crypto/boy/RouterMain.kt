package edu.oswego.crypto.boy

import edu.oswego.crypto.boy.NetUtils.prvByteArray
import edu.oswego.crypto.boy.NetUtils.pubE
import edu.oswego.crypto.boy.NetUtils.pukByteArray
import edu.oswego.crypto.boy.NetUtils.readChunk
import edu.oswego.crypto.boy.NetUtils.recvPlainText
import edu.oswego.crypto.boy.NetUtils.sendEncrypted
import edu.oswego.crypto.boy.NetUtils.writeChunk
import edu.oswego.crypto.boy.cryptosystems.AsymmetricCryptosystem
import edu.oswego.crypto.boy.cryptosystems.Key
import edu.oswego.crypto.boy.cryptosystems.RSA
import edu.oswego.crypto.boy.cryptosystems.RSAKey
import edu.oswego.crypto.boy.packets.chat.*
import edu.oswego.crypto.boy.packets.crypto.CryptoPacketFactory
import edu.oswego.crypto.boy.packets.crypto.HelloPacket
import java.io.BufferedInputStream
import java.io.InputStream
import java.net.InetAddress
import java.net.ServerSocket
import java.net.Socket
import java.nio.ByteBuffer
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ConcurrentLinkedQueue
import kotlin.concurrent.thread

const val ROUTER_PORT: Int = 42096

fun main(args: Array<String>) {
    var serverIpStr = "localhost"
    var serverIp: InetAddress = InetAddress.getByName(serverIpStr)
    // /* comment this line out to allow custom ip
    // Uncomment this if you want to
    while (true) {
        serverIpStr = UI.prompt("What is the server ip?")
        if ("" == serverIpStr) {
            UI.putMessage("client", "Please empty a non-empty ip", UI.MessageTy.Err)
        } else {
            try {
                serverIp = InetAddress.getByName(serverIpStr)
                break
            } catch (e: Exception) {
                UI.putMessage("client", "Please empty a valid ip you fool", UI.MessageTy.Err)
            }
            continue
        }
    }

    val serverSocket = ServerSocket(ROUTER_PORT)

    UI.putMessage("router", "Starting router @${serverSocket.inetAddress}", UI.MessageTy.Info)

    while (true) {
        val socket = serverSocket.accept()
        val inputStream = BufferedInputStream(socket.getInputStream())
        inputStream.mark(2)
        val no: Byte = -1
        val v = inputStream.readNBytes(1)[0]
        if (v == no) {
            UI.putMessage("evil", "Found victim @${socket.inetAddress}", UI.MessageTy.Info)
            thread { mitm1(socket, serverIp) }
        } else if (v == (no - 1).toByte()) {
            UI.putMessage("evil", "Found victim @${socket.inetAddress}", UI.MessageTy.Info)
            thread { mitm2(socket, serverIp) }
        } else {
            inputStream.reset()
            thread {
                UI.putMessage("router", "Serving client @${socket.inetAddress}", UI.MessageTy.Info)
                routerServe(socket, serverIp, inputStream)
            }
        }
    }
}

fun routerServe(clientSocket: Socket, serverIp: InetAddress, clientIn: InputStream) {
    val serverSocket = Socket(serverIp, SERVER_PORT)
    val serverIn = serverSocket.getInputStream()
    val serverOut = serverSocket.getOutputStream()
    val clientOut = clientSocket.getOutputStream()
    val buff = ByteArray(1024 * 128)
    try {
        while (true) {
            var avail = serverIn.available()
            if (avail > 0) {
                val read = serverIn.read(buff)
                clientOut.write(buff, 0, read)
                for (i in 0 until buff.size) buff[i] = 0
            }
            if (clientIn.available() > 0) {
                val read = clientIn.read(buff)
                serverOut.write(buff, 0, read)
                for (i in 0 until buff.size) buff[i] = 0
            }
            // We don't want to kill the processor
            Thread.sleep(5)
        }
    } catch (e: Exception) {
        try { clientSocket.close() } catch (e: Exception) {}
        try { serverSocket.close() } catch (e: Exception) {}
    }
    UI.putMessage("router", "Done serving client @${clientSocket.inetAddress}", UI.MessageTy.Info)
}

fun mitm1(victimSocket: Socket, serverIp: InetAddress) {
    val messagesFromServer = ConcurrentLinkedQueue<ChatPacket>()
    thread { maliciousClient1(serverIp, messagesFromServer) }

    thread {
        val serverName = "anime"
        val puk = RSAKey(Key(pukByteArray), Key(pubE)) as RSAKey<Key, Key>
        val prk = Key(prvByteArray)
        val serverCrypto = RSA<RSAKey<Key, Key>, Key>(puk)

        try {
            val cryptoPacketFactory = CryptoPacketFactory(serverCrypto, RSAKey.keygengen(65, Key.keygen, 4, Key.keygen))
            val inputStream = victimSocket.getInputStream()
            val outputStream = victimSocket.getOutputStream()
            var chunk: ByteArray = readChunk(inputStream)

            // Key exchange
            var packet = cryptoPacketFactory.fromBytes(chunk)
            if (packet == null || packet !is HelloPacket<*>) throw Exception("Expected HelloPacket, instead got $packet")
            val helloPacket = packet as HelloPacket<RSAKey<Key, Key>>
            val clientPublicKey = helloPacket.publicKey
            val serverHello = HelloPacket(puk)
            writeChunk(outputStream, serverHello.toBytes())
            val clientCrypto = RSA<RSAKey<Key, Key>, Key>(clientPublicKey)

            // Client sends Join request
            var plaintext: ByteArray = recvPlainText(inputStream, cryptoPacketFactory, serverCrypto, prk)
            var chatPacket = ChatPacketFactory.fromBytes(plaintext) ?: throw Exception("Failed to parse chat packet...")
            if (chatPacket !is JoinPacket) throw Exception("Expected JoinPacket, instead got $chatPacket")
            val q = messagesFromServer

            // Server sends join ACK with the server name
            val joinAckPacket = JoinAckPacket(serverName)
            sendEncrypted(outputStream, joinAckPacket, clientCrypto)

            // Until the client disconnects:
            // - Send messages from user to all other users (including self) by adding to queue
            // - Send messages from every other user to user by emptying the queue
            while (true) {
                if (inputStream.available() > 4) {
                    val plaintext = recvPlainText(inputStream, cryptoPacketFactory, serverCrypto, prk)
                    val packet = ChatPacketFactory.fromBytes(plaintext)
                    if (packet is ByePacket) break
                    else { /* Ignore everything else */ }
                }
                while (q.isNotEmpty()) {
                    sendEncrypted(outputStream, q.poll(), clientCrypto)
                }
                Thread.sleep(5)
            }

        } catch (e: Exception) {
            UI.log("serve", "Caught exception in server: $e")
            e.printStackTrace()
        }
    }
}

fun mitm2(victimSocket: Socket, serverIp: InetAddress) {
    val messagesFromServer = ConcurrentLinkedQueue<ChatPacket>()
    val messagesFromClient = ConcurrentLinkedQueue<ChatPacket>()

    thread {
        val serverName = "anime"
        val puk = RSAKey(Key(pukByteArray), Key(pubE)) as RSAKey<Key, Key>
        val prk = Key(prvByteArray)
        val serverCrypto = RSA<RSAKey<Key, Key>, Key>(puk)

        try {
            val cryptoPacketFactory = CryptoPacketFactory(serverCrypto, RSAKey.keygengen(65, Key.keygen, 4, Key.keygen))
            val inputStream = victimSocket.getInputStream()
            val outputStream = victimSocket.getOutputStream()
            var chunk: ByteArray = readChunk(inputStream)

            // Key exchange
            var packet = cryptoPacketFactory.fromBytes(chunk)
            if (packet == null || packet !is HelloPacket<*>) throw Exception("Expected HelloPacket, instead got $packet")
            val helloPacket = packet as HelloPacket<RSAKey<Key, Key>>
            val clientPublicKey = helloPacket.publicKey
            val serverHello = HelloPacket(puk)
            writeChunk(outputStream, serverHello.toBytes())
            val clientCrypto = RSA<RSAKey<Key, Key>, Key>(clientPublicKey)

            // Client sends Join request
            var plaintext: ByteArray = recvPlainText(inputStream, cryptoPacketFactory, serverCrypto, prk)
            var chatPacket = ChatPacketFactory.fromBytes(plaintext) ?: throw Exception("Failed to parse chat packet...")
            if (chatPacket !is JoinPacket) throw Exception("Expected JoinPacket, instead got $chatPacket")
            val q = messagesFromServer

            // Server sends join ACK with the server name
            val joinAckPacket = JoinAckPacket(serverName)
            sendEncrypted(outputStream, joinAckPacket, clientCrypto)

            thread { maliciousClient2(serverIp, messagesFromServer, messagesFromClient, chatPacket.username) }

            // Until the client disconnects:
            // - Send messages from user to all other users (including self) by adding to queue
            // - Send messages from every other user to user by emptying the queue
            while (true) {
                if (inputStream.available() > 4) {
                    val plaintext = recvPlainText(inputStream, cryptoPacketFactory, serverCrypto, prk)
                    val packet = ChatPacketFactory.fromBytes(plaintext)
                    messagesFromClient.offer(packet)
                    if (packet is ByePacket) break
                }
                while (q.isNotEmpty()) {
                    sendEncrypted(outputStream, q.poll(), clientCrypto)
                }
                Thread.sleep(5)
            }

        } catch (e: Exception) {
            UI.log("serve", "Caught exception in server: $e")
            e.printStackTrace()
        }
    }
}
