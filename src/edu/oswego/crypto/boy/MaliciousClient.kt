package edu.oswego.crypto.boy

import edu.oswego.crypto.boy.NetUtils.prvByteArray
import edu.oswego.crypto.boy.NetUtils.pubE
import edu.oswego.crypto.boy.NetUtils.pukByteArray
import java.lang.Exception
import java.net.InetAddress
import java.net.Socket
import edu.oswego.crypto.boy.NetUtils.readChunk
import edu.oswego.crypto.boy.NetUtils.recvPlainText
import edu.oswego.crypto.boy.NetUtils.sendEncrypted
import edu.oswego.crypto.boy.NetUtils.writeChunk
import edu.oswego.crypto.boy.cryptosystems.Key
import edu.oswego.crypto.boy.cryptosystems.RSA
import edu.oswego.crypto.boy.cryptosystems.RSAKey
import edu.oswego.crypto.boy.packets.chat.*
import edu.oswego.crypto.boy.packets.crypto.CipherTextPacket
import edu.oswego.crypto.boy.packets.crypto.CryptoPacketFactory
import edu.oswego.crypto.boy.packets.crypto.HelloPacket
import java.io.BufferedInputStream
import java.io.File
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.ConcurrentLinkedQueue
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread

const val delay_ms: Int = 70

fun maliciousClient1(serverIp: InetAddress, messageFwd: ConcurrentLinkedQueue<ChatPacket>) {
    var name = "doom"

    val rsaKeygen = RSAKey.keygengen(65, Key.keygen, 4, Key.keygen)
    val puk = RSAKey(Key(pukByteArray), Key(pubE))
    val prvKey = Key(prvByteArray)
    try {
        val clientCrypto = RSA<RSAKey<Key, Key>, Key>(puk)
        val cryptoPacketFactory = CryptoPacketFactory(clientCrypto, rsaKeygen)
        UI.putMessage("evil", "Connecting to server @" + serverIp.toString() + ":$SERVER_PORT...", UI.MessageTy.Info)
        val socket = Socket(serverIp, SERVER_PORT)
        UI.putMessage("evil", "Connected to server @" + serverIp.toString() + ":$SERVER_PORT", UI.MessageTy.Info)
        val outputStream = socket.getOutputStream()
        val inputStream = socket.getInputStream()

        val helloPacket = HelloPacket(puk)
        writeChunk(outputStream, helloPacket.toBytes())

        var packet = cryptoPacketFactory.fromBytes(readChunk(inputStream))
        if (packet !is HelloPacket<*>) throw Exception("Expected HelloPacket from server, instead got $packet")

        val serverPublicKey = packet.publicKey
        val serverCrypto = RSA<RSAKey<Key, Key>, Key>(serverPublicKey as RSAKey<Key, Key>)

        val joinPacket = JoinPacket(name)
        sendEncrypted(outputStream, joinPacket, serverCrypto)

        val response = recvPlainText(inputStream, cryptoPacketFactory, clientCrypto, prvKey)
        var chatPacket = ChatPacketFactory.fromBytes(response)

        if (chatPacket !is JoinAckPacket) {
            if (chatPacket is RejectPacket) throw Exception("Duplicate username")
            else throw Exception("Expected JoinAckPacket or RejectPacket, instead got $chatPacket")
        }

        UI.putMessage("client", "Server name: ${chatPacket.servername}", UI.MessageTy.Info)

        val shouldRun = AtomicBoolean(true)

        val t1 = thread {
            print("??????")
            UI.putMessage("evil", "Beginning villainous broadcast.", UI.MessageTy.Info)
            val sw = File("sw1.txt")
            val bufferedReader = Scanner(sw.inputStream())
            val lines = Array(14) { _ -> "" }
            while (true) {
                if (!bufferedReader.hasNext()) {
                    break
                }
                for (i in 0 until 14)
                    lines[i] = bufferedReader.nextLine()
                val delay = lines[0].trim().toLong()
                val sb = StringBuilder(68 * 13 + 32)
                sb.append(UI.clear)
                sb.append(UI.gotoOrigin)
                for (i in 1 until 14) {
                    sb.append(lines[i])
                    sb.append('\n')
                }
                sendEncrypted(outputStream, MsgPacket(name, sb.toString()), serverCrypto)
                Thread.sleep(delay * delay_ms)
            }
            shouldRun.set(false)
        }
        val t2 = thread {
            while (shouldRun.get()) {
                if (inputStream.available() < 4) {
                    Thread.sleep(5)
                    continue
                }
                val chunk = recvPlainText(inputStream, cryptoPacketFactory, clientCrypto, prvKey)
                val packet = ChatPacketFactory.fromBytes(chunk)
                if (packet is MsgPacket) {
                    if (packet.sender == name)
                        UI.putMessage(packet.sender, packet.msg, UI.MessageTy.Msg)
                    else
                        messageFwd.add(packet)
                } else {
                    messageFwd.add(packet)
                }
            }
        }
        t1.join()
        t2.stop()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
fun maliciousClient2(serverIp: InetAddress, messageFwd: ConcurrentLinkedQueue<ChatPacket>, msgStream: ConcurrentLinkedQueue<ChatPacket>, name: String) {
    val rsaKeygen = RSAKey.keygengen(65, Key.keygen, 4, Key.keygen)
    val puk = RSAKey(Key(pukByteArray), Key(pubE))
    val prvKey = Key(prvByteArray)
    try {
        val clientCrypto = RSA<RSAKey<Key, Key>, Key>(puk)
        val cryptoPacketFactory = CryptoPacketFactory(clientCrypto, rsaKeygen)
        UI.putMessage("evil", "Connecting to server @" + serverIp.toString() + ":$SERVER_PORT...", UI.MessageTy.Info)
        val socket = Socket(serverIp, SERVER_PORT)
        UI.putMessage("evil", "Connected to server @" + serverIp.toString() + ":$SERVER_PORT", UI.MessageTy.Info)
        val outputStream = socket.getOutputStream()
        val inputStream = socket.getInputStream()

        val helloPacket = HelloPacket(puk)
        writeChunk(outputStream, helloPacket.toBytes())

        var packet = cryptoPacketFactory.fromBytes(readChunk(inputStream))
        if (packet !is HelloPacket<*>) throw Exception("Expected HelloPacket from server, instead got $packet")

        val serverPublicKey = packet.publicKey
        val serverCrypto = RSA<RSAKey<Key, Key>, Key>(serverPublicKey as RSAKey<Key, Key>)

        val joinPacket = JoinPacket(name)
        sendEncrypted(outputStream, joinPacket, serverCrypto)

        val response = recvPlainText(inputStream, cryptoPacketFactory, clientCrypto, prvKey)
        var chatPacket = ChatPacketFactory.fromBytes(response)

        if (chatPacket !is JoinAckPacket) {
            if (chatPacket is RejectPacket) throw Exception("Duplicate username")
            else throw Exception("Expected JoinAckPacket or RejectPacket, instead got $chatPacket")
        }

        UI.putMessage("client", "Server name: ${chatPacket.servername}", UI.MessageTy.Info)

        val shouldRun = AtomicBoolean(true)

        val t1 = thread {
            while (true) {
                var msg = msgStream.poll()
                if (msg == null) { Thread.sleep(5); continue }
                if (msg is ByePacket) break
                if (msg is MsgPacket) {
                    val new_msg = msg.msg.replace("e", "")
                    msg = MsgPacket(msg.sender, new_msg)
                }
                sendEncrypted(outputStream, msg, serverCrypto)
                Thread.sleep(5)
            }
            shouldRun.set(false)
        }
        val t2 = thread {
            while (shouldRun.get()) {
                if (inputStream.available() < 4) {
                    Thread.sleep(5)
                    continue
                }
                val chunk = recvPlainText(inputStream, cryptoPacketFactory, clientCrypto, prvKey)
                val packet = ChatPacketFactory.fromBytes(chunk)
                if (packet is MsgPacket) {
                    messageFwd.add(packet)
                } else {
                    messageFwd.add(packet)
                }
            }
        }
        t1.join()
        t2.stop()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
