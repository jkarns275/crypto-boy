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
import java.nio.ByteBuffer
import java.util.*
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock
import kotlin.concurrent.thread

val ROUTER_IP = InetAddress.getByName("0.0.0.0")
val ROUTER_PORT = 42069

fun main(args: Array<String>) {
    var name = ""
    while (true) {
        name = UI.prompt("What is your name?")
        if ("" == name) {
            UI.putMessage("client", "Please enter a non-empty name", UI.MessageTy.Err)
        } else {
            break
        }
    }

    var serverIpStr = "localhost"
    var serverIp: InetAddress = InetAddress.getByName(serverIpStr)
    /* comment this line out to allow custom ip
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
    // */

    UI.putMessage("client", "Connecting to server @" + serverIp.toString() + ":42069...", UI.MessageTy.Info)
    val rsaKeygen = RSAKey.keygengen(65, Key.keygen, 4, Key.keygen)
    val puk = RSAKey(Key(pukByteArray), Key(pubE))
    val prvKey = Key(prvByteArray)
    try {
        val clientCrypto = RSA<RSAKey<Key, Key>, Key>(puk)
        val cryptoPacketFactory = CryptoPacketFactory(clientCrypto, rsaKeygen)
        val socket = Socket(serverIp, 42069)
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
                val nextLine = readLine()
                if (nextLine == null) {
                    sendEncrypted(outputStream, ByePacket, serverCrypto)
                    UI.log("client", "Leaving server.")
                    socket.close()
                    break
                }
                sendEncrypted(outputStream, MsgPacket(name, nextLine), serverCrypto)
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
                    UI.putMessage(packet.sender, packet.msg, UI.MessageTy.Msg)
                } else if (packet is LeavingPacket) {
                    UI.putMessage("server", "@${packet.username} has left", UI.MessageTy.Info)
                } else if (packet is JoinPacket) {
                    UI.putMessage("server", "@${packet.username} has joined", UI.MessageTy.Info)
                } else {
                    UI.log("client", "Unexpected packet $packet")
                }
            }
        }
        t1.join()
        t2.stop()
    } catch (e: Exception) {
        e.printStackTrace()
    }
}
