package edu.oswego.crypto.boy

import java.lang.Exception
import java.net.InetAddress

val ROUTER_IP = InetAddress.getByName("0.0.0.0")
val ROUTER_PORT = 42069

fun main(args: Array<String>) {
    var name = ""
    while (true) {
        name = UI.prompt("What is your name?")
        if (name == "") {
            UI.putMessage("client", "Please enter a non-empty name", UI.MessageTy.Err)
        } else {
            break
        }
    }

    var serverIpStr = ""
    var serverIp: InetAddress
    while (true) {
        serverIpStr = UI.prompt("What is the server ip?")
        if (serverIpStr == "") {
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

    UI.putMessage("client", "Connecting to server @" + serverIp.toString() + ":42069", UI.MessageTy.Info)
}
