package edu.oswego.crypto.boy

fun main(args: Array<String>) {
    var name = ""
    while (true) {
        name = UI.prompt("What is your name?")
        if (name == "") {
            UI.putMessage("client", "Please enter a non-empty name", UI.MessageTy.Info)
        } else {
            break
        }
    }

}
