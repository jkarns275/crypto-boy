package edu.oswego.crypto.boy

object UI {

    const val LOG_ENABLED = true

    enum class Color(val value: Int) {
        Red(31),
        Green(32),
        Yellow(33),
        Blue(34),
        Magenta(35),
        Cyan(36),
        Reset(0)
    }

    fun setColor(color: Color) {
        print("\u001b[" + color.value + "m")
    }

    enum class MessageTy(val color: Color, val string: String) {
        Info(Color.Yellow, "Info"),
        Msg(Color.Cyan, "Msg"),
        Err(Color.Red, "Err"),
        Dbg(Color.Magenta, "Debug")
    }

    const val clear: String = "\u001b[H\u001b[J"
    const val gotoOrigin: String = "\u001b[0;0H"

    fun putMessage(src: String, msg: String, ty: MessageTy) {
        print("[")
        setColor(ty.color)
        print(ty.string)
        setColor(Color.Reset)
        print("] @")
        setColor(Color.Magenta)
        print(src)
        setColor(Color.Reset)
        print(": ")
        println(msg)
    }

    fun prompt(prompt: String): String {
        print("[")
        setColor(Color.Yellow)
        print("Prompt")
        setColor(Color.Reset)
        print("] @")
        setColor(Color.Magenta)
        print("client")
        setColor(Color.Reset)
        print(": ")
        print(prompt)
        print(" -> ")
        val a = readLine()
        if (a == null) {
            return prompt(prompt)
        } else {
            return a
        }
    }

    fun log(src: String, msg: String) {
        if (LOG_ENABLED) {
            putMessage(src, msg, MessageTy.Dbg)
        }
    }

    fun test() {
        putMessage("josh", "Hey!", MessageTy.Msg)
    }
}