package edu.oswego.crypto.boy.ui

object UI {

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
        Err(Color.Red, "Err")
    }

    fun putMessage(src: String, msg: String, ty: MessageTy) {
        print("[")
        setColor(ty.color)
        print(ty.string)
        setColor(Color.Reset)
        print("] @")
        print(src)
        print(": ")
        println(msg)
    }

    fun test() {
        putMessage("josh", "Hey!", MessageTy.Msg)
    }
}