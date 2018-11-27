package edu.oswego.crypto.boy.cryptosystems

import java.math.BigInteger
import java.nio.ByteBuffer

class RSA {
    companion object {


        fun encrypt(plaintext: String, publicKey: String): IntArray {
            var public = publicKey.toString()
            var splits = public.split(",")
            val n = Integer.parseInt(splits[0])
            val e = Integer.parseInt(splits[1])
            var ciphertext = IntArray(plaintext.length)
            var i = 0
            for (byte in plaintext) {
                val num = byte.toInt().toBigInteger()
                var calc: BigInteger = num.pow(e).mod(n.toBigInteger())
                ciphertext[i] = calc.toInt()
                i++
            }

            var buff:ByteBuffer
            return ciphertext
        }
        fun decrypt(ciphertext:IntArray, d:BigInteger, n:BigInteger ): ByteArray{
            var plaintext = ByteArray(ciphertext.size)
            var i = 0
            for(num in ciphertext){
                val bigNum = num.toBigInteger()
                val numDec = bigNum.pow(d.toInt()).mod(n)
                plaintext[i] = numDec.toByte()
                i++

            }
            return plaintext
        }
    }
}