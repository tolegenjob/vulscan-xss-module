package io.vulscan.xss.canary

import java.security.SecureRandom
import java.util.Random

/** Канарейка: `vsx` + 10 символов `[a-z0-9]` (≈ 51 бит) — безопасна в HTML, JS и URL, в исходных данных не встречается. */
class CanaryFactory(private val random: Random = SecureRandom()) {
    fun next(): String = buildString(PREFIX.length + LENGTH) {
        append(PREFIX)
        repeat(LENGTH) { append(ALPHABET[random.nextInt(ALPHABET.length)]) }
    }

    companion object {
        const val PREFIX = "vsx"
        const val LENGTH = 10
        private const val ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
        val FORMAT = Regex("^vsx[a-z0-9]{10}$")
    }
}
