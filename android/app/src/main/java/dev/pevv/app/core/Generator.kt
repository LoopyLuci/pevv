package dev.pevv.app.core

import java.security.SecureRandom
import kotlin.math.ln
import kotlin.math.roundToInt

data class GenOpts(
    val length: Int = 20,
    val lower: Boolean = true,
    val upper: Boolean = true,
    val digits: Boolean = true,
    val symbols: Boolean = true,
    val avoidAmbiguous: Boolean = true,
)

data class PhraseOpts(val words: Int = 6, val separator: String = "-", val capitalize: Boolean = true, val number: Boolean = true)

/** Password and passphrase generator (src/pevv/gen.ts). The word list is the EFF short list (CC BY 3.0 US). */
object Generator {
    private val rng = SecureRandom()
    private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
    private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    private const val DIGITS = "0123456789"
    private const val SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?/~"
    private val AMBIGUOUS = Regex("[Il1O0o|`'\"]")

    /** Unbiased integer in [0, n) by rejection sampling. */
    fun randInt(n: Int): Int {
        require(n > 0) { "bad range" }
        val lim = (4294967296L / n) * n
        while (true) {
            val v = rng.nextInt().toLong() and 0xffffffffL
            if (v < lim) return (v % n).toInt()
        }
    }

    private fun pools(o: GenOpts): List<String> {
        val raw = listOf(o.lower to LOWER, o.upper to UPPER, o.digits to DIGITS, o.symbols to SYMBOLS).filter { it.first }.map { it.second }
        val list = raw.map { if (o.avoidAmbiguous) it.replace(AMBIGUOUS, "") else it }.toMutableList()
        if (list.isEmpty()) list.add(LOWER)
        return list
    }

    fun generatePassword(o: GenOpts): String {
        val pools = pools(o)
        val len = maxOf(maxOf(8, pools.size), minOf(128, o.length))
        val all = pools.joinToString("")
        val out = ArrayList<Char>()
        for (p in pools) out.add(p[randInt(p.length)])
        while (out.size < len) out.add(all[randInt(all.length)])
        for (i in out.size - 1 downTo 1) {
            val j = randInt(i + 1)
            val t = out[i]
            out[i] = out[j]
            out[j] = t
        }
        return out.joinToString("")
    }

    fun generatePassphrase(o: PhraseOpts, words: List<String>): String {
        val n = o.words.coerceIn(4, 12)
        val list = MutableList(n) {
            val w = words[randInt(words.size)]
            if (o.capitalize) w.replaceFirstChar { c -> c.uppercase() } else w
        }
        if (o.number) {
            val i = randInt(list.size)
            list[i] = list[i] + randInt(10)
        }
        return list.joinToString(o.separator.take(3))
    }

    fun entropyBits(o: GenOpts): Int {
        val size = pools(o).sumOf { it.length }.let { if (it == 0) 26 else it }
        return (o.length * ln(size.toDouble()) / ln(2.0)).roundToInt()
    }

    fun phraseEntropyBits(o: PhraseOpts, wordCount: Int): Int =
        (o.words * ln(wordCount.toDouble()) / ln(2.0) + (if (o.number) ln(10.0 * o.words) / ln(2.0) else 0.0)).roundToInt()

    /** A rough offline guess in bits for a typed password: character-class pool size times length. */
    fun estimateBits(pw: String): Int {
        if (pw.isEmpty()) return 0
        var pool = 0
        if (pw.any { it.isLowerCase() }) pool += 26
        if (pw.any { it.isUpperCase() }) pool += 26
        if (pw.any { it.isDigit() }) pool += 10
        if (pw.any { !it.isLetterOrDigit() }) pool += 33
        if (pool == 0) pool = 26
        val distinct = pw.toSet().size
        val effective = minOf(pw.length, distinct * 2)
        return (effective * ln(pool.toDouble()) / ln(2.0)).roundToInt()
    }
}
