package io.vulscan.xss.detect

import io.vulscan.xss.analysis.HtmlContextClassifier
import io.vulscan.xss.analysis.ReflectionLocator
import io.vulscan.xss.analysis.ReflectionPoint

/** Какие символы выжили в одном «кластере» отражений (одна подстановка пробы) и в каком контексте он начинается. */
data class ClusterSurvival(val point: ReflectionPoint, val surviving: Set<Char>)

object CharacterSurvival {
    val CHARS = listOf('<', '>', '"', '\'', '`', '/', ' ', ';', '-')

    /** `c` + для каждого символа `ch` + `c`: символ выжил, если в ответе есть `c ch c`. */
    fun payload(canary: String): String = buildString {
        append(canary)
        CHARS.forEach { append(it).append(canary) }
    }

    /**
     * Разбивает вхождения канарейки на кластеры (расстояние между соседними вхождениями невелико даже с HTML-кодированием),
     * определяет контекст начала кластера и выжившие символы внутри него.
     */
    fun analyze(body: String, canary: String): List<ClusterSurvival> {
        val offsets = ReflectionLocator.find(body, canary).map { it.offset }
        if (offsets.isEmpty()) return emptyList()
        val clusters = mutableListOf<MutableList<Int>>()
        for (offset in offsets) {
            val last = clusters.lastOrNull()
            if (last != null && offset - last.last() <= canary.length + GAP) last += offset else clusters += mutableListOf(offset)
        }
        return clusters.map { cluster ->
            val start = cluster.first()
            val end = minOf(body.length, cluster.last() + canary.length)
            val window = body.substring(start, end)
            ClusterSurvival(
                point = HtmlContextClassifier.classify(body, start),
                surviving = CHARS.filter { window.contains(canary + it + canary) }.toSet(),
            )
        }
    }

    private const val GAP = 12
}
