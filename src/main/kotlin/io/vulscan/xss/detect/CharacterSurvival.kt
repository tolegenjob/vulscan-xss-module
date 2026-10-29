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
     * Делит вхождения канарейки на кластеры — по одному на подстановку пробы. Если вхождений кратно размеру пробы
     * ([CHARS] + 1), берутся группы подряд; иначе (значение усечено или часть пробы вырезана) — запасной вариант по расстоянию
     * между соседними вхождениями. Затем определяется контекст начала кластера и выжившие символы внутри него.
     */
    fun analyze(body: String, canary: String): List<ClusterSurvival> {
        val offsets = ReflectionLocator.find(body, canary).map { it.offset }
        if (offsets.isEmpty()) return emptyList()
        val perProbe = CHARS.size + 1
        val clusters: List<List<Int>> = if (offsets.size % perProbe == 0) {
            offsets.chunked(perProbe)
        } else {
            val grouped = mutableListOf<MutableList<Int>>()
            for (offset in offsets) {
                val last = grouped.lastOrNull()
                if (last != null && offset - last.last() <= canary.length + GAP) last += offset else grouped += mutableListOf(offset)
            }
            grouped
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

    /** Самый длинный разделитель между соседними канарейками внутри одной пробы (`&#x60;`). */
    private const val GAP = 6
}
