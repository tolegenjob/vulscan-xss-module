package io.vulscan.xss.report

import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.Level
import io.vulscan.xss.detect.Mitigations

data class Score(val base: Int, val adjustments: List<Pair<String, Int>>, val total: Int) {
    fun describe(): String = adjustments.joinToString(";") { (name, delta) -> "$name:${if (delta > 0) "+" else ""}$delta" }
}

/** Уверенность: база по уровню проверки плюс небольшие поправки; всегда в диапазоне 1..99. */
object XssConfidenceScorer {
    const val BASE_SURVIVES = 30
    const val BASE_STRUCTURE = 70
    const val BASE_BROWSER = 95

    fun score(result: DetectionResult): Score {
        val base = when (result.level) {
            Level.STRUCTURE -> BASE_STRUCTURE
            Level.SURVIVES -> BASE_SURVIVES
            else -> error("Confidence is defined only for findings, got ${result.level}")
        }
        val adjustments = mutableListOf<Pair<String, Int>>()
        if (result.stableReflection) adjustments += "stable_reflection" to 5
        if (Mitigations.CSP in result.mitigations) adjustments += "csp" to -10
        val response = result.evidence?.response
        if (response != null && response.status >= 400) adjustments += "error_status" to -15
        if (response != null && response.truncated) adjustments += "truncated_body" to -10
        val total = (base + adjustments.sumOf { it.second }).coerceIn(1, 99)
        return Score(base, adjustments, total)
    }
}
