package io.vulscan.xss.report

import io.vulscan.kit.contracts.Evidence
import io.vulscan.kit.contracts.Highlight
import io.vulscan.kit.contracts.HttpRequestEvidence
import io.vulscan.kit.contracts.HttpResponseEvidence
import io.vulscan.kit.contracts.Observation
import io.vulscan.xss.detect.CharacterSurvival
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.Level

/** Собирает доказательство: запрос, заголовки ответа и фрагмент тела вокруг отражения (±200 символов, не больше 2 КБ). */
object EvidenceBuilder {
    const val WINDOW = 200
    const val MAX_EXCERPT = 2048
    private val RESPONSE_HEADERS = listOf("content-type", "content-security-policy")

    fun build(result: DetectionResult, observations: List<Observation>): Evidence {
        val exchange = requireNotNull(result.evidence) { "Finding without evidence" }
        val request = exchange.request
        val requestEvidence = HttpRequestEvidence(
            method = request.method,
            url = request.url,
            headers = buildMap {
                putAll(request.headers)
                request.contentType?.let { put("Content-Type", it) }
            },
            bodyExcerpt = request.body?.let { String(it, Charsets.UTF_8).take(MAX_EXCERPT) },
        )

        val needle = if (result.level == Level.STRUCTURE && result.probe != null) result.probe.build(exchange.canary) else CharacterSurvival.payload(exchange.canary)
        val body = exchange.body
        val anchor = body.indexOf(needle).let { if (it >= 0) it to needle.length else body.indexOf(exchange.canary) to exchange.canary.length }
        val response = exchange.response
        val headers = response.headers.filterKeys { it.lowercase() in RESPONSE_HEADERS }
        val responseEvidence = if (anchor.first < 0) {
            HttpResponseEvidence(response.status, headers)
        } else {
            var start = (anchor.first - WINDOW).coerceAtLeast(0)
            var end = (anchor.first + anchor.second + WINDOW).coerceAtMost(body.length)
            if (end - start > MAX_EXCERPT) end = start + MAX_EXCERPT
            if (start > 0 && Character.isLowSurrogate(body[start])) start++
            if (end < body.length && end > start && Character.isHighSurrogate(body[end - 1])) end--
            val excerpt = body.substring(start, end)
            val marked = if (anchor.second == needle.length && body.startsWith(needle, anchor.first)) needle else exchange.canary
            HttpResponseEvidence(response.status, headers, excerpt, highlights(excerpt, marked))
        }
        return Evidence(requestEvidence, responseEvidence, observations)
    }

    private fun highlights(excerpt: String, needle: String): List<Highlight> {
        val found = mutableListOf<Highlight>()
        var from = 0
        while (found.size < MAX_HIGHLIGHTS) {
            val index = excerpt.indexOf(needle, from)
            if (index < 0) break
            found += Highlight(index, index + needle.length)
            from = index + needle.length
        }
        return found
    }

    private const val MAX_HIGHLIGHTS = 10
}
