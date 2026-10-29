package io.vulscan.xss.stored

import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.net.ProbeNetworkException
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.kit.net.ProbeTimeoutException
import io.vulscan.xss.analysis.ReflectionContext
import io.vulscan.xss.analysis.ResponseKind
import io.vulscan.xss.canary.CanaryOrigin
import io.vulscan.xss.canary.CanaryRegistry
import io.vulscan.xss.detect.CharacterSurvival
import io.vulscan.xss.detect.ClusterSurvival
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.Exchange
import io.vulscan.xss.detect.HttpText
import io.vulscan.xss.detect.InconclusiveReason
import io.vulscan.xss.detect.Level
import io.vulscan.xss.detect.Mitigations
import io.vulscan.xss.detect.Probe
import io.vulscan.xss.detect.ProbeLibrary
import io.vulscan.xss.detect.ProbeSender
import io.vulscan.xss.detect.RateLimitedException
import io.vulscan.xss.http.RequestBuilder
import io.vulscan.xss.plan.ProbeTarget

/** Общий для задания лимит записей: каждая запись изменяет данные в проверяемом приложении. */
class WriteBudget(val limit: Int = MAX_WRITES) {
    var used = 0
        private set

    val remaining: Int get() = limit - used

    @Synchronized
    fun acquire(): Boolean {
        if (used >= limit) return false
        used++
        return true
    }

    companion object {
        const val MAX_WRITES = 3
    }
}

/**
 * Хранимый XSS: значение записывается через форму и ищется на страницах наблюдения.
 * Запись №1 содержит пробу выживаемости символов, запись №2 (если символы выжили) — пробу структуры.
 */
class StoredXssDetector(
    private val canaries: CanaryRegistry,
    private val writes: WriteBudget,
    private val sender: ProbeSender,
) {
    private class Written(val canary: String, val request: ProbeRequest, val response: ProbeResponse)

    private class Observed(val page: EndpointRef, val exchange: Exchange, val clusters: List<ClusterSurvival>)

    private class Choice(val observed: Observed, val cluster: ClusterSurvival, val probe: Probe)

    fun detect(source: ProbeTarget, observe: List<EndpointRef>): DetectionResult {
        var used = 0
        var written = 0
        fun result(level: Level, reason: InconclusiveReason? = null, note: String? = null) =
            DetectionResult(source, level, reason, requestsUsed = used, writesPerformed = written, note = note)

        fun write(build: (String) -> String): Written {
            val origin = CanaryOrigin(source.endpoint.endpointId, source.parameter.name, source.parameter.location)
            val canary = canaries.create(origin)
            val request = RequestBuilder.build(source.endpoint, source.parameter, build(canary))
            written++
            return Written(canary, request, sender.send(request) { used++ })
        }

        fun observePages(pages: List<EndpointRef>, canary: String): List<Observed> = pages.mapNotNull { page ->
            val request = RequestBuilder.buildPlain(page)
            val response = sender.send(request) { used++ }
            val body = HttpText.decode(response)
            if (canary !in body || !ResponseKind.isHtml(HttpText.contentType(response))) {
                null
            } else {
                Observed(page, Exchange(canary, request, response, body), CharacterSurvival.analyze(body, canary))
            }
        }

        return try {
            if (!writes.acquire()) return result(Level.NOT_REFLECTED, note = "WRITE_LIMIT")
            val first = write { CharacterSurvival.payload(it) }
            if (first.response.status >= 400) return result(Level.NOT_REFLECTED, InconclusiveReason.WRITE_REJECTED)

            val seen = observePages(observe, first.canary)
            if (seen.isEmpty()) return result(Level.NOT_REFLECTED, note = "NOT_OBSERVED")

            val known = seen.flatMap { o -> o.clusters.map { o to it } }.filter { it.second.point.context != ReflectionContext.UNKNOWN }
            if (known.isEmpty()) return result(Level.NOT_REFLECTED, InconclusiveReason.UNKNOWN_CONTEXT)

            val choices = known.sortedBy { ProbeLibrary.danger(it.second.point.context) }.flatMap { (o, cluster) ->
                ProbeLibrary.candidates(cluster.point).filter { cluster.surviving.containsAll(it.required) }.map { Choice(o, cluster, it) }
            }
            if (choices.isEmpty()) {
                val o = seen.first()
                return DetectionResult(
                    source, Level.NEUTRALISED, requestsUsed = used, writesPerformed = written, note = "CHARS_ENCODED",
                    surviving = known.flatMap { it.second.surviving }.toSet(), evidence = o.exchange, observeEndpoint = o.page,
                )
            }

            val best = choices.first()
            fun suspected(note: String? = null) = DetectionResult(
                source, Level.SURVIVES, point = best.cluster.point, surviving = best.cluster.surviving, probe = best.probe,
                evidence = best.observed.exchange, mitigations = Mitigations.of(best.observed.exchange.response.headers),
                reflectionCount = known.size, requestsUsed = used, note = note, observeEndpoint = best.observed.page, writesPerformed = written,
            )

            if (!writes.acquire()) return suspected("PROOF_SKIPPED_WRITE_LIMIT")
            val proof = write { best.probe.build(it) }
            if (proof.response.status >= 400) return suspected("PROOF_WRITE_REJECTED")
            val again = observePages(listOf(best.observed.page), proof.canary).firstOrNull()
            if (again != null && best.probe.verify(again.exchange.body, proof.canary)) {
                DetectionResult(
                    source, Level.STRUCTURE, point = best.cluster.point, surviving = best.cluster.surviving, probe = best.probe,
                    evidence = again.exchange, mitigations = Mitigations.of(again.exchange.response.headers),
                    reflectionCount = known.size, requestsUsed = used, observeEndpoint = best.observed.page, writesPerformed = written,
                )
            } else {
                suspected()
            }
        } catch (e: RateLimitedException) {
            result(Level.NOT_REFLECTED, InconclusiveReason.RATE_LIMITED)
        } catch (e: ProbeNetworkException) {
            sender.recordFailure(e)
            result(Level.NOT_REFLECTED, InconclusiveReason.TARGET_ERROR)
        } catch (e: ProbeTimeoutException) {
            sender.recordFailure(e)
            result(Level.NOT_REFLECTED, InconclusiveReason.TARGET_ERROR)
        }
    }
}
