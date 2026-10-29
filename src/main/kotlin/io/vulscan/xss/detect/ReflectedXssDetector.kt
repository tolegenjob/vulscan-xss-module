package io.vulscan.xss.detect

import io.vulscan.kit.net.ProbeNetworkException
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.kit.net.ProbeTimeoutException
import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.xss.analysis.HtmlContextClassifier
import io.vulscan.xss.analysis.ReflectionLocator
import io.vulscan.xss.analysis.ReflectionPoint
import io.vulscan.xss.analysis.ResponseKind
import io.vulscan.xss.canary.CanaryOrigin
import io.vulscan.xss.canary.CanaryRegistry
import io.vulscan.xss.http.RequestBuilder
import io.vulscan.xss.plan.ProbeTarget
import java.nio.charset.Charset
import java.util.concurrent.atomic.AtomicInteger

fun interface Sleeper {
    fun sleep(millis: Long)
}

/**
 * Проверка одного параметра на отражённый XSS. Экземпляр живёт в рамках одного задания.
 * Бюджет запросов на параметр: отражение ×2, выживаемость символов ×1, доказательство структуры ≤2.
 */
class ReflectedXssDetector(
    private val http: BudgetedHttp,
    private val canaries: CanaryRegistry,
    private val repeatReflectionCheck: Boolean = true,
    private val sleeper: Sleeper = Sleeper { Thread.sleep(it) },
) {
    private val consecutiveFailures = AtomicInteger()

    private class RateLimited : RuntimeException()

    private inner class Session(val target: ProbeTarget) {
        var used = 0

        fun send(build: (String) -> String): Exchange {
            val origin = CanaryOrigin(target.endpoint.endpointId, target.parameter.name, target.parameter.location)
            val canary = canaries.create(origin)
            val request = RequestBuilder.build(target.endpoint, target.parameter, build(canary))
            var throttled = 0
            while (true) {
                used++
                val response = http.execute(request)
                consecutiveFailures.set(0)
                if (!isThrottle(response)) return Exchange(canary, request, response, decode(response))
                if (++throttled >= MAX_THROTTLED) throw RateLimited()
                sleeper.sleep(retryAfterMillis(response))
            }
        }
    }

    fun detect(target: ProbeTarget): DetectionResult {
        val session = Session(target)
        return try {
            run(session)
        } catch (e: RateLimited) {
            DetectionResult(target, Level.NOT_REFLECTED, InconclusiveReason.RATE_LIMITED, requestsUsed = session.used)
        } catch (e: ProbeNetworkException) {
            failure(session, e)
        } catch (e: ProbeTimeoutException) {
            failure(session, e)
        }
    }

    private fun failure(session: Session, e: RuntimeException): DetectionResult {
        if (consecutiveFailures.incrementAndGet() >= MAX_CONSECUTIVE_FAILURES) throw e
        return DetectionResult(session.target, Level.NOT_REFLECTED, InconclusiveReason.TARGET_ERROR, requestsUsed = session.used)
    }

    private fun run(s: Session): DetectionResult {
        val target = s.target
        fun result(level: Level, reason: InconclusiveReason? = null, note: String? = null, count: Int = 0) =
            DetectionResult(target, level, reason, reflectionCount = count, requestsUsed = s.used, note = note)

        val first = s.send { it }
        val reflections = ReflectionLocator.find(first.body, first.canary)
        if (reflections.isEmpty()) return result(Level.NOT_REFLECTED)
        if (!ResponseKind.isHtml(contentType(first.response))) return result(Level.NEUTRALISED, note = "NOT_HTML", count = reflections.size)

        if (repeatReflectionCheck) {
            val second = s.send { it }
            if (ReflectionLocator.find(second.body, second.canary).isEmpty()) {
                return result(Level.NOT_REFLECTED, InconclusiveReason.UNSTABLE, count = reflections.size)
            }
        }

        val points = reflections.map { HtmlContextClassifier.classify(first.body, it.offset) }
            .filter { it.context != io.vulscan.xss.analysis.ReflectionContext.UNKNOWN }
            .distinctBy { Triple(it.context, it.quote, it.tagName) }
            .sortedBy { ProbeLibrary.danger(it.context) }
        if (points.isEmpty()) return result(Level.NOT_REFLECTED, InconclusiveReason.UNKNOWN_CONTEXT, count = reflections.size)

        val survival = s.send { CharacterSurvival.payload(it) }
        val clusters = CharacterSurvival.analyze(survival.body, survival.canary)

        class Choice(val point: ReflectionPoint, val probe: Probe, val surviving: Set<Char>)

        val choices = points.flatMap { point ->
            val inContext = clusters.filter { it.point.context == point.context }
            ProbeLibrary.candidates(point).mapNotNull { probe ->
                inContext.firstOrNull { it.surviving.containsAll(probe.required) }?.let { Choice(point, probe, it.surviving) }
            }
        }.distinctBy { it.probe.id }

        if (choices.isEmpty()) {
            return DetectionResult(
                target, Level.NEUTRALISED, reflectionCount = reflections.size, requestsUsed = s.used,
                surviving = clusters.flatMap { it.surviving }.toSet(), evidence = survival, note = "CHARS_ENCODED",
            )
        }

        for (choice in choices.take(MAX_PROOF_REQUESTS)) {
            val proof = s.send(choice.probe.build)
            if (choice.probe.verify(proof.body, proof.canary)) {
                return DetectionResult(
                    target, Level.STRUCTURE, point = choice.point, surviving = choice.surviving, probe = choice.probe,
                    evidence = proof, mitigations = Mitigations.of(proof.response.headers),
                    reflectionCount = reflections.size, requestsUsed = s.used, stableReflection = repeatReflectionCheck,
                )
            }
        }
        val best = choices.first()
        return DetectionResult(
            target, Level.SURVIVES, point = best.point, surviving = best.surviving, probe = best.probe,
            evidence = survival, mitigations = Mitigations.of(survival.response.headers),
            reflectionCount = reflections.size, requestsUsed = s.used, stableReflection = repeatReflectionCheck,
        )
    }

    private fun header(response: ProbeResponse, name: String): String? =
        response.headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

    private fun contentType(response: ProbeResponse) = header(response, "content-type")

    private fun decode(response: ProbeResponse): String {
        val charset = contentType(response)?.let { Regex("charset=\"?([A-Za-z0-9_.:-]+)", RegexOption.IGNORE_CASE).find(it)?.groupValues?.get(1) }
            ?.let { runCatching { Charset.forName(it) }.getOrNull() } ?: Charsets.UTF_8
        return String(response.body, charset)
    }

    private fun isThrottle(response: ProbeResponse) =
        response.status == 429 || (response.status == 503 && header(response, "retry-after") != null)

    private fun retryAfterMillis(response: ProbeResponse): Long {
        val seconds = header(response, "retry-after")?.trim()?.toLongOrNull() ?: 1L
        return seconds.coerceIn(0, MAX_RETRY_AFTER_SEC) * 1000
    }

    companion object {
        const val MAX_PROOF_REQUESTS = 2
        const val MAX_THROTTLED = 3
        const val MAX_CONSECUTIVE_FAILURES = 5
        const val MAX_RETRY_AFTER_SEC = 30L
    }
}
