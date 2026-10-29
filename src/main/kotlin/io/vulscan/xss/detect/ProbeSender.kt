package io.vulscan.xss.detect

import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.kit.worker.BudgetedHttp
import java.util.concurrent.atomic.AtomicInteger

fun interface Sleeper {
    fun sleep(millis: Long)
}

class RateLimitedException : RuntimeException("Target keeps throttling requests")

/**
 * Отправка проб с учётом ограничения частоты со стороны цели и подряд идущих сбоев.
 * 429 (и 503 с Retry-After) → пауза не дольше 30 с и повтор; третий подряд ответ → [RateLimitedException].
 * Пятый подряд сбой сети → исключение пробрасывается, и задание завершается как TARGET_UNREACHABLE.
 */
class ProbeSender(private val http: BudgetedHttp, private val sleeper: Sleeper) {
    private val consecutiveFailures = AtomicInteger()

    /** [onAttempt] вызывается перед каждой попыткой — по нему считается расход бюджета. */
    fun send(request: ProbeRequest, onAttempt: () -> Unit = {}): ProbeResponse {
        var throttled = 0
        while (true) {
            onAttempt()
            val response = http.execute(request)
            consecutiveFailures.set(0)
            if (!isThrottle(response)) return response
            if (++throttled >= MAX_THROTTLED) throw RateLimitedException()
            sleeper.sleep(retryAfterMillis(response))
        }
    }

    /** Фиксирует сбой; на пятом подряд выбрасывает исходное исключение. */
    fun recordFailure(e: RuntimeException) {
        if (consecutiveFailures.incrementAndGet() >= MAX_CONSECUTIVE_FAILURES) throw e
    }

    private fun isThrottle(response: ProbeResponse) =
        response.status == 429 || (response.status == 503 && HttpText.header(response, "retry-after") != null)

    private fun retryAfterMillis(response: ProbeResponse): Long {
        val seconds = HttpText.header(response, "retry-after")?.trim()?.toLongOrNull() ?: 1L
        return seconds.coerceIn(0, MAX_RETRY_AFTER_SEC) * 1000
    }

    companion object {
        const val MAX_THROTTLED = 3
        const val MAX_CONSECUTIVE_FAILURES = 5
        const val MAX_RETRY_AFTER_SEC = 30L
    }
}
