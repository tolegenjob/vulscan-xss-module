package io.vulscan.xss

import io.vulscan.kit.contracts.ContractExamples
import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterRef
import io.vulscan.kit.contracts.ScanJobPayload
import io.vulscan.kit.contracts.XssOptions
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.kit.worker.BudgetedHttp
import io.vulscan.kit.worker.JobContext
import io.vulscan.kit.worker.MutableJobStats
import io.vulscan.kit.worker.RateLimiter
import io.vulscan.kit.contracts.FindingPayload
import java.time.Instant
import java.util.UUID
import java.util.concurrent.CopyOnWriteArrayList

object TestJobs {
    const val BASE = "http://lab-app:8080"

    fun baseJob(): ScanJobPayload =
        Json.payloadAs(Json.readEnvelope(ContractExamples.valid("scan-job-xss.json")), ScanJobPayload::class.java)
            .copy(deadlineAt = Instant.now().plusSeconds(3600))

    fun endpoint(
        url: String = "$BASE/xss/search",
        method: HttpMethod = HttpMethod.GET,
        parameters: Array<ParameterRef> = arrayOf(param("q")),
        idempotent: Boolean = true,
    ) = EndpointRef(UUID.randomUUID(), method, url, idempotent, parameters.toList())

    fun param(name: String, location: ParamLocation = ParamLocation.QUERY, sample: String? = "test") = ParameterRef(name, location, sample)

    fun job(vararg endpoints: EndpointRef, options: XssOptions = XssOptions(), maxRequests: Int = 600): ScanJobPayload {
        val base = baseJob()
        return base.copy(
            endpoints = endpoints.toList(),
            moduleOptions = base.moduleOptions.copy(xss = options),
            limits = base.limits.copy(maxRequests = maxRequests, requestsPerSecond = 1000, maxConcurrency = 4),
        )
    }

    fun response(
        body: String,
        status: Int = 200,
        contentType: String? = "text/html; charset=utf-8",
        headers: Map<String, String> = emptyMap(),
    ) = ProbeResponse(
        status = status,
        headers = buildMap {
            putAll(headers.mapKeys { it.key.lowercase() })
            if (contentType != null) put("content-type", contentType)
        },
        body = body.toByteArray(Charsets.UTF_8),
        truncated = false,
        elapsedMs = 1,
        finalUrl = BASE,
        redirectChain = emptyList(),
    )
}

/** Контекст задания для тестов: запросы уходят в [app], найденные уязвимости собираются в [findings]. */
class TestRun(job: ScanJobPayload, app: (ProbeRequest) -> ProbeResponse) {
    val requests = CopyOnWriteArrayList<ProbeRequest>()
    val findings = CopyOnWriteArrayList<FindingPayload>()
    val stats = MutableJobStats()
    val http = BudgetedHttp(
        delegate = { request ->
            requests += request
            app(request)
        },
        rateLimiter = RateLimiter(1000),
        maxRequests = job.limits.maxRequests,
        maxConcurrency = job.limits.maxConcurrency,
        deadline = job.deadlineAt,
        isCancelled = { false },
    )
    val ctx = JobContext(job, http, stats, { findings += it }, { false }, { emptyList() })
}
