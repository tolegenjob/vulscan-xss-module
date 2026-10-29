package io.vulscan.xss.plan

import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterRef
import io.vulscan.kit.contracts.SkippedEndpoint

data class PlanResult(val targets: List<ProbeTarget>, val skipped: List<SkippedEndpoint>)

/** Какие параметры модуль умеет подставлять в запрос. */
object ParameterSupport {
    /** null, если параметр поддерживается; иначе причина пропуска. */
    fun unsupportedReason(endpoint: EndpointRef, parameter: ParameterRef): String? = when (parameter.location) {
        ParamLocation.HEADER, ParamLocation.COOKIE -> "UNSUPPORTED_LOCATION"
        ParamLocation.BODY_FORM, ParamLocation.BODY_JSON ->
            if (endpoint.method == HttpMethod.GET || endpoint.method == HttpMethod.HEAD) "UNSUPPORTED_LOCATION" else null
        ParamLocation.PATH -> if (endpoint.url.contains("{${parameter.name}}")) null else "PATH_PLACEHOLDER_MISSING"
        ParamLocation.QUERY -> null
    }

    fun priority(location: ParamLocation): Int = when (location) {
        ParamLocation.QUERY -> 0
        ParamLocation.BODY_FORM -> 1
        ParamLocation.BODY_JSON -> 2
        ParamLocation.PATH -> 3
        else -> 9
    }
}

/**
 * Детерминированный план проб: на параметр отводится [REQUESTS_PER_PARAMETER] запросов, сумма не превышает бюджет.
 * При нехватке бюджета выбираются параметры с более высоким приоритетом (QUERY > BODY_FORM > BODY_JSON > PATH).
 */
class ParameterPlanner(private val maxParamsPerEndpoint: Int = 10) {

    private data class Candidate(val endpointIndex: Int, val rank: Int, val target: ProbeTarget)

    fun plan(endpoints: List<EndpointRef>, maxRequests: Int): PlanResult {
        val skipped = mutableListOf<SkippedEndpoint>()
        val candidates = mutableListOf<Candidate>()

        endpoints.forEachIndexed { endpointIndex, endpoint ->
            val testable = endpoint.parameters.filter { ParameterSupport.unsupportedReason(endpoint, it) == null }
            if (testable.isEmpty()) {
                val reason = endpoint.parameters.firstNotNullOfOrNull { ParameterSupport.unsupportedReason(endpoint, it) } ?: "NO_PARAMETERS"
                skipped += SkippedEndpoint(endpoint.endpointId, reason)
                return@forEachIndexed
            }
            testable
                .sortedBy { ParameterSupport.priority(it.location) }
                .take(maxParamsPerEndpoint)
                .forEachIndexed { rank, parameter -> candidates += Candidate(endpointIndex, rank, ProbeTarget(endpoint, parameter)) }
        }

        val accepted = mutableSetOf<Candidate>()
        var used = 0
        val byPriority = candidates.sortedWith(
            compareBy({ ParameterSupport.priority(it.target.parameter.location) }, { it.endpointIndex }, { it.rank }),
        )
        for (candidate in byPriority) {
            if (used + REQUESTS_PER_PARAMETER > maxRequests) continue
            accepted += candidate
            used += REQUESTS_PER_PARAMETER
        }

        candidates.map { it.target.endpoint }.distinctBy { it.endpointId }.forEach { endpoint ->
            if (accepted.none { it.target.endpoint.endpointId == endpoint.endpointId }) {
                skipped += SkippedEndpoint(endpoint.endpointId, "BUDGET")
            }
        }

        val targets = accepted.sortedWith(compareBy({ it.endpointIndex }, { it.rank })).map { it.target }
        return PlanResult(targets, skipped)
    }

    companion object {
        /** reflection ×2, character survival ×1, structure proof ×≤2. */
        const val REQUESTS_PER_PARAMETER = 5
    }
}
