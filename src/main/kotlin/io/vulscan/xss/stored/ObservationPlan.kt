package io.vulscan.xss.stored

import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.SkippedEndpoint
import io.vulscan.kit.contracts.XssOptions
import io.vulscan.xss.plan.ParameterSupport
import io.vulscan.xss.plan.ProbeTarget

/**
 * [sources] — параметры, через которые значение записывается (POST-форма, не идемпотентный endpoint),
 * [observe] — страницы, на которых оно ищется (GET).
 */
class ObservationPlan(val sources: List<ProbeTarget>, val observe: List<EndpointRef>, val skipped: List<SkippedEndpoint>)

object ObservationPlanner {
    fun plan(endpoints: List<EndpointRef>, options: XssOptions, maxParamsPerEndpoint: Int): ObservationPlan {
        val observeIds = options.observeEndpointIds.toSet()
        val skipped = mutableListOf<SkippedEndpoint>()

        val observe = endpoints.filter { it.endpointId in observeIds }.filter { page ->
            (page.method == HttpMethod.GET).also { if (!it) skipped += SkippedEndpoint(page.endpointId, "UNSUPPORTED_OBSERVATION") }
        }

        val sources = endpoints.filter { it.endpointId !in observeIds && !it.idempotent && it.method == HttpMethod.POST }
            .flatMap { endpoint ->
                endpoint.parameters
                    .filter { it.location == ParamLocation.BODY_FORM && ParameterSupport.unsupportedReason(endpoint, it) == null }
                    .take(maxParamsPerEndpoint)
                    .map { ProbeTarget(endpoint, it, estimatedRequests = 1 + observe.size) }
            }
        return ObservationPlan(sources, observe, skipped)
    }
}
