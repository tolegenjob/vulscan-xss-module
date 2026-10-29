package io.vulscan.xss.plan

import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.ParameterRef

/** Один проверяемый параметр одного endpoint. */
data class ProbeTarget(
    val endpoint: EndpointRef,
    val parameter: ParameterRef,
    val estimatedRequests: Int = ParameterPlanner.REQUESTS_PER_PARAMETER,
)
