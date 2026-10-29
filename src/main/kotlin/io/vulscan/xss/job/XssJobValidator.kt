package io.vulscan.xss.job

import io.vulscan.kit.contracts.ScanJobPayload
import io.vulscan.xss.plan.ParameterSupport

/** Проверки, специфичные для XSS-модуля (общие проверки задания выполняет рантайм). */
object XssJobValidator {
    fun validate(job: ScanJobPayload): List<String> {
        val xss = job.moduleOptions.xss ?: return listOf("moduleOptions.xss is missing")
        val violations = mutableListOf<String>()
        if (!xss.reflected && !xss.stored) violations += "at least one of xss.reflected / xss.stored must be enabled"
        if (xss.stored && !xss.reflected && xss.observeEndpointIds.isEmpty()) {
            violations += "xss.stored requires xss.observeEndpointIds"
        }
        val testable = job.endpoints.any { endpoint ->
            endpoint.parameters.any { ParameterSupport.unsupportedReason(endpoint, it) == null }
        }
        if (!testable) {
            violations += "no endpoint has a testable parameter (QUERY, BODY_FORM, BODY_JSON or PATH with a {placeholder})"
        }
        return violations
    }
}
