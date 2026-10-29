package io.vulscan.xss

import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.worker.DetectionEngine
import io.vulscan.kit.worker.InvalidJobException
import io.vulscan.kit.worker.JobContext
import io.vulscan.xss.config.XssProperties
import io.vulscan.xss.job.XssJobValidator
import io.vulscan.xss.plan.ParameterPlanner

class XssDetectionEngine(private val properties: XssProperties = XssProperties()) : DetectionEngine {
    override val moduleType = ModuleType.XSS

    override fun run(ctx: JobContext) {
        val violations = XssJobValidator.validate(ctx.job)
        if (violations.isNotEmpty()) throw InvalidJobException(violations.joinToString("; "))

        val plan = ParameterPlanner(properties.maxParamsPerEndpoint).plan(ctx.job.endpoints, ctx.job.limits.maxRequests)
        plan.skipped.forEach { ctx.stats.skipped(it.endpointId, it.reason) }
    }
}
