package io.vulscan.xss

import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.worker.CancelledException
import io.vulscan.kit.worker.DetectionEngine
import io.vulscan.kit.worker.InvalidJobException
import io.vulscan.kit.worker.JobContext
import io.vulscan.xss.canary.CanaryRegistry
import io.vulscan.xss.config.XssProperties
import io.vulscan.xss.detect.ProbeLibrary
import io.vulscan.xss.detect.ReflectedXssDetector
import io.vulscan.xss.detect.Sleeper
import io.vulscan.xss.job.XssJobValidator
import io.vulscan.xss.plan.ParameterPlanner
import io.vulscan.xss.report.XssFindingFactory
import java.util.UUID

class XssDetectionEngine(
    private val properties: XssProperties = XssProperties(),
    private val sleeper: Sleeper = Sleeper { Thread.sleep(it) },
) : DetectionEngine {
    override val moduleType = ModuleType.XSS

    init {
        ProbeLibrary.validate()
    }

    override fun run(ctx: JobContext) {
        val violations = XssJobValidator.validate(ctx.job)
        if (violations.isNotEmpty()) throw InvalidJobException(violations.joinToString("; "))

        val plan = ParameterPlanner(properties.maxParamsPerEndpoint).plan(ctx.job.endpoints, ctx.job.limits.maxRequests)
        plan.skipped.forEach { ctx.stats.skipped(it.endpointId, it.reason) }

        val options = requireNotNull(ctx.job.moduleOptions.xss)
        if (!options.reflected) return

        val detector = ReflectedXssDetector(ctx.http, CanaryRegistry(), properties.repeatReflectionCheck, sleeper)
        val reported = HashSet<String>()
        val tested = HashSet<UUID>()
        for (target in plan.targets) {
            if (ctx.isCancelled()) throw CancelledException()
            val result = detector.detect(target)
            if (result.inconclusive != null) ctx.stats.inconclusive()
            if (result.isFinding) {
                val finding = XssFindingFactory.create(result)
                if (reported.add(finding.fingerprint)) ctx.report(finding)
            }
            if (tested.add(target.endpoint.endpointId)) ctx.stats.endpointTested()
        }
    }
}
