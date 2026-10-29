package io.vulscan.xss

import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.XssOptions
import io.vulscan.kit.worker.CancelledException
import io.vulscan.kit.worker.DetectionEngine
import io.vulscan.kit.worker.InvalidJobException
import io.vulscan.kit.worker.JobContext
import io.vulscan.xss.canary.CanaryRegistry
import io.vulscan.xss.config.XssProperties
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.ProbeLibrary
import io.vulscan.xss.detect.ProbeSender
import io.vulscan.xss.detect.ReflectedXssDetector
import io.vulscan.xss.detect.Sleeper
import io.vulscan.xss.job.XssJobValidator
import io.vulscan.xss.plan.ParameterPlanner
import io.vulscan.xss.report.XssFindingFactory
import io.vulscan.xss.stored.ObservationPlanner
import io.vulscan.xss.stored.StoredXssDetector
import io.vulscan.xss.stored.WriteBudget
import java.util.UUID

class XssDetectionEngine(
    private val properties: XssProperties = XssProperties(),
    private val sleeper: Sleeper = Sleeper { Thread.sleep(it) },
) : DetectionEngine {
    override val moduleType = ModuleType.XSS

    init {
        ProbeLibrary.validate()
    }

    /** Состояние одного прогона: что уже сообщено и какие endpoint уже проверялись. */
    private class Run(val ctx: JobContext) {
        val reported = HashSet<String>()
        val tested = HashSet<UUID>()

        fun handle(result: DetectionResult) {
            if (result.inconclusive != null) ctx.stats.inconclusive()
            if (result.isFinding) {
                val finding = XssFindingFactory.create(result)
                if (reported.add(finding.fingerprint)) ctx.report(finding)
            }
            if (tested.add(result.target.endpoint.endpointId)) ctx.stats.endpointTested()
        }
    }

    override fun run(ctx: JobContext) {
        val violations = XssJobValidator.validate(ctx.job)
        if (violations.isNotEmpty()) throw InvalidJobException(violations.joinToString("; "))

        val options = requireNotNull(ctx.job.moduleOptions.xss)
        val canaries = CanaryRegistry()
        val sender = ProbeSender(ctx.http, sleeper)
        val run = Run(ctx)

        if (options.reflected) runReflected(run, options, canaries, sender)
        if (options.stored) runStored(run, options, canaries, sender)
    }

    private fun runReflected(run: Run, options: XssOptions, canaries: CanaryRegistry, sender: ProbeSender) {
        val ctx = run.ctx
        // Часть бюджета резервируется под запись и наблюдение хранимого XSS
        val reserve = if (options.stored && options.allowStore) WriteBudget.MAX_WRITES * (1 + options.observeEndpointIds.size) else 0
        val plan = ParameterPlanner(properties.maxParamsPerEndpoint).plan(ctx.job.endpoints, (ctx.job.limits.maxRequests - reserve).coerceAtLeast(0))
        plan.skipped.forEach { ctx.stats.skipped(it.endpointId, it.reason) }

        val detector = ReflectedXssDetector(canaries, properties.repeatReflectionCheck, sender)
        for (target in plan.targets) {
            if (ctx.isCancelled()) throw CancelledException()
            run.handle(detector.detect(target))
        }
    }

    private fun runStored(run: Run, options: XssOptions, canaries: CanaryRegistry, sender: ProbeSender) {
        val ctx = run.ctx
        val plan = ObservationPlanner.plan(ctx.job.endpoints, options, properties.maxParamsPerEndpoint)
        plan.skipped.forEach { ctx.stats.skipped(it.endpointId, it.reason) }
        if (plan.observe.isEmpty() || plan.sources.isEmpty()) return

        if (!options.allowStore) {
            ctx.stats.inconclusive()
            plan.sources.map { it.endpoint.endpointId }.distinct().forEach { ctx.stats.skipped(it, "STORE_NOT_ALLOWED") }
            return
        }

        val writes = WriteBudget()
        val detector = StoredXssDetector(canaries, writes, sender)
        val limited = HashSet<UUID>()
        for (source in plan.sources) {
            if (ctx.isCancelled()) throw CancelledException()
            val id = source.endpoint.endpointId
            if (writes.remaining == 0) {
                if (id !in run.tested && limited.add(id)) ctx.stats.skipped(id, "WRITE_LIMIT")
                continue
            }
            run.handle(detector.detect(source, plan.observe))
        }
    }
}
