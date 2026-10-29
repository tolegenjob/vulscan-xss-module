package io.vulscan.xss.detect

import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.xss.analysis.ReflectionPoint
import io.vulscan.xss.plan.ProbeTarget

/** L0 — не отражается, L1 — отражается, но обезврежено, L2 — символы выживают, L3 — доказана структура. */
enum class Level { NOT_REFLECTED, NEUTRALISED, SURVIVES, STRUCTURE }

enum class InconclusiveReason { UNSTABLE, RATE_LIMITED, TARGET_ERROR, UNKNOWN_CONTEXT }

class Exchange(val canary: String, val request: ProbeRequest, val response: ProbeResponse, val body: String)

class DetectionResult(
    val target: ProbeTarget,
    val level: Level,
    val inconclusive: InconclusiveReason? = null,
    val point: ReflectionPoint? = null,
    val surviving: Set<Char> = emptySet(),
    val probe: Probe? = null,
    val evidence: Exchange? = null,
    val mitigations: List<String> = emptyList(),
    val reflectionCount: Int = 0,
    val requestsUsed: Int = 0,
    val note: String? = null,
) {
    val isFinding: Boolean get() = inconclusive == null && (level == Level.SURVIVES || level == Level.STRUCTURE)
}
