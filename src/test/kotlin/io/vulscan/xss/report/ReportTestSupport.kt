package io.vulscan.xss.report

import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.xss.TestJobs
import io.vulscan.xss.TestRun
import io.vulscan.xss.canary.CanaryRegistry
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.ReflectedXssDetector
import io.vulscan.xss.plan.ProbeTarget

object ReportTestSupport {
    fun detect(
        url: String = "${TestJobs.BASE}/xss/search",
        app: (ProbeRequest) -> ProbeResponse,
    ): DetectionResult {
        val endpoint = TestJobs.endpoint(url = url)
        val run = TestRun(TestJobs.job(endpoint), app)
        return ReflectedXssDetector(run.http, CanaryRegistry(), true) { }.detect(ProbeTarget(endpoint, endpoint.parameters.first()))
    }
}
