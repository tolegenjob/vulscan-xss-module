package io.vulscan.xss

import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.worker.CancelledException
import io.vulscan.kit.worker.JobContext
import io.vulscan.xss.TestJobs.endpoint
import io.vulscan.xss.detect.FakeApp
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.concurrent.atomic.AtomicInteger

class XssDetectionEngineFlowTest {
    private fun engine() = XssDetectionEngine(sleeper = { })

    @Test
    fun `vulnerable endpoint produces exactly one finding`() {
        val job = TestJobs.job(endpoint())
        val run = TestRun(job, FakeApp.reflecting { "<p>$it</p>" })
        engine().run(run.ctx)
        assertThat(run.findings).hasSize(1)
        assertThat(run.findings.single().verdict).isEqualTo(Verdict.LIKELY)
        assertThat(run.findings.single().severity).isEqualTo(Severity.MEDIUM)
        assertThat(run.stats.testedCount()).isEqualTo(1)
    }

    @Test
    fun `safe endpoint is tested without findings`() {
        val run = TestRun(TestJobs.job(endpoint()), FakeApp.reflecting { "<p>${FakeApp.esc(it)}</p>" })
        engine().run(run.ctx)
        assertThat(run.findings).isEmpty()
        assertThat(run.stats.testedCount()).isEqualTo(1)
    }

    @Test
    fun `duplicate endpoints yield one finding per fingerprint`() {
        val url = "${TestJobs.BASE}/xss/search"
        val run = TestRun(TestJobs.job(endpoint(url = url), endpoint(url = url)), FakeApp.reflecting { "<p>$it</p>" })
        engine().run(run.ctx)
        assertThat(run.findings).hasSize(1)
        assertThat(run.stats.testedCount()).isEqualTo(2)
    }

    @Test
    fun `different endpoints are reported separately`() {
        val run = TestRun(
            TestJobs.job(endpoint(url = "${TestJobs.BASE}/xss/a"), endpoint(url = "${TestJobs.BASE}/xss/b")),
            FakeApp.reflecting { "<p>$it</p>" },
        )
        engine().run(run.ctx)
        assertThat(run.findings.map { it.fingerprint }).doesNotHaveDuplicates().hasSize(2)
    }

    @Test
    fun `request budget smaller than one parameter skips the endpoint with BUDGET`() {
        val job = TestJobs.job(endpoint(), maxRequests = 4)
        val run = TestRun(job, FakeApp.reflecting { "<p>$it</p>" })
        engine().run(run.ctx)
        assertThat(run.requests).isEmpty()
        assertThat(run.stats.snapshot(0, 0).endpointsSkipped.map { it.reason }).containsExactly("BUDGET")
    }

    @Test
    fun `unstable reflection is counted as inconclusive`() {
        val calls = AtomicInteger()
        val run = TestRun(TestJobs.job(endpoint()), FakeApp.reflecting { if (calls.getAndIncrement() == 0) "<p>$it</p>" else "<p>-</p>" })
        engine().run(run.ctx)
        assertThat(run.findings).isEmpty()
        assertThat(run.stats.snapshot(0, 0).inconclusive).isEqualTo(1)
    }

    @Test
    fun `cancelled job stops before the first request`() {
        val job = TestJobs.job(endpoint())
        val run = TestRun(job, FakeApp.reflecting { "<p>$it</p>" })
        val ctx = JobContext(job, run.http, run.stats, { run.findings += it }, { true }, { emptyList() })
        assertThatThrownBy { engine().run(ctx) }.isInstanceOf(CancelledException::class.java)
        assertThat(run.requests).isEmpty()
    }

    @Test
    fun `a job never exceeds its request budget`() {
        val job = TestJobs.job(endpoint(url = "${TestJobs.BASE}/a"), endpoint(url = "${TestJobs.BASE}/b"), maxRequests = 10)
        val run = TestRun(job, FakeApp.reflecting { "<p>$it</p>" })
        engine().run(run.ctx)
        assertThat(run.requests.size).isLessThanOrEqualTo(10)
    }
}
