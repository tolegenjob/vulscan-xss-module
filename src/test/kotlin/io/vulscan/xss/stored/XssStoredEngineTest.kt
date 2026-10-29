package io.vulscan.xss.stored

import io.vulscan.kit.contracts.VulnType
import io.vulscan.kit.worker.InvalidJobException
import io.vulscan.xss.TestJobs
import io.vulscan.xss.TestRun
import io.vulscan.xss.XssDetectionEngine
import io.vulscan.xss.detect.FakeApp.esc
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.UUID

class XssStoredEngineTest {
    private fun engine() = XssDetectionEngine(sleeper = { })

    @Test
    fun `stored xss is found through the engine`() {
        val source = Guestbook.source()
        val page = Guestbook.page()
        val book = Guestbook { it }
        val run = TestRun(TestJobs.job(source, page, options = Guestbook.options(page)), book.app)
        engine().run(run.ctx)
        assertThat(run.findings.map { it.vulnType }).containsExactly(VulnType.XSS_STORED)
        assertThat(run.stats.testedCount()).isEqualTo(1)
    }

    @Test
    fun `without allowStore nothing is written and the check is inconclusive`() {
        val source = Guestbook.source()
        val page = Guestbook.page()
        val book = Guestbook { it }
        val run = TestRun(TestJobs.job(source, page, options = Guestbook.options(page, allowStore = false)), book.app)
        engine().run(run.ctx)
        assertThat(book.posts).isEmpty()
        assertThat(run.findings).isEmpty()
        val stats = run.stats.snapshot(0, 0)
        assertThat(stats.inconclusive).isEqualTo(1)
        assertThat(stats.endpointsSkipped.map { it.reason }).containsExactly("STORE_NOT_ALLOWED")
    }

    @Test
    fun `at most three writes per job and the fourth source is skipped`() {
        val sources = (1..4).map { Guestbook.source("add$it") }
        val page = Guestbook.page()
        val book = Guestbook { esc(it) }
        val run = TestRun(TestJobs.job(*sources.toTypedArray(), page, options = Guestbook.options(page)), book.app)
        engine().run(run.ctx)
        assertThat(book.posts).hasSize(3)
        val skipped = run.stats.snapshot(0, 0).endpointsSkipped
        assertThat(skipped).hasSize(1)
        assertThat(skipped.single().reason).isEqualTo("WRITE_LIMIT")
        assertThat(skipped.single().endpointId).isEqualTo(sources[3].endpointId)
    }

    @Test
    fun `reflected and stored checks share one job within the request budget`() {
        val source = Guestbook.source()
        val page = Guestbook.page()
        val book = Guestbook { it }
        val job = TestJobs.job(source, page, options = Guestbook.options(page, reflected = true), maxRequests = 40)
        val run = TestRun(job, book.app)
        engine().run(run.ctx)
        assertThat(run.requests.size).isLessThanOrEqualTo(40)
        assertThat(run.findings.map { it.vulnType }).contains(VulnType.XSS_STORED)
    }

    @Test
    fun `reserved budget keeps room for the stored check when reflected probing is greedy`() {
        val page = Guestbook.page()
        val greedy = (1..10).map { TestJobs.endpoint(url = "${TestJobs.BASE}/r$it") }
        val source = Guestbook.source()
        val book = Guestbook { it }
        val job = TestJobs.job(*greedy.toTypedArray(), source, page, options = Guestbook.options(page, reflected = true), maxRequests = 40)
        val run = TestRun(job) { request -> if (request.url.contains("/r")) io.vulscan.xss.TestJobs.response("<p>x</p>") else book.app(request) }
        engine().run(run.ctx)
        assertThat(run.requests.size).isLessThanOrEqualTo(40)
        assertThat(run.findings.map { it.vulnType }).contains(VulnType.XSS_STORED)
    }

    @Test
    fun `unknown observation endpoint makes the job invalid`() {
        val source = Guestbook.source()
        val page = Guestbook.page()
        val options = Guestbook.options(page).copy(observeEndpointIds = listOf(UUID.randomUUID()))
        val run = TestRun(TestJobs.job(source, page, options = options), Guestbook { it }.app)
        assertThatThrownBy { engine().run(run.ctx) }.isInstanceOf(InvalidJobException::class.java)
    }
}
