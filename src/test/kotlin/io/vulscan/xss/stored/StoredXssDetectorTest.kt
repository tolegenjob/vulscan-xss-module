package io.vulscan.xss.stored

import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import io.vulscan.kit.contracts.XssDetails
import io.vulscan.xss.TestJobs
import io.vulscan.xss.TestRun
import io.vulscan.xss.canary.CanaryRegistry
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.FakeApp.esc
import io.vulscan.xss.detect.InconclusiveReason
import io.vulscan.xss.detect.Level
import io.vulscan.xss.detect.ProbeSender
import io.vulscan.xss.plan.ProbeTarget
import io.vulscan.xss.report.XssFindingFactory
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class StoredXssDetectorTest {
    private fun detect(book: Guestbook, budget: WriteBudget = WriteBudget()): DetectionResult {
        val source = Guestbook.source()
        val page = Guestbook.page()
        val run = TestRun(TestJobs.job(source, page, options = Guestbook.options(page)), book.app)
        val detector = StoredXssDetector(CanaryRegistry(), budget, ProbeSender(run.http) { })
        return detector.detect(ProbeTarget(source, source.parameters.first()), listOf(page))
    }

    @Test
    fun `unencoded record on the observation page is a likely stored xss`() {
        val book = Guestbook { it }
        val result = detect(book)
        assertThat(result.level).isEqualTo(Level.STRUCTURE)
        assertThat(result.writesPerformed).isEqualTo(2)
        assertThat(result.requestsUsed).isEqualTo(4)
        assertThat(book.entries).hasSize(2)
        assertThat(result.observeEndpoint).isNotNull

        val finding = XssFindingFactory.create(result)
        assertThat(finding.vulnType).isEqualTo(VulnType.XSS_STORED)
        assertThat((finding.details as XssDetails).type).isEqualTo(VulnType.XSS_STORED)
        assertThat(finding.verdict).isEqualTo(Verdict.LIKELY)
        assertThat(finding.severity).isEqualTo(Severity.MEDIUM)
        assertThat(finding.title).startsWith("Хранимый XSS")
        assertThat(finding.evidence.observations.associate { it.key to it.value })
            .containsEntry("writesPerformed", "2")
            .containsKey("observeEndpoint")
            .containsKey("sourceEndpoint")
    }

    @Test
    fun `encoded record gives no finding after a single write`() {
        val book = Guestbook { esc(it) }
        val result = detect(book)
        assertThat(result.level).isEqualTo(Level.NEUTRALISED)
        assertThat(result.isFinding).isFalse()
        assertThat(result.writesPerformed).isEqualTo(1)
        assertThat(book.entries).hasSize(1)
    }

    @Test
    fun `record inside an attribute on the observation page is detected`() {
        val result = detect(Guestbook { "<input value=\"$it\">" })
        assertThat(result.level).isEqualTo(Level.STRUCTURE)
        assertThat(result.probe!!.id).isEqualTo("attr-dq")
    }

    @Test
    fun `value that never shows up on the observation page is not reported`() {
        val result = detect(Guestbook { "-" })
        assertThat(result.level).isEqualTo(Level.NOT_REFLECTED)
        assertThat(result.note).isEqualTo("NOT_OBSERVED")
        assertThat(result.isFinding).isFalse()
    }

    @Test
    fun `rejected write is inconclusive`() {
        val result = detect(Guestbook(writeStatus = 400) { it })
        assertThat(result.inconclusive).isEqualTo(InconclusiveReason.WRITE_REJECTED)
        assertThat(result.writesPerformed).isEqualTo(1)
    }

    @Test
    fun `second write is skipped when the write budget is spent and the finding stays suspected`() {
        val book = Guestbook { it }
        val result = detect(book, WriteBudget(limit = 1))
        assertThat(result.level).isEqualTo(Level.SURVIVES)
        assertThat(result.note).isEqualTo("PROOF_SKIPPED_WRITE_LIMIT")
        assertThat(book.entries).hasSize(1)
        val finding = XssFindingFactory.create(result)
        assertThat(finding.verdict).isEqualTo(Verdict.SUSPECTED)
        assertThat(finding.severity).isEqualTo(Severity.LOW)
    }

    @Test
    fun `an exhausted budget performs no write at all`() {
        val book = Guestbook { it }
        val budget = WriteBudget(limit = 1).also { it.acquire() }
        val result = detect(book, budget)
        assertThat(result.note).isEqualTo("WRITE_LIMIT")
        assertThat(book.posts).isEmpty()
    }

    @Test
    fun `stored fingerprint differs from the reflected one and depends on the observation page`() {
        val source = Guestbook.source()
        val p1 = Guestbook.page()
        val other = TestJobs.endpoint(url = "${TestJobs.BASE}/other", parameters = emptyArray())
        fun fp(page: io.vulscan.kit.contracts.EndpointRef): String {
            val run = TestRun(TestJobs.job(source, page, options = Guestbook.options(page)), Guestbook { it }.app)
            val result = StoredXssDetector(CanaryRegistry(), WriteBudget(), ProbeSender(run.http) { })
                .detect(ProbeTarget(source, source.parameters.first()), listOf(page))
            return XssFindingFactory.fingerprint(result)
        }
        val a = fp(p1)
        assertThat(a).isEqualTo(fp(p1))
        assertThat(a).isNotEqualTo(fp(other))
    }
}
