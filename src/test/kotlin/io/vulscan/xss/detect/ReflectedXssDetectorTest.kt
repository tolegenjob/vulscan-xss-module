package io.vulscan.xss.detect

import io.vulscan.kit.net.ProbeNetworkException
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.xss.TestJobs
import io.vulscan.xss.TestRun
import io.vulscan.xss.analysis.ReflectionContext
import io.vulscan.xss.canary.CanaryRegistry
import io.vulscan.xss.detect.FakeApp.esc
import io.vulscan.xss.detect.FakeApp.escLtGt
import io.vulscan.xss.detect.FakeApp.jsEscQuotes
import io.vulscan.xss.plan.ProbeTarget
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import java.util.concurrent.CopyOnWriteArrayList
import java.util.concurrent.atomic.AtomicInteger

class ReflectedXssDetectorTest {
    private val sleeps = CopyOnWriteArrayList<Long>()

    private fun detect(
        app: (ProbeRequest) -> ProbeResponse,
        repeat: Boolean = true,
        runs: Int = 1,
    ): List<DetectionResult> {
        val endpoint = TestJobs.endpoint()
        val job = TestJobs.job(endpoint)
        val run = TestRun(job, app)
        val detector = ReflectedXssDetector(run.http, CanaryRegistry(), repeat) { sleeps += it }
        val target = ProbeTarget(endpoint, endpoint.parameters.first())
        return List(runs) { detector.detect(target) }
    }

    private fun one(app: (ProbeRequest) -> ProbeResponse) = detect(app).single()

    @Test
    fun `value that is not reflected costs a single request`() {
        val r = one(FakeApp.reflecting { "<p>nothing</p>" })
        assertThat(r.level).isEqualTo(Level.NOT_REFLECTED)
        assertThat(r.inconclusive).isNull()
        assertThat(r.requestsUsed).isEqualTo(1)
    }

    @Test
    fun `raw reflection in html text gives structure proof`() {
        val r = one(FakeApp.reflecting { "<html><body><p>Результаты: $it</p></body></html>" })
        assertThat(r.level).isEqualTo(Level.STRUCTURE)
        assertThat(r.point!!.context).isEqualTo(ReflectionContext.HTML_TEXT)
        assertThat(r.probe!!.id).isEqualTo("tag")
        assertThat(r.requestsUsed).isEqualTo(4)
        assertThat(r.isFinding).isTrue()
    }

    @Test
    fun `html escaped reflection is neutralised`() {
        val r = one(FakeApp.reflecting { "<p>${esc(it)}</p>" })
        assertThat(r.level).isEqualTo(Level.NEUTRALISED)
        assertThat(r.requestsUsed).isEqualTo(3)
        assertThat(r.isFinding).isFalse()
    }

    @Test
    fun `attribute breakout in double quotes`() {
        val r = one(FakeApp.reflecting { "<input name=q value=\"$it\">" })
        assertThat(r.level).isEqualTo(Level.STRUCTURE)
        assertThat(r.point!!.context).isEqualTo(ReflectionContext.ATTR_DOUBLE_QUOTED)
        assertThat(r.probe!!.id).isEqualTo("attr-dq")
    }

    @Test
    fun `escaped quote in attribute is neutralised`() {
        val r = one(FakeApp.reflecting { "<input value=\"${esc(it)}\">" })
        assertThat(r.level).isEqualTo(Level.NEUTRALISED)
    }

    @Test
    fun `single quoted and unquoted attributes`() {
        assertThat(one(FakeApp.reflecting { "<input value='$it'>" }).probe!!.id).isEqualTo("attr-sq")
        assertThat(one(FakeApp.reflecting { "<input value=$it>" }).probe!!.id).isEqualTo("attr-unq")
    }

    @Test
    fun `js string breakout`() {
        val r = one(FakeApp.reflecting { "<script>var q=\"$it\";</script>" })
        assertThat(r.level).isEqualTo(Level.STRUCTURE)
        assertThat(r.point!!.context).isEqualTo(ReflectionContext.SCRIPT_STRING_DQ)
        assertThat(r.probe!!.id).isEqualTo("js-dq")
        assertThat(r.probe!!.injectionProof).isEqualTo("JS_STRING_BREAK")
    }

    @Test
    fun `properly escaped js string with unescaped angle brackets falls back to closing the script tag`() {
        val r = one(FakeApp.reflecting { "<script>var q=\"${jsEscQuotes(it)}\";</script>" })
        assertThat(r.level).isEqualTo(Level.STRUCTURE)
        assertThat(r.probe!!.id).isEqualTo("close:script")
    }

    @Test
    fun `js string with fully escaped value is neutralised`() {
        val r = one(FakeApp.reflecting { "<script>var q=\"${jsEscQuotes(it).replace("<", "\\u003c").replace(">", "\\u003e")}\";</script>" })
        assertThat(r.level).isEqualTo(Level.NEUTRALISED)
    }

    @Test
    fun `comment and textarea contexts`() {
        assertThat(one(FakeApp.reflecting { "<!-- $it -->" }).probe!!.id).isEqualTo("comment-close")
        assertThat(one(FakeApp.reflecting { "<textarea>$it</textarea>" }).probe!!.id).isEqualTo("close:textarea")
    }

    @Test
    fun `json response is not a finding even when reflected`() {
        val r = one(FakeApp.reflecting(contentType = "application/json") { "{\"q\":\"$it\"}" })
        assertThat(r.level).isEqualTo(Level.NEUTRALISED)
        assertThat(r.note).isEqualTo("NOT_HTML")
    }

    @Test
    fun `quote surviving in another context does not count for the attribute`() {
        val r = one(FakeApp.reflecting { "<input value=\"${esc(it)}\"><p>${escLtGt(it)}</p>" })
        assertThat(r.level).isEqualTo(Level.NEUTRALISED)
    }

    @Test
    fun `reflection that disappears on the second request is inconclusive`() {
        val calls = AtomicInteger()
        val r = one(FakeApp.reflecting { if (calls.getAndIncrement() == 0) "<p>$it</p>" else "<p>none</p>" })
        assertThat(r.inconclusive).isEqualTo(InconclusiveReason.UNSTABLE)
        assertThat(r.isFinding).isFalse()
    }

    @Test
    fun `unknown context is inconclusive and never html text`() {
        val r = one(FakeApp.reflecting { "<![CDATA[ $it ]]>" })
        assertThat(r.inconclusive).isEqualTo(InconclusiveReason.UNKNOWN_CONTEXT)
    }

    @Test
    fun `repeated throttling gives up with rate limited and honours the capped retry after`() {
        val r = one { TestJobs.response("", status = 429, headers = mapOf("Retry-After" to "100")) }
        assertThat(r.inconclusive).isEqualTo(InconclusiveReason.RATE_LIMITED)
        assertThat(r.requestsUsed).isEqualTo(3)
        assertThat(sleeps).containsExactly(30_000L, 30_000L)
    }

    @Test
    fun `throttling that clears is retried`() {
        val calls = AtomicInteger()
        val r = one { request ->
            if (calls.getAndIncrement() == 0) TestJobs.response("", status = 429, headers = mapOf("Retry-After" to "2"))
            else FakeApp.reflecting { "<p>$it</p>" }(request)
        }
        assertThat(r.level).isEqualTo(Level.STRUCTURE)
        assertThat(sleeps).containsExactly(2_000L)
    }

    @Test
    fun `network failures become inconclusive and the fifth in a row is rethrown`() {
        val app: (ProbeRequest) -> ProbeResponse = { throw ProbeNetworkException("down") }
        val endpoint = TestJobs.endpoint()
        val run = TestRun(TestJobs.job(endpoint), app)
        val detector = ReflectedXssDetector(run.http, CanaryRegistry())
        val target = ProbeTarget(endpoint, endpoint.parameters.first())
        repeat(4) { assertThat(detector.detect(target).inconclusive).isEqualTo(InconclusiveReason.TARGET_ERROR) }
        assertThatThrownBy { detector.detect(target) }.isInstanceOf(ProbeNetworkException::class.java)
    }

    @Test
    fun `successful response resets the failure counter`() {
        val calls = AtomicInteger()
        val endpoint = TestJobs.endpoint()
        val run = TestRun(TestJobs.job(endpoint)) { request ->
            val n = calls.getAndIncrement()
            if (n in 0..3 || n in 5..8) throw ProbeNetworkException("down") else FakeApp.reflecting { "<p>x</p>" }(request)
        }
        val detector = ReflectedXssDetector(run.http, CanaryRegistry())
        val target = ProbeTarget(endpoint, endpoint.parameters.first())
        repeat(4) { detector.detect(target) }
        assertThat(detector.detect(target).level).isEqualTo(Level.NOT_REFLECTED)
        repeat(4) { assertThat(detector.detect(target).inconclusive).isEqualTo(InconclusiveReason.TARGET_ERROR) }
    }

    @Test
    fun `csp without inline scripts is reported as a mitigation`() {
        val r = one(FakeApp.reflecting(headers = mapOf("Content-Security-Policy" to "default-src 'self'")) { "<p>$it</p>" })
        assertThat(r.level).isEqualTo(Level.STRUCTURE)
        assertThat(r.mitigations).containsExactly("CSP")
    }

    @Test
    fun `csp with unsafe inline is not a mitigation`() {
        val r = one(FakeApp.reflecting(headers = mapOf("Content-Security-Policy" to "script-src 'self' 'unsafe-inline'")) { "<p>$it</p>" })
        assertThat(r.mitigations).isEmpty()
    }

    @Test
    fun `request budget per parameter never exceeds five`() {
        val r = one(FakeApp.reflecting { "<input value=\"$it\"><script>var a='$it';</script>" })
        assertThat(r.requestsUsed).isLessThanOrEqualTo(5)
    }
}
