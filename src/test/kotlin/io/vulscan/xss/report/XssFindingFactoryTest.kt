package io.vulscan.xss.report

import io.vulscan.kit.contracts.Severity
import io.vulscan.kit.contracts.Verdict
import io.vulscan.kit.contracts.VulnType
import io.vulscan.kit.contracts.XssDetails
import io.vulscan.kit.worker.FindingSanitizer
import io.vulscan.xss.TestJobs
import io.vulscan.xss.analysis.ReflectionContext
import io.vulscan.xss.analysis.ReflectionPoint
import io.vulscan.xss.detect.DetectionResult
import io.vulscan.xss.detect.FakeApp
import io.vulscan.xss.detect.Level
import io.vulscan.xss.plan.ProbeTarget
import io.vulscan.xss.report.ReportTestSupport.detect
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class XssFindingFactoryTest {
    private fun structure(headers: Map<String, String> = emptyMap(), status: Int = 200) =
        detect(app = { request ->
            val q = okhttp3.HttpUrl.Companion.run { request.url.toHttpUrl() }.queryParameter("q") ?: ""
            TestJobs.response("<p>$q</p>", status = status, headers = headers)
        })

    private fun suspected() = detect(app = FakeApp.reflecting { "<p>${it.replace("vsxtag", "")}</p>" })

    @Test
    fun `structure proof gives a likely medium finding in russian`() {
        val result = structure()
        assertThat(result.level).isEqualTo(Level.STRUCTURE)
        val f = XssFindingFactory.create(result)
        assertThat(f.verdict).isEqualTo(Verdict.LIKELY)
        assertThat(f.severity).isEqualTo(Severity.MEDIUM)
        assertThat(f.confidence).isEqualTo(75)
        assertThat(f.cwe).isEqualTo("CWE-79")
        assertThat(f.vulnType).isEqualTo(VulnType.XSS_REFLECTED)
        assertThat(f.title).isEqualTo("Отражённый XSS: параметр q (текст HTML)")
        assertThat(f.summary).contains("Разбор DOM").contains("не проверялось")
        assertThat(f.recommendation).contains("Кодируйте")
        val details = f.details as XssDetails
        assertThat(details.context).isEqualTo("HTML_TEXT")
        assertThat(details.injectionProof).isEqualTo("DOM_STRUCTURE")
        assertThat(details.survivingChars).contains("<", ">")
        assertThat(f.parameter!!.name).isEqualTo("q")
        assertThat(f.url).isEqualTo("${TestJobs.BASE}/xss/search")
    }

    @Test
    fun `surviving characters without proof give a suspected low finding`() {
        val result = suspected()
        assertThat(result.level).isEqualTo(Level.SURVIVES)
        val f = XssFindingFactory.create(result)
        assertThat(f.verdict).isEqualTo(Verdict.SUSPECTED)
        assertThat(f.severity).isEqualTo(Severity.LOW)
        assertThat(f.confidence).isEqualTo(35)
        assertThat((f.details as XssDetails).injectionProof).isEqualTo("NONE")
    }

    @Test
    fun `csp lowers severity and confidence`() {
        val f = XssFindingFactory.create(structure(headers = mapOf("Content-Security-Policy" to "default-src 'self'")))
        assertThat(f.severity).isEqualTo(Severity.LOW)
        assertThat(f.confidence).isEqualTo(65)
        assertThat((f.details as XssDetails).mitigations).containsExactly("CSP")
        assertThat(f.summary).contains("Content-Security-Policy")
    }

    @Test
    fun `error status lowers confidence`() {
        assertThat(XssFindingFactory.create(structure(status = 404)).confidence).isEqualTo(60)
    }

    @Test
    fun `severity is never critical`() {
        val severities = listOf(structure(), suspected(), structure(headers = mapOf("Content-Security-Policy" to "default-src 'self'")))
            .map { XssFindingFactory.create(it).severity }
        assertThat(severities).doesNotContain(Severity.CRITICAL, Severity.HIGH)
    }

    @Test
    fun `observations explain how the confidence was reached`() {
        val f = XssFindingFactory.create(structure(status = 404))
        val byKey = f.evidence.observations.associate { it.key to it.value }
        assertThat(byKey["confidenceBase"]).isEqualTo("70")
        assertThat(byKey["confidenceAdjustments"]).isEqualTo("stable_reflection:+5;error_status:-15")
        assertThat(byKey["probe"]).isEqualTo("tag")
        assertThat(byKey["level"]).isEqualTo("L3_STRUCTURE")
    }

    @Test
    fun `finding passes the kit sanitizer and keeps its highlights`() {
        val f = FindingSanitizer.apply(XssFindingFactory.create(structure()))
        val response = f.evidence.response!!
        assertThat(response.highlights).isNotEmpty()
        response.highlights.forEach { h ->
            assertThat(h.start).isGreaterThanOrEqualTo(0)
            assertThat(h.end).isLessThanOrEqualTo(response.bodyExcerpt!!.length)
        }
    }

    // --- fingerprint ---

    private fun result(url: String, context: ReflectionContext = ReflectionContext.HTML_TEXT, name: String = "q"): DetectionResult {
        val endpoint = TestJobs.endpoint(url = url, parameters = arrayOf(TestJobs.param(name)))
        return DetectionResult(ProbeTarget(endpoint, endpoint.parameters.first()), Level.SURVIVES, point = ReflectionPoint(0, context, null, null, null))
    }

    @Test
    fun `fingerprint is a stable sha-256 hex`() {
        val a = XssFindingFactory.fingerprint(result("http://lab-app:8080/xss/search"))
        assertThat(a).matches("[0-9a-f]{64}")
        assertThat(XssFindingFactory.fingerprint(result("http://other-host:9090/xss/search"))).isEqualTo(a)
    }

    @Test
    fun `fingerprint depends on path, parameter and context class`() {
        val base = XssFindingFactory.fingerprint(result("http://h/a"))
        assertThat(XssFindingFactory.fingerprint(result("http://h/b"))).isNotEqualTo(base)
        assertThat(XssFindingFactory.fingerprint(result("http://h/a", name = "p"))).isNotEqualTo(base)
        assertThat(XssFindingFactory.fingerprint(result("http://h/a", ReflectionContext.ATTR_DOUBLE_QUOTED))).isNotEqualTo(base)
    }

    @Test
    fun `quote style does not change the fingerprint but query names are order independent`() {
        val dq = XssFindingFactory.fingerprint(result("http://h/a", ReflectionContext.ATTR_DOUBLE_QUOTED))
        val sq = XssFindingFactory.fingerprint(result("http://h/a", ReflectionContext.ATTR_SINGLE_QUOTED))
        assertThat(dq).isEqualTo(sq)
        val one = XssFindingFactory.fingerprint(result("http://h/a?b=1&a=2"))
        val two = XssFindingFactory.fingerprint(result("http://h/a?a=9&b=7"))
        assertThat(one).isEqualTo(two)
        assertThat(one).isNotEqualTo(XssFindingFactory.fingerprint(result("http://h/a")))
    }
}
