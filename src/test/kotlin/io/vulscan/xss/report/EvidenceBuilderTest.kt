package io.vulscan.xss.report

import io.vulscan.xss.detect.FakeApp
import io.vulscan.xss.report.ReportTestSupport.detect
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class EvidenceBuilderTest {
    private fun evidence(prefix: String, suffix: String) =
        EvidenceBuilder.build(detect(app = FakeApp.reflecting { "$prefix<p>$it</p>$suffix" }), emptyList())

    @Test
    fun `excerpt is a window around the injected value and the highlight covers it`() {
        val e = evidence("A".repeat(900), "B".repeat(900))
        val response = e.response!!
        val excerpt = response.bodyExcerpt!!
        assertThat(excerpt.length).isLessThanOrEqualTo(2048)
        assertThat(excerpt).startsWith("A".repeat(200).takeLast(194))
        val h = response.highlights.first()
        assertThat(excerpt.substring(h.start, h.end)).contains("<vsxtag id=vsx")
        assertThat(h.start).isEqualTo(194 + 3) // 200 символов окна минус 6 символов «<p>» и т.п. проверяются ниже
    }

    @Test
    fun `highlights count utf-16 units when the text has cyrillic and surrogate pairs`() {
        val e = evidence("Поиск 😀 Привет ", " Конец 😀")
        val response = e.response!!
        val excerpt = response.bodyExcerpt!!
        response.highlights.forEach { h ->
            assertThat(h.start).isGreaterThanOrEqualTo(0)
            assertThat(h.end).isLessThanOrEqualTo(excerpt.length)
            assertThat(excerpt.substring(h.start, h.end)).startsWith("vsx")
        }
        assertThat(response.highlights).isNotEmpty()
    }

    @Test
    fun `request evidence carries the probe url and only useful response headers`() {
        val result = detect(app = FakeApp.reflecting(headers = mapOf("Set-Cookie" to "sid=1", "X-Other" to "1", "Content-Security-Policy" to "img-src *")) { "<p>$it</p>" })
        val e = EvidenceBuilder.build(result, emptyList())
        assertThat(e.request.url).contains("q=vsx")
        assertThat(e.response!!.headers.keys.map { it.lowercase() }).containsExactlyInAnyOrder("content-type", "content-security-policy")
    }
}
