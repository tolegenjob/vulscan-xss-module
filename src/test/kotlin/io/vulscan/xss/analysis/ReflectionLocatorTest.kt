package io.vulscan.xss.analysis

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ReflectionLocatorTest {
    @Test
    fun `no occurrences`() {
        assertThat(ReflectionLocator.find("<p>nothing</p>", "vsxabc")).isEmpty()
    }

    @Test
    fun `single occurrence`() {
        assertThat(ReflectionLocator.find("<p>vsxabc</p>", "vsxabc").map { it.offset }).containsExactly(3)
    }

    @Test
    fun `several occurrences in order`() {
        val body = "vsxabc<a href=\"vsxabc\">vsxabc</a>"
        assertThat(ReflectionLocator.find(body, "vsxabc").map { it.offset }).containsExactly(0, 16, 24)
    }

    @Test
    fun `overlapping matches are not duplicated`() {
        assertThat(ReflectionLocator.find("aaaaa", "aa").map { it.offset }).containsExactly(0, 2)
    }

    @Test
    fun `html is recognised by media type only`() {
        assertThat(ResponseKind.isHtml("text/html; charset=utf-8")).isTrue()
        assertThat(ResponseKind.isHtml("Application/XHTML+xml")).isTrue()
        assertThat(ResponseKind.isHtml("application/json")).isFalse()
        assertThat(ResponseKind.isHtml("text/plain")).isFalse()
        assertThat(ResponseKind.isHtml(null)).isFalse()
    }
}
