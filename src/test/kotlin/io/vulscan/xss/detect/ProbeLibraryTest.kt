package io.vulscan.xss.detect

import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ProbeLibraryTest {
    private val forbidden = listOf(Regex("(?i)\\bon[a-z]+\\s*="), Regex("(?i)javascript:"), Regex("(?i)<script"), Regex("(?i)<svg"), Regex("(?i)<img"))

    @Test
    fun `library validates itself`() {
        ProbeLibrary.validate()
    }

    @Test
    fun `no probe contains an executable construct`() {
        val sample = "vsxabcdefghij"
        (ProbeLibrary.all().map { it.build(sample) } + CharacterSurvival.payload(sample)).forEach { value ->
            forbidden.forEach { assertThat(it.containsMatchIn(value)).describedAs("$value vs $it").isFalse() }
        }
    }

    @Test
    fun `every probe embeds the canary so reflection can be located`() {
        val sample = "vsxabcdefghij"
        ProbeLibrary.all().forEach { assertThat(it.build(sample)).contains(sample) }
    }

    @Test
    fun `probe ids are unique`() {
        val ids = ProbeLibrary.all().map { it.id }
        assertThat(ids).doesNotHaveDuplicates()
    }

    @Test
    fun `survival analysis separates clusters and context`() {
        val c = "vsxabcdefghij"
        val payload = CharacterSurvival.payload(c)
        val body = "<p>$payload</p><input value=\"" + payload.replace("\"", "&quot;") + "\">"
        val clusters = CharacterSurvival.analyze(body, c)
        assertThat(clusters).hasSize(2)
        assertThat(clusters[0].surviving).contains('"', '<', '>')
        assertThat(clusters[1].surviving).doesNotContain('"')
    }

    @Test
    fun `mitigation parser handles nonce and missing script source`() {
        assertThat(Mitigations.of(mapOf("content-security-policy" to "script-src 'unsafe-inline' 'nonce-abc'"))).containsExactly("CSP")
        assertThat(Mitigations.of(mapOf("content-security-policy" to "img-src *"))).isEmpty()
        assertThat(Mitigations.of(emptyMap())).isEmpty()
    }
}
