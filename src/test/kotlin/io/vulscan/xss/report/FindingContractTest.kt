package io.vulscan.xss.report

import com.networknt.schema.InputFormat
import com.networknt.schema.SchemaLocation
import com.networknt.schema.SchemaRegistry
import com.networknt.schema.SpecificationVersion
import io.vulscan.kit.contracts.Envelope
import io.vulscan.kit.contracts.FindingPayload
import io.vulscan.kit.contracts.FindingReportedPayload
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.MessageType
import io.vulscan.kit.worker.FindingSanitizer
import io.vulscan.xss.TestJobs
import io.vulscan.xss.detect.FakeApp
import io.vulscan.xss.report.ReportTestSupport.detect
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import org.junit.jupiter.params.ParameterizedTest
import org.junit.jupiter.params.provider.Arguments
import org.junit.jupiter.params.provider.Arguments.arguments
import org.junit.jupiter.params.provider.MethodSource
import java.util.UUID
import java.util.stream.Stream

/** Все findings модуля должны соответствовать JSON-схеме finding-reported.v1 из kit. */
class FindingContractTest {
    companion object {
        private val registry = SchemaRegistry.withDefaultDialect(SpecificationVersion.DRAFT_2020_12)

        private fun errors(finding: FindingPayload): List<String> {
            val envelope = Envelope(
                type = MessageType.FINDING_REPORTED,
                correlationId = UUID.randomUUID(),
                payload = FindingReportedPayload(UUID.randomUUID(), 1, FindingSanitizer.apply(finding)),
            )
            val schema = registry.getSchema(SchemaLocation.of("classpath:schemas/finding-reported.v1.json"))
            return schema.validate(Json.write(envelope), InputFormat.JSON).map { it.toString() }
        }

        @JvmStatic
        fun scenarios(): Stream<Arguments> = Stream.of(
            arguments("html text", FakeApp.reflecting { "<p>$it</p>" }),
            arguments("attribute", FakeApp.reflecting { "<input value=\"$it\">" }),
            arguments("js string", FakeApp.reflecting { "<script>var a=\"$it\";</script>" }),
            arguments("script close", FakeApp.reflecting { "<script>var a=\"${FakeApp.jsEscQuotes(it)}\";</script>" }),
            arguments("comment", FakeApp.reflecting { "<!-- $it -->" }),
            arguments("survives only", FakeApp.reflecting { "<p>${it.replace("vsxtag", "")}</p>" }),
            arguments("with csp", FakeApp.reflecting(headers = mapOf("Content-Security-Policy" to "default-src 'self'")) { "<p>$it</p>" }),
        )
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("scenarios")
    fun `finding conforms to the schema`(name: String, app: (io.vulscan.kit.net.ProbeRequest) -> io.vulscan.kit.net.ProbeResponse) {
        val result = detect(app = app)
        assertThat(result.isFinding).describedAs("scenario $name must produce a finding").isTrue()
        assertThat(errors(XssFindingFactory.create(result))).isEmpty()
    }

    @Test
    fun `finding with a path parameter and body excerpt conforms to the schema`() {
        val endpoint = TestJobs.endpoint(url = "http://lab-app:8080/xss/post")
        val result = detect(url = endpoint.url, app = FakeApp.reflecting { "<p>$it</p>" })
        assertThat(errors(XssFindingFactory.create(result))).isEmpty()
    }
}
