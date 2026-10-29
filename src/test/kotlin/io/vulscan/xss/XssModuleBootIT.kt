package io.vulscan.xss

import com.sun.net.httpserver.HttpServer
import io.vulscan.kit.contracts.AllowedHost
import io.vulscan.kit.contracts.Envelope
import io.vulscan.kit.contracts.FindingReportedPayload
import io.vulscan.kit.contracts.JobCompletedPayload
import io.vulscan.kit.contracts.JobErrorCode
import io.vulscan.kit.contracts.JobFailedPayload
import io.vulscan.kit.contracts.Json
import io.vulscan.kit.contracts.KafkaTopics
import io.vulscan.kit.contracts.MessageType
import io.vulscan.kit.contracts.ModuleType
import io.vulscan.kit.contracts.ScanJobPayload
import io.vulscan.kit.contracts.ScopeRules
import io.vulscan.kit.contracts.TargetRef
import io.vulscan.kit.contracts.VulnType
import io.vulscan.kit.contracts.XssOptions
import io.vulscan.kit.worker.WorkerProperties
import io.vulscan.kit.worker.WorkerRuntime
import io.vulscan.xss.detect.FakeApp
import org.apache.kafka.clients.consumer.ConsumerConfig
import org.apache.kafka.clients.consumer.KafkaConsumer
import org.apache.kafka.clients.producer.KafkaProducer
import org.apache.kafka.clients.producer.ProducerConfig
import org.apache.kafka.clients.producer.ProducerRecord
import org.apache.kafka.common.serialization.StringDeserializer
import org.apache.kafka.common.serialization.StringSerializer
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assumptions.assumeTrue
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import org.testcontainers.DockerClientFactory
import org.testcontainers.kafka.KafkaContainer
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.URLDecoder
import java.time.Duration
import java.util.Properties
import java.util.UUID
import java.util.concurrent.TimeUnit

/** Сквозная проверка: Kafka (Testcontainers) → рантайм kit → XSS-движок → реальные HTTP-запросы к тестовой цели → события в Kafka. */
class XssModuleBootIT {
    private var kafka: KafkaContainer? = null
    private var core: HttpServer? = null
    private var target: HttpServer? = null
    private var runtime: WorkerRuntime? = null
    private lateinit var producer: KafkaProducer<String, String>

    @BeforeEach
    fun setUp() {
        val docker = runCatching { DockerClientFactory.instance().isDockerAvailable }.getOrDefault(false)
        if (System.getenv("CI") == "true") check(docker) { "Docker is required in CI" } else assumeTrue(docker, "Docker is not available")
        kafka = KafkaContainer("apache/kafka:3.9.1").also { it.start() }
        core = server { ex ->
            ex.requestBody.readBytes()
            val body = if (ex.requestURI.path.endsWith("/claim")) {
                """{"leaseExpiresAt":"2030-01-01T00:00:00Z","heartbeatIntervalSec":1}"""
            } else {
                """{"cancel":false,"leaseExpiresAt":"2030-01-01T00:00:00Z"}"""
            }
            reply(ex, body, "application/json")
        }
        target = HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0).also { server ->
            server.createContext("/xss/search") { ex -> reply(ex, page(ex.requestURI.rawQuery) { it }, "text/html; charset=utf-8") }
            server.createContext("/safe/search") { ex -> reply(ex, page(ex.requestURI.rawQuery) { FakeApp.esc(it) }, "text/html; charset=utf-8") }
            server.start()
        }
        producer = KafkaProducer(
            Properties().apply {
                put(ProducerConfig.BOOTSTRAP_SERVERS_CONFIG, kafka!!.bootstrapServers)
                put(ProducerConfig.KEY_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
                put(ProducerConfig.VALUE_SERIALIZER_CLASS_CONFIG, StringSerializer::class.java.name)
            },
        )
        val props = WorkerProperties(
            coreBaseUrl = "http://127.0.0.1:${core!!.address.port}",
            serviceToken = "tok",
            bootstrapServers = kafka!!.bootstrapServers,
            consumerGroup = "it-" + UUID.randomUUID(),
            maxConcurrentJobs = 1,
            allowedPrivateCidrs = listOf("127.0.0.0/8"),
        )
        runtime = WorkerRuntime.create(XssDetectionEngine(), props).also { it.start() }
    }

    @AfterEach
    fun tearDown() {
        runCatching { runtime?.stop() }
        runCatching { producer.close(Duration.ofSeconds(2)) }
        runCatching { core?.stop(0) }
        runCatching { target?.stop(0) }
        runCatching { kafka?.stop() }
    }

    private fun server(handler: (com.sun.net.httpserver.HttpExchange) -> Unit): HttpServer =
        HttpServer.create(InetSocketAddress(InetAddress.getByName("127.0.0.1"), 0), 0).also {
            it.createContext("/", handler)
            it.start()
        }

    private fun reply(ex: com.sun.net.httpserver.HttpExchange, body: String, contentType: String) {
        val bytes = body.toByteArray()
        ex.responseHeaders.add("Content-Type", contentType)
        ex.sendResponseHeaders(200, bytes.size.toLong())
        ex.responseBody.use { it.write(bytes) }
        ex.close()
    }

    private fun page(rawQuery: String?, render: (String) -> String): String {
        val q = rawQuery.orEmpty().split('&').firstOrNull { it.startsWith("q=") }?.substringAfter("q=")
            ?.let { URLDecoder.decode(it, Charsets.UTF_8) }.orEmpty()
        return "<html><body><p>Результаты: ${render(q)}</p></body></html>"
    }

    private fun job(options: XssOptions, vararg paths: String): ScanJobPayload {
        val port = target!!.address.port
        val base = "http://127.0.0.1:$port"
        val endpoints = paths.map { TestJobs.endpoint(url = "$base$it") }
        val template = TestJobs.job(*endpoints.toTypedArray(), options = options)
        return template.copy(
            target = TargetRef(UUID.randomUUID(), base, listOf(AllowedHost("127.0.0.1", listOf(port)))),
            scope = ScopeRules(listOf("$base/")),
            limits = template.limits.copy(requestsPerSecond = 50, maxConcurrency = 2, httpTimeoutMs = 5000),
        )
    }

    private fun send(job: ScanJobPayload) {
        val message = Json.write(Envelope(type = MessageType.SCAN_JOB, correlationId = UUID.randomUUID(), payload = job))
        producer.send(ProducerRecord(KafkaTopics.jobsFor(ModuleType.XSS), job.jobId.toString(), message)).get(10, TimeUnit.SECONDS)
    }

    private fun readEvents(timeoutSec: Long = 60, until: (List<io.vulscan.kit.contracts.RawEnvelope>) -> Boolean): List<io.vulscan.kit.contracts.RawEnvelope> {
        val consumer = KafkaConsumer<String, String>(
            Properties().apply {
                put(ConsumerConfig.BOOTSTRAP_SERVERS_CONFIG, kafka!!.bootstrapServers)
                put(ConsumerConfig.GROUP_ID_CONFIG, "reader-" + UUID.randomUUID())
                put(ConsumerConfig.KEY_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.VALUE_DESERIALIZER_CLASS_CONFIG, StringDeserializer::class.java.name)
                put(ConsumerConfig.AUTO_OFFSET_RESET_CONFIG, "earliest")
            },
        )
        val events = mutableListOf<io.vulscan.kit.contracts.RawEnvelope>()
        consumer.use {
            it.subscribe(listOf(KafkaTopics.JOB_EVENTS))
            val end = System.currentTimeMillis() + timeoutSec * 1000
            while (System.currentTimeMillis() < end && !until(events)) {
                it.poll(Duration.ofMillis(300)).forEach { r -> events += Json.readEnvelope(r.value()) }
            }
        }
        return events
    }

    private fun done(events: List<io.vulscan.kit.contracts.RawEnvelope>) =
        events.any { it.type == MessageType.JOB_COMPLETED || it.type == MessageType.JOB_FAILED }

    @Test
    fun `vulnerable endpoint is reported once and the safe one is not`() {
        val job = job(XssOptions(), "/xss/search", "/safe/search")
        send(job)
        val events = readEvents { done(it) }

        val findings = events.filter { it.type == MessageType.FINDING_REPORTED }.map { Json.payloadAs(it, FindingReportedPayload::class.java) }
        assertThat(findings).hasSize(1)
        val finding = findings.single().finding
        assertThat(finding.vulnType).isEqualTo(VulnType.XSS_REFLECTED)
        assertThat(finding.url).endsWith("/xss/search")
        assertThat(finding.parameter!!.name).isEqualTo("q")
        assertThat(finding.fingerprint).matches("[0-9a-f]{64}")

        val completed = Json.payloadAs(events.single { it.type == MessageType.JOB_COMPLETED }, JobCompletedPayload::class.java)
        assertThat(completed.jobId).isEqualTo(job.jobId)
        assertThat(completed.stats.findingsCount).isEqualTo(1)
        assertThat(completed.stats.endpointsTested).isEqualTo(2)
        assertThat(completed.stats.requestsSent).isBetween(6, 12)
    }

    @Test
    fun `job without enabled checks fails as invalid and is not retried`() {
        send(job(XssOptions(reflected = false, stored = false), "/xss/search"))
        val events = readEvents { done(it) }
        val failed = Json.payloadAs(events.single { it.type == MessageType.JOB_FAILED }, JobFailedPayload::class.java)
        assertThat(failed.errorCode).isEqualTo(JobErrorCode.INVALID_JOB)
        assertThat(failed.retryable).isFalse()
    }
}
