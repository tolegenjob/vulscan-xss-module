package io.vulscan.xss

import com.sun.net.httpserver.HttpServer
import io.vulscan.kit.worker.WorkerRuntime
import io.vulscan.xss.config.XssProperties
import org.slf4j.LoggerFactory
import java.net.InetSocketAddress
import java.util.concurrent.CountDownLatch

fun main() {
    val log = LoggerFactory.getLogger("io.vulscan.xss.Main")
    val env = System.getenv()
    val xss = XssProperties.fromEnv(env)
    val worker = XssProperties.workerFromEnv(env)

    val runtime = WorkerRuntime.create(XssDetectionEngine(xss), worker)
    runtime.start()

    val health = HttpServer.create(InetSocketAddress(xss.healthPort), 0).apply {
        createContext("/health") { ex ->
            val body = """{"status":"UP"}""".toByteArray()
            ex.responseHeaders.add("Content-Type", "application/json")
            ex.sendResponseHeaders(200, body.size.toLong())
            ex.responseBody.use { it.write(body) }
        }
        start()
    }

    val stop = CountDownLatch(1)
    Runtime.getRuntime().addShutdownHook(
        Thread {
            log.info("Shutting down")
            health.stop(0)
            runtime.stop()
            stop.countDown()
        },
    )
    log.info("XSS module started, workerId={}", worker.workerId)
    stop.await()
}
