package io.vulscan.xss.health

import java.net.HttpURLConnection
import java.net.URI
import kotlin.system.exitProcess

/** Проверка для HEALTHCHECK в Dockerfile: в образе нет curl. */
fun main() {
    val port = System.getenv("HEALTH_PORT") ?: "8081"
    val code = try {
        (URI("http://127.0.0.1:$port/health").toURL().openConnection() as HttpURLConnection).run {
            connectTimeout = 2000
            readTimeout = 2000
            responseCode
        }
    } catch (e: Exception) {
        -1
    }
    exitProcess(if (code == 200) 0 else 1)
}
