package io.vulscan.xss.config

import io.vulscan.kit.worker.WorkerProperties

/** Настройки модуля (переменные окружения, см. README). */
data class XssProperties(
    val maxParamsPerEndpoint: Int = 10,
    val repeatReflectionCheck: Boolean = true,
    val healthPort: Int = 8081,
) {
    init {
        require(maxParamsPerEndpoint > 0) { "maxParamsPerEndpoint must be positive" }
    }

    companion object {
        fun fromEnv(env: Map<String, String>) = XssProperties(
            maxParamsPerEndpoint = env["XSS_MAX_PARAMS_PER_ENDPOINT"]?.toIntOrNull() ?: 10,
            repeatReflectionCheck = env["XSS_REPEAT_REFLECTION_CHECK"]?.toBooleanStrictOrNull() ?: true,
            healthPort = env["HEALTH_PORT"]?.toIntOrNull() ?: 8081,
        )

        fun workerFromEnv(env: Map<String, String>): WorkerProperties {
            fun required(name: String) = env[name]?.takeIf { it.isNotBlank() } ?: error("Environment variable $name is required")
            return WorkerProperties(
                coreBaseUrl = required("WORKER_CORE_BASE_URL"),
                serviceToken = required("WORKER_SERVICE_TOKEN"),
                bootstrapServers = env["KAFKA_BOOTSTRAP_SERVERS"] ?: "kafka:9092",
                consumerGroup = env["WORKER_CONSUMER_GROUP"] ?: "xss-module",
                workerId = env["WORKER_ID"] ?: ("xss-" + java.util.UUID.randomUUID().toString().take(8)),
                maxConcurrentJobs = env["WORKER_MAX_CONCURRENT_JOBS"]?.toIntOrNull() ?: 2,
                allowedPrivateCidrs = env["WORKER_ALLOWED_PRIVATE_CIDRS"]
                    ?.split(',')?.map { it.trim() }?.filter { it.isNotEmpty() } ?: emptyList(),
            )
        }
    }
}
