package io.vulscan.xss.canary

import io.vulscan.kit.contracts.ParamLocation
import java.util.UUID
import java.util.concurrent.ConcurrentHashMap

data class CanaryOrigin(val endpointId: UUID, val parameterName: String, val location: ParamLocation)

/** Помнит, из какого параметра пришла каждая канарейка; значения уникальны в пределах задания. */
class CanaryRegistry(private val factory: CanaryFactory = CanaryFactory()) {
    private val origins = ConcurrentHashMap<String, CanaryOrigin>()

    fun create(origin: CanaryOrigin): String {
        while (true) {
            val canary = factory.next()
            if (origins.putIfAbsent(canary, origin) == null) return canary
        }
    }

    fun originOf(canary: String): CanaryOrigin? = origins[canary]

    val size: Int get() = origins.size
}
