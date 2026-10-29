package io.vulscan.xss.canary

import io.vulscan.kit.contracts.ParamLocation
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class CanaryFactoryTest {
    @Test
    fun `canary has the documented format and only safe characters`() {
        val factory = CanaryFactory()
        repeat(1000) {
            val c = factory.next()
            assertThat(c).matches(CanaryFactory.FORMAT.pattern)
            assertThat(c).hasSize(13)
        }
    }

    @Test
    fun `ten thousand canaries do not collide`() {
        val factory = CanaryFactory()
        val values = List(10_000) { factory.next() }
        assertThat(values.toSet()).hasSize(10_000)
    }

    @Test
    fun `registry remembers the origin and never hands out a duplicate`() {
        // генератор, который сначала повторяется: реестр обязан пропустить дубликат
        val fixed = object : java.util.Random() {
            private var calls = 0
            override fun nextInt(bound: Int): Int = if (calls++ < 20) 0 else calls % bound
        }
        val registry = CanaryRegistry(CanaryFactory(fixed))
        val a = registry.create(CanaryOrigin(UUID.randomUUID(), "q", ParamLocation.QUERY))
        val b = registry.create(CanaryOrigin(UUID.randomUUID(), "r", ParamLocation.QUERY))
        assertThat(a).isNotEqualTo(b)
        assertThat(registry.originOf(a)?.parameterName).isEqualTo("q")
        assertThat(registry.originOf(b)?.parameterName).isEqualTo("r")
        assertThat(registry.size).isEqualTo(2)
    }
}
