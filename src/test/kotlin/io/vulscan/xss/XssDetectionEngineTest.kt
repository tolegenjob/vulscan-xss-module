package io.vulscan.xss

import io.vulscan.kit.contracts.XssOptions
import io.vulscan.kit.worker.InvalidJobException
import io.vulscan.xss.TestJobs.endpoint
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class XssDetectionEngineTest {
    @Test
    fun `invalid job is rejected with InvalidJobException`() {
        val job = TestJobs.job(endpoint(), options = XssOptions(reflected = false, stored = false))
        val run = TestRun(job) { TestJobs.response("") }
        assertThatThrownBy { XssDetectionEngine().run(run.ctx) }.isInstanceOf(InvalidJobException::class.java)
        assertThat(run.requests).isEmpty()
    }
}
