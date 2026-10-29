package io.vulscan.xss.job

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ModuleOptions
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.XssOptions
import io.vulscan.xss.TestJobs
import io.vulscan.xss.TestJobs.endpoint
import io.vulscan.xss.TestJobs.param
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test
import java.util.UUID

class XssJobValidatorTest {

    @Test
    fun `valid reflected job passes`() {
        assertThat(XssJobValidator.validate(TestJobs.job(endpoint()))).isEmpty()
    }

    @Test
    fun `job without xss options is invalid`() {
        val job = TestJobs.job(endpoint()).copy(moduleOptions = ModuleOptions())
        assertThat(XssJobValidator.validate(job)).containsExactly("moduleOptions.xss is missing")
    }

    @Test
    fun `reflected and stored both disabled is invalid`() {
        val job = TestJobs.job(endpoint(), options = XssOptions(reflected = false, stored = false))
        assertThat(XssJobValidator.validate(job)).anyMatch { it.contains("at least one") }
    }

    @Test
    fun `stored only without observation pages is invalid`() {
        val job = TestJobs.job(endpoint(), options = XssOptions(reflected = false, stored = true))
        assertThat(XssJobValidator.validate(job)).anyMatch { it.contains("observeEndpointIds") }
    }

    @Test
    fun `stored only with observation pages is valid`() {
        val page = endpoint()
        val job = TestJobs.job(endpoint(), page, options = XssOptions(reflected = false, stored = true, observeEndpointIds = listOf(page.endpointId)))
        assertThat(XssJobValidator.validate(job)).isEmpty()
    }

    @Test
    fun `observation page that is not part of the job is invalid`() {
        val job = TestJobs.job(endpoint(), options = XssOptions(reflected = false, stored = true, observeEndpointIds = listOf(UUID.randomUUID())))
        assertThat(XssJobValidator.validate(job)).anyMatch { it.contains("unknown endpoint") }
    }

    @Test
    fun `endpoint with only header parameters is invalid`() {
        val job = TestJobs.job(endpoint(parameters = arrayOf(param("X-Id", ParamLocation.HEADER))))
        assertThat(XssJobValidator.validate(job)).anyMatch { it.contains("testable parameter") }
    }

    @Test
    fun `body parameter on a GET endpoint is not testable`() {
        val job = TestJobs.job(endpoint(method = HttpMethod.GET, parameters = arrayOf(param("name", ParamLocation.BODY_FORM))))
        assertThat(XssJobValidator.validate(job)).isNotEmpty()
    }

    @Test
    fun `one testable endpoint is enough, others are skipped later`() {
        val job = TestJobs.job(endpoint(parameters = arrayOf(param("X-Id", ParamLocation.HEADER))), endpoint())
        assertThat(XssJobValidator.validate(job)).isEmpty()
    }

    @Test
    fun `path parameter needs a placeholder in the url`() {
        val withoutPlaceholder = TestJobs.job(endpoint(url = "${TestJobs.BASE}/items/1", parameters = arrayOf(param("id", ParamLocation.PATH))))
        assertThat(XssJobValidator.validate(withoutPlaceholder)).isNotEmpty()
        val withPlaceholder = TestJobs.job(endpoint(url = "${TestJobs.BASE}/items/{id}", parameters = arrayOf(param("id", ParamLocation.PATH))))
        assertThat(XssJobValidator.validate(withPlaceholder)).isEmpty()
    }
}
