package io.vulscan.xss.plan

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.xss.TestJobs.BASE
import io.vulscan.xss.TestJobs.endpoint
import io.vulscan.xss.TestJobs.param
import org.assertj.core.api.Assertions.assertThat
import org.junit.jupiter.api.Test

class ParameterPlannerTest {
    private val planner = ParameterPlanner(maxParamsPerEndpoint = 10)

    @Test
    fun `every parameter gets five requests and the plan fits the budget`() {
        val endpoints = listOf(endpoint(parameters = arrayOf(param("a"), param("b"))), endpoint(url = "$BASE/x", parameters = arrayOf(param("c"))))
        val plan = planner.plan(endpoints, maxRequests = 600)
        assertThat(plan.targets).hasSize(3)
        assertThat(plan.targets.sumOf { it.estimatedRequests }).isEqualTo(15)
        assertThat(plan.skipped).isEmpty()
    }

    @Test
    fun `with a budget of 12 only two parameters are chosen by priority, the rest are skipped for BUDGET`() {
        val e1 = endpoint(url = "$BASE/a/{p}", method = HttpMethod.POST, parameters = arrayOf(param("p", ParamLocation.PATH), param("j", ParamLocation.BODY_JSON)))
        val e2 = endpoint(url = "$BASE/b", method = HttpMethod.POST, parameters = arrayOf(param("f", ParamLocation.BODY_FORM), param("q1")))
        val e3 = endpoint(url = "$BASE/c", parameters = arrayOf(param("q2")))
        val plan = planner.plan(listOf(e1, e2, e3), maxRequests = 12)
        assertThat(plan.targets.map { it.parameter.name }).containsExactlyInAnyOrder("q1", "q2")
        assertThat(plan.skipped.map { it.endpointId to it.reason }).containsExactly(e1.endpointId to "BUDGET")
        assertThat(plan.targets.sumOf { it.estimatedRequests }).isLessThanOrEqualTo(12)
    }

    @Test
    fun `selected targets keep the endpoint order`() {
        val e1 = endpoint(url = "$BASE/1", parameters = arrayOf(param("a")))
        val e2 = endpoint(url = "$BASE/2", parameters = arrayOf(param("b")))
        val plan = planner.plan(listOf(e1, e2), 600)
        assertThat(plan.targets.map { it.endpoint.endpointId }).containsExactly(e1.endpointId, e2.endpointId)
    }

    @Test
    fun `within an endpoint QUERY goes before BODY_FORM before BODY_JSON before PATH`() {
        val e = endpoint(
            url = "$BASE/m/{p}",
            method = HttpMethod.POST,
            parameters = arrayOf(param("p", ParamLocation.PATH), param("j", ParamLocation.BODY_JSON), param("f", ParamLocation.BODY_FORM), param("q")),
        )
        val plan = planner.plan(listOf(e), 600)
        assertThat(plan.targets.map { it.parameter.name }).containsExactly("q", "f", "j", "p")
    }

    @Test
    fun `at most maxParamsPerEndpoint parameters are planned per endpoint`() {
        val e = endpoint(parameters = Array(15) { param("p$it") })
        val plan = ParameterPlanner(maxParamsPerEndpoint = 10).plan(listOf(e), 600)
        assertThat(plan.targets).hasSize(10)
    }

    @Test
    fun `unsupported endpoints are skipped with a reason and never fail the plan`() {
        val header = endpoint(url = "$BASE/h", parameters = arrayOf(param("X-Id", ParamLocation.HEADER)))
        val none = endpoint(url = "$BASE/n", parameters = emptyArray())
        val noPlaceholder = endpoint(url = "$BASE/i/1", parameters = arrayOf(param("id", ParamLocation.PATH)))
        val ok = endpoint()
        val plan = planner.plan(listOf(header, none, noPlaceholder, ok), 600)
        assertThat(plan.targets).hasSize(1)
        assertThat(plan.skipped.associate { it.endpointId to it.reason }).containsEntry(header.endpointId, "UNSUPPORTED_LOCATION")
            .containsEntry(none.endpointId, "NO_PARAMETERS")
            .containsEntry(noPlaceholder.endpointId, "PATH_PLACEHOLDER_MISSING")
    }

    @Test
    fun `plan never exceeds the budget for any budget size`() {
        val endpoints = List(7) { i -> endpoint(url = "$BASE/e$i", parameters = Array(4) { j -> param("p$j") }) }
        for (budget in 0..200) {
            val plan = planner.plan(endpoints, budget)
            assertThat(plan.targets.sumOf { it.estimatedRequests }).isLessThanOrEqualTo(budget)
        }
    }

    @Test
    fun `plan is deterministic`() {
        val endpoints = List(3) { i -> endpoint(url = "$BASE/e$i", parameters = arrayOf(param("a"), param("b"))) }
        assertThat(planner.plan(endpoints, 20)).isEqualTo(planner.plan(endpoints, 20))
    }
}
