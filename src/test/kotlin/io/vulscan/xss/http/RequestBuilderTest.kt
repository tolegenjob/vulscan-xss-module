package io.vulscan.xss.http

import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.xss.TestJobs.BASE
import io.vulscan.xss.TestJobs.endpoint
import io.vulscan.xss.TestJobs.param
import org.assertj.core.api.Assertions.assertThat
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test

class RequestBuilderTest {

    @Test
    fun `query value lands in the right parameter, special characters are encoded, others keep their sample`() {
        val e = endpoint(parameters = arrayOf(param("q"), param("page", sample = "2")))
        val r = RequestBuilder.build(e, e.parameters[0], "a<b>\"c' d")
        assertThat(r.url).startsWith("$BASE/xss/search?")
        assertThat(r.url).contains("q=a%3Cb%3E%22c%27%20d").contains("page=2")
        assertThat(r.url).doesNotContain("<").doesNotContain("\"")
        assertThat(r.method).isEqualTo(HttpMethod.GET)
        assertThat(r.body).isNull()
    }

    @Test
    fun `values already present in the url query are kept and the target is replaced`() {
        val e = endpoint(url = "$BASE/s?q=old&lang=ru", parameters = arrayOf(param("q"), param("lang", sample = "en")))
        val r = RequestBuilder.build(e, e.parameters[0], "NEW")
        assertThat(r.url).contains("q=NEW").contains("lang=ru").doesNotContain("q=old")
    }

    @Test
    fun `form body encodes the target and keeps other fields`() {
        val e = endpoint(url = "$BASE/f", method = HttpMethod.POST, parameters = arrayOf(param("name", ParamLocation.BODY_FORM), param("age", ParamLocation.BODY_FORM, "30")))
        val r = RequestBuilder.build(e, e.parameters[0], "a b&c=d")
        assertThat(r.body!!.toString(Charsets.UTF_8)).isEqualTo("name=a+b%26c%3Dd&age=30")
        assertThat(r.contentType).isEqualTo("application/x-www-form-urlencoded")
    }

    @Test
    fun `json body puts the value into a string field by path and keeps typed samples`() {
        val e = endpoint(
            url = "$BASE/j",
            method = HttpMethod.POST,
            parameters = arrayOf(
                param("user.name", ParamLocation.BODY_JSON),
                param("user.age", ParamLocation.BODY_JSON, "30"),
                param("active", ParamLocation.BODY_JSON, "true"),
                param("note", ParamLocation.BODY_JSON, "hi"),
            ),
        )
        val r = RequestBuilder.build(e, e.parameters[0], "x\"y\\z")
        assertThat(r.body!!.toString(Charsets.UTF_8)).isEqualTo("""{"user":{"name":"x\"y\\z","age":30},"active":true,"note":"hi"}""")
        assertThat(r.contentType).isEqualTo("application/json")
    }

    @Test
    fun `path placeholder is replaced by the encoded value, other placeholders use their sample`() {
        val e = endpoint(
            url = "$BASE/u/{uid}/posts/{pid}",
            parameters = arrayOf(param("uid", ParamLocation.PATH, "7"), param("pid", ParamLocation.PATH, null)),
        )
        val r = RequestBuilder.build(e, e.parameters[0], "a/b<c>")
        assertThat(r.url).isEqualTo("$BASE/u/a%2Fb%3Cc%3E/posts/1")
    }

    @Test
    fun `plain alphanumeric canary is not altered by encoding`() {
        val e = endpoint(url = "$BASE/u/{uid}", parameters = arrayOf(param("uid", ParamLocation.PATH)))
        assertThat(RequestBuilder.build(e, e.parameters[0], "vsxabc123").url).endsWith("/u/vsxabc123")
    }

    @Test
    fun `header and cookie parameters are rejected`() {
        val e = endpoint(parameters = arrayOf(param("X-Id", ParamLocation.HEADER)))
        assertThatThrownBy { RequestBuilder.build(e, e.parameters[0], "v") }.isInstanceOf(IllegalArgumentException::class.java)
    }

    @Test
    fun `json quoting escapes control characters`() {
        assertThat(RequestBuilder.quote("a\nb\u0001")).isEqualTo("\"a\\nb\\u0001\"")
    }
}
