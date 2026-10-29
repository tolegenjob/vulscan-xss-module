package io.vulscan.xss.detect

import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.xss.TestJobs
import okhttp3.HttpUrl.Companion.toHttpUrl

/** Простое приложение: страницу строит [page] из значения параметра `q`. */
object FakeApp {
    fun reflecting(
        contentType: String? = "text/html; charset=utf-8",
        headers: Map<String, String> = emptyMap(),
        page: (String) -> String,
    ): (ProbeRequest) -> ProbeResponse = { request ->
        val q = request.url.toHttpUrl().queryParameter("q") ?: ""
        TestJobs.response(page(q), contentType = contentType, headers = headers)
    }

    fun esc(s: String) = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace("\"", "&quot;").replace("'", "&#39;")

    fun escLtGt(s: String) = s.replace("<", "&lt;").replace(">", "&gt;")

    fun jsEscQuotes(s: String) = s.replace("\\", "\\\\").replace("\"", "\\\"").replace("'", "\\'").replace("`", "\\`")
}
