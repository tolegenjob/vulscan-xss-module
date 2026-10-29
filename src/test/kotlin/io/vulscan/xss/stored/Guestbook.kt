package io.vulscan.xss.stored

import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.HttpMethod
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.XssOptions
import io.vulscan.kit.net.ProbeRequest
import io.vulscan.kit.net.ProbeResponse
import io.vulscan.xss.TestJobs
import java.net.URLDecoder
import java.util.concurrent.CopyOnWriteArrayList

/** Гостевая книга в памяти: POST добавляет запись, GET выводит записи через [render]. */
class Guestbook(
    private val writeStatus: Int = 200,
    private val render: (String) -> String,
) {
    val entries = CopyOnWriteArrayList<String>()
    val posts = CopyOnWriteArrayList<String>()

    val app: (ProbeRequest) -> ProbeResponse = { request ->
        if (request.method == HttpMethod.POST) {
            posts += request.url
            if (writeStatus < 400) entries += URLDecoder.decode(String(request.body!!, Charsets.UTF_8).substringAfter('='), Charsets.UTF_8)
            TestJobs.response("ok", status = writeStatus)
        } else {
            TestJobs.response("<html><body><h1>Гостевая книга</h1>" + entries.joinToString("") { "<div class=\"entry\">${render(it)}</div>" } + "</body></html>")
        }
    }

    companion object {
        fun source(path: String = "add") = TestJobs.endpoint(
            url = "${TestJobs.BASE}/guestbook/$path",
            method = HttpMethod.POST,
            parameters = arrayOf(TestJobs.param("message", ParamLocation.BODY_FORM)),
            idempotent = false,
        )

        fun page(): EndpointRef = TestJobs.endpoint(url = "${TestJobs.BASE}/guestbook", parameters = emptyArray())

        fun options(page: EndpointRef, allowStore: Boolean = true, reflected: Boolean = false) =
            XssOptions(reflected = reflected, stored = true, allowStore = allowStore, observeEndpointIds = listOf(page.endpointId))
    }
}
