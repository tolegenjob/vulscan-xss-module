package io.vulscan.xss.detect

import io.vulscan.kit.net.ProbeResponse
import java.nio.charset.Charset

/** Доступ к заголовкам и тексту ответа без зависимости от регистра имён. */
object HttpText {
    fun header(response: ProbeResponse, name: String): String? =
        response.headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value

    fun contentType(response: ProbeResponse): String? = header(response, "content-type")

    fun decode(response: ProbeResponse): String {
        val charset = contentType(response)
            ?.let { Regex("charset=\"?([A-Za-z0-9_.:-]+)", RegexOption.IGNORE_CASE).find(it)?.groupValues?.get(1) }
            ?.let { runCatching { Charset.forName(it) }.getOrNull() } ?: Charsets.UTF_8
        return String(response.body, charset)
    }
}
