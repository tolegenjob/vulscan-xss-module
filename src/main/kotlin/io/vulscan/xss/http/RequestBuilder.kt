package io.vulscan.xss.http

import io.vulscan.kit.contracts.EndpointRef
import io.vulscan.kit.contracts.ParamLocation
import io.vulscan.kit.contracts.ParameterRef
import io.vulscan.kit.net.ProbeRequest
import okhttp3.HttpUrl.Companion.toHttpUrl
import java.net.URLEncoder

/** Подставляет значение в нужное место запроса; остальные параметры получают `sampleValue`. */
object RequestBuilder {
    const val ACCEPT = "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8"

    fun build(endpoint: EndpointRef, target: ParameterRef, value: String): ProbeRequest {
        require(target.location in SUPPORTED) { "Unsupported parameter location ${target.location}" }
        val headers = mapOf("Accept" to ACCEPT)
        val url = buildUrl(endpoint, target, value)
        return when (target.location) {
            ParamLocation.BODY_FORM -> ProbeRequest(
                endpoint.method, url, headers,
                body = formBody(endpoint, target, value).toByteArray(Charsets.UTF_8),
                contentType = "application/x-www-form-urlencoded",
            )
            ParamLocation.BODY_JSON -> ProbeRequest(
                endpoint.method, url, headers,
                body = jsonBody(endpoint, target, value).toByteArray(Charsets.UTF_8),
                contentType = "application/json",
            )
            else -> ProbeRequest(endpoint.method, url, headers)
        }
    }

    private val SUPPORTED = setOf(ParamLocation.QUERY, ParamLocation.BODY_FORM, ParamLocation.BODY_JSON, ParamLocation.PATH)

    private fun same(a: ParameterRef, b: ParameterRef) = a.name == b.name && a.location == b.location

    private fun buildUrl(endpoint: EndpointRef, target: ParameterRef, value: String): String {
        var raw = endpoint.url
        for (p in endpoint.parameters.filter { it.location == ParamLocation.PATH }) {
            val replacement = if (same(p, target)) value else (p.sampleValue ?: "1")
            raw = raw.replace("{${p.name}}", pathEncode(replacement))
        }
        val parsed = raw.toHttpUrl()
        val builder = parsed.newBuilder()
        val present = parsed.queryParameterNames
        for (p in endpoint.parameters.filter { it.location == ParamLocation.QUERY }) {
            if (same(p, target)) builder.setQueryParameter(p.name, value)
            else if (p.name !in present && p.sampleValue != null) builder.addQueryParameter(p.name, p.sampleValue)
        }
        return builder.build().toString()
    }

    private fun formBody(endpoint: EndpointRef, target: ParameterRef, value: String): String =
        endpoint.parameters.filter { it.location == ParamLocation.BODY_FORM }.joinToString("&") { p ->
            val v = if (same(p, target)) value else (p.sampleValue ?: "")
            URLEncoder.encode(p.name, Charsets.UTF_8) + "=" + URLEncoder.encode(v, Charsets.UTF_8)
        }

    private fun jsonBody(endpoint: EndpointRef, target: ParameterRef, value: String): String {
        val root = LinkedHashMap<String, Any>()
        for (p in endpoint.parameters.filter { it.location == ParamLocation.BODY_JSON }) {
            val leaf: Any = if (same(p, target)) Leaf(quote(value)) else Leaf(sampleLiteral(p.sampleValue))
            insert(root, p.name.split('.').filter { it.isNotEmpty() }.ifEmpty { listOf(p.name) }, leaf)
        }
        return render(root)
    }

    private class Leaf(val json: String)

    @Suppress("UNCHECKED_CAST")
    private fun insert(node: MutableMap<String, Any>, path: List<String>, leaf: Leaf) {
        var current = node
        path.dropLast(1).forEach { key ->
            val next = current[key]
            current = if (next is MutableMap<*, *>) next as MutableMap<String, Any> else LinkedHashMap<String, Any>().also { current[key] = it }
        }
        current[path.last()] = leaf
    }

    @Suppress("UNCHECKED_CAST")
    private fun render(node: Any): String = when (node) {
        is Leaf -> node.json
        is Map<*, *> -> (node as Map<String, Any>).entries.joinToString(",", "{", "}") { (k, v) -> "${quote(k)}:${render(v)}" }
        else -> "null"
    }

    /** Числа и булевы значения из примера сохраняют тип, остальное — строка. */
    private fun sampleLiteral(sample: String?): String = when {
        sample == null -> "\"\""
        sample.matches(Regex("-?\\d{1,15}(\\.\\d{1,15})?")) || sample == "true" || sample == "false" -> sample
        else -> quote(sample)
    }

    fun quote(text: String): String = buildString {
        append('"')
        for (c in text) {
            when {
                c == '"' -> append("\\\"")
                c == '\\' -> append("\\\\")
                c == '\n' -> append("\\n")
                c == '\r' -> append("\\r")
                c == '\t' -> append("\\t")
                c < ' ' -> append("\\u%04x".format(c.code))
                else -> append(c)
            }
        }
        append('"')
    }

    /** Кодирует всё, кроме unreserved-символов RFC 3986. */
    fun pathEncode(text: String): String = buildString {
        for (b in text.toByteArray(Charsets.UTF_8)) {
            val c = b.toInt().toChar()
            if (b >= 0 && (c.isLetterOrDigit() && c.code < 128 || c in "-._~")) append(c) else append('%').append("%02X".format(b.toInt() and 0xff))
        }
    }
}
